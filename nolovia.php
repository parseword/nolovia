<?php
/*
 * Copyright 2015-2017 Shaun Cummiskey, <shaun@shaunc.com> <http://shaunc.com>
 * <https://github.com/ampersign/nolovia>
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 * 
 * http://www.apache.org/licenses/LICENSE-2.0
 * 
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and 
 * limitations under the License.
 * 
 * This script fetches and makes use of server lists compiled by: 
 *
 * Jason Lam at http://www.networksec.org/grabbho/block.txt
 * Peter Lowe at http://pgl.yoyo.org/adservers/
 * Malwarebytes at https://hosts-file.net/?s=Download
 * Dan Pollock at http://someonewhocares.org/hosts/
 * Ransomware Tracker at https://ransomwaretracker.abuse.ch/blocklist/
 * SANS Internet Storm Center at https://isc.sans.edu/suspicious_domains.html
 * Spammer Slapper at http://spammerslapper.com/
 * Disconnect at https://disconnect.me/ 
 */

//Server lists and other settings are defined in the configuration file
require_once('config.php');

//Make sure the data directory exists
debug('Performing first-run checks');
if (!file_exists('./data')) {
    debug('Creating ./data directory');
    if (!mkdir('./data')) {
        console_message('Error creating ./data directory in current directory near line '
            . __LINE__, true);
    }
}

//Copy skeleton files to initialize local copies, if they don't exist already
foreach (array('black', 'white') as $file) {
    if (!file_exists('./personal-' . $file . 'list.txt')) {
        debug('Copying default personal-' . $file . 'list.txt to cwd');
        if (!copy('./skel/personal-' . $file . 'list.txt', './personal-' . $file . 'list.txt')) {
            console_message('Error copying default personal-' . $file 
                . 'list.txt to cwd near line ' . __LINE__, true);
        }
    }
}
//If the local hosts-baseline.txt is older than the distribution copy, update it
if ((int) @filemtime('./data/hosts-baseline.txt') < filemtime('./skel/hosts-baseline.txt')) {
    debug('Copying default hosts-baseline.txt to ./data/');
    if (!copy('./skel/hosts-baseline.txt', './data/hosts-baseline.txt')) {
        console_message('Error copying default hosts-baseline.txt to ./data/ near line '
            . __LINE__, true);
    }
}

//Process remote server lists
debug('Fetching host lists from external sources');
foreach ($serverLists as $sl) {
    debug('Processing list: ' . $sl->getName());
    
    //Only fetch this list if the local copy is too old or doesn't exist
    if ((int) @filemtime($sl->getFilePath()) >= FETCH_INTERVAL) {
        debug($sl->getFilePath() . ' exists and is recent, using local copy');
        continue;
    }
    debug('Retrieving list from server: ' . $sl->getName());
    $data = str_replace("\r\n", "\n", @file_get_contents($sl->getUri()));
    debug('Fetched ' . strlen($data) . ' bytes');
    
    //Perform some sanity checks on the data we fetched
    if (strlen($data) < $sl->getMinimumExpectedBytes()) {
        console_message('Server response was only ' . strlen($data) . ' bytes '
            . ', expected at least ' . $sl->getMinimumExpectedBytes(), true);
    }
    if (!preg_match('|' . $sl->getValidationText() . '|si', $data)) {
        console_message('Server response is missing validation text "'
            . $sl->getValidationText() . '"', true);
    }
    
    //If we only want part of the file, glom it out
    if ($sl->getListStartDelimiter() != '' || $sl->getListEndDelimiter() != '') {
        debug('Extracting text between "' . $sl->getListStartDelimiter()
            . '" and "' . $sl->getListEndDelimiter() . '"');
        preg_match('|' . $sl->getListStartDelimiter() . '(.*?)' 
            . $sl->getListEndDelimiter() . '|si', $data, $results);
        $data = $results[1];
        unset($results);
    }
    
    //Remove extra text (e.g. 127.0.0.1) from server entries
    if (count($sl->getReplacePatterns()) > 0) {
        foreach ($sl->getReplacePatterns() as $pattern) {
            debug('Replacing pattern: ' . $pattern);
            $data = preg_replace($pattern, '', $data);
        }
    }
    
    //If finding servers in the list requires matching a pattern, do it now
    if ($sl->getMatchAllPattern() != '') {
        debug('Matching all on pattern: ' . $sl->getMatchAllPattern());
        preg_match_all($sl->getMatchAllPattern(), $data, $results);
        $data = join("\n", $results[1]);
        unset($results);
    }
    
    //Write the file
    if (!$fp = fopen($sl->getFilePath(), 'w+')) {
        console_message('Error opening ' . $sl->getFilePath() 
            . ' for writing near line ' . __LINE__, true);
    }
    fwrite($fp, $data);
    fclose($fp);
}

//Import server lists
debug('External fetching completed, importing lists');
$whitelist = strip_comments(file('personal-whitelist.txt'));
debug('Whitelist contains ' . count($whitelist) . ' entries');
//Static local lists
$hosts = strip_comments(array_merge(
        file('./data/hosts-baseline.txt'),
        file('./personal-blacklist.txt')
    )
);
//Fetched remote lists
foreach ($serverLists as $sl) {
    $hosts = array_merge($hosts, strip_comments(file($sl->getFilePath())));
}
debug('Host list (combined) contains ' . count($hosts) . ' entries');

//Strip leading www. from hosts
debug('Stripping leading www. from hosts');
$hosts = array_map(
    function($val) { return preg_replace('|^www\.|i', '', $val); },
    $hosts
);

//Remove any duplicate hosts
debug('Deduplicating hosts');
$hosts = array_unique(array_map('strtolower', $hosts));
debug('Deduplicated host list contains ' . count($hosts) . ' entries');

//Build a list of domains we're blocking entirely (entire zone/all subdomains)
debug('Building list of fully-blocked domains');
$domains = array();
foreach ($hosts as $host) {
    if (in_array($host, $whitelist)) {
        continue;
    }
    $dots = substr_count($host, '.');
    if ($dots == 1) {
        $domains[] = $host;
    }
    //Special cases: .co.uk, .com.au, etc. have 3 "parts" in their domain
    else if ($dots == 2 && preg_match(REGEX_MULTIPART_TLD, $host)) {
        $domains[] = $host;
    }
}
debug('Fully-blocked domain list contains ' . count($domains) . ' entries');

//Build our list of blocked hosts. It should include
// 1. All domains being blocked in full
// 2. All single hosts that aren't subdomains of 1
//e.g. if we're blocking the entirety of doubleclick.net, we can disregard
//enumerating ad1.doubleclick.net and ad2.doubleclick.net. 
debug('Building final blocklist');
$blockedHosts = $domains;
foreach ($hosts as $host) {
    if (in_array($host, $whitelist)) {
        continue;
    }
    //One list supplies a few .invalid domains, perhaps as honeytokens
    if (substr($host, -8) == '.invalid') {
        continue;
    }
    //Parse the domain out of the hostname
    $parts = explode('.', $host);
    $count = count($parts);
    if ($count > 1) {
        //Special cases: .co.uk, .com.au, etc. have 3 "parts" in their domain
        if (preg_match(REGEX_MULTIPART_TLD, $host)) {
            $domain = $parts[$count-3] . '.' . $parts[$count-2] . '.' . $parts[$count-1];
        }
        else {
            $domain = $parts[$count-2] . '.' . $parts[$count-1];
        }
        if (DEBUG && $DEBUG['printDomainCount']) {
            //Increment the number of hosts we've found for this domain
            if (isset($DEBUG['domainCount'][$domain])) { $DEBUG['domainCount'][$domain]++; } else { $DEBUG['domainCount'][$domain] = 1; }
        }
        if (in_array($domain, $domains) || in_array($domain, $whitelist)) {
            continue;
        }
        $blockedHosts[] = $host;
    }
}
debug('Final blocklist contains ' . count($blockedHosts) . ' entries');

unset($hosts);
sort($blockedHosts);

//Write the bind config file 
$date = date('Y-m-d H:i:s');
$header = <<<EOT
# blackhole.conf
# Generated by nolovia <http://github.com/ampersign/nolovia/>
# Generated at $date

EOT;
debug('Writing bind config file to ./blackhole.conf');
if (!$fp = fopen('./blackhole.conf', 'w+')) {
    console_message('Error opening file for writing near line ' . __LINE__, true);
}
fwrite($fp, $header);
foreach ($blockedHosts as $host) {
    if ($host == 'localhost') {
        continue;
    }
    fwrite($fp, 'zone "' . $host .'" IN { type master; notify no; file "blackhole.zone"; allow-query { recursers; }; };' . "\n");
}
fclose($fp);
debug('All done! Exiting normally');

/* Remove empty lines and #comments from an array */
function strip_comments($arr) {
    //Filter blank lines and lines that start with #
    $arr = array_filter($arr, function($val) {
            return !((strpos($val, '#') === 0) || (strlen($val) == 0));
    });
    //Filter inline #comments
    foreach ($arr as $key=>$val) {
        if (strpos($val, '#') !== false) {
            $arr[$key] = strtok($val, '#');
        }
    }
    return array_map('trim', $arr);
}

/* Display a notification with timestamp and memory statistics */
function console_message($message, $fatal = false) {
    global $timeStart;
    echo date('H:i:s') . ' - ' . sprintf('%6.02f', microtime(true) - $timeStart)
        . 's - ' . sprintf('% 10d', memory_get_usage()) . " bytes - $message\n";
    if ($fatal === true) {
        console_message('FAILURE: The previous error was fatal; exiting');
        exit;
    }
}

/* Wrapper to access debug variables when displaying output */
function debug($message, $fatal = false) {
    if (DEBUG) {
        global $DEBUG;
        console_message($message, $fatal);
    }
}

//Display a list of all multi-host domains, with a count of blocked hosts for each.
//Useful for finding new domains to block fully.
if (DEBUG && $DEBUG['printDomainCount']) {
    debug('Building count of hosts per domain');
    asort($DEBUG['domainCount']);
    foreach(array_keys($DEBUG['domainCount']) as $key) {
        //If we already block this domain fully, or it only has one host, ignore it
        if (in_array($key, $domains) || $DEBUG['domainCount'][$key] == 1)
            unset($DEBUG['domainCount'][$key]);
    }
    var_dump($DEBUG['domainCount']);
    debug('Finished with count of hosts per domain');
}
