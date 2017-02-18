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
 * This script fetches and makes use of a hosts file compiled by Dan Pollock 
 * which can be found at http://someonewhocares.org/hosts/
 */

define('DEBUG', true);
$DEBUG = !DEBUG ? null : array(
    'domainCount' => array(),
    'printDomainCount' => false,
);
$timeStart = microtime(true);

define('REGEX_MULTIPART_TLD', 
    '/com?\.(ar|au|bo|br|co|cc|id|il|in|hk|jp|kr|kz|mx|nz|ph|rs|tr|ua|uk|uy|vn|za)$/');

//Copy skeleton files to initialize local copies, if they don't exist already
debug('Performing first-run checks');
if (!file_exists('./data')) {
    debug('Creating ./data directory');
    if (!mkdir('./data')) {
        console_message('Error creating ./data directory in current directory near line '
            . __LINE__, true);
    }
}
foreach (array('black', 'white') as $file) {
    if (!file_exists('./personal-' . $file . 'list.txt')) {
        debug('Copying default personal-' . $file . 'list.txt to cwd');
        if (!copy('./skel/personal-' . $file . 'list.txt', './personal-' . $file . 'list.txt')) {
            console_message('Error copying default personal-' . $file 
                . 'list.txt to cwd near line ' . __LINE__, true);
        }
    }
}
if (!file_exists('./data/hosts-baseline.txt')) {
    debug('Copying default hosts-baseline.txt to ./data/');
    if (!copy('./skel/hosts-baseline.txt', './data/hosts-baseline.txt')) {
        console_message('Error copying default hosts-baseline.txt to ./data/ near line '
            . __LINE__, true);
    }
}

//Create backups before writing new files
debug('Backups beginning');
foreach (array('hosts-hphosts.txt', 'hosts-baseline.txt', 'hosts-someonewhocares.txt',
    'hosts-spammerslapper.txt', 'hosts-yoyo.txt', 'hosts-isc.txt') as $filename) {
    if (file_exists('./data/' . $filename)) {
        debug('copy(./data/' . $filename . ', ./data/' . $filename . '.bak)');
        copy('./data/' . $filename, './data/' . $filename . '.bak');
    }
}
debug('Backups completed, fetching host lists from external sources');

//Host list: pgl.yoyo.org
debug('Processing list: yoyo.org');
if ((!file_exists('./data/hosts-yoyo.txt')) || filemtime('./data/hosts-yoyo.txt') < time()-86400) {
    debug('Retrieving list from server: yoyo.org');
    $data = file_get_contents('http://pgl.yoyo.org/adservers/serverlist.php?hostformat=nohtml&mimetype=plaintext');
    debug('Fetched ' . strlen($data) . ' bytes');
    if ((strlen($data) > 30000) && (preg_match('|2o7.net|mi', $data))) {
        if (!$fp = fopen('./data/hosts-yoyo.txt', 'w+')) {
            console_message('Error opening file for writing near line ' . __LINE__, true);
        }
        fwrite($fp, $data);
        fclose($fp);
    }
    else {
        debug('Unexpected server response from server: yoyo.org');
    }
}

//Host list: spammerslapper.com
debug('Processing list: spammerslapper.com');
if ((!file_exists('./data/hosts-spammerslapper.txt')) || filemtime('./data/hosts-spammerslapper.txt') < time()-86400) {
    debug('Retrieving list from server: spammerslapper.com');
    $data = file_get_contents('http://spammerslapper.com/downloads/adblock_include.conf');
    debug('Fetched ' . strlen($data) . ' bytes');
    if ((strlen($data) > 30000) && (preg_match('|2o7.net|mi', $data))) {
        //Parse hosts out of the "Ad Blocking" section only
        list($good, $bad) = explode('//End Ad Blocking', $data);
        preg_match_all('|zone "(.*?)"|', $good, $results);
        if (count($results[1])) {
            $data = '';
            foreach ($results[1] as $host) {
                $data .= trim($host) . "\n";
            }
            if (!$fp = fopen('./data/hosts-spammerslapper.txt', 'w+')) {
                console_message('Error opening file for writing near line ' . __LINE__, true);
            }
            fwrite($fp, $data);
            fclose($fp);
            unset($results);
        }
    }
    else {
        debug('Unexpected response from server: spammerslapper.com');
    }
}

//Host list: hpHosts from Malwarebytes
debug('Processing list: hosts-file.net');
if ((!file_exists('./data/hosts-hphosts.txt')) || filemtime('./data/hosts-hphosts.txt') < time()-86400) {
    debug('Retrieving list from server: hosts-file.net');
    $data = file_get_contents('http://hosts-file.net/ad_servers.txt');
    debug('Fetched ' . strlen($data) . ' bytes');
    if ((strlen($data) > 30000) && (preg_match('|2o7.net|mi', $data))) {
        $data = str_replace("\r\n", "\n", $data);
        $data = preg_replace('|^127.0.0.1(\s+)|mi', '', $data);
        //Strip trailing dot if one exists (theoads.com.)
        $data = preg_replace('|\.$|mi', '', $data);
        if (!$fp = fopen('./data/hosts-hphosts.txt', 'w+')) {
            console_message('Error opening file for writing near line ' . __LINE__, true);
        }
        fwrite($fp, $data);
        fclose($fp);
        unset($data);
    }
    else {
        debug('Unexpected response from server: hosts-file.net');
    }
}

//Host list: someonewhocares.com
debug('Processing list: someonewhocares.com');
if ((!file_exists('./data/hosts-someonewhocares.txt')) || filemtime('./data/hosts-someonewhocares.txt') < time()-86400) {
    debug('Retrieving list from server: someonewhocares.com');
    $data = file_get_contents('http://someonewhocares.org/hosts/hosts');
    debug('Fetched ' . strlen($data) . ' bytes');
    if ((strlen($data) > 30000) && (preg_match('|2o7.net|mi', $data))) {
        //Parse hosts out of the "<ad-sites>" section only
        list($junk, $good) = explode('#<ad-sites>', $data);
        list($good, $junk) = explode('#</ad-sites>', $good);
        $data = preg_replace('|^127.0.0.1(\s+)|mi', '', $good);
        unset($junk, $good);
        if (!$fp = fopen('./data/hosts-someonewhocares.txt', 'w+')) {
            console_message('Error opening file for writing near line ' . __LINE__, true);
        }
        fwrite($fp, $data);
        fclose($fp);
        unset($data);
    }
    else {
        debug('Unexpected response from server: someonewhocares.com');
    }
}

//Host list: ISC suspicious domains
debug('Processing list: isc.sans.edu');
if ((!file_exists('./data/hosts-isc.txt')) || filemtime('./data/hosts-isc.txt') < time()-86400) {
    debug('Retrieving list from server: isc.sans.edu');
    $data = file_get_contents('https://isc.sans.edu/feeds/suspiciousdomains_Low.txt');
    debug('Fetched ' . strlen($data) . ' bytes');
    if ((strlen($data) > 1000) && (preg_match('|dshield|mi', $data))) {
        if (!$fp = fopen('./data/hosts-isc.txt', 'w+')) {
            console_message('Error opening file for writing near line ' . __LINE__, true);
        }
        fwrite($fp, $data);
        fclose($fp);
    }
    else {
        debug('Unexpected server response from server: isc.sans.edu');
    }
}

//Import server lists
debug('External fetching completed, importing lists');
$whitelist = strip_comments(file('personal-whitelist.txt'));
debug('Whitelist contains ' . count($whitelist) . ' entries');
$hosts = strip_comments(array_merge(
            file('./data/hosts-baseline.txt'),
            file('./data/hosts-hphosts.txt'),
            file('./data/hosts-isc.txt'),
            file('./data/hosts-someonewhocares.txt'),
            file('./data/hosts-spammerslapper.txt'),
            file('./data/hosts-yoyo.txt'),
            file('./personal-blacklist.txt')
        )
);
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
    if (count($parts) > 1) {
        //Special cases: .co.uk, .com.au, etc. have 3 "parts" in their domain
        if (preg_match(REGEX_MULTIPART_TLD, $host)) {
            $domain = $parts[count($parts)-3] . '.' . $parts[count($parts)-2] . '.' . $parts[count($parts)-1];
        }
        else {
            $domain = $parts[count($parts)-2] . '.' . $parts[count($parts)-1];
        }
        if (DEBUG) {
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
if (DEBUG && ($DEBUG['printDomainCount'] === true)) {
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
