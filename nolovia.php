<?php

/*
 * Copyright 2015, 2019 Shaun Cummiskey, <shaun@shaunc.com> <https://shaunc.com>
 * Repository: <https://github.com/parseword/nolovia>
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
 * Disconnect at https://disconnect.me/
 * Jason Lam at http://www.networksec.org/grabbho/block.txt
 * Peter Lowe at http://pgl.yoyo.org/adservers/
 * Malwarebytes at https://hosts-file.net/?s=Download
 * Malware Domain List at https://www.malwaredomainlist.com/
 * Dan Pollock at http://someonewhocares.org/hosts/
 * Ransomware Tracker at https://ransomwaretracker.abuse.ch/blocklist/
 * SANS Internet Storm Center at https://isc.sans.edu/suspicious_domains.html
 * Spammer Slapper at http://spammerslapper.com/
 * Vetyt Yhonay at https://github.com/Yhonay/antipopads/
 * ZeroDot1 at https://zerodot1.github.io/CoinBlockerLists/
 */

$timeStart = microtime(true);

/* Server lists and other settings are defined in the configuration file */
if (!file_exists('./config.php')) {
    console_message('Copying default config.php-dist to config.php, '
            . 'please review config.php for application settings.');
    if (!copy('./config.php-dist', './config.php')) {
        console_message('Error copying config.php-dist to config.php', true);
    }
}

/* Warn if the distribution config is newer than the local one */
if ((int) @filemtime('./config.php') < filemtime('./config.php-dist')) {
    console_message('NOTICE: php.config-dist is newer than your config.php.');
    console_message('NOTICE: Please check for new settings to ensure proper operation.');
    console_message('NOTICE: You can view the most recent configuration changes at:');
    console_message('NOTICE: https://github.com/parseword/nolovia/commits/master/config.php-dist');
}
require_once('./config.php');

/* Make sure the data directory exists */
debug('Performing first-run checks');
if (!file_exists('./data')) {
    debug('Creating ./data directory');
    if (!mkdir('./data')) {
        console_message('Error creating ./data directory in current directory '
                . 'near line ' . __LINE__, true);
    }
}

/* Copy skeleton files to initialize local copies if needed */
foreach (array('black', 'white') as $file) {
    if (!file_exists('./personal-' . $file . 'list.txt')) {
        debug('Copying default personal-' . $file . 'list.txt to cwd');
        if (!copy('./skel/personal-' . $file . 'list.txt',
                        './personal-' . $file . 'list.txt')) {
            console_message('Error copying default personal-' . $file
                    . 'list.txt to cwd near line ' . __LINE__, true);
        }
    }
}

/* If the local hosts-baseline.txt is older than the distribution, update it */
if ((int) @filemtime('./data/hosts-baseline.txt') < filemtime('./skel/hosts-baseline.txt')) {
    debug('Copying default hosts-baseline.txt to ./data/');
    if (!copy('./skel/hosts-baseline.txt', './data/hosts-baseline.txt')) {
        console_message('Error copying default hosts-baseline.txt to ./data/ near line '
                . __LINE__, true);
    }
}

/*
 * Fetch remote server lists. This will attempt to download a fresh copy of each
 * list defined in config.php, unless it was already downloaded recently. The
 * grace period defaults to 12 hours, and can be set in config.php.
 */
debug('Fetching host lists');
foreach ($serverLists as $sl) {

    debug('Processing list: ' . $sl->getName());

    /* Skip this file if it's already been downloaded recently */
    if (!FORCE_FETCH && (int) @filemtime($sl->getFilePath()) >= FETCH_INTERVAL) {
        debug($sl->getFilePath() . ' exists and is recent, using local copy');
        continue;
    }

    /* How many times should we retry if the download fails? */
    $fetchAttempts = defined('FETCH_ATTEMPTS') ? FETCH_ATTEMPTS : 1;

    for ($i = 1; $i <= $fetchAttempts; $i++) {

        /* Try to retrieve the file */
        $error = false;
        debug("Retrieving URI (try #{$i}): " . $sl->getUri());
        $data = str_replace("\r\n", "\n", @file_get_contents($sl->getUri()));
        debug('Fetched ' . strlen($data) . ' bytes');

        /* Perform some sanity checks on the data we fetched */
        if (strlen($data) < $sl->getMinimumExpectedBytes()) {
            console_message('Server response was only ' . strlen($data) . ' bytes,'
                    . ' expected at least ' . $sl->getMinimumExpectedBytes());
            $error = true;
        }
        if (!preg_match('|' . $sl->getValidationText() . '|si', $data)) {
            console_message('Server response is missing validation text "'
                    . $sl->getValidationText() . '"');
            $error = true;
        }

        /* If something went wrong, see if we should try again */
        if ($error) {
            if ($i >= $fetchAttempts) {
                /* Too many retries for this file */
                console_message('Exhausted retry attempts fetching ' . $sl->getName());
                $sl->setFetchFailed(true);
            }
            continue;
        }

        /* This list was successfully retrieved */
        break;
    }

    /* Bail on failure */
    if ($sl->getFetchFailed()) {
        console_message('Not writing list ' . $sl->getName()
                . ' to disk due to fetch failure', FETCH_FAILURE_FATALITY_FLAG);
        continue;
    }

    /* If we only want part of the file, glom it out */
    if ($sl->getListStartDelimiter() != '' || $sl->getListEndDelimiter() != '') {
        debug('Extracting text between "' . $sl->getListStartDelimiter()
                . '" and "' . $sl->getListEndDelimiter() . '"');
        preg_match('|' . $sl->getListStartDelimiter() . '(.*?)'
                . $sl->getListEndDelimiter() . '|si', $data, $results);
        $data = $results[1];
        unset($results);
    }

    /* Remove extra text (e.g. 127.0.0.1) from server entries */
    foreach ($sl->getReplacePatterns() as $pattern) {
        debug('Replacing pattern: ' . $pattern);
        $data = preg_replace($pattern, '', $data);
    }

    /* If finding servers in the list requires matching a pattern, do it now */
    if ($sl->getMatchAllPattern() != '') {
        debug('Matching all on pattern: ' . $sl->getMatchAllPattern());
        preg_match_all($sl->getMatchAllPattern(), $data, $results);
        $data = join("\n", $results[1]);
        unset($results);
    }

    /* Write the cleaned file contents */
    if (!$fp = fopen($sl->getFilePath(), 'w+')) {
        console_message('Error opening ' . $sl->getFilePath()
                . ' for writing near line ' . __LINE__, true);
    }
    fwrite($fp, $data);
    fclose($fp);
    unset($data);
}

/* Import the server lists from disk */
debug('External fetching completed, importing lists');
$whitelist = strip_comments(file('personal-whitelist.txt'));
debug('Whitelist contains ' . count($whitelist) . ' entries');
/* Local lists */
$hosts = strip_comments(array_merge(
                file('./data/hosts-baseline.txt'),
                file('./personal-blacklist.txt')
        )
);
/* Fetched remote lists */
foreach ($serverLists as $sl) {
    if ($sl->getFetchFailed()) {
        continue;
    }
    debug('Loading list ' . $sl->getName() . ' from file ' . $sl->getFilePath());
    $hosts = array_merge($hosts, strip_comments(file($sl->getFilePath())));
}
debug('Host list (combined) contains ' . count($hosts) . ' entries');

/* Strip leading www. from hostnames */
debug('Stripping leading www. from hostnames');
$hosts = array_map(function($val) {
    return preg_replace('|^www\.|i', '', $val);
}, $hosts);

/* Strip trailing dot from hostnames */
debug('Stripping trailing dot from hostnames');
$hosts = array_map(function($val) {
    return preg_replace('|\.$|i', '', $val);
}, $hosts);

/* Discard entries with invalid characters */
debug('Discarding entries with invalid characters');
$hosts = strip_invalid($hosts);

/* Remove any duplicate hosts */
debug('Deduplicating hosts');
$hosts = array_unique(array_map('strtolower', $hosts));
debug('Scrubbed host list contains ' . count($hosts) . ' entries');

/* Build a list of domains we're blocking fully (entire zone/all subdomains) */
debug('Building list of fully-blocked domains');
$domains = [];

foreach ($hosts as $host) {

    /* Skip whitelisted hosts */
    if (in_array($host, $whitelist)) {
        continue;
    }

    /*
     * Count the dots in the hostname to see if it's a zone apex, which we want,
     * as opposed to a subdomain, which we'll get to later.
     */
    $dots = substr_count($host, '.');
    if ($dots == 1) {
        //$domains is multidimensional, keyed off the first character of the domain
        $firstCharacter = substr($host, 0, 1);
        if (!isset($domains[$firstCharacter])) {
            $domains[$firstCharacter] = [];
        }
        $domains[$firstCharacter][] = $host;
    }
    //Special cases: .co.uk, .com.au, etc. have 3 "parts" in their domain
    else if ($dots == 2 && preg_match(REGEX_MULTIPART_TLD, $host)) {
        //$domains is multidimensional, keyed off the first character of the domain
        $firstCharacter = substr($host, 0, 1);
        if (!isset($domains[$firstCharacter])) {
            $domains[$firstCharacter] = [];
        }
        $domains[$firstCharacter][] = $host;
    }
}

/* Make a flattened copy of the multidimensional $domains array */
$fullyBlockedDomains = [];
foreach (array_keys($domains) as $key) {
    $fullyBlockedDomains = array_merge($fullyBlockedDomains, $domains[$key]);
}
debug('Fully-blocked domain list contains ' . count($fullyBlockedDomains) . ' entries');

/*
 * Now build the complete list of blocked hosts. It should include:
 *
 *      1. All domains that are blocked in full
 *      2. All single hostnames that aren't subdomains of fully-blocked domains
 *
 * For example, if we're blocking doubleclick.net in its entirety, we can
 * disregard enumerating ad1.doubleclick.net and ad2.doubleclick.net, as
 * they're covered by the apex zone.
 */
debug('Building final blocklist');

/* Start with the list of fully-blocked domains */
$blockedHosts = $fullyBlockedDomains;

foreach ($hosts as $host) {

    /* Skip whitelisted hosts */
    if (in_array($host, $whitelist)) {
        continue;
    }

    /* One list supplies a few .invalid domains, perhaps as honeytokens */
    if (substr($host, -8) == '.invalid') {
        continue;
    }

    /* The underscore is not permitted in hostnames, per RFC1912 et al */
    if (strpos($host, '_') !== false) {
        continue;
    }

    /* Parse the domain out of the hostname */
    $parts = explode('.', $host);
    $count = count($parts);

    if ($count > 1) {

        /* Special cases: .co.uk, .com.au, etc. have 3 "parts" in their domain */
        if (preg_match(REGEX_MULTIPART_TLD, $host)) {
            $domain = $parts[$count - 3]
                    . '.' . $parts[$count - 2]
                    . '.' . $parts[$count - 1];
        }
        else {
            $domain = $parts[$count - 2] . '.' . $parts[$count - 1];
        }

        if (DEBUG && $DEBUG['printDomainCount']) {
            /* Increment the number of hosts we've found for this domain */
            if (isset($DEBUG['domainCount'][$domain])) {
                $DEBUG['domainCount'][$domain] ++;
            }
            else {
                $DEBUG['domainCount'][$domain] = 1;
            }
        }

        /* $domains is multi-dimensional, keyed off the first character of the domain */
        $firstCharacter = substr($domain, 0, 1);
        if (in_array($domain, $domains[$firstCharacter]) || in_array($domain,
                        $whitelist)) {
            /* This host is either already blocked or is whitelisted */
            continue;
        }
        $blockedHosts[] = $host;
    }
}
debug('Final blocklist contains ' . count($blockedHosts) . ' entries');

unset($hosts, $domains);
sort($blockedHosts);

/* Write the resolver config files */
$date = date('Y-m-d H:i:s');

foreach ($resolvers as $r) {

    /* Skip disabled resolvers */
    if (!$r->isEnabled()) {
        continue;
    }

    /* Build a header comment */
    $header = <<<EOT
# {$r->getFileName()}
# DNS blackhole configuration for advertising, tracking, and malware servers
# Generated by nolovia <https://github.com/parseword/nolovia/>
# Generated at $date

EOT;

    /* Write a config file in this resolver's format */
    debug('Writing ' . $r->getName() . ' config file to ' . $r->getFilePath());
    if (!$fp = fopen($r->getFilePath(), 'w+')) {
        console_message('Error opening file for writing near line ' . __LINE__,
                true);
    }
    fwrite($fp, $header);
    foreach ($blockedHosts as $host) {
        if ($host == 'localhost') {
            continue;
        }
        fwrite($fp,
                str_replace('%HOST%', $host, $r->getZoneDefinitionTemplate()));
    }
    fclose($fp);
}
debug('All done! Exiting normally');

/**
 * Remove empty lines and #comments from an array of strings.
 *
 * @param array $arr The array to filter
 * @return array The filtered array
 */
function strip_comments($arr) {
    /* Filter blank lines and lines that start with # */
    $arr = array_filter($arr,
            function($val) {
        return !((strpos($val, '#') === 0) || (strlen($val) == 0));
    });
    /* Filter inline #comments */
    foreach ($arr as $key => $val) {
        if (strpos($val, '#') !== false) {
            $arr[$key] = strtok($val, '#');
        }
    }
    return array_map('trim', $arr);
}

/**
 * Remove patently bogus hostnames from an array of strings. This performs a
 * rudimentary test for valid characters, and doesn't actually validate any
 * particular domain formats.
 *
 * @param array $arr The array to filter
 * @return array The filtered array
 */
function strip_invalid($arr) {
    return array_filter($arr,
            function($val) {
        return !preg_match('|[^A-Z0-9\-\.]|i', $val);
    });
}

/**
 * Display a console message, with an elapsed time value and memory statistics.
 *
 * @global float $timeStart The time that execution began, from microtime(true)
 * @param string $message The message to display
 * @param bool $fatal Whether or not this message expresses a fatal error
 */
function console_message($message, $fatal = false) {
    global $timeStart;
    echo date('H:i:s') . ' - ' . sprintf('%6.02f', microtime(true) - $timeStart)
    . 's - ' . sprintf('% 10d', memory_get_usage()) . " bytes - {$message}\n";
    if ($fatal === true) {
        console_message('FAILURE: The previous error was fatal; exiting');
        exit;
    }
}

/**
 * A wrapper to call console_message() only if DEBUG is true
 *
 * @global bool $DEBUG The constant named DEBUG
 * @param string $message The message to display
 * @param bool $fatal Whether or not this message expresses a fatal error
 */
function debug($message, $fatal = false) {
    if (DEBUG) {
        global $DEBUG;
        console_message($message, $fatal);
    }
}

//Display a list of all multi-host domains, with a count of blocked hosts for each.
//Useful for finding new domains to block fully.
/*
 * If DEBUG is true, display a list of all domains that contain multiple hosts,
 * with a count of blocked hosts for each. Useful for finding domains that should
 * potentially be fully blocked.
 */
if (DEBUG && $DEBUG['printDomainCount']) {
    debug('Building count of hosts per domain');
    asort($DEBUG['domainCount']);
    foreach (array_keys($DEBUG['domainCount']) as $key) {
        /* If we block this domain fully, or it only has one host, ignore it */
        if (in_array($key, $fullyBlockedDomains) || $DEBUG['domainCount'][$key] == 1)
            unset($DEBUG['domainCount'][$key]);
    }
    var_dump($DEBUG['domainCount']);
    debug('Finished with count of hosts per domain');
}
