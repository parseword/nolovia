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

require_once('./model/ServerList.php');
$timeStart = microtime(true);

//Enabling debug mode makes the script more chatty
define('DEBUG', true);
$DEBUG = !DEBUG ? null : array(
    'domainCount' => array(),
    //Enable this to print a list of all domains, with a count of blocked hosts
    //in each. Useful for finding domains you may want to block entirely.
    'printDomainCount' => false,
);

//Only retrieve external host lists if the local copy is older than this interval
define('FETCH_INTERVAL', time()-86400);

//Recognize some TLDs with more than one part, e.g. com.au
define('REGEX_MULTIPART_TLD', 
    '/com?\.(ar|au|bo|br|co|cc|id|il|in|hk|jp|kr|kz|mx|nz|ph|rs|tr|ua|uk|uy|vn|za)$/');

//Set up the external server lists we're going to fetch
$serverLists = array();

$sl = new ServerList('pgl.yoyo.org');
$sl->setFilePath('./data/hosts-yoyo.txt');
$sl->setUri('http://pgl.yoyo.org/adservers/serverlist.php?hostformat=nohtml&mimetype=plaintext');
$sl->setMinimumExpectedBytes(30720);
$sl->setValidationText('2o7.net');
$serverLists[] = $sl;

$sl = new ServerList('Spammer Slapper');
$sl->setFilePath('./data/hosts-spammerslapper.txt');
$sl->setUri('http://spammerslapper.com/downloads/adblock_include.conf');
$sl->setListEndDelimiter('//End Ad Blocking');
$sl->setValidationText('2o7.net');
$sl->setMatchAllPattern('|zone "(.*?)"|');
$serverLists[] = $sl;

$sl = new ServerList('hpHosts from Malwarebytes');
$sl->setFilePath('./data/hosts-hphosts.txt');
$sl->setUri('http://hosts-file.net/ad_servers.txt');
$sl->setMinimumExpectedBytes(512000);
$sl->setValidationText('2o7.net');
$sl->setReplacePatterns(array('|^127.0.0.1(\s+)|m', '|\.$|m'));
$serverLists[] = $sl;

$sl = new ServerList('someonewhocares.org');
$sl->setFilePath('./data/hosts-someonewhocares.txt');
$sl->setUri('http://someonewhocares.org/hosts/hosts');
$sl->setListStartDelimiter('#<ad-sites>');
$sl->setListEndDelimiter('#</ad-sites>');
$sl->setValidationText('2o7.net');
$sl->setReplacePatterns(array('|^127.0.0.1(\s+)|m'));
$serverLists[] = $sl;

$sl = new ServerList('SANS ISC Suspicious Domains');
$sl->setFilePath('./data/hosts-isc.txt');
$sl->setUri('https://isc.sans.edu/feeds/suspiciousdomains_Low.txt');
$sl->setMinimumExpectedBytes(4096);
$sl->setValidationText('Suspicious Domain List');
$serverLists[] = $sl;

$sl = new ServerList('networksec.org');
$sl->setFilePath('./data/hosts-networksec.txt');
$sl->setUri('http://www.networksec.org/grabbho/block.txt');
$sl->setMinimumExpectedBytes(1024);
$sl->setValidationText('badlist');
$serverLists[] = $sl;

$sl = new ServerList('Disconnect Malvertising');
$sl->setFilePath('./data/hosts-disconnect-malvertising.txt');
$sl->setUri('https://disconnect.me/lists/malvertising');
$sl->setMinimumExpectedBytes(65536);
$sl->setValidationText('2o7.net');
$serverLists[] = $sl;

$sl = new ServerList('Ransomware Tracker from abuse.ch');
$sl->setFilePath('./data/hosts-ransomware-tracker.txt');
$sl->setUri('https://ransomwaretracker.abuse.ch/downloads/RW_DOMBL.txt');
$sl->setMinimumExpectedBytes(10240);
$sl->setValidationText('Ransomware Domain Blocklist');
$serverLists[] = $sl;
