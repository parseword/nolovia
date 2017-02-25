# nolovia
nolovia is an ad-blocking config file generator for bind

_From Latin, loosely: **nolo**, I don't want; **via**, a path or route_.

nolovia is a config file generator that assists in implementing a blackholing DNS server or DNS firewall. nolovia fetches several public lists of advertising, tracking, analytics, malware, and other potentially undesirable servers. These lists are then merged and minimized as much as possible, and exported as a config file suitable for use with the `bind` DNS resolver. A corresponding blackhole zone file is included.

## Why operate a local DNS server? 

Running your own DNS is a more powerful alternative to `hosts` file-based ad blocking and tracker blocking. 

* A DNS server can blackhole entire domains, even when you don't know all of their hostnames or subdomains.
* With a local DNS server, you configure your blocking rules in one place, instead of constantly updating a text file on all the devices on your network. 
* Unlike `hosts` files, practically every smartphone will let you set its DNS server without rooting it or installing custom software

## Using nolovia, quick writeup edition

Ensure you already have a working instance of the `bind` DNS resolver prior to starting. There are lots of tutorials on installing bind for your OS, and doing so is beyond the scope of this document. Make a backup of your existing `named.conf` file. Then obtain and run nolovia:

`mkdir nolovia && cd nolovia`    
`git clone https://github.com/ampersign/nolovia.git .`    
`php nolovia.php`

This will generate a file named blackhole.conf. Copy that file and the included blackhole.zone file somewhere that makes sense for your system, like `/var/named/` or `c:\bind\`. 

Edit your `named.conf` to define an access control list (ACL) named "recursers," this will define who's allowed to query your DNS server recursively. For security purposes, only hosts on your local network should be allowed:

    acl recursers {
        localhost;
        localnets;
    };


Now look at the `options { ... }` stanza in your `named.conf` and find the recursion settings. If recursion is already enabled, you can skip this step. To enable recursion *for the recursers ACL only*, set:

    recursion yes;
    allow-recursion { recursers; };

Finally, add the following to the end of `named.conf`,

    include "/var/named/blackhole.conf";

Restart bind with `service named restart` or `rndc reload` as appropriate for your system, and make sure all the devices on your network are set to use your bind instance as their DNS server.

Now see what breaks! Some sites you use might lose functionality because of server blocking. Edit the personal-whitelist.txt and personal-blacklist.txt files to tweak nolovia's generated lists to your liking, then run it again to create a new blackhole.conf file. Once you've worked out any kinks, consider setting up a weekly cron job to make an updated blackhole.conf, copy it to whever bind looks for it, and reload the name server.

## TODO:

* Export zone files for additional resolvers
* Filter hostnames N levels deep instead of just 2, e.g. if metric.gstatic.com is blocked, p2-aahhyknavsj2m-wtnlrzkba6lht33q-if-v6exp3-v4.metric.gstatic.com should be recognized as a subdomain instead of making a separate entry
* Support RPZ or hole-punching (e.g. "block all of evilcompany.tld *except* safeserver.evilcompany.tld")

