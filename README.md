# nolovia
nolovia is an ad-blocking config file generator for `bind`, `NSD`, or other 
DNS resolvers

_From Latin, loosely: **nolo**, I don't want; **via**, a path or route_.

nolovia helps you implement a blackholing DNS server or DNS "sinkhole" firewall, 
by generating configuration files that block potentially malicious servers.

nolovia ingests several public lists of advertising, tracking, analytics, malware, 
cryptojacking, and other undesirable servers. These lists are merged and minimized, 
then exported as a config file suitable for use with the `bind` or `nsd` DNS resolvers. 
A corresponding blackhole [zone file](https://raw.githubusercontent.com/parseword/nolovia/master/blackhole.zone) is included.

## Why operate a local DNS server? 

Running your own DNS is a more powerful alternative to `hosts` file-based ad 
blocking and tracker blocking. 

* A DNS server can blackhole entire domains, even when you don't know all of their hostnames or subdomains.
* With a local DNS server, you configure your blocking rules in one place, instead of constantly updating a text file on all the devices on your network. 
* Unlike `hosts` files, practically every smartphone will let you configure the DNS server without rooting it or installing custom software.

## Using nolovia with `bind`

1. Ensure you already have a working instance of the [`bind` DNS resolver](https://www.isc.org/downloads/bind/) prior to 
starting. There are lots of tutorials on installing `bind` for your OS. 

2. Make a backup of your existing `named.conf` file. 

3. Obtain and run nolovia:

`mkdir nolovia && cd nolovia`    
`git clone https://github.com/parseword/nolovia.git .`    
`php nolovia.php`

This will generate a file named `blackhole.conf`. 

4. Copy `blackhole.conf` and the included `blackhole.zone` file to locations that 
suit your `bind` installation, like `/var/named/` or `c:\bind\`.

5. Edit your `named.conf` to define an access control list (ACL) named "recursers," 
this will determine who's allowed to query your DNS server recursively. For 
security purposes, only hosts on your local network should be allowed:

    acl recursers {
        localhost;
        localnets;
    };

Now look at the `options { ... }` stanza in your `named.conf` and find the 
recursion settings. To enable recursion *for the recursers ACL only*, set:

    recursion yes;
    allow-recursion { recursers; };

6. Finally, add the following to the end of `named.conf`, specifying the path to
which you copied `blackhole.conf`:

    include "/var/named/blackhole.conf";

Restart `bind` with `service named restart` or `rndc reload` as appropriate for 
your system, and make sure all the devices on your network are set to use your 
`bind` instance as their DNS server.

## Using nolovia with `NSD`

1. Ensure you already have a working instance of the [`NSD` DNS resolver](https://www.nlnetlabs.nl/projects/nsd/) prior to 
starting. There are lots of tutorials on installing `NSD` for your OS. 

2. Make a backup of your existing `nsd.conf` file. 

3. Obtain nolovia and create its configuration file:

`mkdir nolovia && cd nolovia`    
`git clone https://github.com/parseword/nolovia.git .`    
`cp config.php-dist config.php`

4. Edit config.php to enable `NSD` support

Out of the box, nolovia's `NSD` support isn't enabled. Open the `config.php` 
file in the editor of your choice, and look for this section, which is around 
line 70 as of this writing:

    //nsd (disabled by default)
    $r = new ResolverConfiguration('nsd');
    $r->setEnabled(false);
    ...
    
Change `$r->setEnabled(false);` to `$r->setEnabled(true);` and save the file.

5. Run nolovia

`php nolovia.php`

This will generate a file named `blackhole-nsd.conf`.

6. Copy `blackhole-nsd.conf` to your system's NSD configuration directory, e.g.  
`/etc/nsd/conf.d/`. The default settings for NSD should automatically load any 
.conf files in that directory; if this doesn't occur, you'll need to edit your 
`nsd.conf` file and add the line 

    `include: "/path/to/blackhole-nsd.conf"`.

7. The nolovia distribution includes a `blackhole.zone` file. Copy this file 
into your NSD `zonesdir`, which is probably `/etc/nsd/`.

Restart `NSD` with `service nsd restart` or `nsd-control reconfig` as appropriate  
for your system, and make sure the devices on your network are set to use your 
`NSD` instance as their DNS server.

## After installation

Now see what breaks! Some sites you use might lose functionality because of 
server blocking. Edit the personal-whitelist.txt and personal-blacklist.txt 
files to tweak nolovia's generated lists to your liking, then run it again to 
create a new blackhole.conf file. Once you've worked out any kinks, consider 
setting up a daily cron job to make an updated blackhole.conf, copy it to 
wherever your resolver looks for it, and reload the name server.

## TODO:

* Export zone files for additional resolvers
* Add capability to filter entire TLDs (e.g. .top)
* Filter hostnames N levels deep instead of just 2, e.g. if metric.gstatic.com is blocked, p2-aahhyknavsj2m-wtnlrzkba6lht33q-if-v6exp3-v4.metric.gstatic.com should be recognized as a subdomain instead of making a separate entry
* Support RPZ or hole-punching (e.g. "block all of evilcompany.tld *except* safeserver.evilcompany.tld")

