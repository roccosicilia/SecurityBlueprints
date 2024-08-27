# Mr. Robot

## Enumeration

``` bash
# Port Scan
nmap -sC -v 192.168.1.21           
Starting Nmap 7.94SVN ( https://nmap.org ) at 2024-08-26 00:40 CEST
Not shown: 997 filtered tcp ports (no-response)
PORT    STATE  SERVICE
22/tcp  closed ssh
80/tcp  open   http
|_http-title: Site doesn't have a title (text/html).
| http-methods: 
|_  Supported Methods: GET HEAD POST OPTIONS
|_http-favicon: Unknown favicon MD5: D41D8CD98F00B204E9800998ECF8427E
443/tcp open   https
| ssl-cert: Subject: commonName=www.example.com
| Issuer: commonName=www.example.com
| Public Key type: rsa
| Public Key bits: 1024
| Signature Algorithm: sha1WithRSAEncryption
| Not valid before: 2015-09-16T10:45:03
| Not valid after:  2025-09-13T10:45:03
| MD5:   3c16:3b19:87c3:42ad:6634:c1c9:d0aa:fb97
|_SHA-1: ef0c:5fa5:931a:09a5:687c:a2c2:80c4:c792:07ce:f71b
|_http-favicon: Unknown favicon MD5: D41D8CD98F00B204E9800998ECF8427E
|_http-title: Site doesn't have a title (text/html).
| http-methods: 
|_  Supported Methods: GET HEAD POST OPTIONS

# nikto

# dir 
gobuster dir -u http://192.168.1.21 -w /usr/share/wordlists/dirb/common.txt
===============================================================
Gobuster v3.6
by OJ Reeves (@TheColonial) & Christian Mehlmauer (@firefart)
===============================================================
[+] Url:                     http://192.168.1.21
[+] Method:                  GET
[+] Threads:                 10
[+] Wordlist:                /usr/share/wordlists/dirb/common.txt
[+] Negative Status codes:   404
[+] User Agent:              gobuster/3.6
[+] Timeout:                 10s
===============================================================
Starting gobuster in directory enumeration mode
===============================================================
/.hta                 (Status: 403) [Size: 213]
/.htaccess            (Status: 403) [Size: 218]
/.htpasswd            (Status: 403) [Size: 218]
/0                    (Status: 301) [Size: 0] [--> http://192.168.1.21/0/]
/admin                (Status: 301) [Size: 234] [--> http://192.168.1.21/admin/]
/atom                 (Status: 301) [Size: 0] [--> http://192.168.1.21/feed/atom/]
/audio                (Status: 301) [Size: 234] [--> http://192.168.1.21/audio/]
/blog                 (Status: 301) [Size: 233] [--> http://192.168.1.21/blog/]
/css                  (Status: 301) [Size: 232] [--> http://192.168.1.21/css/]
/dashboard            (Status: 302) [Size: 0] [--> http://192.168.1.21/wp-admin/]
/favicon.ico          (Status: 200) [Size: 0]
/feed                 (Status: 301) [Size: 0] [--> http://192.168.1.21/feed/]
/images               (Status: 301) [Size: 235] [--> http://192.168.1.21/images/]
/Image                (Status: 301) [Size: 0] [--> http://192.168.1.21/Image/]
/image                (Status: 301) [Size: 0] [--> http://192.168.1.21/image/]
/index.html           (Status: 200) [Size: 1188]
/index.php            (Status: 301) [Size: 0] [--> http://192.168.1.21/]
/intro                (Status: 200) [Size: 516314]
/js                   (Status: 301) [Size: 231] [--> http://192.168.1.21/js/]
/license              (Status: 200) [Size: 19930]
/login                (Status: 302) [Size: 0] [--> http://192.168.1.21/wp-login.php]
/page1                (Status: 301) [Size: 0] [--> http://192.168.1.21/]
/phpmyadmin           (Status: 403) [Size: 94]
/readme               (Status: 200) [Size: 7334]
/rdf                  (Status: 301) [Size: 0] [--> http://192.168.1.21/feed/rdf/]
/robots               (Status: 200) [Size: 41]
/robots.txt           (Status: 200) [Size: 41]
/rss                  (Status: 301) [Size: 0] [--> http://192.168.1.21/feed/]
/rss2                 (Status: 301) [Size: 0] [--> http://192.168.1.21/feed/]
/sitemap              (Status: 200) [Size: 0]
/sitemap.xml          (Status: 200) [Size: 0]
/video                (Status: 301) [Size: 234] [--> http://192.168.1.21/video/]
/wp-admin             (Status: 301) [Size: 237] [--> http://192.168.1.21/wp-admin/]
/wp-content           (Status: 301) [Size: 239] [--> http://192.168.1.21/wp-content/]
/wp-includes          (Status: 301) [Size: 240] [--> http://192.168.1.21/wp-includes/]
/wp-config            (Status: 200) [Size: 0]
/wp-cron              (Status: 200) [Size: 0]
/wp-links-opml        (Status: 200) [Size: 228]
/wp-load              (Status: 200) [Size: 0]
/wp-login             (Status: 200) [Size: 2682]
/wp-mail              (Status: 403) [Size: 3018]
/wp-settings          (Status: 500) [Size: 0]
/wp-signup            (Status: 302) [Size: 0] [--> http://192.168.1.21/wp-login.php?action=register]
/xmlrpc               (Status: 405) [Size: 42]
/xmlrpc.php           (Status: 405) [Size: 42]
Progress: 4614 / 4615 (99.98%)
===============================================================
Finished
===============================================================
```


Flag 1:
- from robots.txt

```
# content of robots.txt
User-agent: *
fsocity.dic
key-1-of-3.txt

# content of kay-1-of-3.txt
073403c8a58a1f80d943455fb30724b9

# content of fsocity.dic
true
false
wikia
from
the
now
...
```