# SickOS

## Port Scan / Enumeration

``` bash
# port scan
nmap -sC 192.168.1.15  
Starting Nmap 7.94SVN ( https://nmap.org ) at 2024-08-23 23:14 CEST
Stats: 0:00:15 elapsed; 0 hosts completed (1 up), 1 undergoing Script Scan
NSE Timing: About 86.72% done; ETC: 23:15 (0:00:02 remaining)
Nmap scan report for ubuntu.homenet.telecomitalia.it (192.168.1.15)
Host is up (0.013s latency).
Not shown: 998 filtered tcp ports (no-response)
PORT   STATE SERVICE
22/tcp open  ssh
| ssh-hostkey: 
|   1024 66:8c:c0:f2:85:7c:6c:c0:f6:ab:7d:48:04:81:c2:d4 (DSA)
|   2048 ba:86:f5:ee:cc:83:df:a6:3f:fd:c1:34:bb:7e:62:ab (RSA)
|_  256 a1:6c:fa:18:da:57:1d:33:2c:52:e4:ec:97:e2:9e:af (ECDSA)
80/tcp open  http
|_http-title: Site doesn't have a title (text/html).
```

``` bash
# directory discovery
$ gobuster dir -u http://192.168.1.15 -w /usr/share/wordlists/dirb/common.txt

===============================================================
Gobuster v3.6
by OJ Reeves (@TheColonial) & Christian Mehlmauer (@firefart)
===============================================================
[+] Url:                     http://192.168.1.15
[+] Method:                  GET
[+] Threads:                 10
[+] Wordlist:                /usr/share/wordlists/dirb/common.txt
[+] Negative Status codes:   404
[+] User Agent:              gobuster/3.6
[+] Timeout:                 10s
===============================================================
Starting gobuster in directory enumeration mode
===============================================================
/index.php            (Status: 200) [Size: 163]
/test                 (Status: 301) [Size: 0] [--> http://192.168.1.15/test/]
Progress: 4614 / 4615 (99.98%)
===============================================================
Finished
===============================================================
```

``` bash
# vuln scan (Nikto)
nikto -h http://192.168.1.15                                  
- Nikto v2.5.0
---------------------------------------------------------------------------
+ Target IP:          192.168.1.15
+ Target Hostname:    192.168.1.15
+ Target Port:        80
+ Start Time:         2024-08-23 23:22:21 (GMT2)
---------------------------------------------------------------------------
+ Server: lighttpd/1.4.28
+ /: Retrieved x-powered-by header: PHP/5.3.10-1ubuntu3.21.
+ /: The anti-clickjacking X-Frame-Options header is not present. See: https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/X-Frame-Options
+ /: The X-Content-Type-Options header is not set. This could allow the user agent to render the content of the site in a different fashion to the MIME type. See: https://www.netsparker.com/web-vulnerability-scanner/vulnerabilities/missing-content-type-header/
+ No CGI Directories found (use '-C all' to force check all possible dirs)
+ OPTIONS: Allowed HTTP Methods: OPTIONS, GET, HEAD, POST .
+ /?=PHPB8B5F2A0-3C92-11d3-A3A9-4C7B08C10000: PHP reveals potentially sensitive information via certain HTTP requests that contain specific QUERY strings. See: OSVDB-12184
+ /?=PHPE9568F36-D428-11d2-A769-00AA001ACF42: PHP reveals potentially sensitive information via certain HTTP requests that contain specific QUERY strings. See: OSVDB-12184
+ /?=PHPE9568F34-D428-11d2-A769-00AA001ACF42: PHP reveals potentially sensitive information via certain HTTP requests that contain specific QUERY strings. See: OSVDB-12184
+ /?=PHPE9568F35-D428-11d2-A769-00AA001ACF42: PHP reveals potentially sensitive information via certain HTTP requests that contain specific QUERY strings. See: OSVDB-12184
+ /test/: Directory indexing found.
+ /test/: This might be interesting.
+ /#wp-config.php#: #wp-config.php# file found. This file contains the credentials.
+ 8102 requests: 0 error(s) and 11 item(s) reported on remote host
+ End Time:           2024-08-23 23:23:59 (GMT2) (98 seconds)
---------------------------------------------------------------------------

# vuln scan (nmap)

```

- get HTTP server versione: lighttpd/1.4.28
