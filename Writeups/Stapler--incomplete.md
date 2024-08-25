# Stapler

## Enumeration

``` bash
# port scan
nmap -sT 192.168.1.28
Starting Nmap 7.94SVN ( https://nmap.org ) at 2024-08-21 12:04 CEST
Nmap scan report for red.initech.homenet.telecomitalia.it (192.168.1.28)
Host is up (0.011s latency).
Not shown: 992 filtered tcp ports (no-response)
PORT     STATE  SERVICE
20/tcp   closed ftp-data
21/tcp   open   ftp
22/tcp   open   ssh
53/tcp   open   domain
80/tcp   open   http
139/tcp  open   netbios-ssn
666/tcp  open   doom
3306/tcp open   mysql

# directory discovery
gobuster dir -u http://192.168.1.28 -w /usr/share/wordlists/dirb/big.txt
===============================================================
Gobuster v3.6
by OJ Reeves (@TheColonial) & Christian Mehlmauer (@firefart)
===============================================================
[+] Url:                     http://192.168.1.28
[+] Method:                  GET
[+] Threads:                 10
[+] Wordlist:                /usr/share/wordlists/dirb/big.txt
[+] Negative Status codes:   404
[+] User Agent:              gobuster/3.6
[+] Timeout:                 10s
===============================================================
Starting gobuster in directory enumeration mode
===============================================================
/.bashrc              (Status: 200) [Size: 3771]
/.profile             (Status: 200) [Size: 675]
Progress: 20469 / 20470 (100.00%)
===============================================================
Finished
===============================================================

# nikto scan
nikto -h http://192.168.1.28
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
+ Target IP:          192.168.1.28
+ Target Hostname:    192.168.1.28
+ Target Port:        80
+ Start Time:         2024-08-21 12:11:32 (GMT2)
---------------------------------------------------------------------------
+ Server: No banner retrieved
+ /: The anti-clickjacking X-Frame-Options header is not present. See: https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/X-Frame-Options
+ /: The X-Content-Type-Options header is not set. This could allow the user agent to render the content of the site in a different fashion to the MIME type. See: https://www.netsparker.com/web-vulnerability-scanner/vulnerabilities/missing-content-type-header/
+ No CGI Directories found (use '-C all' to force check all possible dirs)
+ /.bashrc: User home dir was found with a shell rc file. This may reveal file and path information.
+ /.profile: User home dir with a shell profile was found. May reveal directory information and system configuration.
+ 8110 requests: 9 error(s) and 4 item(s) reported on remote host
+ End Time:           2024-08-21 12:14:17 (GMT2) (165 seconds)
---------------------------------------------------------------------------
+ 1 host(s) tested

# nmap vuln scan
nmap -sC --script vuln 192.168.1.28
Starting Nmap 7.94SVN ( https://nmap.org ) at 2024-08-21 12:07 CEST
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
| smb-vuln-regsvc-dos:
|   VULNERABLE:
|   Service regsvc in Microsoft Windows systems vulnerable to denial of service
|     State: VULNERABLE
|       The service regsvc in Microsoft Windows 2000 systems is vulnerable to denial of service caused by a null deference
|       pointer. This script will crash the service if it is vulnerable. This vulnerability was discovered by Ron Bowes
|       while working on smb-enum-sessions.
|_
|_smb-vuln-ms10-061: false
|_smb-vuln-ms10-054: false

# enum4linux
 =================================( Share Enumeration on 192.168.1.28 )=================================


	Sharename       Type      Comment
	---------       ----      -------
	print$          Disk      Printer Drivers
	kathy           Disk      Fred, What are we doing here?
	tmp             Disk      All temporary files should be stored here
	IPC$            IPC       IPC Service (red server (Samba, Ubuntu))
Reconnecting with SMB1 for workgroup listing.

	Server               Comment
	---------            -------

	Workgroup            Master
	---------            -------
	WORKGROUP            RED

[+] Attempting to map shares on 192.168.1.28

//192.168.1.28/print$	Mapping: DENIED Listing: N/A Writing: N/A
//192.168.1.28/kathy	Mapping: OK Listing: OK Writing: N/A
//192.168.1.28/tmp	Mapping: OK Listing: OK Writing: N/A
```

- user profile file via HTTP: .bashrc, .profile
- SMB vuln CVE-2009-3103
- readable share: //192.168.1.28/kathy  //192.168.1.28/tmp

## Collect Information

- from the SMB share

```
smbclient //192.168.1.28/kathy -U " "%" "
Try "help" to get a list of possible commands.
smb: \> ls
  .                                   D        0  Fri Jun  3 18:52:52 2016
  ..                                  D        0  Mon Jun  6 23:39:56 2016
  kathy_stuff                         D        0  Sun Jun  5 17:02:27 2016
  backup                              D        0  Sun Jun  5 17:04:14 2016
```

- from the backup directory
 - get file "vsftpd.conf", "wordpress-4.tar.gz"

```
smb: \> cd backup
smb: \backup\> dir
  .                                   D        0  Sun Jun  5 17:04:14 2016
  ..                                  D        0  Fri Jun  3 18:52:52 2016
  vsftpd.conf                         N     5961  Sun Jun  5 17:03:45 2016
  wordpress-4.tar.gz                  N  6321767  Mon Apr 27 19:14:46 2015

		19478204 blocks of size 1024. 16397092 blocks available
smb: \backup\> get vsftpd.conf
getting file \backup\vsftpd.conf of size 5961 as vsftpd.conf (111.9 KiloBytes/sec) (average 50.3 KiloBytes/sec)
smb: \backup\> get wordpress-4.tar.gz
getting file \backup\wordpress-4.tar.gz of size 6321767 as wordpress-4.tar.gz (976.1 KiloBytes/sec) (average 959.2 KiloBytes/sec)
smb: \backup\>
```

- the vsftpd.conf is configured for anon user (?)

``` bash
# Allow anonymous FTP? (Disabled by default).
anonymous_enable=YES
anon_root=/var/ftp/anonymous

# try it
ftp 192.168.1.28
Connected to 192.168.1.28.
220-
220-|-----------------------------------------------------------------------------------------|
220-| Harry, make sure to update the banner when you get a chance to show who has access here |
220-|-----------------------------------------------------------------------------------------|
220-
220
Name (192.168.1.28:sheliak): anonymous
331 Please specify the password.
Password:
230 Login successful.
Remote system type is UNIX.
Using binary mode to transfer files.
ftp> ls
550 Permission denied.
200 PORT command successful. Consider using PASV.
150 Here comes the directory listing.
-rw-r--r--    1 0        0             107 Jun 03  2016 note
226 Directory send OK.
ftp>

# get note file
cat note
Elly, make sure you update the payload information. Leave it in your FTP account once your are done, John.
```

---- stucked ----

- new NMAP scan for all port: found port 12380
 - HTTP: static page
 - HTTPS: static page with /robots.txt file

```
User-agent: *
Disallow: /admin112233/
Disallow: /blogblog/
```

- Found INITECH BLOG: https://192.168.1.28:12380/blogblog/ (wordpress)

```
wpscan --disable-tls-checks --url https://192.168.1.28:12380/blogblog/
