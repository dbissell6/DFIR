# The Blue Book

![image](https://github.com/dbissell6/DFIR/assets/50979196/01043023-47b7-44dc-87f8-fa31247b9b1d)

## Intro

The handbook is written to be accessible to new forensic CTF players and is designed to serve as a reference similar to a hacktricks guide. Hopefully useful to someone with no experience wanting to start and to someone with experience that needs a quick reference. 

1) [Network traffic analysis](https://github.com/dbissell6/DFIR/blob/main/Blue_Book/Blue_Book.md#pcaps-pcap) 

2) [Logs + Registry](https://github.com/dbissell6/DFIR/blob/main/Blue_Book/Blue_Book.md#logs--registry)
 
3) [Files/Executables](https://github.com/dbissell6/DFIR/blob/main/Blue_Book/Blue_Book.md#filesexecutables) 

4) [Memory forensics](https://github.com/dbissell6/DFIR/blob/main/Blue_Book/Blue_Book.md#memory-dumps)
 
5) [Disk](https://github.com/dbissell6/DFIR/blob/main/Blue_Book/Blue_Book.md#Disk)

6) [Infected Host](https://github.com/dbissell6/DFIR/blob/main/Blue_Book/Blue_Book.md#infected-host)

7) [Cloud](https://github.com/dbissell6/DFIR/blob/main/Blue_Book/Blue_Book.md#cloud)

8) [SIEMS](https://github.com/dbissell6/DFIR/blob/main/Blue_Book/Blue_Book.md#siems)


## How to use this

If completly new to CTFs and no idea what to do and good start would be to search for the file extention of artifact they gave you in the challenge. 

![image](https://github.com/dbissell6/DFIR/assets/50979196/788aa547-5faf-41b6-818b-051af6d80311)

![image](https://github.com/dbissell6/DFIR/assets/50979196/d7d8cba0-01a6-4567-9a30-d76cb60130cd)

If that isnt helpful sometimes the challenge is understanding what you have. Start with section 3 [Files/Executables](https://github.com/dbissell6/DFIR/blob/main/Blue_Book/Blue_Book.md#filesexecutables) 

Opening the view on the right side is helpful too

![image](https://github.com/dbissell6/DFIR/assets/50979196/a58f9e87-b510-4c23-bb0d-86a249e95396)

## DFIR
When completing DFIR CTFs understanding the story that the evidence is telling is crucial. As a forensic analyst, you need to piece together the who, what, where, when, and how of an attack. A packet capture file (pcap) can reveal a lot about an attack, such as an IP address attempting to bruteforce a website. When the attacker finally gains access, this is a significant piece of the puzzle, and it could also be where a flag is located. Therefore, it's essential to keep detailed notes that reconstruct the timeline of critical events.

Filtering. A commom theme here is there is too much data. It is not feasible to look through logs or a pcap manually. Instead of thinking I am going to do a thing that will find the flag like in a needle in a haystack, think
I am going to remove a bunch of useless stuff.

The structure of this document is sectioned by type of evidence typically given. 


## Fundemental Ideas That Will be encountered

General tip. Most challenges medium and above require the player to create a python script.

## Decoding

Decoding is the process of converting encoded data into a readable format. Encoding is a technique used to represent data in a specific format, often to save space or to ensure data integrity. Decoding is used to analyze binary data or to extract data from file formats that are not natively supported by forensic tools.

-    Base64 decoding: Base64 is a commonly used encoding technique that converts binary data into ASCII characters to make it more readable and transportable. Forensic analysts often encounter Base64-encoded data in email attachments or web traffic. Decoding Base64 involves converting the encoded data back into its original binary format.

-    URL decoding: URLs often contain special characters, such as %20 (which represents a space), that are encoded to make them safe for transmission over the internet. Forensic analysts may encounter encoded URLs in web browser history or network traffic. URL decoding involves converting the encoded characters back into their original form.

-    Unicode decoding: Unicode is a standard for encoding text in various writing systems, such as Chinese, Arabic, and Cyrillic. Forensic analysts may encounter Unicode-encoded text in emails, documents, or chat messages. Decoding Unicode involves converting the encoded text back into its original form.

For instance the string 'hello@world.com' can be encoded these 5 ways

-    Base64: "aGVsbG9Ad29ybGQuY29t"

-    URL Encoding: "hello%40world.com"

-    Hexadecimal Encoding: "68656c6c6f40776f726c642e636f6d"

-    ASCII Encoding: "104 101 108 108 111 64 119 111 114 108 100 46 99 111 109"

-    Unicode Encoding: "\u0068\u0065\u006c\u006c\u006f\u0040\u0077\u006f\u0072\u006c\u0064\u002e\u0063\u006f\u006d"

To decode in linux  

![image](https://user-images.githubusercontent.com/50979196/229380187-b3c34620-e19a-470f-a13f-f8c1d8eeb253.png)


### Cyberchef  
Useful for most decoding  
https://gchq.github.io/CyberChef/

https://github.com/mattnotmax/cyberchef-recipes#

## Decryption

Encryption is an idea that permeates all domains of digital forensics and incident response (DFIR), from incident triage to malware analysis and network forensics. In today's world, encryption is widely used to protect sensitive information, and it is often encountered in digital evidence. As such, understanding encryption is essential for any DFIR practitioner. Encryption can be used to protect data at rest, data in transit, or both, and can be implemented in various ways, from encryption of individual files to full-disk encryption of an entire computer system. Additionally, encryption can be encountered in various contexts, such as communication protocols, malware communication, or encryption of files stored in the cloud.

Encryption can pose significant challenges to DFIR investigations, as it can prevent investigators from accessing or understanding the protected data. In some cases, encryption may be used by malicious actors to hide their activities or exfiltrate data from a network undetected. Understanding encryption, therefore, is essential for identifying and analyzing encrypted data, as well as for determining the appropriate techniques to recover or bypass it.

Furthermore, encryption may also be encountered in forensic artifacts such as logs, memory dumps, and registry entries. These artifacts may contain encrypted data that can provide valuable insights into an incident or investigation, and decrypting this data may be critical for understanding the full scope of an incident.

In summary, understanding encryption and its use cases is essential for any DFIR practitioner. Encryption can pose significant challenges to investigations, but it can also provide valuable insights into an incident or investigation. As such, DFIR practitioners should be familiar with the basics of encryption and the common encryption tools and techniques used in digital investigations.

### Common types


-    AES (Advanced Encryption Standard): This is a symmetric encryption algorithm that is widely used for data encryption. It uses block ciphers with a key size of 128, 192, or 256 bits.

-    RSA: This is an asymmetric encryption algorithm that is widely used for securing data transmission over the internet. It uses a public-private key pair to encrypt and decrypt data.

-    DES (Data Encryption Standard): This is a symmetric encryption algorithm that uses block ciphers with a key size of 56 bits. It is not considered secure for modern applications.

-    Triple DES (3DES): This is a symmetric encryption algorithm that uses DES with three keys applied in sequence. It provides a higher level of security than DES.

-    Blowfish: This is a symmetric encryption algorithm that uses block ciphers with a variable key size of up to 448 bits. It is widely used for file encryption.

-    Twofish: This is a symmetric encryption algorithm that uses block ciphers with a key size of 128, 192, or 256 bits. It is designed to be faster and more secure than AES.

-    ChaCha20: This is a symmetric encryption algorithm that is designed to be fast and secure. It uses a 256-bit key and can be used for data encryption, password hashing, and other applications.


### OpenSSL

OpenSSL is an open-source software library that provides cryptographic functions and tools for a wide range of applications. It includes a number of command-line tools that can be used for tasks such as generating key pairs, creating certificates, and encrypting data.

Common OpenSSL Commands

OpenSSL includes many command-line tools, some of which are commonly used in DFIR investigations. Here are some of the most commonly used OpenSSL commands and their syntax:

    openssl genpkey: generates a private key
    openssl req: generates a certificate signing request (CSR)
    openssl x509: manages SSL/TLS certificates
    openssl enc: encrypts and decrypts files
    openssl dgst: computes message digests (hashes) of files

Common OpenSSL Use Cases

OpenSSL can be used for a wide range of tasks, including generating SSL/TLS certificates, encrypting files and data, and creating digital signatures.

Example: Decrypting a File

To decrypt a file encrypted with AES-256 or DES3 encryption using OpenSSL, use the following commands:

For AES-256 encryption:

```openssl aes256 -d -salt -in [encrypted file] -out [decrypted file] -k [password]```

For example, to decrypt a file named flag.txt.enc using the password unbreakablepassword1234567, you would use the following command:

```openssl aes256 -d -salt -in flag.txt.enc -out flag -k unbreakablepassword1234567```

For DES3 encryption:

```openssl des3 -d -salt -in [encrypted file] -out [decrypted file] -k [password]```

For example, to decrypt a file named file.des3 using the password supersecretpassword123, you would use the following command:

```openssl des3 -d -salt -in file.des3 -out file.txt -k supersecretpassword123```


# PCAPS (.pcap)


## Intro 

Pcaps stand for packet catpure and they are the events (or a log of the events) of what happenened on the network or 'over the wire'. For noobs they can be best conceptualized as text message logs.

Sender | Receiver | Time | Messege
```
Bob -> Alice - 5:00pm - Hi
Alice -> Bob - 5:01pm - oh-hey.jpeg
Bob -> Alice - 5:02pm - What you doing tomorrow?
Charles -> Bob - 5:03pm - Dont text my girlfriend!
```

Pcaps are the most encountered DFIR artifact encountered in challenges. The issue/challenge with pcapcs is they can contain hundreds of thousands of packets. It is not practical to look at the log packet by packet, therefor the typical work flow will be use something like zeek to find something intresting and manually investigate the packet further in wireshark.


### 2 Flavors of Challenges

There are 2 flavors of pcaps and 4-5 different types of challenges regarding skill. 

The first flavor and most seen is a typical network catpure. These are large captures with the flag hidden in a single packet maybe containing html traffic. This can often be thought of as finding a needle in a haystack.

The second flavor is when every packet will be needed. This can be seen in something like a usb logger and almost instantly is an encoding or encrpytion problem.

### 5 levels

1) Flag found plaintext 
2) Flag encoded in rot13 or base64
3) Flag hidden in encryption that needs credentials
4) File found containing binary that needs to be reversed
5) Something tough

Most often in level 3 challenges and above the pcap will be just one piece of evidence and will need to combine it with something else(find creds in a .evtx to decyrpt something in wireshark)

There is a transisiton from putting a flag in the pcap to having players answer 5-10 questions about the attack seen in the pcap to get the flag. This means easy challenges will never contain a flag in the pcap, making easy wins like grep impossible.

## Foundational Network Concepts


### Protocols

A protocol is a set of rules that govern how data is transmitted and received between devices on a network. Protocols are essential for ensuring that devices can communicate with each other effectively and efficiently. Common protocols typically operate on a specified port.

#### OSI

The OSI (Open Systems Interconnection) model is a conceptual model that defines how communication between different computer systems should be implemented. It is a layered approach, with each layer performing specific functions and passing information to the next layer up or down the stack.

The OSI model has seven layers, each of which has a specific function. These layers are:


| Layer Number | Layer Name         | Responsibilities and Protocols |
|--------------|--------------------|--------------------------------|
| 7            | Application Layer  | Providing services to applications; protocols like HTTP, FTP, and SMTP. |
| 6            | Presentation Layer | Presentation and formatting of data; protocols such as SSL and TLS. |
| 5            | Session Layer      | Managing sessions between applications; protocols like NetBIOS. |
| 4            | Transport Layer    | Reliable data transfer between applications on different devices; protocols like TCP and UDP. |
| 3            | Network Layer      | Routing data packets between networks; protocols like IP. |
| 2            | Data Link Layer    | Reliable data transfer over a physical link; protocols such as Ethernet and Wi-Fi. |
| 1            | Physical Layer     | Transmitting raw bit streams over a physical medium, such as a wire or radio signal. |

Examples

| Layer        | Examples                                              |
|--------------|-------------------------------------------------------|
| Application  | DNS, DHCP, SSH, HTTPS, FTP, SNMP, SMTP, POP3          |
| Presentation | Encryption, Encoding, SSL, ASCII, EBCDIC, TIFF, GIF, PICT, JPEG, MPEG, MIDI |
| Session      | NFS, NetBios names, RPC, SQL                          |
| Transport    | TCP, UDP, RTP, SCTP                                   |
| Network      | IPv4, IPv6, ICMPv4, ICMPv6, IPX                       |
| Data Link    | Ethernet, PPP, FDDI, ATM, IEEE 802.5/802.2, HDLC, Frame Relay |
| Physical     | Ethernet (IEEE802.3), Wi-Fi (IEEE 802.11), FDDI, B8ZS, V.35, V.24, RJ45 |


#### TCP/IP Layers

| Layer |
|-------|
| Application |
| Transport |
| Internet |
| Network Access |


### Common protocols

| Protocol Name                        | Acronym | Description |
|-------------------------------------|---------|-------------|
| Transmission Control Protocol       | TCP     | This is a reliable, connection-oriented protocol that provides error checking and flow control. It is used for applications that require a high level of reliability, such as web browsing, email, and file transfer. |
| User Datagram Protocol              | UDP     | This is a connectionless, unreliable protocol that is often used for applications that prioritize speed over reliability, such as video streaming, online gaming, and voice over IP (VoIP) services. |
| Internet Protocol                   | IP      | This is the primary protocol used for routing data across the internet. IP provides the addressing and routing information needed to ensure that data is sent to the correct destination. |
| Hypertext Transfer Protocol         | HTTP    | This is the protocol used by web browsers to request and receive web pages and other resources from web servers. |
| Domain Name System                  | DNS     | This protocol is used to translate domain names (such as www.example.com) into IP addresses that computers can understand. |
| Simple Mail Transfer Protocol       | SMTP    | This protocol is used to send email messages between servers and clients. |
| File Transfer Protocol              | FTP     | This protocol is used to transfer files between computers on a network. |

### Ports

In computer networking, a port is a communication endpoint that is used to identify a specific process or service running on a networked device. Ports are identified by a number between 0 and 65535, with the first 1024 reserved for well-known services and protocols.

When data is transmitted over a network, it is sent to a specific port number on a device, which allows the operating system to identify the process or service that should receive the data. For example, when you browse the web, your web browser sends requests to port 80 (or 443 for HTTPS) on the server hosting the website you are accessing. The server then sends the web page data back to your browser on a different port number.

Some common ports that are used for network services and applications include:

-    Port 80: HTTP web traffic
-    Port 443: HTTPS encrypted web traffic
-    Port 25: SMTP email traffic
-    Port 53: DNS traffic
-    Port 21: FTP file transfer traffic
-    Port 22: SSH secure shell traffic
-    Port 3389: RDP remote desktop traffic

## Wireshark 

Wireshark is a tool that allows you to analyze network traffic at the packet level and examine the contents of individual packets, including the source and destination addresses, protocols used, and any data transmitted. This can be extremely useful for troubleshooting network issues, identifying security threats, and developing and testing network protocols.


Most Pcaps are too long to look through packet by packet. So opening up wireshark you should have a plan and be looking out for some things. Look for anamolies. 

To open wireshark, open up a terminal, navigate to the pcap
```
wireshark sus_file.pcp
```

### Statistics

Useful to get a quick big picture of the pcap.


#### I/O Graph
---
Can be useful to see frequency of packets sent or the size of packets sent over time. 

![image](https://github.com/dbissell6/DFIR/assets/50979196/006d18e6-e023-417f-9011-100e0cc3143c)


#### Conversations
---
Conversations are bidirectional traffic flow between two specific endpoints. An endpoint can be a combination of an IP address and a port number. Thus, for TCP/UDP traffic, a conversation is uniquely identified by both source and destination IP addresses and port numbers.

Duration & Activity: Conversations that last for an unusually long or short time could be sus.

![image](https://github.com/dbissell6/DFIR/assets/50979196/66593d3e-146b-48a4-aa63-58974bfe6af2)


### Helpful Queries

![Pasted image 20230212122101](https://user-images.githubusercontent.com/50979196/221450082-f592ae4c-daef-4035-a0f5-aed4e3c256b4.png)



1. ```ip.addr != 192.0.2.1```: This display filter command excludes packets with an IP address of 192.0.2.1. You can replace "192.0.2.1" with any IP address you want to exclude.
 
2.  ```tcp```: This display filter command only shows TCP packets. You can replace "tcp" with "udp" to only show UDP packets, or with "icmp" to only show ICMP packets., or http: This display filter command only shows HTTP packets. -   (http.request: This display filter command only shows HTTP request packets. http.response: This display filter command only shows HTTP response packets.)
   
3.  ```ip.src == 192.0.2.1```: This display filter command only shows packets with a source IP address of 192.0.2.1.
   
4.  ```ip.dst == 192.0.2.1```: This display filter command only shows packets with a destination IP address of 192.0.2.1.
   
5.  ```tcp.port == 80```: This display filter command only shows TCP packets using port 80 (HTTP).
   
6.  ```udp.port == 53```: This display filter command only shows UDP packets using port 53 (DNS).
7. ```udp.length > 500```: This display filter command only shows UDP packets with a length greater than 500 bytes.
   
8.  ```frame.time >= "Feb 13, 2022 12:00:00"```: This display filter command only shows packets captured after the specified date and time.
### Export Objects
One of the first things to do is determine if any files were transfered. This can be done by in wireshark by File -> Export Objects -> (probably http, try all)


![Pasted image 20230212115835](https://user-images.githubusercontent.com/50979196/221450122-e1115a06-7d90-453e-9e30-bad69b92ea8d.png)

Clicking on HTTP for example will bring up a screen showing files wireshark found and an option to preview and download. It is important to remember that if you find credentials and decrypt traffic to come back here and look for new files wireshark may have found.

### Streams
![Pasted image 20230212123447](https://user-images.githubusercontent.com/50979196/221450162-f3187e94-1e3a-4ec7-8611-5e05f4fadd4c.png)


To access streams right click on a packet

![Pasted image 20230212123647](https://user-images.githubusercontent.com/50979196/221450181-2bbd9132-4d32-410a-a94e-67119e6d00fa.png)

### Encryption in Wireshark

Encryption may be encountered in Wireshark captures, and can be identified by the use of protocols such as SSL/TLS or SSH. When encryption is used, the data being transmitted is protected and cannot be viewed in plain text. However, it is possible to view the encrypted traffic in Wireshark and attempt to decrypt it using the appropriate keys or passwords. To do this, select the encrypted traffic in Wireshark and then use the "Follow SSL Stream" or "Follow SSH Stream" options to view the encrypted data. If the appropriate keys or passwords are available, they can be entered in the "Decode As" settings to decrypt the traffic.

###  Decrpyt TLS

Input RSA key
From G, but TLS instead of SSL

![Pasted image 20230113164502](https://user-images.githubusercontent.com/50979196/221450214-77e163e3-dc62-4555-b15c-811c27d5f114.png)

![Pasted image 20230113164429](https://user-images.githubusercontent.com/50979196/221450223-9ff74041-c577-41ee-9c5a-88688848ee6c.png)

![Pasted image 20230113164557](https://user-images.githubusercontent.com/50979196/221450269-c795cfa1-5921-44ce-9aa6-a33de361632f.png)


marshall in the middle Similar method used in but instead of a RSA to decrypt the TLS it is a secrets.log


### Decrypt SMB2

HTB Rouge shows how to decrypt SMB2 traffic.

In order to decrypt SMB2 traffic in wireshark you need a session id and a session key.
To get the session key we need a couple things.
1) User's password or its md5 hash
2) Username and domain
3) Ntproofstr
4) Initial SMB session key

We can find all the info we need in the session setup request

![Pasted image 20221121132110](https://github.com/dbissell6/DFIR/assets/50979196/6817bb8d-392c-4dca-9526-1d034c8adab9)

![Pasted image 20221121141412](https://github.com/dbissell6/DFIR/assets/50979196/fa86cfbd-5897-4a22-ab7e-141c78f8b2eb)

![Pasted image 20221121141627](https://github.com/dbissell6/DFIR/assets/50979196/3deb3c1c-bb96-4d7c-8df0-bd8ef8965fc7)

![Pasted image 20221121115333](https://github.com/dbissell6/DFIR/assets/50979196/a24ef938-3ba3-4a1c-ac11-cbfbdb7db135)

```
Edit > Preferences > Protocols > SMB2
```

![Pasted image 20221121131210](https://github.com/dbissell6/DFIR/assets/50979196/07dbef05-8cb1-4d22-b2d0-ff3632a58aff)

### Decrypt winrm

![Pasted image 20221125081327](https://github.com/dbissell6/DFIR/assets/50979196/49eeb941-f7fe-4452-b875-62de9dd1719c)

![Pasted image 20221125080137](https://github.com/dbissell6/DFIR/assets/50979196/ab3841a4-1dfd-426f-9f67-9c33ae3138ca)

```
python3 winrm_decrypt.py capture.pcap -n 8bb1f8635e5708eb95aedf142054fc95 > decrypted
```

HTB keep the steam going
### HID - USB

Some pcaps are not of a network, but keyboard commands captured by a USB. There are a couple challenges(logger, deadly arthropod) that require you to decode these commands. Doing so typically yields the flag.
There are some python scripts that will do the decoding, becareful with cases(A or a).  But they essentially map 
![image](https://user-images.githubusercontent.com/50979196/229363610-efd7635b-9467-4550-8a1d-dd93362bea65.png)

In wireshark

![image](https://user-images.githubusercontent.com/50979196/229363428-52f23471-42d6-4f72-855e-4637ce652bee.png)
Notice very bottom says usage and gives 2 symbols, those are the 2 options depending if shift or caps lock was used.


To learn a full wirehark tutorial chris greer

## Tshark
Sometimes it is useful to extract data from wireshark, this can be done with tshark

```
tshark -r capture.pcapng -T fields -e data -Y "!(_ws.expert) && ip.src == 172.17.0.2 && ip.src!=172.17.0.3" > output 
```

## Suricata

Suricata excels at exhaustive dissection of network traffic, meticulously seeking potential signs of malicious activities within PCAP data. Its power lies in its ability to thoroughly evaluate our network's state and delve into the specifics of individual application-layer transactions in PCAP captures. The effectiveness of Suricata heavily depends on a finely tuned set of rules.

![image](https://github.com/dbissell6/DFIR/assets/50979196/ba264e57-bcac-4868-9090-b0f69ff961d0)

### Rules

Sample rules
```
alert http any any -> any any (msg:"Investigate suspicious connections, possible Dridex infection"; sid:2200073; rev:2;)
alert http any any -> any any (msg:"Suspicious JavaScript function, possible Dridex infection";  content:""; file_data;  sid:10000005;)
```
https://docs.suricata.io/en/suricata-6.0.0/rules/intro.html

## Network Miner

NetworkMiner is a renowned network forensic analysis tool, specifically designed to parse and interpret network traffic encapsulated in PCAP files. It excels at extracting files from network traffic, identifying hosts, and offers passive OS fingerprinting capabilities. With its user-friendly interface, it provides a comprehensive view of network interactions, making it a favorite among digital forensics and incident response professionals.

Getting info for files from the transfer

![image](https://github.com/dbissell6/DFIR/assets/50979196/ad029d04-3e6c-46c1-8e73-340c97f2c01b)


## Zui 

The "Zui" desktop application, a part of Brim, allows users to efficiently navigate and manipulate their super-structured data lakes, promoting a more intuitive and streamlined data experience.

Zed is a new kind of data model and format that combines the best of logs, Avro, and columnar data. Rather than being strictly row-based or columnar, Zed provides a super-structured format that allows users to effectively query and analyze data

Query by alert number

![image](https://github.com/dbissell6/DFIR/assets/50979196/4970333b-86bf-4254-9ab7-2e87a8b0a3a1)


![image](https://github.com/dbissell6/DFIR/assets/50979196/be9cea62-88cd-403e-addb-4f3d8fce0bbf)


## Snort

Operates as a packet logger or sniffer akin to Suricata, allowing a comprehensive inspection of network traffic. Snort's capability to identify and log all activities within the PCAP traffic provides an in-depth view of the situation and detailed logs of application layer transactions in PCAP data.

![image](https://github.com/dbissell6/DFIR/assets/50979196/1759bfdf-92b8-4a5d-88fa-45b2e179c383)

![image](https://github.com/dbissell6/DFIR/assets/50979196/77e0b1c2-cfb3-45d3-8032-a1f5609259bc)


https://docs.snort.org/

### Rules

Can specify rules in

```
/root/snorty/etc/snort/snort.lua
```
![image](https://github.com/dbissell6/DFIR/assets/50979196/b1c34229-6cea-4166-bbf4-1fe91b7c1821)

Similar to suricata, not the same.
https://docs.suricata.io/en/latest/rules/differences-from-snort.html

```
sudo snort -c /root/snorty/etc/snort/snort.lua --daq-dir /usr/local/lib/daq -r capture.pcapng
```
`-A cmg` displays alert information along with packet headers and payload.

`-R /home/ViviG/local.rules` Loads rules not found in .lua

-c configuration file
--daq data acquistion

## Zeek


In brief, Zeek is optimized for interpreting network traffic and generating logs based on that traffic. It is not optimized for byte matching, and users seeking signature detection approaches would be better served by trying intrusion detection systems such as Suricata. Zeek is also not a protocol analyzer in the sense of Wireshark, seeking to depict every element of network traffic at the frame level, or a system for storing traffic in packet capture (PCAP) form. Rather, Zeek sits at the “happy medium” representing compact yet high fidelity network logs, generating better understanding of network traffic and usage.


![image](https://github.com/dbissell6/DFIR/assets/50979196/60722e91-6894-49b6-a0a9-d43f7f8bbe44)


```
/usr/local/zeek/bin/zeek -C -r ../pcaps/psexec_pth_download_meterpreter.pcap
```

### Zeek Cut

Get columns 

![image](https://github.com/dbissell6/DFIR/assets/50979196/a7344d61-e8f4-4f4e-9fa0-d2edffc540cf)


https://docs.zeek.org/en/stable/examples/index.html

## Aircrack-ng
Aircrack-ng is a powerful tool for analyzing WiFi packet captures and can be used to crack various types of encryption keys used to protect WiFi network traffic. Some of the encryption keys that Aircrack-ng can crack include WEP (Wired Equivalent Privacy), WPA (Wi-Fi Protected Access), and WPA2 (Wi-Fi Protected Access II).  

Cracking wifi passwords

![Pasted image 20230222082539](https://user-images.githubusercontent.com/50979196/221450312-2ecdfc1e-9086-4434-b7c8-e82bfee254ca.png)

# Logs + Registry
## Intro
Logs are similar to pcaps in they are a long list of events.

In some cases, logs may contain references to files or binary data, but the actual data is not stored within the log itself. For example, a security log might contain an entry that indicates that a file was created or deleted, but the actual file is not stored within the log. Here things like powershell commands are highly sus.

Tasks
-   Analyze log files to identify the cause of a system malfunction, detect a security breach, or recover deleted files.
-   Identify and extract important information, such as passwords, email addresses, or credit card numbers.

Knowlegde
-   Understanding of log formats and types, such as system logs, application logs, and security logs.
-   Awareness of common attack techniques and patterns, such as SQL injection, cross-site scripting (XSS), and phishing attacks.
-   Knowledge of common indicators of compromise (IoCs), such as IP addresses, domain names, file hashes, and user agent strings.
-   Ability to identify anomalous log entries, such as multiple failed login attempts from the same IP address, or unusual file access patterns.

## Windows Logs

The main types of Event Viewer (EVTX) logs in Windows are:

1.  System: This log contains information about system-level events, such as system startup and shutdown, hardware events, and driver events.
   
2.  Application: This log contains information about events generated by applications and services, such as application crashes, application installation and removal, and service start and stop events.
   
3.  Security: This log contains information about security-related events, such as logon and logoff events, privilege use events, and audit events.
   
4.  Setup: This log contains information about setup events, such as the installation and removal of Windows components and updates.

5.  Forwarded Events: This log contains information about events that have been forwarded from other computers in the network to the local computer.

   6. SYSMON: Not all hosts generate these by default, if they do, a good place to start.
## Getting logs from a windows machine

Check available logs.
```
Get-WinEvent -ListLog * | Select-Object LogName, RecordCount, IsClassicLog, IsEnabled, LogMode, LogType | Format-Table -AutoSize
```
Also stored at
```
C:\Windows\System32\winevt\logs
```

## Windows Logs EventId - Description

| EventId | Description |
|---------------|-------------|
| **4104** | PowerShell script block logging |
| **4624** | Successful account logon |
| **4625** | Failed account logon |
| **4648** | Logon using explicit credentials |
| **4634** | An account was logged off |
| **4688** | A new process was created |
| **4670** | Permissions on an object were changed |
| **4697** | A service was installed on the system |
| **4698** | A scheduled task was created |
| **4699** | A scheduled task was deleted |
| **4700** | A scheduled task was enabled |
| **4701** | A scheduled task was disabled |
| **4702** | A scheduled task was updated |
| **4719** | System audit policy was changed |
| **4720** | A user account was created |
| **4722** | A user account was enabled |
| **4723** | A user attempted to change an account's password |
| **4724** | An attempt was made to reset an account's password |
| **4725** | A user account was disabled |
| **4726** | A user account was deleted |
| **4727** | A security-enabled global group was created |
| **4728** | A member was added to a security-enabled global group |
| **4729** | A member was removed from a security-enabled global group |
| **4732** | A member was added to a security-enabled local group |
| **4733** | A member was removed from a security-enabled local group |
| **4738** | A user account was changed |
| **4740** | A user account was locked out |
| **4767** | A user account was unlocked |
| **4771** | Kerberos pre-authentication failed |
| **4776** | The domain controller attempted to validate the credentials for an account (NTLM authentication) |
| **4798** | A user's local group membership was enumerated |
| **4799** | A security-enabled local group membership was enumerated |
| **4826** | Boot configuration data loaded |
| **4902** | The Per-user audit policy table was created |
| **4904** | An attempt was made to register a security event source |
| **4905** | An attempt was made to unregister a security event source |
| **4912** | Per-user audit policy was changed |
| **4964** | Special groups have been assigned to a new logon |
| **5024** | The Windows Firewall Service started |
| **5025** | The Windows Firewall Service stopped |
| **5033** | The Windows Firewall Driver started |
| **5037** | The Windows Firewall Driver detected critical runtime error, terminating |
| **5058** | Key file operation |
| **5059** | Key migration operation |
| **5061** | Cryptographic operation |
| **5062** | A kernel-mode cryptographic self-test was performed |
| **5095** | The Windows Firewall setting to allow or deny an application changed |
| **5124** | A security setting was updated on the OCSP Responder Service |
| **5156** | The Windows Filtering Platform allowed a connection |
| **5157** | The Windows Filtering Platform blocked a connection |


## Sysmon EventId - Description

```
Event ID 1: Process creation
Event ID 2: A process changed a file creation time
Event ID 3: Network connection
Event ID 4: Sysmon service state changed
Event ID 5: Process terminated
Event ID 6: Driver loaded
Event ID 7: Image loaded
Event ID 8: CreateRemoteThread
Event ID 9: RawAccessRead
Event ID 10: ProcessAccess
Event ID 11: FileCreate
Event ID 12: RegistryEvent (Object create and delete)
Event ID 13: RegistryEvent (Value Set)
Event ID 14: RegistryEvent (Key and Value Rename)
Event ID 15: FileCreateStreamHash
Event ID 16: ServiceConfigurationChange
Event ID 17: PipeEvent (Pipe Created)
Event ID 18: PipeEvent (Pipe Connected)
Event ID 19: WmiEvent (WmiEventFilter activity detected)
Event ID 20: WmiEvent (WmiEventConsumer activity detected)
Event ID 21: WmiEvent (WmiEventConsumerToFilter activity detected)
Event ID 22: DNSEvent (DNS query)
Event ID 23: FileDelete (File Delete archived)
Event ID 24: ClipboardChange (New content in the clipboard)
Event ID 25: ProcessTampering (Process image change)
Event ID 26: FileDeleteDetected (File Delete logged)
Event ID 27: FileBlockExecutable
Event ID 28: FileBlockShredding
Event ID 29: FileExecutableDetected
Event ID 255: Error


Sysmon uses abbreviated versions of Registry root key names, with the following mappings:
Key name 	Abbreviation
HKEY_LOCAL_MACHINE 	HKLM
HKEY_USERS 	HKU
HKEY_LOCAL_MACHINE\System\ControlSet00x 	HKLM\System\CurrentControlSet
HKEY_LOCAL_MACHINE\Classes 	HKCR

```

## Analyzing from Windows

### Event Viewer

Windows Event Viewer is a built-in administrative tool in Microsoft Windows operating systems that provides a consolidated view of event logs generated 
by system components and applications. 

![image](https://github.com/dbissell6/DFIR/assets/50979196/e4afe9ed-8fca-4171-b88c-6a7d17f43bfd)

![image](https://github.com/dbissell6/DFIR/assets/50979196/8f0e2554-91f2-4210-a9dc-a9c20826673b)

Filter Current Log.

![image](https://github.com/dbissell6/DFIR/assets/50979196/19dd3dc2-13f7-4016-a436-b8447bcbc95f)

XML query

![image](https://github.com/dbissell6/DFIR/assets/50979196/cf24cb3a-35e1-4e22-8bdb-e2a324f9334e)


```
<QueryList>
  <Query Id="0" Path="file://C:\Users\Blue\htb_interview\Microsoft-Windows-Sysmon%254Operational.evtx">
    <Select Path="file://C:\Users\Blue\htb_interview\Microsoft-Windows-Sysmon%254Operational.evtx">
      *[System[(EventID=1 or EventID=3)]]
    </Select>
  </Query>
</QueryList>
```

Find. Search for strings

![image](https://github.com/dbissell6/DFIR/assets/50979196/dc88619d-12c1-4789-b756-69e232d5b933)


### EvtxECmd

Event Log Explorer Command

![image](https://github.com/dbissell6/DFIR/assets/50979196/84b738a7-cfd0-4d46-ae75-dd55f3a7fcee)

![image](https://github.com/dbissell6/DFIR/assets/50979196/b17ca80b-720b-4b98-8791-ae6049a2b96d)

![image](https://github.com/dbissell6/DFIR/assets/50979196/f2ae4c77-a5da-4359-9ea8-5ea808b7e358)


### Log Parser 2.2

Log Parser 2.2 is a powerful, versatile tool developed by Microsoft that allows users to extract pertinent information from a variety of log files using a SQL-like syntax. 

![image](https://github.com/dbissell6/DFIR/assets/50979196/17bbf96f-132e-4e0e-8350-5c9f6f702cae)

![image](https://github.com/dbissell6/DFIR/assets/50979196/b2f4e3d0-5203-4894-862b-c8223483d953)


### Log Lizard

Log Lizard is an advanced log analysis tool designed to simplify the process of browsing, searching, and analyzing log files. With its intuitive graphical user interface and robust processing backend, Log Lizard makes it easy for users to dive deep into complex log data. Can create visualizations.


![image](https://github.com/dbissell6/DFIR/assets/50979196/eb1feb17-9acb-4723-b25e-74fe91ced55e)

Similar query for Log Parser 2.2

![image](https://github.com/dbissell6/DFIR/assets/50979196/f533d1f1-6078-4351-8b38-b7420ac0cb98)


### Powershell scripts

Search for a keyword in a directory of evtxs

```
# Define the directory containing EVTX files
$evtxDirectory = "C:\Tools\chainsaw\EVTX-ATTACK-SAMPLES\Lateral Movement"

# Define the keyword filter for the network share path
$keywordFilter = "\\*\PRINT"

# Loop through each EVTX file in the directory
Get-ChildItem -Path $evtxDirectory -Filter *.evtx | ForEach-Object {
    $evtxFile = $_.FullName

    # Search the EVTX file for events matching the keyword filter
    $events = Get-WinEvent -Path $evtxFile | Where-Object { $_.Message -like "*$keywordFilter*" }

    # If events are found, output the file name and event details
    if ($events.Count -gt 0) {
        Write-Host "Events found in $($evtxFile):"
        $events | ForEach-Object {
            Write-Host "File Name: $($evtxFile)"
            Write-Host "Time: $($_.TimeCreated)"
            Write-Host "Message: $($_.Message)"
            Write-Host "---"
        }
    }
}
```

Get-WinEvent filter on ID

![image](https://github.com/dbissell6/DFIR/assets/50979196/71f6c55d-ecca-4132-82c5-ef460a147bb7)


### DeepBlue

Open Source Framework to automatically parse evtx logs and look for evil.

![image](https://github.com/dbissell6/DFIR/assets/50979196/6d318518-5edb-4b7d-ac55-1dd1c1248f99)

![image](https://github.com/dbissell6/DFIR/assets/50979196/e48cc810-2e27-4b01-9524-b7875ad47fcc)

## Analyzing from Linux

### evtx_dump 

Outputs a json

https://github.com/omerbenamram/evtx

![image](https://github.com/dbissell6/DFIR/assets/50979196/9b232f8a-a3ab-4734-8924-bab9d41bb8a6)

![image](https://github.com/dbissell6/DFIR/assets/50979196/7e688bb3-fc1f-42d8-b690-9ffb0a0a818c)

#### Using jq to surf

The jq tool is extremely versatile for parsing and manipulating JSON data.

See first record

![image](https://github.com/dbissell6/DFIR/assets/50979196/ca487e30-c370-4c57-af3f-cdc214ce3a78)


Filter for records with eventID 4624

![image](https://github.com/dbissell6/DFIR/assets/50979196/3e2d8c45-9ff0-4d67-8345-3f6a63fa68e7)


Check total occurences

![image](https://github.com/dbissell6/DFIR/assets/50979196/54b0afbb-c314-4bf3-8b1a-ee02c72471f6)


See occurences of target usernames after filtering

![image](https://github.com/dbissell6/DFIR/assets/50979196/5e3fbe3a-db19-40fb-905b-a75d0de284dd)

Last example

![image](https://github.com/dbissell6/DFIR/assets/50979196/740e5000-f176-40e9-9fec-65a657f5eebc)


### .EVTX_dump python

They can be parsed using evtx_dump.py to output a xml.


![Pasted image 20221029120345](https://user-images.githubusercontent.com/50979196/221450336-c3adc6da-3d0c-4d3d-8c7a-25fd5a349135.png)

![image](https://user-images.githubusercontent.com/50979196/221738025-e0593c2b-363f-4f79-84ca-1efc09cf9345.png)


### Chainsaw

Chainsaw is a command-line interface tool that can be used to analyze log files generated by various applications and systems. It provides an efficient way to navigate through large log files and supports filtering and searching capabilities. CLI Chainsaw can also be used to parse and correlate log entries from different sources, allowing for more comprehensive analysis of system behavior.


![Pasted image 20230320145917](https://user-images.githubusercontent.com/50979196/229359837-e8573f3a-9f92-4db4-9f16-75ae988cebcc.png)

![image](https://github.com/dbissell6/DFIR/assets/50979196/be6ed469-0ee9-4b40-80b4-a0068ad7a2d0)


### sigma

Sigma is a generic and open standard for defining log and detection patterns. It provides a structured way to describe log patterns in a human-readable YAML format. These patterns can then be converted into various SIEM (Security Information and Event Management) tool queries or detection rules to identify potential security threats or incidents based on log data.

Using hunt(+ sigma, rules, mappings)


![image](https://github.com/dbissell6/DFIR/assets/50979196/3ac4f54d-57a8-437a-b801-7e0b9b242342)

![image](https://github.com/dbissell6/DFIR/assets/50979196/8262311b-64ac-4579-96a8-ffc5ebd80d77)

#### sigmac

Sigmac takes Sigma rules as input and converts them into query formats for various Tools, log management solutions and security information and event management (SIEM) systems.


Generate a query for powershell from a sigma rule.

![image](https://github.com/dbissell6/DFIR/assets/50979196/88c95b5c-53a0-4f4a-a3af-e6013e28c1d7)

```
python sigmac -t powershell 'C:\Tools\chainsaw\sigma\rules\windows\file\file_access\file_access_win_credential_manager_stealing.yml'
```

Same query for splunk

![image](https://github.com/dbissell6/DFIR/assets/50979196/1096596d-b79e-47a5-b82b-0ae1db3ea5aa)


## Registry

The Windows registry is a hierarchical database that stores configuration settings and options for the Windows operating system and other installed applications. During a CTF, the registry can be a valuable source of information for forensic analysts, as it contains details about installed applications, user accounts, system settings, and much more.

Persistence is a technique used by attackers to maintain access to a compromised system, even after the system has been rebooted or other defensive measures have been taken. The Windows registry is a common location for attackers to establish persistence, as it provides a centralized location for storing configuration settings that can be executed automatically upon system startup or other trigger events.

Attackers may use a variety of techniques to establish persistence via the registry, including adding or modifying registry keys or values, creating scheduled tasks, or installing malicious services. By doing so, they can ensure that their malicious code will execute every time the system boots up, allowing them to maintain access and continue to carry out their objectives.

Identifying and analyzing registry keys related to persistence can be a key part of the challenge. This may involve searching for suspicious or unusual keys or values, examining the contents of known persistence mechanisms (such as scheduled tasks), or using specialized tools and techniques to identify and analyze hidden or obfuscated persistence methods. 

### Registry Editor

Native windows application to view registry. 

![image](https://github.com/dbissell6/DFIR/assets/50979196/103b92ac-203b-4e51-b159-5d49e799be01)


### Hive
Hive files are an important component of the Windows Registry, containing critical system and user-specific information.

The SAM hive file contains user account information such as hashed passwords, login timestamps, and group information. The SYSTEM hive file provides information about file execution times, USB devices connected, and system information such as the local timezone and last shutdown time. The SOFTWARE hive file contains information about both user and system software, including the operating system version and build, network connections, and input/output devices. The SECURITY hive file contains information about security measures and policies in place for the system.

One tool commonly used for extracting passwords from the SAM hive file is Mimikatz. It can also be used to extract other sensitive information from the hive files, such as cached credentials and stored certificates.

To run Mimikatz successfully and extract sensitive information from hive files, administrative-level permissions are usually required. This is because Mimikatz works by injecting itself into the memory space of running processes and accessing sensitive information that is typically only available to privileged users.

https://github.com/dbissell6/Shadow_Stone/blob/main/RedBook/5-Privilege%20Escalation/Windows.md#hklmsam


User-specific hive files include the Amcache.hve file, which contains information about application executables(Recently ran), such as their full path, size, and SHA-1 hashes. 
The ntuser.dat file contains information about autostart applications, recently accessed files, and last execution times of applications. 
The UsrClass.dat file contains information about user-specific shellbags.

### Registry Explorer

Registry Explorer is a tool developed by Eric Zimmerman. It allows users to examine the contents of Windows registry files in a comprehensive manner. 

Using Tools -> Find

![image](https://github.com/dbissell6/DFIR/assets/50979196/0893e121-3aee-4152-bb2e-0455306faa56)


### AmcacheParser

The Amcache is a repository that holds essential data about installed applications and executables. This data encompasses information such as file paths, sizes, digital signatures, and timestamps of the last execution of applications.

Found at
```
C:\Windows\AppCompat\Programs\Amcache.hve
```
On windows make sure Amcache.hve and logs are all together in same dir/folder

![image](https://github.com/dbissell6/DFIR/assets/50979196/1e138b9f-d729-4879-8f85-edc85db89a2b)


![image](https://github.com/dbissell6/DFIR/assets/50979196/09703637-4b75-4773-8bb1-4df6adbf822d)


### regshell

Cli tool allows traverse the registry. 

![image](https://github.com/dbissell6/DFIR/assets/50979196/53163a8d-9521-4638-a0be-d63985e80fa6)

![image](https://github.com/dbissell6/DFIR/assets/50979196/dfeab73f-8a4b-4f38-a8e7-35710476c1f6)


![image](https://github.com/dbissell6/DFIR/assets/50979196/efd52960-936f-40bc-91d0-fefb696db125)


### RegRipper

RegRipper is a popular open-source tool used for extracting and analyzing information from the Windows registry. RegRipper can be used to quickly and efficiently extract key artifacts from the registry, including user and account information, installed software, network settings, and much more.

RegRipper operates by applying a series of pre-defined plugins or "rippers" to the registry, each of which is designed to extract specific types of information. This modular design allows users to easily customize and extend RegRipper's functionality, tailoring it to their specific forensic needs.

RegRipper can be a powerful tool for analyzing Windows systems and identifying potential security issues. By using RegRipper to extract and analyze registry data,for insights into the inner workings of a system and identify potential indicators of compromise (IOCs) or persistence mechanisms.


### Important Registry Paths for Forensic Analysis

| Registry Path                                                     | Description                                               |
|-------------------------------------------------------------------|-----------------------------------------------------------|
| HKLM\SYSTEM\CurrentControlSet\Control\ComputerName                 | Computer name                                             |
| HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall          | Installed software                                        |
| HKCU\Software\Microsoft\Windows\CurrentVersion\Explorer\RecentDocs | Recent documents                                          |
| HKCU\Software\Microsoft\Windows\CurrentVersion\Explorer\ComDlg32\OpenSaveMRU | Recently opened/saved files           |
| HKCU\Software\Microsoft\Windows\CurrentVersion\Explorer\RunMRU    | Run history                                               |
| HKLM\SYSTEM\CurrentControlSet\Services\Tcpip\Parameters           | Network configuration                                    |
| HKCU\Software\Microsoft\Internet Explorer\TypedURLs               | Typed URLs in Internet Explorer                           |
| HKCU\Software\Microsoft\Windows\CurrentVersion\Internet Settings  | Internet settings                                         |
| HKLM\SYSTEM\CurrentControlSet\Services\bam\UserSettings          | Recently executed programs                               |
| HKCU\Software\Microsoft\Office                                     | Microsoft Office usage                                   |
| HKLM\SYSTEM\CurrentControlSet\Enum\USB                              | USB device history                                       |
| HKCU\Software\Microsoft\Windows\CurrentVersion\Explorer\MountPoints2 | Mounted devices                                        |
| HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon       | Winlogon settings                                        |
| HKLM\SYSTEM\CurrentControlSet\Control\TimeZoneInformation         | Time zone information                                    |
| HKCU\Software\Microsoft\Windows\CurrentVersion\Explorer\UserAssist | UserAssist data                                          |
| HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\ProfileList     | User profile paths                                       |
| HKCU\Control Panel\Desktop                                         | Desktop settings                                         |
| HKCU\Software\Microsoft\Windows\CurrentVersion\Explorer\Shell Folders | User-specific folders                                 |
| HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Group Policy       | Group policy settings                                    |
| HKLM\SYSTEM\CurrentControlSet\Control\Session Manager\Memory Management | Memory management settings                         |
| HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Windows        | Windows folder paths                                     |
| HKCU\Software\Microsoft\Windows\CurrentVersion\Policies\Explorer   | User-specific policies                                  |
| HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\NetworkList\Profiles | Network profiles                                      |
| HKCU\Software\Microsoft\Windows\CurrentVersion\Explorer\FileExts   | File extension actions                                  |
| HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Drivers32       | System drivers                                           |
| HKCU\Software\Microsoft\Search Assistant\ACMru                    | Search Assistant history                                 |
| HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\AeDebug         | Debugger settings                                        |
| HKCU\Software\Microsoft\Windows\CurrentVersion\Applets\Regedit     | Last key viewed in Regedit                               |
| HKLM\SYSTEM\CurrentControlSet\Control\SafeBoot                    | Safe boot options                                        |

https://redteamrecipe.com/Registry-Attack-Vectors/

# Other Windows artifacts


## Master File Table (MFT)

The NTFS file system includes a crucial component known as the Master File Table (MFT), which contains information about every file on an NTFS volume, including its attributes like size, timestamps, permissions, and data content. Files and directories in NTFS are represented either within the MFT or in areas described by MFT entries. When files are added, the MFT grows with new entries, and when files are deleted, their MFT entries are marked as available for reuse, but the allocated disk space for these entries remains unchanged. NTFS reserves a specific space, called the MFT zone, to ensure the MFT remains contiguous, and file and directory space is allocated from this zone once all other volume space is used up.


### MFTECmd.exe 
Tool to parse MFT +($Boot...)

![image](https://github.com/dbissell6/DFIR/assets/50979196/65638932-3b22-4945-bec3-85c795ecb3bc)


![image](https://github.com/dbissell6/DFIR/assets/50979196/f74b64ff-aeb7-4821-b224-62fd469e8d36)

### MTF Explorer

Can load raw MFT. Useful but takes 45 minutes to load

![image](https://github.com/dbissell6/DFIR/assets/50979196/298cb258-b113-4aee-85b8-e9d9e76bf540)


## Windows prefetch(.pf)

Windows Prefetch files are designed to improve the application startup process by preloading essential components into memory based on past usage patterns. The information they contain typically includes:

* Name of the Executable: This is the main executable file associated with the application.

* Unicode List of DLLs (Dynamic Link Libraries): DLLs are shared libraries containing code and data that multiple programs can use simultaneously. The prefetch file lists the DLLs associated with the executable.

* Execution Count: This indicates how many times the executable has been run, helping the system understand the application's frequency of use.

* Timestamp: The timestamp indicates the last time the program was run, assisting in determining the most recent usage of the application.

### Can Examine using WindowsPrefetchView

Files found in `C:\Windows\Prefetch`

Can also import a folder of .pfs `Options -> Advanced_Options`

![image](https://github.com/dbissell6/DFIR/assets/50979196/f426127b-2744-4ef1-bf57-cb499f384769)

### PECmd.exe

![image](https://github.com/dbissell6/DFIR/assets/50979196/0eee2a31-9710-42b6-a601-9fb2a80a75b9)

## Schtasks

Found at
```
C:\Windows\System32\Tasks
```

## Shellbags
Shellbags, short for "shell folders and bagMRU," are a forensic artifact found in Microsoft Windows operating systems. They are part of the Windows Explorer feature that remembers how folders are displayed (view settings) and stores user interaction with the file system, including folder navigation and access times.

Found in registry at

```

• USRCLASS.DAT\Local Settings\Software\Microsoft\Windows\Shell\BagMRU
• USRCLASS.DAT\Local Settings\Software\Microsoft\Windows\Shell\Bags
• NTUSER.DAT\Software\Microsoft\Windows\Shell\BagMRU
• HKEY_CURRENT_USER\Software\Microsoft\Windows\Shell\Bags
```

### Shell Bags Explorer

Looking at offline UsrClass.dat

![image](https://github.com/dbissell6/DFIR/assets/50979196/c1776763-15d8-4437-afe1-222a6364ca12)


## .lnk (Windows Shortcut) Files

.LNK files, also known as Windows shortcuts, are small files containing a reference to a target file or directory. When a user clicks on a .LNK file, it redirects them to the specified target, allowing for quick access to applications, files, or folders.

On linux can use file and exiftool to see contents

![image](https://github.com/dbissell6/DFIR/assets/50979196/ce95b0e7-fdd4-4001-b595-881620651ad9)

## Windows Management Instrumentation Repository (WMI)

Found at
```
C/Windows/System32/wbem/Repository
```

The WMI repository is a database that contains information about the Windows Management Instrumentation (WMI) classes installed on a computer, and it has the following structure:

* OBJECTS.DATA: Objects managed by WMI

* INDEX.BTR: Index of files imported into OBJECTS.DATA

* MAPPING[1-3].MAP: Correlates data in OBJECTS.DATA and INDEX.BTR

WMI can be used to install event filters, providers, consumers, and bindings that execute code when a defined event occurs. Examples of events that may be subscribed to are the wall clock time, user logging, or the computer's uptime. Adversaries may use the capabilities of WMI to subscribe to an event and execute arbitrary code when that event occurs, providing persistence on a system.

![Pasted image 20221116224453](https://github.com/dbissell6/DFIR/assets/50979196/6491e06d-1f6c-4a25-8b09-cdaa9ada3fa8)

WMI data is stored in
```
\Windows\System32\wbem\Repository
```

Interesting search terms
.exe .vbs .ps1 .dll .eval ActiveXObject powershell CommandLineTemplate ScriptText

use wmic for recon
```
wmic process get CSName, Description,ExecutablePath,ProcessId

wmic useraccount list full

wmic group list full

wmic netuse list full
```

## JumpLists

Jump Lists in Windows offer quick access to recent files and common tasks for applications. From a cyber perspective, they can reveal user behavior patterns, recent file access, and priority actions. Analyzing them aids in understanding user activities and potential malicious actions associated with specific applications. Jump Lists are essential for creating a forensic timeline and identifying accessed files, making them valuable for security analysis.

On Windows 10 stored at 
```
C:\Users\<Username>\AppData\Local\Microsoft\Windows\Recent\AutomaticDestinations
```

### JLEcmd (Jump List Explorer Command Line)

JLECmd is tailored for extracting and interpreting data from Jump List files, which can provide valuable information regarding a user's activity, including recently or frequently accessed documents, pictures, and more.

![image](https://github.com/dbissell6/DFIR/assets/50979196/2172d8e6-1844-409f-bfb4-ed18cba0f5d4)

## Application Compatibility Cache (Shimcache)

Maintains a log of program execution data to aid compatibility and performance improvements. It captures data like file paths, execution timestamps, and flags denoting program execution. For investigators, Shimcache is valuable in identifying recently run programs and their respective files.

Found at
```
Registry: HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\Session Manager\AppCompatCache
```
### AppCompatCacheParser 

AppCompatCacheParser is another forensic tool developed by Eric Zimmerman, and it's specifically designed to parse the Application Compatibility Cache. 

![image](https://github.com/dbissell6/DFIR/assets/50979196/10942c11-789b-47c7-9ce0-c07be69df89c)

![image](https://github.com/dbissell6/DFIR/assets/50979196/ac479b6b-7fb6-4b1b-bf67-7806cf557b29)


## Userassist
Userassist keys are registry artifacts used to see what programs the user ran, and when. 

Keys found in 
```
NTUSER.DAT 
```

## RunMRU Lists
The RunMRU (Most Recently Used) lists in the Windows Registry store information about recently executed programs from various locations, such as the Run and RunOnce keys. These lists can indicate which programs were run, when they were executed, and potentially reveal user activity.

Found at
```
Registry: HKEY_CURRENT_USER\Software\Microsoft\Windows\CurrentVersion\Explorer\RunMRU
```


## Timeline Explorer

Most of the tools that have been used to parse windows artifacts have been made by Zimmerman and can be found here.

`
https://ericzimmerman.github.io/#!index.md
`

Most of these tools create output that can be ingested into a spreadsheet gui similar to excel. 


Dark mode

Tools -> Skins -> Ofiice 2019 Black

Easy Filtering

![image](https://github.com/dbissell6/DFIR/assets/50979196/530378ee-6bec-4c92-b3ce-59f53c80c449)

Column Chooser

![image](https://github.com/dbissell6/DFIR/assets/50979196/e27fe806-5d89-4640-990c-ae54b2182347)

Drag columns to remove from table

![image](https://github.com/dbissell6/DFIR/assets/50979196/d1214aa0-b97a-4f54-a7a5-68ff715db23b)


`
https://aboutdfir.com/toolsandartifacts/windows/timeline-explorer/
`


# Linux logs

Linux logs are an essential source of information for conducting digital forensics and incident response analysis in a CTF competition. There are several types of Linux logs that can be analyzed, including system logs (e.g., syslog), authentication logs (e.g., auth.log), and kernel logs (e.g., dmesg). Each of these logs provides valuable insights into the system's behavior and can help identify signs of intrusion or compromise.

When analyzing Linux logs in a CTF DFIR competition, it is important to focus on specific entries that could indicate suspicious activity. These entries may include failed login attempts, unusual system behavior, and any unauthorized access attempts. Additionally, analyzing the logs in conjunction with other system artifacts (e.g., memory dumps, network traffic) can provide a more comprehensive picture of the incident and help to identify potential threat actors.


| Name of Log               | Location                                | Purpose                                           | Key Information                                          |
|---------------------------|-----------------------------------------|---------------------------------------------------|----------------------------------------------------------|
| System Logs               | `/var/log/syslog` & `/var/log/messages` | General system activity logging.                   | - System boot-up and shutdown messages.                  |
|                           |                                         |                                                   | - Informational, warning, and error messages from system services. |
| Authentication Logs       | `/var/log/auth.log`                     | Track user authentication activities.              | - Successful and failed login attempts.                  |
|                           |                                         |                                                   | - Use of sudo commands.                                  |
|                           |                                         |                                                   | - SSH logins.                                           |
| Daemon Logs               | `/var/log/daemon.log`                  | Logs from background services (daemons).           | - Service start/stop messages.                           |
|                           |                                         |                                                   | - Service-specific messages.                             |
| Kernel Logs               | `/var/log/kern.log`                    | Logs from the Linux kernel.                        | - Hardware-related messages.                             |
|                           |                                         |                                                   | - Driver issues.                                         |
|                           |                                         |                                                   | - Kernel panics.                                        |
| DPKG Logs                 | `/var/log/dpkg.log`                    | Software packages (Debian-based distributions).    | - Installed, upgraded, or removed software.              |
| YUM Logs                  | `/var/log/yum.log`                     | Software packages (RedHat-based distributions).    | - Installed or removed software.                         |
| Cron Logs                 | `/var/log/cron`                        | Logs from the cron daemon.                         | - Scheduled tasks execution logs.                        |
| Mail Logs                 | `/var/log/maillog` or `/var/log/mail.log` | Mail server logs.                                | - Sent and received email messages.                      |
|                           |                                         |                                                   | - SMTP, POP3, and IMAP messages.                         |
| Apache Access and Error Logs | `/var/log/apache2/access.log` & `/var/log/apache2/error.log` | Apache web server logs. | - Client requests.                                       |
|                           |                                         |                                                   | - Server errors.                                         |
| Boot Log                  | `/var/log/boot.log`                    | System boot messages.                              | - Messages during system startup.                        |


![image](https://github.com/dbissell6/DFIR/assets/50979196/962852b7-cbc8-4613-a551-e9d7dc9be510)


## access logs stats

![image](https://github.com/dbissell6/DFIR/assets/50979196/4ca95ef1-d9e1-4fae-9550-827c5586e757)


Get stats of resources accesed. Assumes url is 7th entry

`
awk '{print $7}' access.log | sort | uniq -c | sort -rn
`

![image](https://github.com/dbissell6/DFIR/assets/50979196/e14ed95f-e178-4d77-bfb5-e072f8b4fa45)

Same thing but for the client IP that is accessing the server

![image](https://github.com/dbissell6/DFIR/assets/50979196/72df384a-86b8-4adf-8eeb-78c0e06119c0)


Stats for resource accessed excluding client IPs

![image](https://github.com/dbissell6/DFIR/assets/50979196/c81ba0be-2ce6-4513-9b40-06b18db03ab5)

Same thing as above, this time just looking for specific IP

![image](https://github.com/dbissell6/DFIR/assets/50979196/230261aa-1c70-4d35-96f5-16e39bbb2d38)

With bytes >= 10000

![image](https://github.com/dbissell6/DFIR/assets/50979196/d8400a8c-8ec0-4fff-a0d7-2c57ae05cfc5)


## Useful Greps

New User Creation

`
sudo grep 'new user' /var/log/auth.log
`

Failed Login Attempts

`
sudo grep 'Failed password' /var/log/auth.log
`

IPs connected SSH

`
sudo grep 'sshd.*Accepted' /var/log/auth.log | awk '{print $(NF-3)}'
`


## Sus Commands
chmod, whoami, sudo, netstat ... typical exploit and elevate commands

vim/nano can be used to make malicious changes to files.

## Persistence using Cronjobs  

In Linux, cron is a time-based job scheduler that runs commands at specified intervals. An attacker may use cron to maintain persistence on a compromised system by creating a cronjob to execute a malicious script at regular intervals. This script could be used to create backdoors, steal data, or perform other malicious activities.

```/var/spool/cron```

![image](https://github.com/dbissell6/DFIR/assets/50979196/b011015a-c38a-4e41-825b-f0e564f6d422)



# Internet History artifacts

## Zone Identifier
When a file is downloaded from the internet, Windows assigns it a Zone Identifier (ZoneId). This could be helpful to see a files orgins or if a files name has changed. Can be found in the /mft/$J(USN).

### Using Powershell

![image](https://github.com/dbissell6/DFIR/assets/50979196/50f0871d-71e0-45dc-bae6-ea1c3853a9c8)

![image](https://github.com/dbissell6/DFIR/assets/50979196/382385a4-2c6e-454f-b9e3-1e1b4ec580d9)

### using MFT + Timeline

![image](https://github.com/dbissell6/DFIR/assets/50979196/1c80c672-10fe-4bca-9e5e-e884e67c6deb)

![image](https://github.com/dbissell6/DFIR/assets/50979196/0b878258-8fb5-4ca0-a300-7dea564c9892)

## Browser artifacts

NirLauncher -> BrowsingHistoryView

![image](https://github.com/dbissell6/DFIR/assets/50979196/ecbae68b-502e-43b6-8087-7d781c9373c0)




# Files/Executables
## Intro
When it comes to CTF challenges, file analysis is an essential skill for any blue team member. These challenges can range in complexity from a simple long text file that needs to be searched for a flag to a complex executable that requires reverse engineering. As a blue team member, you need to be equipped with the right tools and techniques to analyze any file you encounter during a CTF.

One of the first steps in investigating a file is to identify its type using the `file` command. This command can reveal information such as the file type, architecture, and endianness. Another useful command is `strings`, which can be used to extract all printable strings from a file. This can be helpful in finding clues or identifying certain strings that could be indicative of malicious behavior.

Having a solid understanding of file analysis is crucial in identifying potential threats and responding to attacks in a timely and efficient manner. So whether you're dealing with a simple text file or a complex executable, it's important to have the right tools and techniques at your disposal to effectively analyze and respond to any file-based attack.

```
file sus.elf
strings sus.txt
```

## Strings
The strings command in Linux is a useful utility that enables users to extract printable characters from binary files. This command searches for and displays all the printable character sequences (i.e., strings) found in a binary file, which can be helpful in analyzing and debugging the file.

One common use case for the strings command is in analyzing executable files and libraries. For example, if you're trying to troubleshoot an issue with a program, you can use strings to extract any relevant information that may be stored within the binary file, such as error messages or configuration options.

Two of the most popular switches used with strings are:

    -a  
This switch tells strings to look for strings in all sections of the file, including those that are not typically examined by default. This can be helpful in identifying strings that are buried deep within the binary file.

    -n  
This switch specifies the minimum length of the strings that strings will display. By default, strings will display all strings that are at least four characters long, but you can use the -n switch to adjust this minimum length to your liking.


`strings -el -n 12 winfile.doc `

-el: This option specifies the encoding of the strings to search for. The l stands for "little-endian". This means strings will search for 16-bit little-endian encoded characters. This is particularly useful when dealing with files from Windows systems, as some files (like those from the Windows Registry/.doc) might store strings in UTF-16 little-endian encoding.

## Floss

Can also be used to get static strings from binaries

![image](https://github.com/dbissell6/DFIR/assets/50979196/30656dd6-a02a-46bd-9636-5ee644f7ec45)


## Getting hashes 
Useful to make sure file hasnt been altered and to submit to virustotal.

### MD5 + SHA256
From linux

![image](https://github.com/dbissell6/DFIR/assets/50979196/fea9af7e-7d36-4ed1-a092-0301555e1a5e)

From Windows Powershell

![image](https://github.com/dbissell6/DFIR/assets/50979196/ffeac5ea-5d9a-4f65-b9a8-0c2556d463e4)

From Windows cmd

![image](https://github.com/dbissell6/DFIR/assets/50979196/7adf7213-03ec-44a9-856b-e191d71952ca)


### Imphash
Works by concat the lowercase of import functions.

![image](https://github.com/dbissell6/DFIR/assets/50979196/d77dc28e-9f11-48d0-a70f-07a272d04a82)

### PE Hashes

pestudio

![image](https://github.com/dbissell6/DFIR/assets/50979196/5aec7f41-5f58-4a94-a5aa-0762d91eba18)

## Sigcheck

![image](https://github.com/dbissell6/DFIR/assets/50979196/bc61f562-b9f7-4012-bf47-94e5abfc410f)


## Common file types

Below are some of the most common files we might come across. Short recap here, more indepth reversing/pwning guide can be found SOMEWHERE ELSE
### File Type Key
Files are typically determined by thier magic bytes or headers.
If you have a file that has a wrong extentions, no extentions, or corrputed you can check the magic bytes in something like hexedit.

| File Type     | Hex Signature                    | ASCII Signature  |
|---------------|----------------------------------|------------------|
| ani           | 52 49 46 46                      | RIFF             |
| au            | 2E 73 6E 64                      | .snd             |
| bmp           | 42 4D F8 A9                      | BM..             |
| bmp           | 42 4D 62 25                      | BM%              |
| bmp           | 42 4D 76 03                      | BMv              |
| cab           | 4D 53 43 46                      | MSCF             |
| DOC (.doc)    | d0 cf 11 e0 a1 b1 1a e1          | ...              |
| DOCX (.docx)  |                                  | PK               |
| dll           | 4D 5A 90 00                      | MZ..             |
| Excel         | D0 CF 11 E0                      | ...              |
| exe           | 4D 5A 50 00                      | MZP.             |
| exe           | 4D 5A 90 00                      | MZ..             |
| flv           | 46 4C 56 01                      | FLV.             |
| gif           | 47 49 46 38 39 61                | GIF89a           |
| gif           | 47 49 46 38 37 61                | GIF87a           |
| gz            | 1F 8B 08 08                      | ..               |
| ico           | 00 00 01 00                      | ....             |
| jpeg          | FF D8 FF E1                      | ..               |
| jpeg          | FF D8 FF E0                      | JFIF             |
| jpeg          | FF D8 FF FE                      | JFIF             |
| Linux bin     | 7F 45 4C 46                      | .ELF             |
| mp3           | 49 44 33 2E                      | ID3.             |
| mp3           | 49 44 33 03                      | ID3.             |
| msi           | D0 CF 11 E0                      | ...              |
| OFT           | 4F 46 54 32                      | OFT2             |
| PDF           | 25 50 44 46                      | %PDF             |
| PNG (.png)    | 89 50 4e 47                 | .PNG             |
| PPT           | D0 CF 11 E0                      | ...              |
| rar           | 52 61 72 21                      | Rar!             |
| sfw           | 43 57 53 06/08                   | CWS..            |
| tar           | 1F 8B 08 00                      | ..               |
| tgz           | 1F 9D 90 70                      | ..p              |
| Word          | D0 CF 11 E0                      | ...              |
| wmv           | 30 26 B2 75                      | 0&.u             |
| XLS (.xls)    | d0 cf 11 e0 a1 b1 1a e1          | ...              |
| XLSX (.xlsx)  |                                  | PK               |
| zip           | 50 4B 03 04                      | PK..             |

https://www.garykessler.net/library/file_sigs.html

### Windows/Macros(.docm, .doc, .bin, .vba, .pptm, .one)
.docm .doc .bin .vba .pptm .one .rtf

can sometimes using unzip or 7z on word files can reveal hidden content.

#### .rtf

The Rich Text Format (RTF) is a document file format developed by Microsoft, primarily used for cross-platform document interchange. While RTF files don't support macros (a common vector for malware in .doc or .docx formats), they are not inherently safe. RTF documents can embed OLE (Object Linking and Embedding) objects. In the context of this vulnerability, a maliciously crafted RTF document can embed a tainted OLE object related to the Equation Editor, thereby triggering the exploit(Cve-2017-11882).

rtfdump.py

![image](https://github.com/dbissell6/DFIR/assets/50979196/e6719690-7d28-4a56-b681-350c61e94d14)

Extract and display object at index 7 in hex format.

![image](https://github.com/dbissell6/DFIR/assets/50979196/8735d324-0ed9-4bed-8798-8066dfbefcf3)


#### Olevba Tools
A Python module that allows for the analysis of Microsoft Office documents (e.g., Word, Excel, PowerPoint) to detect and extract any embedded VBA (Visual Basic for Applications) macros. It can be used for security assessments, forensics analysis, and malware analysis, as VBA macros can be used as a vector for malware infection and data exfiltration. Olevba is able to parse the VBA code, extract the embedded binaries, and detect any obfuscation techniques used in the macro. 

![Pasted image 20230212151320](https://user-images.githubusercontent.com/50979196/221450379-c3e6b586-0b8d-4146-b960-02865564b9ea.png)

#### oledump.py

![image](https://github.com/dbissell6/DFIR/assets/50979196/01f81fb5-b474-4758-aa4c-13f6cbf6b015)

To get single stream

```
python3 oledump.py ~/Desktop/MalDoc101/sample.bin -s 16
```

#### xlsx

Use exiftool to get info

![image](https://github.com/dbissell6/DFIR/assets/50979196/65b8dfcf-8444-46bb-ac23-02ad34a1a038)


Extract text from cells of xlsx by converting to csv 

![image](https://github.com/dbissell6/DFIR/assets/50979196/4da65d21-2c65-46ae-bdbe-c045d6b7e6c4)

![image](https://github.com/dbissell6/DFIR/assets/50979196/a3ad9950-2bfb-4ec4-ba21-798036a6bb58)


### Windows Executables (.exe, .dll, .so, .ps1)

These files can contain malicious code that attackers may use to compromise a system. Analyzing these files can reveal information about how an attack was carried out. Often these will be obfuscated, it is a whole seperate art to bring light.


.psm1 -	The *.psm1 file extension represents a PowerShell module file. It defines what the module is and what is contained within it.
.psd1 -	The *.psd1 is a PowerShell data file detailing the contents of a PowerShell module in a table of key/value pairs.
.dll - A Windows file containg code that can be used by another program(.exe)
.NET -  .NET files are essentially assemblies, primarily comprising of DLLs (Dynamic Link Libraries) and EXEs (Executable Files). These assemblies are built from the source code using .NET languages such as C#, VB.NET, and F#.

#### Important DLLs

| DLL Name     | Description                                         |
|--------------|-----------------------------------------------------|
| User32.dll   | All user interface and interaction functions.       |
| Kernel32.dll | Basic functions for the operating system.           |
| WSock32.dll  | Basic networking functions.                         |
| Gdi32.dll    | Functions responsible for graphics management.      |
| Advapi32.dll | Advanced user functionality.                        |
| Ws2_32.dll   | Functions responsible for managing network sockets. |
| Ntdll32.dll  | Crucial functions for proper kernel operation.      |
| Msvcrt.dll   | Standard “lib C” library functions.                 |

### Linux Executables (.sh, .bin, .elf)   

In Linux, executable files don't necessarily have a specific file extension like in Windows

.sh (shell script)
.bin (binary file)
.elf (executable and linkable format)
.run (installer script)
.out (object file)

### Image files (.jpg, .png, .bmp)

These files can contain hidden messages or steganography, where data is hidden within the image.

A .bmp  file is a bitmap image file format that contains uncompressed image data. The file starts with a 14-byte header that contains information about the file format, such as the file size, offset to the pixel data, and the number of bits per pixel. After the header, there is an optional color table that maps color values to specific pixels. The pixel data follows the color table (if present) and is stored row-by-row, with each row padded to a multiple of 4 bytes. Each pixel is represented by a series of bits that indicate its color and position in the image. The size of the pixel data can be calculated based on the file size and offset values in the header. It is important to note that .bmp files do not contain any compression or encryption.

A .png file is made up of chunks of data, where each chunk contains information about the image. Each chunk starts with a 4-byte length field, which specifies the number of bytes in the chunk (excluding the length field itself). This is followed by a 4-byte type field, which identifies the type of data in the chunk. After the type field comes the chunk data, which can be of varying length depending on the type of chunk. Finally, the chunk ends with a 4-byte CRC (Cyclic Redundancy Check) field, which is used to verify the integrity of the chunk data.

The first chunk in a PNG file is always the IHDR (Image Header) chunk, which contains basic information about the image such as its dimensions, color depth, and compression method.

To summarize, each chunk in a PNG file contains 4 fields in the following order:

-    Length (4 bytes): specifies the number of bytes in the chunk (excluding the length field itself).
-    Type (4 bytes): identifies the type of data in the chunk.
-    Chunk data (variable length): the actual data contained in the chunk.
-    CRC (4 bytes): a checksum used to verify the integrity of the chunk data.


### Compressed Files (.zip, .rar, .tar.gz, .7z, .bz2, .cab, ...)

Compressed files are a common way of packaging and distributing multiple files or directories as a single archive. In a CTF, compressed files may contain clues or important information that can aid in solving challenges. Here are some common types of compressed files:

-   .zip: This is a popular compression format that is widely used in both Windows and Linux environments. It supports both lossless compression and encryption of archive contents. To extract the contents of a .zip file, one can use the 'unzip' command in Linux or a file archiver software in Windows.
    
-   .rar: This is another popular compression format that is known for its high compression ratio. It supports both lossless compression and encryption of archive contents. To extract the contents of a .rar file, one can use the 'unrar' command in Linux or a file archiver software in Windows.
    
-   .tar.gz: This is a common compression format used in Linux environments. It combines multiple files or directories into a single archive and compresses the archive using the gzip algorithm. To extract the contents of a .tar.gz file, one can use the 'tar' and 'gzip' commands in Linux.
-   .7z: This is a compression format that offers high compression ratios and supports both lossless and lossy compression. It is commonly used for compressing large files. To extract the contents of a .7z file, one can use the '7za' command in Linux or a file archiver software in Windows.

-    .tar: This is a file format used for archiving files and directories in a Unix-based system. It does not compress the archive but combines multiple files or directories into a single archive. To extract the contents of a .tar file, one can use the 'tar' command in Linux.

-    .tar.bz2: This is a compression format that combines the tar archive and the bzip2 compression algorithm. It is commonly used in Linux environments. To extract the contents of a .tar.bz2 file, one can use the 'tar' and 'bzip2' commands in Linux.

-    .tgz: This is a compression format that combines the tar archive and the gzip compression algorithm. It is commonly used in Linux environments. To extract the contents of a .tgz file, one can use the 'tar' and 'gzip' commands in Linux.

-    .tar.xz: This is a compression format that combines the tar archive and the xz compression algorithm. It is commonly used in Linux environments. To extract the contents of a .tar.xz file, one can use the 'tar' and 'xz' commands in Linux.

-    .zipx: This is an extension of the .zip format that supports advanced compression methods such as LZMA, PPMD, and WavPack. It is commonly used in Windows environments. To extract the contents of a .zipx file, one can use a file archiver software in Windows.

-    .cab: This is a file format used for distributing software components in a Windows environment. It is commonly used for device drivers and system files. To extract the contents of a .cab file, one can use the 'cabextract' command in Linux or a file archiver software in Windows.

-    .iso: This is a file format used for creating disc images of CDs or DVDs. It is commonly used for distributing operating system installation media. To extract the contents of an .iso file, one can mount the image as a virtual drive or use a file archiver software in Windows.

### Audio files (e.g., MP3, WAV)
Information can be hidden in the frequency spectrum of the audio signal, in unused space within the file, or by modifying the phase of the audio waveform.  
### Video files (e.g., MP4, AVI)
Information can be hidden within the individual frames of the video, in unused space within the file, or by modifying the motion vectors of the video stream.

### Email (.eml)

### PDF (.pdf)

![image](https://github.com/dbissell6/DFIR/assets/50979196/b3728cc7-9fe3-4828-a6c2-97a49ab30d85)


![image](https://github.com/dbissell6/DFIR/assets/50979196/e3a1e84d-65d7-4742-a908-002392fcab53)

## Decompressing

Files may be compressed in all sorts of ways to avoid detection. Some of the most common decompressing tools + commands.
```
unzip file.zip
gzip -d file.gz
bzip2 -d file.bz2
tar -xf file.tar
7z x file.7z
unrar x file.rar
xz -d file.xz
cabextract file.cab
lzip -d -k flag
lz4 -d flag.out flag2.out
lzma -d -k flag2.lzma
lzop -d -k flag2.lzop -o flag3
lzip -d -k flag3
```


# Reconstructing 

Some times you may come across something(like an Hex output in wireshark) that needs to be recontructed back into a binary or a zip. Sometimes you come across a file with a corrupted header that needs to be fixed.

## Intro

Before diving into tools like hexedit, it's essential to grasp what you're seeing in a hex editor. Every file on your computer, from an image to an executable, is essentially a collection of bytes. These bytes are stored in binary format – sequences of ones and zeros – which are not easily readable by humans. Hexadecimal representation provides a more human-readable format for these sequences.

![image](https://github.com/dbissell6/DFIR/assets/50979196/f4ffc9ff-0954-4d19-b8a6-75b87fe0244c)


Offset: On the leftmost column, you'll often see the "offset." This represents the location of the byte in the file. It helps you identify where you are, especially in extensive files.

Hexadecimal Values: The next broad section shows the file's content in hexadecimal format(Base 16, 0-255 int). Each two-character hex value corresponds to a byte in the file. This is where modifications are often made when correcting corrupted files or altering binary data.

ASCII Representation: On the right side, many hex editors provide an ASCII representation of the file's bytes. While not all bytes translate to visible characters (some might show as dots or other symbols), this view can help you spot strings or familiar patterns in the file.

Example/Reminder one value represented 4 ways

```
Decimal: 90
Binary: 01011010
Hexadecimal: 5A
ASCII: 'Z'
```

https://www.ibm.com/support/pages/decimal-hexadecimal-ebcdic-ascii-bit-conversion-tables

## Binwalk

Binwalk is a popular tool used in cybersecurity for analyzing and extracting information from binary files, such as firmware images and file systems. With binwalk, analysts can identify and extract various components of a binary file, including the file system, bootloader, and kernel.

![image](https://github.com/dbissell6/DFIR/assets/50979196/34c98f59-bb60-465e-b80e-b26d627b1986)

Two popular switches used with binwalk are:

    -e  
This switch tells binwalk to extract the identified file systems from the binary file. This is useful when you want to extract and analyze the file system components of a firmware image.

    -y 
This switch tells binwalk to suppress confirmation prompts during extraction. This can be useful when you want to automate the extraction process and don't want to be prompted for confirmation every time.



## xxd

xxd is a command-line utility that is used to convert binary files into hexadecimal and vice versa. It can be used to create a hexadecimal dump of a binary file, or to convert a hexadecimal dump back into a binary file. xxd is useful for analyzing binary files and for converting between different formats.

![Pasted image 20230213121602](https://user-images.githubusercontent.com/50979196/221450472-5829ddc8-15a5-4b61-ac00-240bd1ea7346.png)

## Hexedit
Hexedit is a hexadecimal editor that allows users to modify binary files directly. It can be used to view and edit the contents of binary files at the byte level, and can be particularly useful for changing specific bytes in a file. In the Pico CTF challenge "Tunnel," Hexedit was used to change the header of a .bmp file.

![image](https://github.com/dbissell6/DFIR/assets/50979196/5f1f63c2-8013-4d1d-a28a-5c1112ab3f88)



# Malware Analysis

Please watch if first time doing this- https://www.youtube.com/watch?v=gjVmeKWOsEU

Malware analysis is the process of dissecting malicious software to understand its functionality, behavior, and purpose. 

We want to understand what the malware does. Does it encyrpt our files? Does it send a reverse shell? If so, how?


https://www.youtube.com/@jstrosch/featured



## Virus total 
can be useful to get some information from  

![Pasted image 20230212170655](https://user-images.githubusercontent.com/50979196/221450418-70e59b66-d291-4a83-9540-d71735b7e4a5.png)


To add: Malware dropping files,


## Assembly 

Registers

| Description               | 64-bit Register | 32-bit Register |
|---------------------------|-----------------|-----------------|
| **Data/Arguments**        |                 |                 |
| Syscall/Return            | rax             | eax             |
| Saved Register            | rbx             | ebx             |
| Destination Operand       | rdi             | edi             |
| Source Operand            | rsi             | esi             |
| 3rd Argument              | rdx             | edx             |
| Loop Counter              | rcx             | ecx             |
| 5th Argument              | r8              | r8d             |
| 6th Argument              | r9              | r9d             |
| **Pointer Registers**     |                 |                 |
| Base Stack                | rbp             | ebp             |
| Current Stack             | rsp             | esp             |
| Instruction (Call only)   | rip             | eip             |


Instructions
| Instruction | Description                                              |
|-------------|----------------------------------------------------------|
| `cmp`       | Compare two operands and set flags based on the result.  |
| `jne`       | Jump if not equal (based on the zero flag).              |
| `je`        | Jump if equal (based on the zero flag).                  |
| `mov`       | Move data between registers or between a register and memory. |
| `add`       | Add two operands and store the result.                   |
| `sub`       | Subtract two operands and store the result.              |
| `mul`       | Multiply two operands.                                   |
| `div`       | Divide two operands.                                     |
| `lea`	      | Load effective address of source into destination register. | 

What this looks like in gdb

![image](https://github.com/dbissell6/DFIR/assets/50979196/5b22ff89-ec23-4c0d-b93b-9e1a18d0b7eb)


The cmp instruction is comparing the value located at memory address [rbp-0x4] to 0x0 (which is just 0).

The jne instruction checks the result of that comparison:

>    If the value at [rbp-0x4] is NOT equal to 0: The program will "jump" to the instruction at the memory address 0x555555552ec (which we can label as <main+307> based on your provided image).

>    If the value at [rbp-0x4] IS equal to 0: The program will not jump and instead will continue executing the next instruction in sequence, which in this case is the lea rax, [rip+0x2e2b] instruction.

$rbp-0x4: This indicates the memory address you want to inspect. $rbp refers to the base pointer register, which usually points to the base of the current function's stack frame. Subtracting 0x4 from it offsets the address by 4 bytes (or 32 bits).




## static vs dynamic


## **Static Analysis Techniques**
 Static analysis techniques involve analyzing the code of a program without actually executing it. Some techniques include disassembly, decompilation, and string analysis. Disassembly involves translating machine code into assembly code to better understand the program's behavior. Decompilation involves converting compiled code back into its original source code. String analysis involves analyzing the strings contained within a program to identify potential malicious behavior.

### Example simple .sh 


![image](https://github.com/dbissell6/DFIR/assets/50979196/38c4f389-be45-40da-849f-ff7f42103656)

Run strings on file, notice base64 encoded text 

![image](https://github.com/dbissell6/DFIR/assets/50979196/dc126fe4-5ded-40ba-82cd-34f5df32c16e)

### Ghidra

Ghidra is an open-source reverse engineering framework developed by the National Security Agency, offering a suite of capabilities to analyze compiled code and decompile it into higher-level representations.

![image](https://github.com/dbissell6/DFIR/assets/50979196/02e2d697-9302-4c59-a38b-109acbfcfbd7)


## **Dynamic Analysis Techniques**
Dynamic analysis techniques involve analyzing the behavior of a program as it executes. Techniques like debugging and sandboxing can be used to analyze malware in a controlled environment. Debugging allows analysts to step through a program and observe its behavior at runtime. Sandboxing involves running a program in an isolated environment to analyze its behavior without risking damage to the host system.


### gdb

GDB, short for the GNU Debugger, is the standard debugger for the GNU software system.

![image](https://github.com/dbissell6/DFIR/assets/50979196/7860cc07-f9bb-424b-918f-387b24414304)

| Command                 | Description                                   |
|-------------------------|-----------------------------------------------|
| `b *0x00000000004008cf` | Sets a breakpoint at the specified address.   |
| `info functions`        | Displays information about functions.         |
| `disassemble main`                 | Displays the assembly code of the main function.|
| `run`                   | Starts the program being debugged.            |
| `c`                     | Continues the program after a breakpoint.     |
| `n`                     | Executes the next line of code.               |
| `s`                     | Steps into functions.                         |
| `list`                  | Shows the source code.                        |
| `info registers`        | Displays the CPU registers.                   |
| `x/10x $esp`            | Examines memory. Here, it shows 10 words in hexadecimal starting from the ESP register. |
| `print $eax`                  | Displays the value of the EAX register.            |
| `set $eax=0x12345678`         | Sets the EAX register to the value `0x12345678`.   |
| `x/s $rdi`                    | Displays the string pointed to by the RDI register.|
| `watch *0x004005f0`           | Sets a watchpoint at the given memory address.     |
| `info breakpoints`            | Lists all breakpoints and watchpoints.             |
| `delete 1`                    | Deletes breakpoint number 1.   |
| `info proc mappings`          |  Detailed view of the memory layout of the running process. |
| `quit`                  | Exits GDB.                                    |



![image](https://github.com/dbissell6/DFIR/assets/50979196/0475b88d-aa76-4ba9-8943-344b5d4a0247)


### r2

Radare2 powerful open-source tool used for reverse engineering, forensics, and binary analysis.

First run aaa(analyze all). Then can run commands, here listing functions.


![image](https://github.com/dbissell6/DFIR/assets/50979196/24c8de02-9a0f-499a-a126-92261bcad6c4)


| Command                 | Description                                   |
|-------------------------|-----------------------------------------------|
| `db 0x004008cf`         | Sets a breakpoint at the specified address.   |
| `afl`                   | Lists all functions in the binary.            |
| `iz`                    | Displays all strings in binary.               |
| `iE`                    | Displays information about binarys entrypoint.|
| `pdf @ main`            | Displays the assembly code of the main function.|
| `dc`                    | Starts the program being debugged.            |
| `dc`                    | Continues the program after a breakpoint.     |
| `ds`                    | Executes the next instruction.                |
| `dr`                    | Displays the CPU registers.                   |
| `px 10 @ rsp`           | Examines memory. Shows 10 bytes from RSP.     |
| `dr eax`                | Displays the value of the EAX register.       |
| `dr eax=0x12345678`     | Sets the EAX register to `0x12345678`.        |
| `psz @ rdi`             | Displays the string pointed to by RDI.        |
| `db`                    | Lists all breakpoints.                        |
| `db-0x004008cf`         | Deletes breakpoint at `0x004008cf`.           |
| `dm`                    | Displays memory maps. Similar to GDB's `info proc mappings`.|
| `V` |                   | Enters visual mode, which allows you to interactively navigate through the binary using a graphical interface. |
| `VV`|                   | Enters graph mode, which displays the control flow graph of the current function. |
| `q`                     | Exits Radare2.                                |

![image](https://github.com/dbissell6/DFIR/assets/50979196/1f710d08-62b9-4bcb-a7b6-17d29fd92023)

`v` example

![image](https://github.com/dbissell6/DFIR/assets/50979196/6f944a0f-c94d-4110-baf8-1223914d8cfb)


### IDA

IDA is a leading disassembler and debugger used in software reverse engineering, renowned for its in-depth binary analysis capabilities and interactive interface.

![image](https://github.com/dbissell6/DFIR/assets/50979196/52f35413-2a06-440a-955a-38a2175c2ca4)


### dnSpy

dnSpy is a debugger and .NET assembly editor, which can be used to inspect, debug, and edit .NET assemblies. One of its powerful features is the ability to decompile .NET assemblies back to C# or VB.NET source code, providing insights into the underlying functionality of the software. dnSpy allows users to set breakpoints, step through code, and inspect variables and objects, making it a valuable tool for reverse engineering and debugging .NET applications.


![image](https://github.com/dbissell6/DFIR/assets/50979196/8881de65-03e0-437e-811c-31693517365b)


## Procmon

Process Monitor, commonly referred to as ProcMon, is a monitoring tool from the Sysinternals suite. It combines the features of two legacy Sysinternals utilities – Filemon and Regmon. ProcMon provides real-time file system, Registry, and process/thread activity monitoring. 


![image](https://github.com/dbissell6/DFIR/assets/50979196/7a91f502-25ba-4fa1-b681-e03380bebb6d)

Can filter with process name or pid...

![image](https://github.com/dbissell6/DFIR/assets/50979196/857658bd-6246-4826-b8e9-1b435c9cf810)

Can filter type of activity (Registry, filesystem, network)

![image](https://github.com/dbissell6/DFIR/assets/50979196/7c2711d4-5f0c-4391-a62c-05322251b5f7)

## Process Explorer

Process Explorer is another tool from the Sysinternals suite, and it provides detailed information about which handles and DLLs processes have opened or loaded. It offers a more in-depth view than the standard Windows Task Manager.



## Regshot

Regshot is an open-source (GNU GPL) tool that allows users to take a snapshot of the system registry and then compare it with a second one, made after doing system changes or installing a new software product.

Take first shot 

![image](https://github.com/dbissell6/DFIR/assets/50979196/6369f784-fabb-4267-a876-b7d0f9d1fc94)

Run malware

![image](https://github.com/dbissell6/DFIR/assets/50979196/808e22dd-29ad-4f6a-864e-58898c4cb208)

Take second shot

![image](https://github.com/dbissell6/DFIR/assets/50979196/d7c69dfb-5a69-4bef-b71a-84ba460065b9)

Compare

![image](https://github.com/dbissell6/DFIR/assets/50979196/b06f0d06-94ba-425a-a581-81598164bd7c)



## Sandboxes

### Noriben

Noriben can be used for dynamic analysis monitoring creation of processes.

Start from command line, run executable in question, when finihed stop Noriben, get output 

![image](https://github.com/dbissell6/DFIR/assets/50979196/f3f80f0d-7a6b-4042-9219-187570dba020)


![image](https://github.com/dbissell6/DFIR/assets/50979196/a3718827-65db-4f74-8afa-b5a53e902430)


### hybrid-analysis

Web based

![image](https://github.com/dbissell6/DFIR/assets/50979196/926cf34b-9543-4a80-b394-d95ee0d9fa27)


### any.run

Any.Run is an interactive online sandbox service designed for the analysis of suspicious files and URLs. Any.Run provides real-time feedback, including network traffic, file system changes, and other system behaviors

![image](https://github.com/dbissell6/DFIR/assets/50979196/5ecd943c-278e-42e8-9499-ae86540a3d2d)


### Alien Vault

Web based, can check hashes and run in sandboxes

https://otx.alienvault.com

## Deobfuscation

Deobfuscation is the process of removing obfuscation from code or data, making it more readable and easier to understand. The key distinction between this and decoding or decrypting is that the computer can already comprehend the code; it's only you who can't.  Obfuscation is often used by malware authors to hide their malicious code from analysis or detection, which makes deobfuscation a critical skill for digital forensics and incident response (DFIR) professionals. Deobfuscation techniques can range from simple string decoding to complex disassembly and reverse engineering, and require a deep understanding of programming languages and software architectures. This section will cover some of the most common deobfuscation techniques used in DFIR, and provide practical examples and tools to help you improve your deobfuscation skills.

This can be dealt with live or static methods. 

Almost any computer code(.exe,.php,.py) can be obfuscated.

### Example PHP

Below is obfuscated php. Often an easy win in these senarios involves being able to find an eval call. If we can find this we can get the deobfuscated version of the code.
```
map-update.php                
-----------------------------310973569542634246533468492466
Content-Disposition: form-data; name="uploaded_file"; filename="galacticmap.php"
Content-Type: application/x-php

<?php 
snipped...

$iyzQ5h8qf6 .= "\\o>\n u]d> wd ;  Gaoe : ettsssn\"= \$   \$t\$4: lewf l;]e% 'L c'capt a maaOFre mF <'  hnv\n {e >< n>\"\n  Ednn   aets.t.c  m{ \$oem0  d\"n('d\n,a1 ]L h/hce'vveemlS"; 
$iyzQ5h8qf6 .= "Ie }pi'b<ee <e  \n).<t l\" }  Tett m dsp\"c cof o  mw\"o)' []e s[  ds )  o'ot= abn=euTLca\n_l.r/cx(br   ) td o..\n  [re- u ft:>oconi d\$ on]d - "; 
$iyzQ5h8qf6 .= "\" r\$'' \$'% )oe . i'nlac'=e[Etl ne\$>bhe\$r    )\"d> a  e  '(nD s i /\nmomtl et de e?' w=[m e o]1  rc\$\$\"ohaurtd'='Sor a d<>occ>t <  ?>  dppc  d"; 
$iyzQ5h8qf6 .= "'ti t lc/\n/m/ae  y er=  ; r \"o:x w,s { hfv<nime-yif's[re m'ib< (m\"a / {d\"\" =orh  oC-s -heom<apbip &p  [ &'\n i(ed e n % \n!oiah=de=fpriUu'ya e.r b\"'d;b t"; 
$iyzQ5h8qf6 .= " \ni.  \"sio  woTp re(ma!jionee e &\"( r \$t\$xe'c e\$1  i ll2'd='oe'lpbf)d '\$.sr<cr\nl h  r . .in   "; 
for($i = 0; $i < $pPziZoJiMpcu; $i++) $liGBOKxsOGMz[] = ""; 
for($i = 0; $i < (strlen($iyzQ5h8qf6) / $pPziZoJiMpcu); $i++) { for($r = 0; $r < $pPziZoJiMpcu; $r++) $liGBOKxsOGMz[$r] .= $iyzQ5h8qf6[$r + $i * $pPziZoJiMpcu]; } 
$bhrTeZXazQ = trim(implode("", $liGBOKxsOGMz)); 
$bhrTeZXazQ = "?>$bhrTeZXazQ"; 
eval( $bhrTeZXazQ ); 
?>
```
Changing that eval to a print, then running the code will show us what would have been evaluated. 

![image](https://user-images.githubusercontent.com/50979196/229360590-6be77a92-d4a9-474b-9b15-82386ab91033.png)
![image](https://user-images.githubusercontent.com/50979196/229360633-63def415-8df9-478c-bd7a-bff3b24d5648.png)


reversing,  decompiling, deobfuscating, decoding, decrypting, 

## Changing the flow of the code / debugging

Debugging enhances code analysis by providing a dynamic, interactive approach that offers a real-time view of malware behavior. Analysts can validate their findings, observe runtime effects, and deepen their understanding of program execution.

Intro to debugging to bypass checks

https://github.com/dbissell6/DFIR/blob/main/Malware_Analysis_Debug.md

# Windows malware

## PE (Portable Executable)

PE is the standard file format for executable programs in Windows, encompassing both standalone executables (EXE) and dynamic link libraries (DLLs). It's a structured file format that includes information necessary for the operating system to load, manage, and execute the program.

### Essential PE File Sections

* .text  - contains DLLs used by the program
* .rdata - read only data
* .data  - contains static variables
* .rsrc  - Resource information


### Unpacking

Packing can hinder string analysis since references to strings are usually obscured or removed. Additionally, it replaces or disguises conventional PE sections with a compact loader stub that retrieves the original code from a compressed data section.

### upx
Running strings before unpacking yields nothing interesting

![image](https://github.com/dbissell6/DFIR/assets/50979196/08701348-f896-4283-9878-5f0bfdb5c612)


### PE-Bear

PE-Bear designed for static analysis of (primarily) Windows PE (Portable Executable) files.

![image](https://github.com/dbissell6/DFIR/assets/50979196/59e977c8-d7cf-4bce-a862-272630775f2e)


### CFF Explorer

CFF Explorer(Compact File Format Explorer), is a popular tool for analyzing and manipulating PE files.


![image](https://github.com/dbissell6/DFIR/assets/50979196/2c0f3518-d02b-4d37-a553-a2918204e8c9)


### Depdendecy Walker

Dependency Walker is a free utility that scans any 32-bit or 64-bit Windows module (exe, dll, ocx, sys, etc.) and builds a hierarchical tree diagram of all dependent modules. It provides valuable information about module functions, entry points, and other internal details useful for debugging and troubleshooting.

![image](https://github.com/dbissell6/DFIR/assets/50979196/b39eb9a2-a7ac-46f5-a97e-b5542fda4e40)


### Resource Hacker

Resource Hacker is a utility to view, modify, rename, add, delete, and extract resources in 32-bit and 64-bit Windows executables and resource files (*.res)

![image](https://github.com/dbissell6/DFIR/assets/50979196/38225c42-64d4-4249-a91a-3f3281e9bc78)



## Deobfuscation Windows

OLEBA should be here

### Example 'static' powershell script 

Here the light obfuscation allows us to not have to run the script. Instead we can make a simple python script to understand what would have executed.

![Pasted image 20221101223940](https://github.com/dbissell6/DFIR/assets/50979196/928357ee-68f0-49eb-8d2f-588d5547287c)

![Pasted image 20221101224024](https://github.com/dbissell6/DFIR/assets/50979196/18ad2c6d-ec83-43f4-8b86-14e79c2ca7e7)

![Pasted image 20221101224154](https://github.com/dbissell6/DFIR/assets/50979196/b20807de-afde-4ad8-afac-be739149d321)



### Example base64 gzipped powershell script


See base64strings and Decompress
![image](https://github.com/dbissell6/DFIR/assets/50979196/ca26ed70-b7d4-4f23-9298-26d66d5f4134)

![image](https://github.com/dbissell6/DFIR/assets/50979196/88e82ffa-fa0d-42cb-b628-a54204851c5a)

Just to finish this off see another base64 and a xor

![image](https://github.com/dbissell6/DFIR/assets/50979196/1320d5bc-11b9-47e3-8b9c-e4d1d2544f4b)

### Example messy powershell "Dynamic"

![image](https://github.com/dbissell6/DFIR/assets/50979196/6e68a218-1150-4bfe-acb6-fefb74d2900e)

![image](https://github.com/dbissell6/DFIR/assets/50979196/b4fab743-6fa3-46c3-8bfb-f3fc592a6cde)




# Steganography 
### Intro
Steganography is a technique used to hide information within other files or data, making it difficult to detect without the use of special tools or techniques. This technique can be used to conceal sensitive information or to hide messages in plain sight.

In the realm of CTF challenges, steganography problems can come in all shapes and sizes. Image files are a common choice for hiding information, where the data is often stored in the least significant bits or in unused space within the image file. However, other types of files, such as audio or video files, can also be used.

There are countless methods and tools for hiding information in files, making this area of forensics a bit of a "wild west". Common tools used for steganography analysis include steghide, outguess, and zsteg, among others. Techniques for steganalysis, or the detection of hidden information, can include visual inspection, frequency analysis, and entropy analysis, among others.

### LSB 

The Least Significant Byte (LSB) is an important concept in computer science and cryptography, and is often used in Capture the Flag (CTF) competitions. The LSB refers to the lowest-order bit in a binary representation of a number, and is often used in steganography and encryption techniques to hide information within the least significant bits of a message.

In steganography, the LSB technique involves hiding a message within the least significant bits of a larger, innocuous-looking message. For example, an image or audio file might be used as the carrier message, with the hidden message encoded in the LSBs of the color or audio data. The LSBs are modified slightly to encode the hidden message without significantly changing the appearance or sound of the carrier message.

In cryptography, the LSB technique can be used to encrypt and decrypt messages using the same key. By encoding the message in the LSBs of the data, an encrypted message can appear random and difficult to decode without the proper key.

In a CTF competition, participants may be challenged to find hidden messages encoded in the LSBs of images, audio files, or other types of data. Participants may use tools such as binwalk or stegsolve to analyze the LSBs of a file and extract hidden information.

Overall, the concept of LSB is an important one in computer science and cryptography, and can be particularly useful in steganography and encryption techniques. In a CTF competition, participants who are familiar with the LSB technique can have an advantage when it comes to finding hidden messages and solving challenges.


### MSB 

The Most Significant Byte (MSB) is another important concept in computer science and digital systems. Unlike the LSB, which refers to the lowest-order bit in a binary representation of a number, the MSB refers to the highest-order bit in a binary representation of a number.

In digital systems, the MSB is often used to indicate the sign of a number, with a value of 0 indicating a positive number and a value of 1 indicating a negative number. In addition, the MSB is often used to determine the magnitude of a number, with the remaining bits representing the value of the number itself.

In some contexts, the MSB can also be used in cryptographic techniques, similar to the LSB. For example, in stream ciphers, the MSB can be used to generate a key stream that is XORed with the plaintext to produce the ciphertext.

In a CTF competition, participants may encounter challenges that require them to manipulate the MSB of a binary value in order to uncover a hidden message or solve a puzzle.

### exiftool

The exiftool command is a valuable tool to analyze and extract information from a variety of file formats. One common use case for exiftool in a CTF is analyzing digital photos to extract hidden metadata that might contain clues or hints.

Using exiftool, CTF participants can extract and display metadata information from digital photos such as camera settings, GPS location data, timestamps, and more. This can provide valuable insights into the origin and context of the photo, and may even reveal hidden messages or clues that can help participants solve the CTF challenge.

Two popular switches used with exiftool in a CTF context are:

    -b  
This switch extracts binary data from metadata fields, such as thumbnail images embedded in the photo. This can be useful for finding hidden information that might not be immediately visible in the photo itself.

    -trailer  
This switch tells exiftool to extract metadata information from the trailer of a file. This can be useful for finding hidden information that might be appended to the end of the file, such as secret messages or encrypted data.

Overall, the exiftool command is a powerful and flexible tool for analyzing and extracting metadata from a variety of file formats, and can be especially useful in a CTF competition where participants are challenged to extract hidden information and solve puzzles.

### Stegveritas 

A steganography tool that can be used to detect hidden information within images. It allows for the identification of the type of steganography being used and can extract hidden data from images. Stegveritas also has the capability to recover lost data. It seems to be the most versatile tool as it can analyze a wide range of file types.

![Pasted image 20230315125251](https://user-images.githubusercontent.com/50979196/229358521-cef4dff7-2319-4f69-a35f-c3983a1f7e5a.png)


### Steghide 
A steganography tool that allows users to embed hidden data within image and audio files. It uses strong encryption algorithms to hide the data and is useful for hiding sensitive information or secret messages within images or audio files. Steghide can also extract hidden data from files.

![Pasted image 20230216081232](https://user-images.githubusercontent.com/50979196/221450510-6200f7e2-45b7-4669-afb4-430cad7c25f7.png)

### Zsteg 
A steganography tool that can be used to detect hidden information within images. It can be used to identify the type of steganography being used, extract hidden data, and even recover lost data. Zsteg is particularly useful for identifying the presence of LSB (Least Significant Bit) steganography, which is a common technique used to hide data within images.
![Pasted image 20230221160217](https://user-images.githubusercontent.com/50979196/221450531-b66bfdf7-3c9d-4cd0-9a20-54fe3d14c5ef.png)

### Stegsolve 
A Java-based tool that can be used to analyze and manipulate images for steganography purposes. It provides a range of filters and visual aids to help users identify hidden information within images. Stegsolve is particularly useful for identifying the location and type of steganography being used within an image.
![Pasted image 20230221202426](https://user-images.githubusercontent.com/50979196/221450558-7c93ed5f-4a8a-450a-84d1-8d77d9b77458.png)

### If stuck with Steg

https://stegonline.georgeom.net/checklist




# Memory Dumps
## Intro
Memory dumps are a type of digital forensic artifact that can be used to analyze the state of a computer's memory at the time of a crash or system failure. Memory dumps contain a complete snapshot of the memory contents of a computer, including the contents of volatile memory such as RAM, as well as the contents of any mapped physical memory pages. Memory dumps can be used to diagnose and troubleshoot system issues, as well as to recover and analyze digital evidence related to malicious activities or other incidents.

In digital forensics and incident response (DFIR), memory dumps are considered a valuable artifact because they can provide insight into the state of a system at the time of an event of interest, including information about running processes, open network connections, and any malicious activity that may have been occurring in memory. Memory dumps can be analyzed using a variety of tools, including those specifically designed for memory analysis, as well as more general-purpose digital forensics tools.


**Fileless Malware**: Fileless malware is a type of malware that operates entirely in memory, making it difficult to detect and analyze. It can be executed through legitimate processes, such as PowerShell or WMI, and can evade traditional antivirus solutions.

Crash dump files will contain memory dump when system crashes

Page files stores data when the RAM is low on space - not a memory file

Common File formats of memory dumps 
-   Raw binary format (.bin)
-   Microsoft crash dump format (.dmp)
-   RAW (.raw)

## Kernel 

Kernels are responsible for managing system resources, such as memory, processes, and input/output operations. They provide a layer of abstraction between the hardware and the rest of the operating system, and allow applications to interact with the hardware without having to know the details of the underlying hardware.

Windows and Linux have different kernel architectures, although they share many similar concepts. The Windows kernel is a monolithic kernel, which means that all core system services are part of a single executable file (ntoskrnl.exe). The Windows kernel is responsible for managing memory, processes, threads, file systems, input/output operations, and other system services.

On the other hand, the Linux kernel is a modular kernel, which means that core system services are implemented as loadable kernel modules. This allows for greater flexibility and modularity, as system services can be loaded or unloaded dynamically as needed. The Linux kernel is responsible for managing memory, processes, threads, file systems, input/output operations, and other system services, and provides a wide range of configurable options and features.

In terms of memory forensics, the differences between Windows and Linux kernels can affect how memory is organized and accessed by memory forensics tools such as Volatility. For example, the Windows kernel uses a Virtual Address Descriptor (VAD) tree to manage process memory, while the Linux kernel uses a Virtual Memory Area (VMA) structure. The details of how the kernel manages memory can affect how memory forensics tools parse and interpret the data, and can impact the accuracy and completeness of the analysis.

Overall, understanding the kernel architecture and how it manages system resources is an important aspect of memory forensics analysis, and can help analysts to correctly interpret and analyze the data in memory. The differences between Windows and Linux kernels are important to consider when using memory forensics tools on different operating systems.

## Executive Objects

Windows is written in C and uses C structures. Some of these structures are Executive Objects. These executive objects are under the management (creation, protection, deletion, etc.) of the Windows Object Manager, a fundamental component of the kernel implemented through the NT module. Every executive object is preceded by a header in memory. Before an instance of an exectuve object is created, a memory block must be allocated. 

| Object        | Description                                                                   |
|---------------|-------------------------------------------------------------------------------|
| Event         | Synchronization object used to signal events between processes.              |
| Mutant        | Synchronization object, also known as a mutex, used for mutual exclusion.     |
| Semaphore     | Synchronization object used to control access to a common resource.           |
| Directory     | Represents a directory or folder in the file system.                          |
| Key           | Represents a key in the Windows registry.                                    |
| IoCompletion  | Used for asynchronous input/output (I/O) completion notifications.            |
| File          | Represents a file in the file system.                                        |
| WindowStation | Represents a window station used to manage windows, menus, atoms, and hooks.  |
| Process       | Represents a running process in the operating system.                         |
| Thread        | Represents a thread, the basic unit of execution within a process.            |
| Desktop       | Represents a desktop object contained within a window station.                |
| ALPC Port     | Represents an Advanced Local Procedure Call (ALPC) port.                      |
| SymbolicLink  | Represents a symbolic link in the object namespace.                           |
| Timer         | Represents a timer object used for scheduling timed notifications.            |
| KeyedEvent    | Synchronization object used to signal events between processes.              |
| Section       | Represents a memory section object, used for memory mapping and sharing.      |
| Token         | Represents an access token containing security information for a logon session.|
| Job           | Represents a job object, used to manage and track sets of processes.          |
| EtwRegistration | Used for event tracing registration.                                        |
| Type          | Represents an object type in the object manager namespace.                    |



## Strings
It is possible to run strings on a memory dump to extract info

![image](https://github.com/dbissell6/DFIR/assets/50979196/271f4112-a784-43e3-80cf-1338872e62ad)

Grep for commands
`
strings PhysicalMemory.raw | grep -E "(cmd|powershell|bash)[^\s]+"
`

## Volatility

Volatility 3 is an Open-Source memory forensics tool that allows analysts to extract and analyze information from a computer's volatile memory, such as running processes, network connections, and open files. To do this, Volatility needs to know the kernel version and build of the operating system from which the memory was obtained. This is because the kernel is responsible for managing the memory and processes, and its data structures and behavior can change between different versions or builds of the operating system.

`
https://volatility3.readthedocs.io/en/latest/index.html
`


### Fix



Two primary types of network artifacts are sockets and connections. 

Kernel modules are pieces of code that can be dynamically loaded and unloaded into the operating system's kernel at runtime.



### General Steps

1.    Processes
2.    DLL and Handles
3.    Network
4.    Code Injection
5.    Rootkits
6.    Dump

### Windows Commands

To see options

![image](https://github.com/dbissell6/DFIR/assets/50979196/cae9895d-1e7c-4c77-98b7-2e1627fccba5)


Get image information
```
python3 ~/Tools/volatility3-1.0.0/vol.py -f memory.raw windows.info   
```
See Process List
```
python3 ~/Tools/volatility3-1.0.0/vol.py -f memory.raw windows.pslist
```
See Process List + Hiddens

```
python3 ~/Tools/volatility3-1.0.0/vol.py -f memory.raw windows.psscan
```

Can sort by create time

![image](https://github.com/dbissell6/DFIR/assets/50979196/e2e3fa0d-75bc-45c5-bc1c-7b594af3cbf9)


![image](https://github.com/dbissell6/DFIR/assets/50979196/9ccae185-d43b-461d-ae0e-c30a6050b466)


See Process tree
```
python3 ~/Tools/volatility3-1.0.0/vol.py -f memory.raw windows.pstree
```
See all active network connections and listening programs
```
python3 ~/Tools/volatility3-1.0.0/vol.py -f memory.raw windows.netscan
```
Find all handles opened by process 3424. A handle represents an active instance of a kernel object that is currently open, like a file, registry key, mutex, process, or thread.

```
python3 ~/Tools/volatility3-1.0.0/vol.py -f memory.raw windows.handles --pid 3424
```
List all available Windows Registry hives in memory
```
python3 ~/Tools/volatility3-1.0.0/vol.py -f memory.raw windows.registry.hivelist
```
Print a specific Windows Registry key, subkeys and values
```
python3 ~/Tools/volatility3-1.0.0/vol.py -f memory.raw windows.registry.printkey --key "Software\Microsoft\Windows\CurrentVersion" --recurse
```
Print Windows Registry UserAssist
```
python3 ~/Tools/volatility3-1.0.0/vol.py -f memory.raw windows.registry.userassist
```
Dump windows registry hivelist
```
python3 ~/Tools/volatility3-1.0.0/vol.py -f memory.raw -o "dump" windows.registry.hivelist --dump
```
File Scan
```
python3 ~/Tools/volatility3-1.0.0/vol.py -f memory.raw windows.filescan | grep 'rsteven\Desktop\vlc-win32\vlc.exe'
```
Extract file
```
$ python3 ~/Tools/volatility3-1.0.0/vol.py -f memory.raw windows.dumpfiles --virtaddr 0xad81ecda9910 --dump-dir .
```
Dump Windows user password hashes
![Pasted image 20221123074049](https://user-images.githubusercontent.com/50979196/221450622-46170f92-5a13-42dd-a7ff-4b9b1479f2b1.png)

Print dlls
```
python3 ~/Tools/volatility3-1.0.0/vol.py -f memory.raw windows.dlllist
```
PoolScanner

Memory pools are regions of memory set aside for dynamic memory allocation during the execution of a program.

![image](https://github.com/dbissell6/DFIR/assets/50979196/0f6f8df5-1462-4ff7-80b3-d03b8a6f196d)


BigPools

To print large kernel pools in a memory dump.

![image](https://github.com/dbissell6/DFIR/assets/50979196/ba4baa77-84d8-4969-bfd6-0b653e39c6b6)


memmap

Analyze memory mappings for a specific process (PID 8580) from the provided memory dump file (PhysicalMemory.raw) and extracts relevant details about these memory mappings.

![image](https://github.com/dbissell6/DFIR/assets/50979196/605b8d23-b56a-4b8c-a7f9-76a4b236a44f)


envars

Display the environment variables for processes running in the memory image

![image](https://github.com/dbissell6/DFIR/assets/50979196/b9d4d2f8-1ba9-4bba-9093-32e2691e16e0)

vadinfo

![Pasted image 20231011051428](https://github.com/dbissell6/DFIR/assets/50979196/250c46f8-c94a-47be-a1af-a565eb183210)
Virtual Address Descriptors (VAD):

The VAD tree in Windows provides metadata about the virtual memory regions allocated by a process. Each node in this tree represents a block of committed virtual memory, a memory-mapped file, or a reserved block of addresses.

1. **Memory Analysis**: It helps forensic analysts understand what regions of memory a process was using, how it was using them, and what permissions were set.
2. **Find Hidden or Injected Code**: Malware might inject code into a process's address space. By analyzing the VAD tree, you can identify anomalous or unexpected memory regions which might indicate such injections.
3. **Memory-Mapped Files**: These are areas of virtual memory that are mapped to a physical file on disk. This is common for shared libraries/DLLs. A malware might map a malicious DLL into a process's memory.
4. **Discover Protection Mechanisms**: Some software might employ anti-debugging or anti-analysis techniques, such as self-modifying code. Understanding the memory permissions can give insights into such behaviors.


Memory Permissions:

Memory permissions determine how a certain region of memory can be accessed.
- **PAGE_EXECUTE**: The memory can be executed as code. This is often seen in regions where the actual binary code of a process resides.
- **PAGE_EXECUTE_READ**: The memory can be executed as code, and can be read.
- **PAGE_EXECUTE_READWRITE**: The memory can be executed as code, read from, and written to. This permission can be concerning, as it might indicate a region where malicious shellcode could be inserted and executed.
- **PAGE_EXECUTE_WRITECOPY**: Similar to the above but can be written to if a process attempts to modify it. A new private copy is made for the process.




ldrmodules

The ldrmodules plugin in Volatility is used to list the loaded modules (DLLs) for a specific process. It is particularly valuable for detecting unlinked or hidden DLLs which can be indicative of malicious activity. 

Each module will have three columns: InLoad, InInit, and InMem. These indicate whether the module is:

    Loaded into memory (InLoad)
    Initialized (InInit)
    Present in the process memory (InMem)

If all three columns for a specific module are False, it might suggest the operation of a rootkit or malicious software trying to conceal its activities.

![image](https://github.com/dbissell6/DFIR/assets/50979196/8f738a78-e847-4c06-9cdb-ccc0eade7acc)


Modules:
The Modules plugin in Volatility examines the metadata structures linked through PsLoadedModuleList, a doubly linked list. When the operating system loads new modules, they are added to this list. By analyzing this list, the Modules plugin allows you to understand the relative temporal order of module loading. Essentially, you can determine the sequence in which modules were loaded into the system.

Modscan:
The Modscan plugin employs pool tag scanning across the physical address space, even including memory that has been freed or deallocated. Does not follow the EPROCESS list which can be useful to find hidden processes. It specifically searches for MmLd, which is the pool tag associated with module metadata. This plugin is valuable for identifying both unlinked modules and modules that were previously loaded. By scanning the pool tags, it helps uncover module-related information, contributing to a comprehensive analysis of the system's module activities.

![image](https://github.com/dbissell6/DFIR/assets/50979196/c4645d8c-9dc8-444a-8f72-1d8885987acf)



### Vol Extras

https://readthedocs.org/projects/volatility3/downloads/pdf/latest/
https://dfir.science/2022/02/Introduction-to-Memory-Forensics-with-Volatility-3

## VolShell

![image](https://github.com/dbissell6/DFIR/assets/50979196/89a51b9d-eb60-4465-83b1-72ec863f77ad)

### Running plugins

![image](https://github.com/dbissell6/DFIR/assets/50979196/eb22bc11-3146-481e-823d-ca07a7e4d3ae)

Module requirement

![image](https://github.com/dbissell6/DFIR/assets/50979196/8ed04277-6635-44c6-813a-25a9a448031e)

### help

![image](https://github.com/dbissell6/DFIR/assets/50979196/e49999cb-7467-4a1a-a86d-49939ca463a6)


## yara

![image](https://github.com/dbissell6/DFIR/assets/50979196/9c18bff0-267c-4830-85c4-bf7e3286b76f)


Rules at
```
https://github.com/Yara-Rules/rules
```

![image](https://github.com/dbissell6/DFIR/assets/50979196/0db2eace-aa03-4359-abc3-c87d9d8ca107)



# Disk

## Intro
Disk images are copies of an entire disk drive or a portion of it. In DFIR, disk images are an essential tool for preserving the evidence and state of the original disk. Analyzing disk images can reveal important information such as deleted files, hidden files, and other artifacts that can provide valuable insight into an incident.Some common forms of disk images include raw images, Encase images, and AFF4 images.

Typically found as: .img, .dd, .raw, ISO, EWF(Expert witness format. contains raw + metadata), .ad1

Virtual Drive Formats: .vmdk, .vhdx

Differences in the way that Linux and Windows handle disk drives, which can be relevant to forensic analysis in a CTF challenge.

-    File systems: Linux and Windows use different file systems to organize and store data on disk drives. Windows primarily uses the NTFS (New Technology File System) file system, while Linux typically uses the ext4 (Fourth Extended File System) file system. There are also other file systems used by both operating systems, such as FAT32, exFAT, and ReFS (Resilient File System). Different file systems have different structures and metadata, which can affect the way that files are stored, accessed, and recovered.

-    Permissions and ownership: Linux and Windows use different approaches to managing permissions and ownership of files and directories. Linux uses a permission model based on users, groups, and permissions bits (e.g., read, write, execute), while Windows uses a more complex permission model that includes access control lists (ACLs) and security identifiers (SIDs). This can affect the way that files and directories are accessed and modified, as well as the ability to recover deleted files or data.

-    Disk partitioning: Linux and Windows use different methods for partitioning disk drives. Windows uses the Master Boot Record (MBR) or the newer GUID Partition Table (GPT) for partitioning, while Linux typically uses the GPT partitioning scheme. Different partitioning schemes can affect the way that data is organized and accessed on the disk, as well as the ability to recover deleted files or data.

-    Forensic tools and techniques: Different forensic tools and techniques may be needed to analyze disk drives on Linux versus Windows. For example, some tools may be more effective at recovering data from a specific file system or partitioning scheme, while others may be better suited for analyzing permissions and ownership. It is important to understand the differences between Linux and Windows disk drives when selecting and using forensic tools and techniques for a CTF challenge.

**File Carving**: File carving is a technique used to extract data from a file or disk image without the use of a file system. This technique can be used to recover lost or deleted files or to analyze malware that may be hiding within a file. Some commonly used file carving tools include Scalpel, Foremost, and PhotoRec. It requires a deep understanding of the file structure and data recovery techniques.


Hard drive type

-    The capacity to recover deleted files is influenced by the type of hard drive utilized. In the case of mechanical hard drives, it's advisable to refrain from deleting data directly from the disk, as marking it as deleted prompts the hard drive to overwrite the area with fresh data. Hence, deleting the data becomes an unnecessary action. On the other hand, Solid-State Drives (SSD) face limitations in writing new data to already occupied areas. Writing data to a marked-as-deleted area on an SSD involves two operations: first, erasing the old data, and then writing the new data. SSDs often implement techniques to periodically remove data marked for deletion, enhancing their speed. Consequently, the presence of deleted files is generally lower on an SSD compared to a mechanical disk.



## FTK Imager to extract a .ad1

File -> Add Evidence Item -> Image -> source path -> Finish


Evidence Tree -> right click on root -> Export Files

![image](https://github.com/dbissell6/DFIR/assets/50979196/e16c1e2c-2de0-46bd-9d08-0763019635d3)

![image](https://github.com/dbissell6/DFIR/assets/50979196/a6837611-5839-421e-acfb-54c8d00bbb10)


## Example fdisk+Mount Linux

Mounting a file system in Linux is similar to gaining access to a victim system on platforms like Hack The Box (HTB). However, there are some key differences. Unlike a live computer, the mounted system is just a file system, and you cannot run commands like netstat to view current connections. You arnt on the system, just the file system like plugging in an external hardrive. Despite this, the process of enumeration from a pentesting perspective is similar. The advantage of mounting a file system is that you can use sudo, which grants you root access to the mounted system, allowing for more comprehensive analysis and investigation. This is useful when looking for sensitive information or and intresting executable... Other times you may only need to extract logs.

In order to mount a filesystem, you typically need to first determine the offset or starting point of the filesystem within the disk image or device file. Once you have determined the offset, you can then use the "mount" command with the "-o loop" option to mount the filesystem at the specified location.

To find offset in order to mount.
```
fdisk -l disk.img
```
![Pasted image 20230216134532](https://user-images.githubusercontent.com/50979196/221450652-341c6db0-16a0-4fec-bafc-094d9a3f56d1.png)

![Pasted image 20230216134646](https://user-images.githubusercontent.com/50979196/221450672-b00b0f20-2d3c-4326-b7f4-07564f01b4ac.png)

```
mkdir test
```
```
 sudo mount -o loop,offset=210763776 disk.flag.img test/   
```
![Pasted image 20230216101009](https://user-images.githubusercontent.com/50979196/221450698-af50833b-dc66-47a8-96d9-01d5568a69e8.png)

### automate search

Just like pentesting we can use linpeas in the mount. This has helped me to find important files in CTFs.
```
 sudo /usr/share/peass/linpeas/linpeas.sh -f ~/PICO/Forensics/Orchid/test 
```

Noob tip if you mount the system and you try to access something like root and it says permission denied, use sudo
```
sudo ls -la root
```

## Example fdisk+Mount Windows

![Pasted image 20230318133623](https://user-images.githubusercontent.com/50979196/229358946-72832415-38f2-4742-ba91-c91332de8981.png)
![Pasted image 20230318133610](https://user-images.githubusercontent.com/50979196/229358957-684da311-e205-419d-a3e2-29e26e6bfc4e.png)
![Pasted image 20230318133553](https://user-images.githubusercontent.com/50979196/229358976-02560289-3226-4f8f-af22-11dc6e120430.png)
![Pasted image 20230318133535](https://user-images.githubusercontent.com/50979196/229359015-4c1dd124-6f5e-4709-9168-335a1d6ea0cf.png)
![Pasted image 20230318133520](https://user-images.githubusercontent.com/50979196/229359026-40b14558-22fb-4a98-9e80-7e52a39465e3.png)

## Autopsy on Linux

GUI to look at disk.

![image](https://github.com/dbissell6/DFIR/assets/50979196/0a786bbe-9ff6-496a-954d-9159ba36ae13)


![image](https://github.com/dbissell6/DFIR/assets/50979196/f0b23d9c-2655-4529-8980-2b7df58535af)

New Case -> Add Host -> Add Image -> Analyze -> File Analysis


![image](https://github.com/dbissell6/DFIR/assets/50979196/8c4d7c83-4111-41fe-8f79-e47c2f3b8c78)

![image](https://github.com/dbissell6/DFIR/assets/50979196/a4fcf7a2-8897-41fc-af6a-b44c82f7ad74)

![image](https://github.com/dbissell6/DFIR/assets/50979196/36734528-4de2-4deb-bb42-52b0b577b6bf)


![image](https://github.com/dbissell6/DFIR/assets/50979196/08a2ecbe-2cc1-44e9-9357-e37bfa0d0837)

In file analysis can browse directories and see All Deleted Files. 

### Autopsy on Windows

![image](https://github.com/dbissell6/DFIR/assets/50979196/95281b66-8ff0-4f22-8e5f-5f1796926074)


Open Case -> Next -> Finish

![image](https://github.com/dbissell6/DFIR/assets/50979196/19d0c14c-afda-418b-ad62-114874ab4ddf)

Start analysis, this will take a while.

![image](https://github.com/dbissell6/DFIR/assets/50979196/59681d80-b5e6-4158-bcda-d5c73b038c6d)


### Autopsy Timeline


![image](https://github.com/dbissell6/DFIR/assets/50979196/31272248-c42d-4ec8-a2c9-f173a27f712c)

## Mount Windows on Windows

```
Mount-DiskImage -Access ReadOnly -ImagePath 'C:\Users\Blue\Desktop\Artifact Of Dangerous Sighting\HostEvidence_PANDORA\2023-03-09T132449_PANDORA.vhdx'
```
![image](https://github.com/dbissell6/DFIR/assets/50979196/ce18f597-cff5-4bb5-b52f-c0791bd6ebc5)


![image](https://github.com/dbissell6/DFIR/assets/50979196/b0ada041-cf64-43bf-8a49-25b5f11aeb1a)


![image](https://github.com/dbissell6/DFIR/assets/50979196/2634f8f8-8e73-47ad-8c15-251a25da069a)


### Alternate data streams

Alternate Data Streams are a feature of the NTFS file system that allows multiple data streams to be associated with a single file. While the primary data stream contains the file's actual content, these additional streams can store metadata or even other files discreetly, often going unnoticed by standard file browsing tools, making them a potential avenue for concealing data or malicious activity.

![Pasted image 20230930155804](https://github.com/dbissell6/DFIR/assets/50979196/cb46efd3-4520-49cc-9719-6741da939656)

![Pasted image 20230930160814](https://github.com/dbissell6/DFIR/assets/50979196/0a50308f-2a19-43d0-8d59-d264c0f66c5a)

![Pasted image 20230930160904](https://github.com/dbissell6/DFIR/assets/50979196/368a57fb-5a68-402a-9c9c-8399380caf9f)


## PowerForensics

PowerForensics is a powerful and flexible tool for digital forensic investigations on Windows systems. Can use on mounted systems or live systems. PowerForensics offers a suite of cmdlets that can extract a variety of forensic artifacts, such as the Master File Table (MFT), Volume Boot Record (VBR), Event Logs, and more.

`
Get-ForensicFileRecord -VolumeName E:
`

![image](https://github.com/dbissell6/DFIR/assets/50979196/3d04b74f-3f55-4891-84b3-986f5906cf8c)

`
Get-ForensicAlternateDataStream -VolumeName E:
`

Alternate Data Stream

![image](https://github.com/dbissell6/DFIR/assets/50979196/55ff5415-8af6-4a4b-9880-bb600afa9528)


Example HTB Artifact Of Dangerous Sighting

## SluethKit

SleuthKit is another popular open-source digital forensic platform that provides a set of command-line tools for analyzing disk images. It supports a wide range of file systems, including FAT, NTFS, and EXT, and can be used to recover deleted files, view file metadata, and perform keyword searches.

    mmls: The 'mmls' command is used to display the partition layout of a disk image. It identifies the start and end sectors of each partition and displays other information such as the partition type, size, and offset. This information is important for identifying the partition that contains the file system you're interested in.

    fsstat: The 'fsstat' command is used to display information about a file system, such as its size, block size, and the number of allocated and unallocated blocks. It can also display information about the file system's metadata, such as the location of the Master File Table (MFT) in NTFS file systems.

    fls: The 'fls' command is used to list the contents of a file system. It displays the files and directories in the file system along with their attributes and inode numbers. The 'fls' command can also display deleted files and directories, which can be important for recovering data that has been deleted by an attacker or lost due to a system crash.

`sudo mmls dds1-alpine.flag.img `

![image](https://github.com/dbissell6/DFIR/assets/50979196/ed23a38f-35e9-417d-9ab4-fdc8b938a3e8)


`sudo fsstat -o 2048 dds1-alpine.flag.img `

Replace '2048' with the start sector of the partition you're interested in.

![image](https://github.com/dbissell6/DFIR/assets/50979196/c05f3d8e-583e-4b4f-90d4-7973659a280e)


Use the 'fls' command to list the contents of the file system:

`sudo fls -o 2048 -f ext3 dds1-alpine.flag.img `

![image](https://github.com/dbissell6/DFIR/assets/50979196/775bd734-5a20-4edd-930b-a70508643dab)


Search a folder recursivly by specifying inode

`sudo fls -r -o 2048 dds1-alpine.flag.img 20324`

![image](https://github.com/dbissell6/DFIR/assets/50979196/48d7d6f5-e553-45d9-a253-f9c8e4a1ed2c)



## foremost

Foremost is a tool that is used for file recovery and reconstruction. It can be used to recover deleted files, carve out files from disk images, and extract files from various file formats. Foremost is particularly useful for recovering files from damaged or corrupted disks, or for recovering files that have been deleted or lost.

Foremost uses a technique called file carving to recover files from disk images or other sources. It scans through the input data looking for specific file headers and footers, and then extracts the data between them. Foremost supports a wide range of file types, including images, audio files, videos, documents, and archives.

Foremost can be used in a variety of scenarios, such as when trying to recover deleted files, investigating a cybercrime incident, or recovering data from a damaged disk. It is a powerful tool for file recovery and reconstruction and can help in restoring valuable data that may have been lost or deleted.



## RAID Disk recovery

### RAID Intro

RAID, or Redundant Array of Independent Disks, is a technology that allows multiple hard drives to be used as a single logical unit for storing data. While RAID can provide increased performance and redundancy, it can also make data recovery more challenging in the event of a disk failure.

RAID 5 is a popular type of RAID configuration that provides both data redundancy and increased performance. However, in CTF competitions, RAID 5 arrays are often deliberately subjected to various types of failures to test the contestants' ability to recover data.

Some common types of RAID 5 failures that may be encountered in CTFs include:

-   Single Drive Failure: If a single drive in a RAID 5 array fails, the array can still function. However, the array becomes more vulnerable to additional drive failures, and the performance may be degraded.

-   Multiple Drive Failures: If multiple drives fail in a RAID 5 array, data loss can occur. The number of drive failures that can be tolerated depends on the number of drives in the array and the stripe size. In CTFs, multiple drive failures may be simulated by removing multiple drives from the array.

-   Rebuild Failure: When a failed drive is replaced in a RAID 5 array, the data is rebuilt onto the new drive from the parity data. However, if the parity data is incorrect or missing, the rebuild may fail, and data loss can occur. In CTFs, contestants may be given a partially rebuilt RAID 5 array and asked to recover the missing data.

-   RAID Controller Failure: If the RAID controller fails in a RAID 5 array, the array can become inaccessible. In CTFs, contestants may be given a faulty RAID controller and asked to recover the data without the controller.

To successfully recover data from a failed RAID 5 array in a CTF, contestants must have a deep understanding of RAID 5 configurations, data recovery techniques, and tools. By practicing and gaining experience with these challenges, contestants can become more skilled at recovering data from RAID 5 arrays and gain a competitive advantage in CTF competitions.

### XOR
In a RAID 5 array with n drives, data is striped across n-1 drives, and a parity block is stored on the remaining drive. The parity block is generated using an XOR operation on the corresponding blocks of data on the other drives. This means that if one of the drives fails, the missing data can be reconstructed using the data on the remaining drives and the parity block.

Here's an example to illustrate how XOR can be used to recover missing data in a RAID 5 array:

Suppose we have a RAID 5 array with 3 drives, A, B, and C, and a block size of 512 bytes. We write a file that is 1KB in size, which is striped across the drives as follows:

    Block 1 is written to drive A
    Block 2 is written to drive B
    Block 3 is written to drive C
    Parity block is calculated as XOR of blocks 1, 2, and 3 and written to drive A (the parity block can be written to any drive)

If drive B fails, we can recover the missing data as follows:

    Read blocks 1 and 3 from drives A and C, respectively
    Calculate the missing block 2 as the XOR of blocks 1, 3, and the parity block on drive A: Block 2 = Block 1 XOR Block 3 XOR Parity
    Write the recovered data to a new drive to rebuild the RAID array

By using XOR to calculate the missing block, we can recover the data that was lost due to the failure of one of the drives in the RAID 5 array. However, if more than one drive fails, the recovery process becomes more complex and may require specialized tools and techniques.

The following python psuedocode first simulates a file that is 1KB in size and striped across a RAID 5 array with three drives. It then simulates a single drive failure by removing drive B from the array. Finally, it uses XOR to recover the missing data from the remaining drives and the parity block.

```
# Define the RAID 5 array configuration
drives = ['A', 'B', 'C']    # Drive labels
block_size = 512            # Block size in bytes

# Simulate a file that is 1KB in size striped across the drives
data = b'0123456789' * 100  # 1KB file data
n_blocks = len(data) // block_size
stripe = [[] for _ in range(len(drives))]
parity = [0] * block_size

for i in range(n_blocks):
    block = data[i*block_size:(i+1)*block_size]
    parity = [p ^ b for p, b in zip(parity, block)]
    for j in range(len(drives)):
        if j != i % len(drives):
            stripe[j].append(block)

stripe.append(parity)

# Simulate a single drive failure (drive B)
failed_drive = 1

# Recover the missing data using XOR
recovered_data = b''
for i in range(n_blocks):
    if failed_drive == i % len(drives):
        block1 = stripe[(i+1)%len(drives)][i//len(drives)]
        block2 = stripe[(i+2)%len(drives)][i//len(drives)]
        recovered_block = bytes([b1 ^ b2 ^ p for b1, b2, p in zip(block1, block2, parity)])
        recovered_data += recovered_block
    else:
        block = stripe[i%len(drives)][i//len(drives)]
        recovered_data += block

print(recovered_data)
```


https://blog.bi0s.in/2020/02/09/Forensics/RR-HackTM/

### mdadm

mdadm is a Linux utility used for managing and monitoring software RAID devices. It allows users to create, manage, and monitor RAID devices, as well as to assemble and disassemble RAID arrays. In CTFs, mdadm can be used to reconstruct a RAID 5 array using information about the disks that make up the array. This can be helpful when trying to recover data or find hidden clues in a CTF challenge that involves a RAID 5 array.

### losetup

losetup is a Linux command used to set up and control loop devices, which are virtual block devices that allow a file to be accessed as if it were a block device. In the context of RAID 5 reconstruction in a CTF, losetup can be used to map individual disks or partitions that make up a RAID 5 array to a loop device. Once the disks are mapped to loop devices, tools like mdadm can be used to assemble the array and recover the data.

```
Scenario:
You are participating in a CTF and have been given an image of a RAID 5 array. The image consists of four disks, with one of them having failed. Your task is to reconstruct the array and recover the data. The image file is named raid5.img.

Steps:

    Determine the block size of the RAID array by inspecting the image file. You can use the fdisk command to view the partition table of the image file and note the block size. Let's assume that the block size is 512 bytes.

bash

fdisk -l raid5.img

    Create loop devices for the image file and each disk image. You can use the losetup command to associate the image files with loop devices. Let's assume that the disk images are named disk1.img, disk2.img, and disk3.img.

bash

losetup -fP raid5.img
losetup -fP disk1.img
losetup -fP disk2.img
losetup -fP disk3.img

    Use mdadm to create the RAID 5 array using the loop devices. The -C option creates a new array, -l5 specifies RAID level 5, -n4 specifies the number of disks in the array, and missing indicates that one disk is missing.

bash

mdadm -C /dev/md0 -l5 -n4 missing /dev/loop0 /dev/loop1 /dev/loop2

    Verify that the array is created successfully and check the status. The /proc/mdstat file shows the current status of the array.

bash

cat /proc/mdstat

    Use mdadm to add the failed disk to the array. The -a option adds a new device to the array.

bash

mdadm /dev/md0 -a /dev/loop3

    Once the array is reconstructed, mount it and recover the data as necessary.

bash

mount /dev/md0 /mnt/raid



```


# Infected host

## Intro
2 things to take from here 

1) Extracting the artifacts
2) Performing an analysis from (a copy) of the infected host machine


# Extracting

This may not come up often on a CTF, in CTFs you are almost always provided with the artifacts to analyze. However it could happpen and more likly if you are here you are going to want a job
in this domain and you really dont want to get into a job interview and know complex things like malware analysis and miss what they consider to be fundentamental questions like the  process of making a copy
of a disk. `Crede experto`

One question in this domain is if you are working on a site and someone thinks thier computer is compromised what should you do. DO NOT TURN IT OFF, this will elimiate the volatile memory. DO, Disconnect it from the network. 
Make the copies of the artifacts you need.


## Dump Windows Disk

### FTK Imager

File -> Create Disk Image - Physical Drive -> Add -> E01 -> fill info -> finish -> start

Expert Witness Format (.e01) contains not only the raw disk image (similar to a .dd file) but also additional metadata and information related to the forensic image.

This may take a while

![image](https://github.com/dbissell6/DFIR/assets/50979196/84d4ecea-b863-4fb1-9d49-2070249e49a6)


### Caine 

Press F12 when booting select Caine

![image](https://github.com/dbissell6/DFIR/assets/50979196/ba313772-e911-414f-a851-8a8defd7e4d1)





## KAPE (Kroll Artifact Parser and Extractor)

KAPE extracts artifacts from a system, isnt open source. 

### Velociraptor + KAPE

Velociraptor is a robust EDR tool that allows for remote artifact collection and analysis at scale. Leveraging its Velociraptor Query Language (VQL) and Hunt capabilities, analysts can efficiently gather host-based information and artifacts, streamlining evidence collection and enabling rapid triage.

Choose a host -> New Hunt -> Configure Hunt -> Select Artifacts -> Configure Parameters -> Launch -> Download results -> Available Downloads

![image](https://github.com/dbissell6/DFIR/assets/50979196/792ce1c1-0bcd-4185-9633-5fab519615d2)

Choose Windows.Kape

![image](https://github.com/dbissell6/DFIR/assets/50979196/02e8611c-9109-44a4-85fd-93a224eed119)


![image](https://github.com/dbissell6/DFIR/assets/50979196/52c33979-1150-4571-b819-74bad1c94ec8)

![image](https://github.com/dbissell6/DFIR/assets/50979196/98ca346b-24c6-4161-87f0-9c99bf1bd50d)

![image](https://github.com/dbissell6/DFIR/assets/50979196/e9115645-3670-4932-a064-e3c6a01e635e)


```
Typical output/
|-- Windows/
|   |-- $Boot
|   |-- $Extend
|   |-- $LogFile
|   |-- $MFT
|   |-- $Recycle.Bin
|   |-- ProgramData
|   |-- Program Files
|   |-- Users
|   |-- System32
|       |-- config
|       |-- LogFiles
|       |-- SleepStudy
|       |-- sru
|       |-- Tasks
|       |-- wbem
|       |-- WDI
|       |-- winevt
|           |-- Logs
```
![image](https://github.com/dbissell6/DFIR/assets/50979196/026a5c02-b22e-479b-89dd-c8cf1ba4253f)


## Dump Linux Disk

### dd

![image](https://github.com/dbissell6/DFIR/assets/50979196/7f79b088-69a1-4019-8cff-05ecdac38f33)


## Dump Windows Memory

### FTK Imager

Capture memory -> 

![image](https://github.com/dbissell6/DFIR/assets/50979196/38266a54-6d01-49f4-9ccd-02bc38807810)

![image](https://github.com/dbissell6/DFIR/assets/50979196/b0f7dfd7-65f2-4d4d-872f-332ec0630322)

![image](https://github.com/dbissell6/DFIR/assets/50979196/20817b80-3e46-4bf1-b43c-ce5dd997d104)

![image](https://github.com/dbissell6/DFIR/assets/50979196/8b4b221a-0646-4b66-bf23-315b6d6cabd2)

output .mem

### Velociraptor + memdump

![image](https://github.com/dbissell6/DFIR/assets/50979196/b632dc83-e695-47a1-9d14-f308190a9811)


output will be our .raw

![image](https://github.com/dbissell6/DFIR/assets/50979196/1c6b9a6a-52a1-437e-b9ed-f202bc6e7a16)



## Dump Linux Memory


## Network (.pcap)

Unlike logs, pcaps are not saved and kept by default. We will need to run something. This can be useful in conjuction when checking malware to see if its reaching out.

### Capture pcaps on Linux

#### wireshark

Wireshark -> pick interface -> let run -> Stop -> Save

![image](https://github.com/dbissell6/DFIR/assets/50979196/b48d4534-dd63-4df8-b7ca-e84903b1655d)


#### tcpdump

![image](https://github.com/dbissell6/DFIR/assets/50979196/0feb1122-9cd6-49c7-b63b-0569521986e0)


### Capture pcaps on Windows


# Live analysis Windows

Analyzing a live system or a direct copy of a virtual machine (VM) rather than static artifacts like disk images offers numerous advantages. These include real-time data analysis, dynamic state assessment, behavioral analysis, memory forensics, immediate triage, interaction with running services, malware detection and analysis, contextual understanding, reduced imaging time, and improved resource availability. While live analysis provides these benefits, it's essential to adhere to proper forensic procedures to minimize impact on the live system. A combined approach involving both live and artifact analysis ensures a comprehensive understanding of the incident and enhances the investigative process.

One way to do this is to mount Caine in the vm. 

On Virtual Box
`Devices -> Optical Drives -> Caine.iso`

In the VM
`This PC -> CD Drive CAINE`

## Some manual enumeration

get powershell history

```
type (Get-PSReadlineOption).HistorySavePath
```
Check loaded modules

![image](https://github.com/dbissell6/DFIR/assets/50979196/2d3c6f37-cca1-42c9-bd55-531c4f4381f1)

filtering on properties

![image](https://github.com/dbissell6/DFIR/assets/50979196/0db2a4ad-7a0d-460e-a6ed-c7e1227eeefc)

sorting

`Get-Service | Sort-Object -Property Status`

Finding/fitering with where

![image](https://github.com/dbissell6/DFIR/assets/50979196/2533415e-ecaf-4919-b9ad-eb800ca9ffc9)


Get registry

![image](https://github.com/dbissell6/DFIR/assets/50979196/4ce4bb02-38c3-4fee-ad0a-0bfe20c4f347)



## NirLauncher

NirLauncher is a tool package created by NirSoft that offers a collection of small utilities for various purposes, including system analysis, network monitoring, password recovery, and more. 


![image](https://github.com/dbissell6/DFIR/assets/50979196/e10bc1f6-aea4-4ad3-96ab-f2fb69d74a4d)


## Windows File Analyzer

Windows File Analyzer is a forensic tool designed to examine various Windows artifacts, such as registry hives, event logs, hibernation files and many more.

![image](https://github.com/dbissell6/DFIR/assets/50979196/ebc48498-88b3-42aa-a219-4fcc84585b54)

## Autoruns

Used on a live device to inspect registry and schd tasks and show processes that will run on startup.

![image](https://github.com/dbissell6/DFIR/assets/50979196/8a1009af-3192-45dc-8d88-0bc531d91caa)

## DNS
Can give clues to sites visited.

ipconfig /displaydns

![image](https://github.com/dbissell6/DFIR/assets/50979196/f04f22cc-5157-41fc-b7ce-fff8d74a53c5)

![image](https://github.com/dbissell6/DFIR/assets/50979196/29036a98-4300-41da-aac6-cd32c8f515d5)





# Live analysis Linux

Can nc into host to extract info to ensure nothing is put on disk.

![image](https://github.com/dbissell6/DFIR/assets/50979196/4ecb6bf4-012f-4c39-937c-417a460a217b)


![image](https://github.com/dbissell6/DFIR/assets/50979196/27159179-1119-411e-9bb2-0274c9922fc2)


lsof can be better than ps

![image](https://github.com/dbissell6/DFIR/assets/50979196/bdedec95-c780-402f-b9ad-e0ad3e229083)


## LinuxRescueCD

![image](https://github.com/dbissell6/DFIR/assets/50979196/9ac766ff-56a3-4304-88ca-fc1c5327b777)


# Cloud




## AWS


## Azure



# SIEMS

SIEM, which stands for Security Information and Event Management, is a comprehensive solution designed to provide real-time analysis of security alerts and events generated by various hardware and software entities within an IT infrastructure. Using a SIEM feels like a mix of viewing logs and see

## Splunk

Find available data sources

```
| metadata type=sourcetypes index=* | table sourcetype
```
```
| metadata type=sources index=* | table source
```

See Fields from a source

```
sourcetype="WinEventLog:Security" | fieldsummary
```


![image](https://github.com/dbissell6/DFIR/assets/50979196/c9d9219b-4537-4f00-bdd2-cab36f81bb6a)


![image](https://github.com/dbissell6/DFIR/assets/50979196/64a4ca2a-14f1-42f2-83bc-934db85978cc)

Can use sigmac to create queries

[Sigmac](https://github.com/dbissell6/DFIR/blob/main/Blue_Book/Blue_Book.md#sigmac)

Search and sort by client ID

```
index=* | stats count by clientip | sort - count
```



**Complex Examples**
```
index=*  Sysmon source="WinEventLog:Microsoft-Windows-Sysmon/Operational"  EventCode=3 |
bin _time span=1h |
stats count as NetworkConnections by _time, Image |
streamstats time_window=24h avg(NetworkConnections) as avg stdev(NetworkConnections) as stdev by Image |
eval isOutlier=if(NetworkConnections > (avg + (0.5*stdev)), 1, 0) | search isOutlier=1
```

*    We target network connection events with EventCode=3 and group them hourly. For every distinct process (Image), we tally the network connection events in each time slot.
*    A rolling 24-hour average and standard deviation of connection counts for each process is calculated using streamstats.
*    With the eval command, we tag events as outliers if their connection counts exceed 0.5 standard deviations from the average, indicating potential anomalies.
*    The results are then refined to display only these outliers.




## ELK

The ELK Stack, consisting of Elasticsearch, Logstash, and Kibana, is a robust suite of tools that collectively enable organizations to efficiently search, analyze, and visualize vast volumes of data in real-time.


### Discover

### controling columns

On left side can search for a feature and add it as a column by clickling blue + . 

![image](https://github.com/dbissell6/DFIR/assets/50979196/1267c1b4-aee8-44a3-9c36-159fda7eefc6)


#### Useful queries examples





# move



```mermaid
graph TD;
    A-->B;
    A-->C;
    B-->D;
    C-->D;
```


<details>

<summary>Tips for collapsed sections</summary>

### You can add a header

You can add text within a collapsed section. 

You can add an image or a code block, too.

```ruby
   puts "Hello World"
```

</details>



**Data Exfiltration Techniques**: Data exfiltration techniques are methods used by attackers to extract data from a compromised system. Common techniques include DNS exfiltration, FTP exfiltration, and HTTP exfiltration. DNS exfiltration involves sending stolen data in DNS queries. FTP exfiltration involves using FTP to transfer data to an attacker-controlled server. HTTP exfiltration involves sending stolen data over HTTP requests.





##
Bulk_Extractor is a tool that will scan pcaps, mem.raw ...
