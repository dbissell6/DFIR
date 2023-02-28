# The Blue Book
## Intro

In a world where cyber attacks are becoming more frequent and sophisticated, the ability to detect and respond to such attacks is critical for any organization. During a Cybersecurity Capture The Flag (CTF) competition, the blue team is responsible for detecting and responding to cyber attacks, and this often involves forensic analysis of systems, networks, and data.

This handbook is specifically geared towards the blue team during a CTF, and aims to provide a comprehensive guide for blue team forensics. In a CTF, the blue team's goal is to defend their systems against simulated cyber attacks launched by the red team, and this requires a deep understanding of key tools and techniques that can be used to detect and respond to such attacks.

Throughout this handbook, we will cover the various challenges that blue teams might encounter in a CTF. The structure of this document is sectioned by type of evidence given. 

1) Network traffic analysis, 
 
2) System logs analysis,
 
3) Files/Executables, 

4) Memory forensics 
 
5) Disk. We will also introduce key tools and techniques that can be used to detect and respond to cyber attacks during a CTF.

By the end of this handbook, you should have a solid understanding of blue team forensics and be equipped with the knowledge and tools necessary to effectively detect and respond to cyber attacks during a CTF.

Often it is important to remember that in more difficult challanges the flag cannot be found if you dont understand the story the evidence is telling. Therefore, keep detailed notes that reconstruct the timeline of important events.

## Ideas That Will be encountered
Malware Analysis Tools: Malware analysis tools are software programs used by analysts to dissect malware and understand its behavior. Some commonly used tools include IDA Pro, Ghidra, OllyDbg, and Immunity Debugger. IDA Pro is a disassembler and debugger that allows analysts to analyze the assembly code of a program. Ghidra is an open-source reverse engineering tool that allows for static analysis of binary files. OllyDbg is a debugger that allows analysts to step through a program and analyze its behavior. Immunity Debugger is a powerful debugger that can be used to find vulnerabilities in software. Each tool has its own strengths and use cases.

Static Analysis Techniques: Static analysis techniques involve analyzing the code of a program without actually executing it. Some techniques include disassembly, decompilation, and string analysis. Disassembly involves translating machine code into assembly code to better understand the program's behavior. Decompilation involves converting compiled code back into its original source code. String analysis involves analyzing the strings contained within a program to identify potential malicious behavior.

Dynamic Analysis Techniques: Dynamic analysis techniques involve analyzing the behavior of a program as it executes. Techniques like debugging and sandboxing can be used to analyze malware in a controlled environment. Debugging allows analysts to step through a program and observe its behavior at runtime. Sandboxing involves running a program in an isolated environment to analyze its behavior without risking damage to the host system.

Fileless Malware: Fileless malware is a type of malware that operates entirely in memory, making it difficult to detect and analyze. It can be executed through legitimate processes, such as PowerShell or WMI, and can evade traditional antivirus solutions. Detection and analysis of fileless malware requires a thorough understanding of the underlying system and its behavior.

Data Exfiltration Techniques: Data exfiltration techniques are methods used by attackers to extract data from a compromised system. Common techniques include DNS exfiltration, FTP exfiltration, and HTTP exfiltration. DNS exfiltration involves sending stolen data in DNS queries. FTP exfiltration involves using FTP to transfer data to an attacker-controlled server. HTTP exfiltration involves sending stolen data over HTTP requests.

Advanced Obfuscation Techniques: Advanced obfuscation techniques are used by malware authors to make their code more difficult to analyze and detect. Techniques like code obfuscation and packers can make malware more resilient to analysis. Detection and analysis of advanced obfuscation techniques requires a deep understanding of the underlying code and the ability to identify patterns and anomalies.

File Carving: File carving is a technique used to extract data from a file or disk image without the use of a file system. This technique can be used to recover lost or deleted files or to analyze malware that may be hiding within a file. Some commonly used file carving tools include Scalpel, Foremost, and PhotoRec. It requires a deep understanding of the file structure and data recovery techniques.

## Encryption

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

### Encryption in Wireshark

Encryption may be encountered in Wireshark captures, and can be identified by the use of protocols such as SSL/TLS or SSH. When encryption is used, the data being transmitted is protected and cannot be viewed in plain text. However, it is possible to view the encrypted traffic in Wireshark and attempt to decrypt it using the appropriate keys or passwords. To do this, select the encrypted traffic in Wireshark and then use the "Follow SSL Stream" or "Follow SSH Stream" options to view the encrypted data. If the appropriate keys or passwords are available, they can be entered in the "Decode As" settings to decrypt the traffic.


# PCAPS
## Intro
Pcaps stand for packet catpure and they are the events (or a log of the events) of what happenened on the network or 'over the wire'. For noobs they can be best conceptualized as text message logs.
```
Bob -> Alice - Hi
Alice -> Bob - oh-hey.jpeg
Bob -> Alice - What you doing tomorrow?
Charles -> Bob - Dont text my girlfriend!
```
There are 2 flavors of pcaps and 4-5 different types of challenges regarding skill. 

### 2 Flavors 
The first flavor and most seen is a typical network catpure. These are large captures with the flag hidden in a single packet maybe containing html traffic. This can often be thought of as finding a needle in a haystack

The second flavor is when every packet will be needed. This can be seen in something like a usb logger and almost instalntly is a encrpytion problem.

### 5 levels
1) flag found plaintext 
2) flag encoded in rot13 or base64
3) flag hidden in encryption that needs credentials
4) file found containing binary that needs to be reversed
5)  something tough

Most often in level 3 challenges and above the pcap will be just one piece of evidence and will need to combine it with something else(find creds in a .evtx to decyrpt something in wireshark)

## Wireshark 

Most Pcaps are too long to look through packet by packet. So opening up wireshark you should have a plan and be looking out for some things(also use Pcap-analysis https://github.com/dbissell6/PCAP_Analysis). 

To open wireshark, open up a terminal, navigate to the pcap
```
wireshark sus_file.pcp
```
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


### Input RSA key to decrpyt TLS
From G, but TLS instead of SSL

![Pasted image 20230113164502](https://user-images.githubusercontent.com/50979196/221450214-77e163e3-dc62-4555-b15c-811c27d5f114.png)
![Pasted image 20230113164429](https://user-images.githubusercontent.com/50979196/221450223-9ff74041-c577-41ee-9c5a-88688848ee6c.png)
![Pasted image 20230113164557](https://user-images.githubusercontent.com/50979196/221450269-c795cfa1-5921-44ce-9aa6-a33de361632f.png)


marshall in the middle Similar method used in but instead of a RSA to decrypt the TLS it is a secrets.log

Rouge shows how to decrypt SMB2 traffic

To learn a full wirehark tutorial chris greer

### Tshark
Sometimes it is useful to extract data from wireshark, this can be done with tshark

```
tshark -r capture.pcapng -T fields -e data -Y "!(_ws.expert) && ip.src == 172.17.0.2 && ip.src!=172.17.0.3" > output 
```

## Aircrack-ng
cracking wifi passwords

![Pasted image 20230222082539](https://user-images.githubusercontent.com/50979196/221450312-2ecdfc1e-9086-4434-b7c8-e82bfee254ca.png)

# Logs
## Intro
Logs are similar to pcaps in they are a long list of events, the main difference is logs tend to be local events(obviously not true for things like browser/apache/nginx logs).

In some cases, logs may contain references to files or binary data, but the actual data is not stored within the log itself. For example, a security log might contain an entry that indicates that a file was created or deleted, but the actual file is not stored within the log. Here things like powershell commands are highly sus.

Tasks
-   Analyze log files to identify the cause of a system malfunction, detect a security breach, or recover deleted files.
-   Identify and extract important information, such as passwords, email addresses, or credit card numbers.

Knowlegde
-   Understanding of log formats and types, such as system logs, application logs, and security logs.
-   Awareness of common attack techniques and patterns, such as SQL injection, cross-site scripting (XSS), and phishing attacks.
-   Knowledge of common indicators of compromise (IoCs), such as IP addresses, domain names, file hashes, and user agent strings.
-   Ability to identify anomalous log entries, such as multiple failed login attempts from the same IP address, or unusual file access patterns.


## .EVTX
The main types of Event Viewer (EVTX) logs in Windows are:

1.  System: This log contains information about system-level events, such as system startup and shutdown, hardware events, and driver events.
   
2.  Application: This log contains information about events generated by applications and services, such as application crashes, application installation and removal, and service start and stop events.
   
3.  Security: This log contains information about security-related events, such as logon and logoff events, privilege use events, and audit events.
   
4.  Setup: This log contains information about setup events, such as the installation and removal of Windows components and updates.

5.  Forwarded Events: This log contains information about events that have been forwarded from other computers in the network to the local computer.

They can be parsed using evtx_dump.py or windows has a native program. 


![Pasted image 20221029120345](https://user-images.githubusercontent.com/50979196/221450336-c3adc6da-3d0c-4d3d-8c7a-25fd5a349135.png)
![image](https://user-images.githubusercontent.com/50979196/221738025-e0593c2b-363f-4f79-84ca-1efc09cf9345.png)

Ok we have the txt but there a similar problem as with pcaps(lots of data) However there is no wireshark (use https://github.com/dbissell6/EVTX_analysis)


# Files/Executables
## Intro
When it comes to CTF challenges, file analysis is an essential skill for any blue team member. These challenges can range in complexity from a simple long text file that needs to be searched for a flag to a complex executable that requires reverse engineering. As a blue team member, you need to be equipped with the right tools and techniques to analyze any file you encounter during a CTF.

One of the first steps in investigating a file is to identify its type using the `file` command. This command can reveal information such as the file type, architecture, and endianness. Another useful command is `strings`, which can be used to extract all printable strings from a file. This can be helpful in finding clues or identifying certain strings that could be indicative of malicious behavior.

Having a solid understanding of file analysis is crucial in identifying potential threats and responding to attacks in a timely and efficient manner. So whether you're dealing with a simple text file or a complex executable, it's important to have the right tools and techniques at your disposal to effectively analyze and respond to any file-based attack.

```
file sus.elf
strings sus.txt
```
Sandboxes
## Common file types

Below are some of the most common files we might come across. Short recap here, more indepth reversing/pwning guide can be found SOMEWHERE ELSE
### File Type Key
Files are typically determined by thier magic bytes or headers.
If you have a file that has a wrong extentions, no extentions, or corrputed you can check the magic bytes in something like hexedit.
```
-   PDF (.pdf) - %PDF-
-   ZIP (.zip) - PK
-   GZIP (.gz) - \x1f\x8b
-   TAR (.tar) - \x75\x73\x74\x61\x72
-   RAR (.rar) - Rar!
-   PNG (.png) - \x89\x50\x4e\x47\x0d\x0a\x1a\x0a
-   JPEG (.jpg, .jpeg) - \xff\xd8\xff
-   GIF (.gif) - GIF87a or GIF89a
-   BMP (.bmp) - BM
-   WAV (.wav) - RIFF
-   MP3 (.mp3) - ID3
-   AVI (.avi) - RIFF
-   EXE (.exe) - MZ
-   DOC (.doc) - \xd0\xcf\x11\xe0\xa1\xb1\x1a\xe1
-   DOCX (.docx) - PK
-   XLS (.xls) - \xd0\xcf\x11\xe0\xa1\xb1\x1a\xe1
-   XLSX (.xlsx) - PK
-   PPT (.ppt) - \xd0\xcf\x11\xe0\xa1\xb1\x1a\xe1
-   PPTX (.pptx) - PK
-   ELF (.elf) - \x7fELF
-   Shell script (.sh) - #!/bin/sh
-   Java Archive (.jar) - PK
-   Python script (.py) - #!/usr/bin/env python
-   PHP script (.php) - <?php
-   HTML (.html) - <!DOCTYPE html>
```
### Windows/Macros(.docm, .doc, .bin, .vba, .pptm)
.docm .doc .bin .vba .pptm

can sometimes using unzip or 7z on word files can reveal hidden content.

Olevba
A Python module that allows for the analysis of Microsoft Office documents (e.g., Word, Excel, PowerPoint) to detect and extract any embedded VBA (Visual Basic for Applications) macros. It can be used for security assessments, forensics analysis, and malware analysis, as VBA macros can be used as a vector for malware infection and data exfiltration. Olevba is able to parse the VBA code, extract the embedded binaries, and detect any obfuscation techniques used in the macro. 
![Pasted image 20230212151320](https://user-images.githubusercontent.com/50979196/221450379-c3e6b586-0b8d-4146-b960-02865564b9ea.png)

### Windows Executables (.exe, .dll, .so, .ps1)

These files can contain malicious code that attackers may use to compromise a system. Analyzing these files can reveal information about how an attack was carried out.

### Linux Executables (.sh, .bin, .elf)   

In Linux, executable files don't necessarily have a specific file extension like in Windows

.sh (shell script)
.bin (binary file)
.elf (executable and linkable format)
.run (installer script)
.out (object file)

### Image files (.jpg, .png, .bmp)

These files can contain hidden messages or steganography, where data is hidden within the image.

.bmp  is primarily used for storing digital images and icons, but can also be used for storing simple graphics and illustrations. BMP files are widely recognized by image processing software and can be easily converted to other image file formats for use in different applications.

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
## VirusTotal

Virus total can be useful to get some information from

![Pasted image 20230212170655](https://user-images.githubusercontent.com/50979196/221450418-70e59b66-d291-4a83-9540-d71735b7e4a5.png)


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
```



## Reconstructing 

Some times you may come across something(like an Hex output in wireshark) that needs to be recontructed back into a binary or a zip. Sometimes you come across a file with a corrupted header that needs to be fixed.
### Binwalk
Binwalk is a tool that is used to analyze and extract firmware images, file systems, and other binary files. It can be used to identify the different components of a binary file, such as the file system, bootloader, and kernel. Binwalk is particularly useful when analyzing firmware images and other embedded systems.
### xxd
xxd is a command-line utility that is used to convert binary files into hexadecimal and vice versa. It can be used to create a hexadecimal dump of a binary file, or to convert a hexadecimal dump back into a binary file. xxd is useful for analyzing binary files and for converting between different formats.

![Pasted image 20230213121602](https://user-images.githubusercontent.com/50979196/221450472-5829ddc8-15a5-4b61-ac00-240bd1ea7346.png)

### Hexedit
Hexedit is a hexadecimal editor that allows users to modify binary files directly. It can be used to view and edit the contents of binary files at the byte level, and can be particularly useful for changing specific bytes in a file. In the Pico CTF challenge "Tunnel," Hexedit was used to change the header of a .bmp file.

### foremost

Foremost is a tool that is used for file recovery and reconstruction. It can be used to recover deleted files, carve out files from disk images, and extract files from various file formats. Foremost is particularly useful for recovering files from damaged or corrupted disks, or for recovering files that have been deleted or lost.

Foremost uses a technique called file carving to recover files from disk images or other sources. It scans through the input data looking for specific file headers and footers, and then extracts the data between them. Foremost supports a wide range of file types, including images, audio files, videos, documents, and archives.

Foremost can be used in a variety of scenarios, such as when trying to recover deleted files, investigating a cybercrime incident, or recovering data from a damaged disk. It is a powerful tool for file recovery and reconstruction and can help in restoring valuable data that may have been lost or deleted.
## Stegnography 
### Intro
Steganography is a technique used to hide information within other files or data, making it difficult to detect without the use of special tools or techniques. This technique can be used to conceal sensitive information or to hide messages in plain sight.

In the realm of CTF challenges, steganography problems can come in all shapes and sizes. Image files are a common choice for hiding information, where the data is often stored in the least significant bits or in unused space within the image file. However, other types of files, such as audio or video files, can also be used.

There are countless methods and tools for hiding information in files, making this area of forensics a bit of a "wild west". Common tools used for steganography analysis include steghide, outguess, and zsteg, among others. Techniques for steganalysis, or the detection of hidden information, can include visual inspection, frequency analysis, and entropy analysis, among others.

### LSB 



### exiftool



### Steghide 
A steganography tool that allows users to embed hidden data within image and audio files. It uses strong encryption algorithms to hide the data and is useful for hiding sensitive information or secret messages within images or audio files. Steghide can also extract hidden data from files.

![Pasted image 20230216081232](https://user-images.githubusercontent.com/50979196/221450510-6200f7e2-45b7-4669-afb4-430cad7c25f7.png)

### Zsteg 
A steganography tool that can be used to detect hidden information within images. It can be used to identify the type of steganography being used, extract hidden data, and even recover lost data. Zsteg is particularly useful for identifying the presence of LSB (Least Significant Bit) steganography, which is a common technique used to hide data within images.
![Pasted image 20230221160217](https://user-images.githubusercontent.com/50979196/221450531-b66bfdf7-3c9d-4cd0-9a20-54fe3d14c5ef.png)

### Stegsolve 
A Java-based tool that can be used to analyze and manipulate images for steganography purposes. It provides a range of filters and visual aids to help users identify hidden information within images. Stegsolve is particularly useful for identifying the location and type of steganography being used within an image.
![Pasted image 20230221202426](https://user-images.githubusercontent.com/50979196/221450558-7c93ed5f-4a8a-450a-84d1-8d77d9b77458.png)

# Memory Dumps
## Intro
Memory dumps are a type of digital forensic artifact that can be used to analyze the state of a computer's memory at the time of a crash or system failure. Memory dumps contain a complete snapshot of the memory contents of a computer, including the contents of volatile memory such as RAM, as well as the contents of any mapped physical memory pages. Memory dumps can be used to diagnose and troubleshoot system issues, as well as to recover and analyze digital evidence related to malicious activities or other incidents.

In digital forensics and incident response (DFIR), memory dumps are considered a valuable artifact because they can provide insight into the state of a system at the time of an event of interest, including information about running processes, open network connections, and any malicious activity that may have been occurring in memory. Memory dumps can be analyzed using a variety of tools, including those specifically designed for memory analysis, as well as more general-purpose digital forensics tools.

Common File formats of memory dumps 
-   Raw binary format (.bin)
-   Microsoft crash dump format (.dmp)

## Volatility

Volatility 3 - An open-source memory forensics framework

### Commands

Get image information
```
python3 ~/Tools/volatility3-1.0.0/vol.py -f memory.raw windows.info   
```
See Process List
```
python3 ~/Tools/volatility3-1.0.0/vol.py -f memory.raw windows.pslist
```
See all active network connections and listening programs
```
python3 ~/Tools/volatility3-1.0.0/vol.py -f memory.raw windows.netscan
```
Find all handles opened by process 3424
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
Dump Windows user password hashes
![Pasted image 20221123074049](https://user-images.githubusercontent.com/50979196/221450622-46170f92-5a13-42dd-a7ff-4b9b1479f2b1.png)

Print dlls
```
python3 ~/Tools/volatility3-1.0.0/vol.py -f memory.raw windows.dlllist
```



https://readthedocs.org/projects/volatility3/downloads/pdf/latest/
https://dfir.science/2022/02/Introduction-to-Memory-Forensics-with-Volatility-3

# Disk

## Intro
Disk images are copies of an entire disk drive or a portion of it. In DFIR, disk images are an essential tool for preserving the evidence and state of the original disk. Analyzing disk images can reveal important information such as deleted files, hidden files, and other artifacts that can provide valuable insight into an incident.Some common forms of disk images include raw images, Encase images, and AFF4 images.

Typically found as .img or dd
Windows can be found as .img, .vmdk, .vhdx, .dd, .raw

Differences in the way that Linux and Windows handle disk drives, which can be relevant to forensic analysis in a CTF challenge.

-    File systems: Linux and Windows use different file systems to organize and store data on disk drives. Windows primarily uses the NTFS (New Technology File System) file system, while Linux typically uses the ext4 (Fourth Extended File System) file system. There are also other file systems used by both operating systems, such as FAT32, exFAT, and ReFS (Resilient File System). Different file systems have different structures and metadata, which can affect the way that files are stored, accessed, and recovered.

-    Permissions and ownership: Linux and Windows use different approaches to managing permissions and ownership of files and directories. Linux uses a permission model based on users, groups, and permissions bits (e.g., read, write, execute), while Windows uses a more complex permission model that includes access control lists (ACLs) and security identifiers (SIDs). This can affect the way that files and directories are accessed and modified, as well as the ability to recover deleted files or data.

-    Disk partitioning: Linux and Windows use different methods for partitioning disk drives. Windows uses the Master Boot Record (MBR) or the newer GUID Partition Table (GPT) for partitioning, while Linux typically uses the GPT partitioning scheme. Different partitioning schemes can affect the way that data is organized and accessed on the disk, as well as the ability to recover deleted files or data.

-    Forensic tools and techniques: Different forensic tools and techniques may be needed to analyze disk drives on Linux versus Windows. For example, some tools may be more effective at recovering data from a specific file system or partitioning scheme, while others may be better suited for analyzing permissions and ownership. It is important to understand the differences between Linux and Windows disk drives when selecting and using forensic tools and techniques for a CTF challenge.



There are many tools available to create and analyze disk images, including:

1.  dd: A Unix tool that is commonly used to create raw disk images.

2.  EnCase: A proprietary forensic software that is widely used in the industry to create and analyze disk images.
   
3.  FTK Imager: A free tool developed by AccessData that can be used to create and analyze disk images.
   
4.  Autopsy: An open-source digital forensics platform that includes a disk imaging tool(Can do Windows).
   
5.  X-Ways Forensics: A commercial forensic software that includes a disk imaging tool.  



## Example fdisk+Mount

Mounting a file system in Linux is similar to gaining access to a victim system on platforms like Hack The Box (HTB). However, there are some key differences. Unlike a live computer, the mounted system is just a file system, and you cannot run commands like netstat to view current connections. Despite this, the process of enumeration from a pentesting perspective is similar. The advantage of mounting a file system is that you can use sudo, which grants you root access to the mounted system, allowing for more comprehensive analysis and investigation.

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

Just like pentesting we can use linpeas in the mount
```
 sudo /usr/share/peass/linpeas/linpeas.sh -f ~/PICO/Forensics/Orchid/test 
```

Noob tip if you mount the system and you try to access something like root and it says permission denied, use sudo
```
sudo ls -la root
```


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
### SluethKit

SleuthKit is another popular open-source digital forensic platform that provides a set of command-line tools for analyzing disk images. It supports a wide range of file systems, including FAT, NTFS, and EXT, and can be used to recover deleted files, view file metadata, and perform keyword searches.

    mmls: The 'mmls' command is used to display the partition layout of a disk image. It identifies the start and end sectors of each partition and displays other information such as the partition type, size, and offset. This information is important for identifying the partition that contains the file system you're interested in.

    fsstat: The 'fsstat' command is used to display information about a file system, such as its size, block size, and the number of allocated and unallocated blocks. It can also display information about the file system's metadata, such as the location of the Master File Table (MFT) in NTFS file systems.

    fls: The 'fls' command is used to list the contents of a file system. It displays the files and directories in the file system along with their attributes and inode numbers. The 'fls' command can also display deleted files and directories, which can be important for recovering data that has been deleted by an attacker or lost due to a system crash.

sudo mmls win_image.dd


sudo fsstat -o 2048 win_image.dd

Replace '2048' with the start sector of the partition you're interested in.

Use the 'fls' command to list the contents of the file system:

sudo fls -o 2048 -f ntfs win_image.dd


also another htb challenge had it from cyberpocalypse
