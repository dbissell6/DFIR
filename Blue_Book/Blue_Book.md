# CTF Blue Team HackTricks
## Intro

In a world where cyber attacks are becoming more frequent and sophisticated, the ability to detect and respond to such attacks is critical for any organization. During a Cybersecurity Capture The Flag (CTF) competition, the blue team is responsible for detecting and responding to cyber attacks, and this often involves forensic analysis of systems, networks, and data.

This handbook is specifically geared towards the blue team during a CTF, and aims to provide a comprehensive guide for blue team forensics. In a CTF, the blue team's goal is to defend their systems against simulated cyber attacks launched by the red team, and this requires a deep understanding of key tools and techniques that can be used to detect and respond to such attacks.

Throughout this handbook, we will cover the various challenges that blue teams might encounter in a CTF, including network traffic analysis, system logs analysis, and memory forensics. We will also introduce key tools and techniques that can be used to detect and respond to cyber attacks during a CTF.

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

# PCAPS
## Intro
Pcaps stand for packet catpure and they are the events (or a log of the events) of what happenened on the network or 'over the wire'. For noobs they can be best conceptualized as text message logs.

Bob -> Alice - Hi
Alice -> Bob - oh-hey.jpeg
Bob -> Alice - What you doing tomorrow?
Charles -> Bob - Dont text my girlfriend!

There are 2 flavors of pcaps and 4-5 different types of challenges regarding skill. 

2 flavors 
the first flavor and most seen is a typical network catpure maybe containing html traffic. This can often be thought of as finiding a needle in a haystack

The second flavor is when every packet will be needed. this can be seen in something like a usb logger and almost instalntly is a encrpytion problem.

5 levels
1) flag found plaintext 
2) flag encoded in rot13 or base64
3) flag hidden in encryption that needs credentials
4) file found containing binary that needs to be reversed
5)  something tough

Most often in level 3 challegnes and above the pcap will be just one piece of evidence and will need to combine it with something else(find creds in a .evtx to decyrpt something in wireshark)

## Wireshark 

Most Pcaps are too long to look through packet by packet. So opening up wireshark you should have a plan and be looking out for some things(also use Pcap-analysis https://github.com/dbissell6/PCAP_Analysis). 

To open wireshark, open up a terminal, navigate to the pcap
```
wireshark sus_file.pcp
```
### Helpful Queries


![[Pasted image 20230212122101.png]]

1. ip.addr != 192.0.2.1: This display filter command excludes packets with an IP address of 192.0.2.1. You can replace "192.0.2.1" with any IP address you want to exclude.
 
2.  tcp: This display filter command only shows TCP packets. You can replace "tcp" with "udp" to only show UDP packets, or with "icmp" to only show ICMP packets., or http: This display filter command only shows HTTP packets. -   (http.request: This display filter command only shows HTTP request packets. http.response: This display filter command only shows HTTP response packets.)
   
3.  ip.src == 192.0.2.1: This display filter command only shows packets with a source IP address of 192.0.2.1.
   
4.  ip.dst == 192.0.2.1: This display filter command only shows packets with a destination IP address of 192.0.2.1.
   
5.  tcp.port == 80: This display filter command only shows TCP packets using port 80 (HTTP).
   
6.  udp.port == 53: This display filter command only shows UDP packets using port 53 (DNS).
7. udp.length > 500: This display filter command only shows UDP packets with a length greater than 500 bytes.
   
8.  frame.time >= "Feb 13, 2022 12:00:00": This display filter command only shows packets captured after the specified date and time.
### Export Objects
One of the first things to do is determine if any files were transfered. This can be done by in wireshark by File -> Export Objects -> (probably http, try all)

![[Pasted image 20230212115835.png]]

Clicking on HTTP for example will bring up a screen showing files wireshark found and an option to preview and download. It is important to remember that if you find credenti9als and decrypt traffic to come back here and look for new files wireshark may have found.

### Streams
![[Pasted image 20230212123447.png]]

To access streams right click on a packet
![[Pasted image 20230212123647.png]]



### Input RSA key to decrpyt TLS
From G, but TLS instead of SSL
![[Pasted image 20230113164502.png]]
![[Pasted image 20230113164429.png]]
![[Pasted image 20230113164557.png]]








marshall in the middle Similar method used in but instead of a RSA to decrypt the TLS it is a secrets.log

Rouge shows how to decrypt SMB2 traffic

### Tshark
Sometimes it is useful to extract data from wireshark, this can be done with tshark

```
tshark -r capture.pcapng -T fields -e data -Y "!(_ws.expert) && ip.src == 172.17.0.2 && ip.src!=172.17.0.3" > output 
```

## Aircrack-ng
cracking wifi passwords
![[Pasted image 20230222082539.png]]

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

![[Pasted image 20221029120345.png]]

Ok we have the txt but  there a similar problem as with pcaps(lots of data) However there is no wireshark (use https://github.com/dbissell6/EVTX_analysis)


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
- PDF (.pdf) - %PDF-
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
![[Pasted image 20230212151320.png]]
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

### Compressed Files (.zip, .rar, .tar.gz)

Compressed files are a common way of packaging and distributing multiple files or directories as a single archive. In a CTF, compressed files may contain clues or important information that can aid in solving challenges. Here are some common types of compressed files:

-   .zip: This is a popular compression format that is widely used in both Windows and Linux environments. It supports both lossless compression and encryption of archive contents. To extract the contents of a .zip file, one can use the 'unzip' command in Linux or a file archiver software in Windows.
    
-   .rar: This is another popular compression format that is known for its high compression ratio. It supports both lossless compression and encryption of archive contents. To extract the contents of a .rar file, one can use the 'unrar' command in Linux or a file archiver software in Windows.
    
-   .tar.gz: This is a common compression format used in Linux environments. It combines multiple files or directories into a single archive and compresses the archive using the gzip algorithm. To extract the contents of a .tar.gz file, one can use the 'tar' and 'gzip' commands in Linux.

### Audio files (e.g., MP3, WAV)
Information can be hidden in the frequency spectrum of the audio signal, in unused space within the file, or by modifying the phase of the audio waveform.
### Video files (e.g., MP4, AVI)
Information can be hidden within the individual frames of the video, in unused space within the file, or by modifying the motion vectors of the video stream.
## VirusTotal

Virus total can be useful to get some information from

![[Pasted image 20230212170655.png]]

## Reconstructing 

Some times you may come across something(like an Hex output in wireshark) that needs to be recontructed back into a binary or a zip. 
### Binwalk
Binwalk is a tool that is used to analyze and extract firmware images, file systems, and other binary files. It can be used to identify the different components of a binary file, such as the file system, bootloader, and kernel. Binwalk is particularly useful when analyzing firmware images and other embedded systems.
### xxd
xxd is a command-line utility that is used to convert binary files into hexadecimal and vice versa. It can be used to create a hexadecimal dump of a binary file, or to convert a hexadecimal dump back into a binary file. xxd is useful for analyzing binary files and for converting between different formats.

![[Pasted image 20230213121602.png]]
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

### Steghide 
A steganography tool that allows users to embed hidden data within image and audio files. It uses strong encryption algorithms to hide the data and is useful for hiding sensitive information or secret messages within images or audio files. Steghide can also extract hidden data from files.

![[Pasted image 20230216081232.png]]
### Zsteg 
A steganography tool that can be used to detect hidden information within images. It can be used to identify the type of steganography being used, extract hidden data, and even recover lost data. Zsteg is particularly useful for identifying the presence of LSB (Least Significant Bit) steganography, which is a common technique used to hide data within images.
![[Pasted image 20230221160217.png]]
### Stegsolve 
A Java-based tool that can be used to analyze and manipulate images for steganography purposes. It provides a range of filters and visual aids to help users identify hidden information within images. Stegsolve is particularly useful for identifying the location and type of steganography being used within an image.
![[Pasted image 20230221202426.png]]
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
![[Pasted image 20221123074049.png]]
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
![[Pasted image 20230216134532.png]]
![[Pasted image 20230216134646.png]]
```
mkdir test
```
```
 sudo mount -o loop,offset=210763776 disk.flag.img test/   
```
![[Pasted image 20230216101009.png]]
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

The RAID Disk recovery section will cover the different types of RAID configurations, common causes of RAID failures, and techniques for identifying and repairing RAID issues. Additionally, we'll discuss tools and techniques for data recovery from RAID arrays, including software-based RAID recovery and hardware-based RAID recovery. By understanding the fundamentals of RAID disk recovery and having a solid toolkit of recovery techniques at your disposal, you'll be better equipped to handle data loss incidents and recover critical information in a timely manner.
https://blog.bi0s.in/2020/02/09/Forensics/RR-HackTM/

also another htb challenge had it from cyberpocalypse