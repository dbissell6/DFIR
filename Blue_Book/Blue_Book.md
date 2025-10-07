# The Blue Book

![image](https://github.com/dbissell6/DFIR/assets/50979196/01043023-47b7-44dc-87f8-fa31247b9b1d)

## Intro

The handbook is written to be accessible to new forensic CTF players and is designed to serve as a reference similar to a hacktricks guide. Hopefully useful to someone with no experience wanting to start and to someone with experience that needs a quick reference. 

0) [Decoding+Decryption](https://github.com/dbissell6/DFIR/blob/main/Blue_Book/Blue_Book.md#DecodingDecryption)

1) [Network traffic analysis](https://github.com/dbissell6/DFIR/blob/main/Blue_Book/Blue_Book.md#pcaps-pcap) 

2) [Logs + Registry + Artifacts](https://github.com/dbissell6/DFIR/blob/main/Blue_Book/Blue_Book.md#logs--registry--artifacts)
 
3) [Files/Executables](https://github.com/dbissell6/DFIR/blob/main/Blue_Book/Blue_Book.md#filesexecutables) 

4) [Memory forensics](https://github.com/dbissell6/DFIR/blob/main/Blue_Book/Blue_Book.md#memory-dumps)
 
5) [Disk](https://github.com/dbissell6/DFIR/blob/main/Blue_Book/Blue_Book.md#Disk)

6) [Infected Host](https://github.com/dbissell6/DFIR/blob/main/Blue_Book/Blue_Book.md#infected-host)

7) [Cloud](https://github.com/dbissell6/DFIR/blob/main/Blue_Book/Blue_Book.md#cloud)

8) [SIEMS](https://github.com/dbissell6/DFIR/blob/main/Blue_Book/Blue_Book.md#siems)

9) [OSINT](https://github.com/dbissell6/DFIR/blob/main/Blue_Book/Blue_Book.md#osint)


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

# Decoding+Decryption

## Cyberchef  

Useful for most decoding  
`https://gchq.github.io/CyberChef/`

`https://github.com/mattnotmax/cyberchef-recipes#`


## Dcode

dCode.fr is a collection of over 900 tools to help solve games, riddles, ciphers, mathematics, puzzles, etc.
`https://www.dcode.fr/en`



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

Binary to decimal

![image](https://github.com/user-attachments/assets/cbb8d1fd-ac44-4e60-95df-4e37cc53d73a)

![image](https://github.com/user-attachments/assets/e0b1ff23-6a94-416a-878e-3b8e5d684eb6)

Hex to decimal

![image](https://github.com/user-attachments/assets/d05380fe-7b8a-4080-9359-920d9fc5727b)



## Decryption

Encryption is an idea that permeates all domains of digital forensics and incident response (DFIR), from incident triage to malware analysis and network forensics. In today's world, encryption is widely used to protect sensitive information, and it is often encountered in digital evidence. As such, understanding encryption is essential for any DFIR practitioner. Encryption can be used to protect data at rest, data in transit, or both, and can be implemented in various ways, from encryption of individual files to full-disk encryption of an entire computer system. Additionally, encryption can be encountered in various contexts, such as communication protocols, malware communication, or encryption of files stored in the cloud.

Encryption can pose significant challenges to DFIR investigations, as it can prevent investigators from accessing or understanding the protected data. In some cases, encryption may be used by malicious actors to hide their activities or exfiltrate data from a network undetected. Understanding encryption, therefore, is essential for identifying and analyzing encrypted data, as well as for determining the appropriate techniques to recover or bypass it.

Furthermore, encryption may also be encountered in forensic artifacts such as logs, memory dumps, and registry entries. These artifacts may contain encrypted data that can provide valuable insights into an incident or investigation, and decrypting this data may be critical for understanding the full scope of an incident.

In summary, understanding encryption and its use cases is essential for any DFIR practitioner. Encryption can pose significant challenges to investigations, but it can also provide valuable insights into an incident or investigation. As such, DFIR practitioners should be familiar with the basics of encryption and the common encryption tools and techniques used in digital investigations.

### symmetric vs asymmetric

Symmetric - Uses one(same) key for both encryption and decryption.

ASymmetric - One key for encryption, another key for decryption.

### Common types


-    AES (Advanced Encryption Standard): This is a symmetric encryption algorithm that is widely used for data encryption. It uses block ciphers with a key size of 128, 192, or 256 bits.

-    RSA: This is an asymmetric encryption algorithm that is widely used for securing data transmission over the internet. It uses a public-private key pair to encrypt and decrypt data.

-    DES (Data Encryption Standard): This is a symmetric encryption algorithm that uses block ciphers with a key size of 56 bits. It is not considered secure for modern applications.

-    Triple DES (3DES): This is a symmetric encryption algorithm that uses DES with three keys applied in sequence. It provides a higher level of security than DES.

-    Blowfish: This is a symmetric encryption algorithm that uses block ciphers with a variable key size of up to 448 bits. It is widely used for file encryption.

-    Twofish: This is a symmetric encryption algorithm that uses block ciphers with a key size of 128, 192, or 256 bits. It is designed to be faster and more secure than AES.

-    ChaCha20: This is a symmetric encryption algorithm that is designed to be fast and secure. It uses a 256-bit key and can be used for data encryption, password hashing, and other applications.

### XOR

XOR (exclusive OR) is a fundamental operation used in cryptography and data obfuscation.

Key Points

    Binary Operation: XOR operates on the binary representations of the numeric codes for characters.
    Reversibility: XORing the ciphertext with the same key reverses the operation, revealing the original plaintext.
    Encryption of Letters: The process is the same for any character; what matters are the binary representations of those characters and the key.

Example

Suppose we want to encrypt the letter A using the key K. In ASCII:

    A is represented by the number 65.
    K is represented by the number 75.

The binary representations are:

    A = 65 = 01000001 in binary.
    K = 75 = 01001011 in binary.

Encrypt A with key (K)
```
  01000001  (A)
⊕ 01001011  (K)
-----------
  00001010  (Result)
```
Decrypt encrypted A with key (K)
```
  00001010  (Encrypted A/Result)
⊕ 01001011  (K)
-----------
  01000001  (A)
```

<details>
<summary> Code: Python code to mess around with xor </summary>


```
def xor_encrypt_decrypt(input_string, key):
    # Convert the input string to bytes if it's not already
    input_bytes = input_string.encode() if isinstance(input_string, str) else input_string
    key_bytes = key.encode() if isinstance(key, str) else key
    
    # Perform XOR operation between each byte of the input and the key
    output_bytes = bytes([b ^ key_bytes[i % len(key_bytes)] for i, b in enumerate(input_bytes)])
    
    return output_bytes

# Example usage
key = "secret"
plaintext = "Hello, XOR!"
ciphertext = xor_encrypt_decrypt(plaintext, key)
decrypted_text = xor_encrypt_decrypt(ciphertext, key).decode()

print(f"Plaintext: {plaintext}")
print(f"Ciphertext (hex): {ciphertext.hex()}")
print(f"Decrypted text: {decrypted_text}")
```
</details>

Cyberchef example

![image](https://github.com/dbissell6/DFIR/assets/50979196/ca5d693d-b14c-4498-afa4-16eee91ece0c)

### AES

Often aes messages will have the first 16 bytes of the message contain the IV.

<details>

<summary>Python code inputs file and key. Automatically parses out IV</summary>


```
   from Crypto.Cipher import AES
from Crypto.Util.Padding import unpad
import hashlib
import os

def decrypt_aes_file(key, input_file_path, output_file_path):
    # Read the input file
    with open(input_file_path, 'rb') as f:
        data = f.read()

    # Extract the IV and ciphertext from the input data
    iv = data[:16]   # First 16 bytes for IV
    ciphertext = data[16:]  # Rest is the ciphertext

    # Derive the AES key using SHA256
    derived_key = hashlib.sha256(key.encode()).digest()

    # Create the AES cipher object with CBC mode
    cipher = AES.new(derived_key, AES.MODE_CBC, iv)

    # Decrypt the data
    decrypted_data = cipher.decrypt(ciphertext)

    try:
        # Unpad the decrypted data using PKCS7 padding
        decrypted_data = unpad(decrypted_data, AES.block_size)

        # Write the decrypted data to the output file
        with open(output_file_path, 'wb') as f_out:
            f_out.write(decrypted_data)

        print(f"Decryption successful! Output saved to {output_file_path}")

    except ValueError as e:
        print(f"Decryption failed: {e}")

if __name__ == "__main__":
    # Input the key, file paths
    key = input("Enter the key: ")
    input_file = input("Enter the path of the encrypted file: ")
    output_file = input("Enter the path where decrypted output should be saved: ")

    # Call the decryption function
    decrypt_aes_file(key, input_file, output_file)
                                                      
```


![image](https://github.com/user-attachments/assets/64a78c9c-478f-4d0e-8d42-874d1363253c)

![image](https://github.com/user-attachments/assets/c0db0b4f-f227-46a2-a9a1-0eb58f4108ce)


</details>

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

### TrueCrypt

TrueCrypt was a popular disk encryption software that could encrypt whole drives, partition volumes, or create a virtual encrypted disk within a file. Discontinued in 2014 Veracrypt currently is the alternative. Still sometimes seen as forensic evidence with .tc extention.   

Volatility 2 is able to retrieve password if cached. 

![Pasted image 20240322203048](https://github.com/dbissell6/DFIR/assets/50979196/60cd5602-a22b-4c9e-af5e-05563510f67a)

Can mount 
![Pasted image 20240322203437](https://github.com/dbissell6/DFIR/assets/50979196/9d2fe88c-b3b3-4e31-abd5-8b4e58e9febc)

![Pasted image 20240322203715](https://github.com/dbissell6/DFIR/assets/50979196/fc87352f-762b-4086-9577-4069ab956101)

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



## Foundational Network Concepts


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



#### DNS

DNS is scrutinized for evidence of tunneling, a technique attackers use to bypass security measures for data theft or command execution. Detecting irregular DNS requests helps identify such breaches.

| Record Type | Purpose                                                                 |
|-------------|-------------------------------------------------------------------------|
| A           | Maps a domain to an IPv4 address.                                       |
| AAAA        | Maps a domain to an IPv6 address.                                       |
| CNAME       | Maps a domain to another domain name (aliasing).                        |
| MX          | Specifies mail exchange servers for the domain.                         |
| TXT         | Allows the domain admin to insert any text into the DNS record.         |
| NS          | Specifies the authoritative name servers for the domain.                 |
| PTR         | Provides a domain name in reverse-IP lookups.                           |
| SOA         | Contains administrative information about the domain, such as the primary name server and contact details for the domain administrator. |
| SRV         | Specifies the location of services like VOIP, SIP, and XMPP.            |



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

### Search for strings in packets

![image](https://github.com/user-attachments/assets/45a906f5-10a7-4a59-9ac5-2a58b2147663)

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

### Protocols in Wireshark

#### NetBIOS Name Service (NBNS)

NetBIOS Name Service (NBNS) is a protocol that operates over UDP on port 137. It is part of the NetBIOS suite of services, which is used for name resolution on local networks. NBNS allows computers to register their names and resolve NetBIOS names to IP addresses on a local network, similar to how DNS resolves domain names to IP addresses on the internet.

From a digital forensics standpoint, NBNS traffic can be quite useful in several scenarios:

Identifying Devices on a Network:

Device Discovery: By analyzing NBNS traffic, you can discover devices on a network, including their NetBIOS names and IP addresses. This can be particularly useful in mapping out the network topology.
    
Device Role Identification: The NetBIOS name often includes clues about the role of the device (e.g., "FORELA-WKSTN001"), which can help in identifying critical assets.

![image](https://github.com/user-attachments/assets/55541ce0-50a3-42b1-9bf8-d20f656928f4)


### Encryption in Wireshark

Encryption may be encountered in Wireshark captures, and can be identified by the use of protocols such as SSL/TLS or SSH. When encryption is used, the data being transmitted is protected and cannot be viewed in plain text. However, it is possible to view the encrypted traffic in Wireshark and attempt to decrypt it using the appropriate keys or passwords. To do this, select the encrypted traffic in Wireshark and then use the "Follow SSL Stream" or "Follow SSH Stream" options to view the encrypted data. If the appropriate keys or passwords are available, they can be entered in the "Decode As" settings to decrypt the traffic.

###  Decrpyt TLS

#### TLS v1.2 + RSA Key Exchange

    Look for: Server Hello, Certificate → x509 with RSA public key

    Also works for old SMTP/POP3/IMAP/FTPS with SSL

✅ The server's public key is vulnerable:

    Small key sizes (e.g. 512-bit, 768-bit)

    Reused primes or weak randomness


![Pasted image 20250424205523](https://github.com/user-attachments/assets/3acbbf02-6083-4be8-81d8-683ebaf1a7c2)


Save the hex output as `my_certificate` Convert to binary. Get the Modulus.

![Pasted image 20250424210033](https://github.com/user-attachments/assets/06b4b7d0-3e86-4778-9535-f3752f538bbf)

Clean it

![Pasted image 20250424210200](https://github.com/user-attachments/assets/69b308cc-b4e6-45dd-9b18-2c08bd39401b)

Convert from hex to decimal

![Pasted image 20250424211424](https://github.com/user-attachments/assets/8996a996-69d7-4209-a9b6-0e7e4f1b02c8)

![Pasted image 20250424211322](https://github.com/user-attachments/assets/98c13496-7376-4d37-a0e6-4f537048a84c)


Use factors to create private key

![Pasted image 20250424211502](https://github.com/user-attachments/assets/06b7aac8-70bf-42cd-8174-29e1e025c795)

Load key in Wireshark

![Pasted image 20250424212357](https://github.com/user-attachments/assets/5ba63a0b-f5f3-4b18-9edd-e4c04c3e3b63)


Now we can see traffic

![Pasted image 20250424211736](https://github.com/user-attachments/assets/5527263c-0d67-43ce-b3cd-b669fd8fe5dc)


#### Input RSA key

From G, but TLS instead of SSL

![Pasted image 20230113164502](https://user-images.githubusercontent.com/50979196/221450214-77e163e3-dc62-4555-b15c-811c27d5f114.png)

![Pasted image 20230113164429](https://user-images.githubusercontent.com/50979196/221450223-9ff74041-c577-41ee-9c5a-88688848ee6c.png)

![Pasted image 20230113164557](https://user-images.githubusercontent.com/50979196/221450269-c795cfa1-5921-44ce-9aa6-a33de361632f.png)

##### Setting this up

```
# 1 Generate a 2048-bit RSA private key
openssl genrsa -out server_rsa.key 2048

# 2 Create a self-signed certificate
openssl req -new -x509 -key server_rsa.key -out server_rsa.crt -days 365 -subj "/CN=localhost"
```

Start server

```
openssl s_server -cert server_rsa.crt -key server_rsa.key -tls1_2 -cipher RSA -accept 4433

```

![image](https://github.com/user-attachments/assets/8a832ff4-787e-45d9-987e-f8a6dd798e66)


Connect

`openssl s_client -connect localhost:4433 -tls1_2`

![image](https://github.com/user-attachments/assets/d904e53a-ce08-474c-b0c6-d08a1713b767)

![image](https://github.com/user-attachments/assets/3cb1c14b-e985-47de-9d06-3f6719fe64a8)

Follow adding key as before in Wireshark.

![image](https://github.com/user-attachments/assets/075ac9b5-1eb0-4830-a70e-ea4d0ec66bb9)


#### With a log file

marshall in the middle uses similar method used but instead of a RSA to decrypt the TLS it is a secrets.log

Find something like

![history](https://github.com/dbissell6/DFIR/assets/50979196/a85c4fbf-5cd9-4f90-8e56-718c9539f54c)

Content of sslkey.log might look something like

```
CLIENT_HANDSHAKE_TRAFFIC_SECRET 1883768c955100059c9e4ebcd16d8168e762436f65f66aaf905680f3e8a439a6 35f05c44c0d5cd5b9b80622cc6f7314895a0a0a45a2fa249291a509db8156256
SERVER_HANDSHAKE_TRAFFIC_SECRET 1883768c955100059c9e4ebcd16d8168e762436f65f66aaf905680f3e8a439a6 3a8ec62b1e2b1505ce7a44f1a7977490f302beef16c993b28ac4b1b512a2db76
CLIENT_RANDOM 53172363ba45dbe949f9f5c237c39b4a14f2a9d55cefb751420120a105a07c3e d877c33bdfa568ecc0c2e2304814cc9160209eee8d6b2ffb620f198a451d488010786fd0e7b4bf9c03a462b2af3aa1f8
CLIENT_HANDSHAKE_TRAFFIC_SECRET c42740946ffc0245c919b390949ee549079e8be2e0e4a59e8c0e7487c292822d bb5dd2319fdab57773785e3ec3a6949bc551fad6c090d113a6ed225c9e0a3d3e
```

Decrypt similar to using key

![tls](https://github.com/dbissell6/DFIR/assets/50979196/e0ae5cd0-5493-4a1f-8136-2789269a7ae0)

#### Preshared key


##### Setting it up 

Setting up server with psk of `4d79537570657253656372657450534b`.

`openssl s_server -psk 4d79537570657253656372657450534b -nocert -cipher PSK-AES128-CBC-SHA -accept 4433 -tls1_2`

![image](https://github.com/user-attachments/assets/41ebaa76-5063-4f6b-b3ca-3b92e1dbc308)


Connect

`openssl s_client -psk 4d79537570657253656372657450534b -cipher PSK-AES128-CBC-SHA -connect localhost:4433 -tls1_2`

![image](https://github.com/user-attachments/assets/fa4073a3-61c1-453f-9c1f-9329f6b764ac)


Encrypted

![image](https://github.com/user-attachments/assets/60a2066c-716e-4d32-bf18-2bf5f438dba2)

Enter PSK to decrypt traffic in Wireshark

`Preferences-TLS-PSK`

![image](https://github.com/user-attachments/assets/6d640643-c4ee-40ac-ada4-107a8b3a75e9)


Decrypted

![image](https://github.com/user-attachments/assets/842a95a8-7d35-4ca6-b8cb-6df6c9567a2e)


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

### Getting user password from SMB

We need to create a string of 5 parts found in the traffic.

![image](https://github.com/user-attachments/assets/a453769f-72a9-4e20-8364-9c91f75d5818)

For the last section NTLMv2Response we must remove the first 16 bytes/32 characters.

We should see something like this in the pcap.

![image](https://github.com/user-attachments/assets/97a87800-4c0d-4a13-9a6f-222f5a5f095e)


We can find 4 of the pieces in
```
Session Setup Request
```

```
SMB2 (Server Message Block Protocol Version 2) -> Session Setup Response (0x1) -> Security Blob -> GSS-API Generic **** ->
Simple Protected Negotiation -> negTokenTarg -> NTLM Secure Service Provider -> -> NTLM Response -> NTLMv2 Response -> NTProofStr.
```

![image](https://github.com/user-attachments/assets/832d2e73-c824-4935-94b9-13132d7a200d)

The last piece can be found 

```
Session Setup Response
```

```
SMB2 (Server Message Block ProtocolVersion 2) -> Session Setup Response (0x1) -> Security Blob -> GSS-API Generic ->
SimpleProtected Negotiation -> negTokenTarg -> NTLM Secure Service Provider -> NTLM Server Challenge.
```

![image](https://github.com/user-attachments/assets/b207b112-3704-43cc-a0eb-07ca35659218)

In total it should look like

![image](https://github.com/user-attachments/assets/d1dcec6c-7e98-49f0-b368-24a7a07de6ff)


Can try to crack hash in responder.

```
hashcat -m 5600 responder_hash /usr/share/wordlists/rockyou.txt 
```

![image](https://github.com/user-attachments/assets/6eaad109-36ae-414e-a750-70e5926d9bb0)

```
PCAP=Some.pcapng

# 1) CHALLENGE (Type 2): get server challenge per tcp.stream
tshark -r "$PCAP" -Y "ntlmssp.ntlmserverchallenge" -T fields \
  -e tcp.stream -e ntlmssp.ntlmserverchallenge \
  > /tmp/chal.txt

# 2) AUTH (Type 3): get user, domain, NTLMv2 response per tcp.stream
tshark -r "$PCAP" -Y "ntlmssp.ntlmv2_response && ntlmssp.auth.username" -T fields \
  -e tcp.stream -e ntlmssp.auth.username -e ntlmssp.auth.domain -e ntlmssp.ntlmv2_response \
  > /tmp/auth.txt

# 3) Join by stream and format for hashcat -m 5600 (NetNTLMv2)
awk 'NR==FNR {chal[$1]=$2; next}
     {
       stream=$1; user=$2; dom=$3; resp=$4;
       ntproof=substr(resp,1,32); blob=substr(resp,33);
       printf "%s::%s:%s:%s:%s\n", user, dom, chal[stream], ntproof, blob
     }' /tmp/chal.txt /tmp/auth.txt > netntlmv2.txt

echo "[+] Wrote netntlmv2.txt"
```


### Kerberos Analysis and Decryption

#### AS-REP Hash Extraction


![Pasted image 20250101230155](https://github.com/user-attachments/assets/88298450-7b6b-4dee-b734-9a3f4c1331e7)

Manually getting the components from Wireshark.

![Pasted image 20250101230815](https://github.com/user-attachments/assets/e71150aa-5060-4165-b4ef-0dc15fabaad2)

Constructing the hash for john

![Pasted image 20250101230934](https://github.com/user-attachments/assets/f1a0fc72-8e45-4b47-8307-aad59e337dd4)

hashcat needs a different format, the username and realm must be included, even though it doesnt use it.

![Pasted image 20250101231556](https://github.com/user-attachments/assets/fc397bef-c387-4a9f-917b-dce57c2a7297)


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

https://github.com/WangYihang/USB-Mouse-Pcap-Visualizer

### Bluetooth

`https://www.bluetooth.com/wp-content/uploads/Files/Specification/HTML/Core-54/out/en/host/security-manager-specification.html`


Key Protocols & Packets

    SBC 
    L2CAP (Logical Link Control and Adaptation Protocol) – 


`Wireless - Bluetooh Devices`

![image](https://github.com/user-attachments/assets/0901b9fb-5c9d-4609-8df4-0823e5b2de5a)


`Telephony-RTP-RTP Streams`

![image](https://github.com/user-attachments/assets/1bdf6b20-0a98-421f-a2f1-0c34012f58f9)


#### LTK

https://github.com/dbissell6/DFIR/blob/main/WalkThroughs/Apoorv_CTF_2025.md#dura-lesc-sed-lesc-from-pwnme

## Data Exfiltration

### ICMP

#### TTL

![image](https://github.com/user-attachments/assets/3d519083-eb5e-456f-9fe3-70d261aa87c9)

![image](https://github.com/user-attachments/assets/a565f90e-27f3-4990-bd7c-213899021f2d)


`tshark -r exfiltration_activity_pctf_challenge.pcapng -Y "ip.src == 192.168.237.132 && icmp" -T fields -e ip.ttl | awk '{for(i=1;i<=NF;i++) printf("%c", $i)}`

#### CheckSum

Given pcap of ICMP notice short and checksum is one of three.

Use tshark to extract checksums.

`tshark -r chall.pcap -Y "icmp" -T fields -e icmp.checksum`

Use cyberchef to convert to morse code.

![image](https://github.com/user-attachments/assets/7045f995-db80-4f6c-aaf4-683709156145)


### TCP

#### Flags

`tshark -r abnormal_illegal.pcapng -T fields -e 'tcp.flags.str' 'ip.addr==192.168.237.149'| sort | uniq -c`

`tshark -r abnormal_illegal.pcapng -Y "tcp.flags.syn==1 and tcp.flags.fin==1" -T fields -e tcp.flags`

![image](https://github.com/user-attachments/assets/791805e2-f60c-4193-9e2f-62a7ef6b6300)

![image](https://github.com/user-attachments/assets/f44c2208-35c7-4229-8170-4876354ebd49)

<details>

<summary>Python code to convert flags to binary</summary>

```
   flag_mapping = {"0x0003": "00", "0x0007": "01", "0x000b": "10", "0x000f": "11"}

# Extract flags from tshark output
flags = open("flags.txt", "r").readlines()  # Your actual flag data here
flags = [flag.strip() for flag in flags]

binary = "".join(flag_mapping[flag] for flag in flags)
print(binary)

def binary_to_ascii(binary_string):
    # Split the binary string into chunks of 8 bits
    ascii_chars = [binary_string[i:i+8] for i in range(0, len(binary_string), 8)]

    # Convert each chunk of 8 bits into its ASCII character
    ascii_string = ''.join([chr(int(b, 2)) for b in ascii_chars])

    return ascii_string

print('')

# Convert to ASCII
ascii_result = binary_to_ascii(binary)

# Print the result
print(ascii_result)

```

</details>

### DNS


#### Subdomains

Common Attack Example: Attackers use the DNS query names (subdomains) to encode data and send it out. For example, requests might look like data1.malicious-domain.com, data2.malicious-domain.com, etc., where data1, data2, and so on contain pieces of the data being exfiltrated.

Notice a bunch of wierd DNS traffic

![image](https://github.com/user-attachments/assets/3d1ff9c0-961c-4d39-99db-d2b84190f3c1)

Use tshark to extract and clean

```
tshark -q -r shark2.pcapng -Y "ip.dst == 18.217.1.57 && dns.qry.name" -T fields -e dns.qry.name | cut -d'.' -f1 | uniq | tr -d '\n'
```

![image](https://github.com/user-attachments/assets/2198ee96-c378-4b63-8035-f555cec1f83a)

### HTTP


#### Cookies

![image](https://github.com/user-attachments/assets/eebdd233-ce84-445f-b4a6-abe3c976debd)

```
tshark -r httpcookies.pcapng -Y "http.cookie" -T fields -e http.cookie | sed 's/Session=//g' | tr -d '\n' | base64 -d | tail > flag.txt
```

![image](https://github.com/user-attachments/assets/4ed4d6fa-4913-4a27-819d-61c8800cc2fd)


## Tshark
Sometimes it is useful to extract data from pcaps, this can be done with tshark

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

![image](https://github.com/dbissell6/DFIR/assets/50979196/32b3af92-cb32-4e1d-a12b-7dff2aa98f48)


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


## JA3

JA3 is a method for creating fingerprints of SSL/TLS clients based on the specific attributes of the TLS handshake process. It generates an MD5 hash of the concatenation of SSL version, accepted ciphers, list of extensions, elliptic curves, and elliptic curve point formats, creating a unique identifier for a client's SSL/TLS profile. This fingerprinting technique is useful for identifying, tracking, and correlating malicious clients or malware communications over encrypted channels.

https://github.com/salesforce/ja3

Input pcap search for IP in question.

![image](https://github.com/dbissell6/DFIR/assets/50979196/36583c54-2682-4e33-8f25-748c874f1fe8)


# Logs + Registry + Artifacts
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
| **1102** | The audit log was cleared |
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
| **7001** | Service start operations |
| **7022** | Service hung on starting |
| **7045** | A serviuce was installed on the system |


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

move
Convert windowds time format
```
https://www.epochconverter.com/ldap
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

For multiple conditions

`./chainsaw search -t 'Event.EventData.ProcessId: =4' -t 'Event.System.EventID: =18' ~/Desktop/Tracer/Tracer/C/Windows/System32/winevt/logs/*`

To and From with tau

`~/Tools/chainsaw/chainsaw search -t 'Event.System.EventID: =4688' C/Windows/System32/winevt/logs/* --timestamp 'Event.System.TimeCreated_attributes.SystemTime' --from '2025-08-24T22:50:57' --to '2025-08-24T23:55:00' --timezone 'UTC' --skip-errors`

#### sigma

Sigma is a generic and open standard for defining log and detection patterns. It provides a structured way to describe log patterns in a human-readable YAML format. These patterns can then be converted into various SIEM (Security Information and Event Management) tool queries or detection rules to identify potential security threats or incidents based on log data.

Using hunt(+ sigma, rules, mappings)


![image](https://github.com/dbissell6/DFIR/assets/50979196/3ac4f54d-57a8-437a-b801-7e0b9b242342)

![image](https://github.com/dbissell6/DFIR/assets/50979196/8262311b-64ac-4579-96a8-ffc5ebd80d77)


Adding a level to help filter events
```
./chainsaw hunt -s sigma -r rules -m mappings/sigma-event-logs-all.yml /home/kali/Desktop/Tracer/Tracer/C/Windows/System32/winevt/logs --skip-errors --level high
```

Using from and to(filtering time)

![image](https://github.com/dbissell6/DFIR/assets/50979196/296b4957-0f93-4db2-a27a-eb19333d16ed)


Output to csv

![image](https://github.com/dbissell6/DFIR/assets/50979196/e030de8f-7ba8-44d5-b602-84644db9c256)


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

### reglookup

![image](https://github.com/user-attachments/assets/05dda3df-4da0-4ef0-8730-d565906bda30)

### regshell

Cli tool allows traverse the registry. 

![image](https://github.com/dbissell6/DFIR/assets/50979196/53163a8d-9521-4638-a0be-d63985e80fa6)

![image](https://github.com/dbissell6/DFIR/assets/50979196/dfeab73f-8a4b-4f38-a8e7-35710476c1f6)

![image](https://github.com/dbissell6/DFIR/assets/50979196/efd52960-936f-40bc-91d0-fefb696db125)


### RegRipper

RegRipper is a popular open-source tool used for extracting and analyzing information from the Windows registry. RegRipper can be used to quickly and efficiently extract key artifacts from the registry, including user and account information, installed software, network settings, and much more.

RegRipper operates by applying a series of pre-defined plugins or "rippers" to the registry, each of which is designed to extract specific types of information. This modular design allows users to easily customize and extend RegRipper's functionality, tailoring it to their specific forensic needs.

RegRipper can be a powerful tool for analyzing Windows systems and identifying potential security issues. By using RegRipper to extract and analyze registry data,for insights into the inner workings of a system and identify potential indicators of compromise (IOCs) or persistence mechanisms.

To use all plugins (Something annoying is that sometimes the binary wont work unlkess you put an extra space or 2 after the -a)

![image](https://github.com/user-attachments/assets/962f0825-adc3-4494-a377-36a6b4f034c5)


Cal also guess the hive file type
```
-g
```
List all plugins
```
-l
```

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

### AmcacheParser

The Amcache is a repository that holds essential data about installed applications and executables. This data encompasses information such as file paths, sizes, digital signatures, and timestamps of the last execution of applications.

Found at
```
C:\Windows\AppCompat\Programs\Amcache.hve
```
On windows make sure Amcache.hve and logs are all together in same dir/folder

![image](https://github.com/dbissell6/DFIR/assets/50979196/1e138b9f-d729-4879-8f85-edc85db89a2b)


![image](https://github.com/dbissell6/DFIR/assets/50979196/09703637-4b75-4773-8bb1-4df6adbf822d)

# Other Windows artifacts

https://www.sans.org/posters/windows-forensic-analysis/
https://www.sans.org/gated-content?resource=/Shared/Website%20Public%20Content/Posters%20and%20Cheat%20Sheets/SANS_DFPS_FOR500_v4.17_02-23.pdf

https://www.sans.org/blog/running-ez-tools-natively-on-linux-a-step-by-step-guide/

## Master File Table (MFT)

The NTFS file system includes a crucial component known as the Master File Table (MFT), which contains information about every file on an NTFS volume, including its attributes like size, timestamps, permissions, and data content. Files and directories in NTFS are represented either within the MFT or in areas described by MFT entries. When files are added, the MFT grows with new entries, and when files are deleted, their MFT entries are marked as available for reuse, but the allocated disk space for these entries remains unchanged. NTFS reserves a specific space, called the MFT zone, to ensure the MFT remains contiguous, and file and directory space is allocated from this zone once all other volume space is used up.

Each MFT record is 1024 bytes in size. Files smaller than 1024 bytes are stored directly in the MFT file itself, known as MFT Resident files. During Windows filesystem investigations, it's crucial to search for any malicious or suspicious files that may be resident in the MFT. This can reveal the contents of malicious files/scripts. 

Zone Identifier - to see where a file was downloaded from

https://learn.microsoft.com/en-us/windows/win32/fileio/master-file-table

### Chainsaw

MFT utilizing the `dump` option and enabling output.

![image](https://github.com/user-attachments/assets/31a1c655-13cb-4cf3-976f-d6cc7a33255f)

has a `--decode-data-streams` option

### MFTECmd.exe 
Tool to parse MFT +($Boot...)

![image](https://github.com/dbissell6/DFIR/assets/50979196/65638932-3b22-4945-bec3-85c795ecb3bc)


![image](https://github.com/dbissell6/DFIR/assets/50979196/f74b64ff-aeb7-4821-b224-62fd469e8d36)

### MTF Explorer

Can load raw MFT. Useful but takes 45 minutes to load

![image](https://github.com/dbissell6/DFIR/assets/50979196/298cb258-b113-4aee-85b8-e9d9e76bf540)

## UsnJrnl (Update Sequence Number Journal)

The UsnJrnl is a feature of the NTFS file system that logs changes to files and directories on the volume. Each update or modification to a file or directory creates an entry in the UsnJrnl, which includes metadata such as timestamps, file attributes, and the nature of the change (e.g., created, modified, deleted).

Forensic investigators often analyze the UsnJrnl to determine file activity, reconstruct timelines, or identify tampering with system files. 

### Use MFTECmd to parse the USN

![image](https://github.com/user-attachments/assets/2b2809ac-c344-4ac6-8f4c-e5f7087d6bf5)



### usnjrnl_rewind

```https://github.com/CyberCX-DFIR/usnjrnl_rewind```


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

### Using exiftool

![image](https://github.com/user-attachments/assets/c9b51c56-0125-46d4-a1dd-131344d2024c)


### PECmd.exe

![image](https://github.com/dbissell6/DFIR/assets/50979196/0eee2a31-9710-42b6-a601-9fb2a80a75b9)

## Appdata

The C:\Users\$USER\AppData directory in Windows operating systems is a central hub for storing user-specific application data. This hidden folder is critical for both application functionality and forensic investigations, as it contains data that applications do not want exposed to regular user browsing, which might alter or delete sensitive information unintentionally.

The AppData folder is subdivided into three key subdirectories:

```Roaming:``` This folder contains data that moves with a user profile from one computer to another in environments where user profiles are managed on a network. Applications store configuration data here, like user settings and profiles that need to be consistent across multiple workstations.
```Local:``` Stores data that is specific to a single computer, used for data that doesn’t need to be with the user’s profile as they move to different machines. This includes cached data and larger files that don’t need to roam.
```LocalLow:``` Used by applications that run with lower security settings than the normal user context, such as Internet Explorer when operating in protected mode.

### ActivitiesCache.db

Shows execution times of programs and might hold Clipboard payloads.

![image](https://github.com/dbissell6/DFIR/assets/50979196/5943ec9e-eeed-4b94-9796-b3182d55724a)

#### Clipboard

Can find clipboard data in `AppData/Local/ConnectedDevicesPlatform/<USER>/ActivitiesCache.db` in SmartLookup table, ClipboardPayload

`python3 -c 'import sqlite3,json,base64,sys; print("\n".join(base64.b64decode(i["content"]).decode("utf-8","ignore") for (p,) in sqlite3.connect(sys.argv[1]).execute("select ClipboardPayload from SmartLookup") if p and p!="[]" for i in json.loads(p) if i.get("formatName")=="Text"))' ./ActivitiesCache.db`

<img width="1786" height="420" alt="image" src="https://github.com/user-attachments/assets/53306002-13e0-460c-a082-64c8b3bcfa83" />


### rdp Bitmap

Found at 
```
/Users/*/AppData/Local/Microsoft/Terminal Server Client/Cache/Cache0000.bin
```

![image](https://github.com/user-attachments/assets/67371897-53f2-494e-a822-3f23d6ee09f6)

-b option will stitch them all as a non organized collage

![image](https://github.com/user-attachments/assets/fb1a2ab1-5a14-4f41-8ff2-791a2351c7b2)


```https://github.com/ANSSI-FR/bmc-tools```

Can use this to stitch images together

```
https://github.com/BSI-Bund/RdpCacheStitcher
```


### Powershell history

```
C:\Users\htb-student\AppData\Roaming\Microsoft\Windows\PowerShell\PSReadLine\ConsoleHost_history.txt
```

![image](https://github.com/dbissell6/DFIR/assets/50979196/1bc4e7eb-1e18-4310-8533-913342e6bbb7)



### Browser history 

Most browser artifcats are found here. Has its own section below.



## Shellbags
Shellbags, short for "shell folders and bagMRU," are a forensic artifact found in Microsoft Windows operating systems. They are part of the Windows Explorer feature that remembers how folders are displayed (view settings) and stores user interaction with the file system, including folder navigation and access times.

It's important to note that shellbags are focused on the user's interactions with the GUI, and not all file system interactions are reflected in this data, thus shellbags would typically be relevant when a user is using Remote Desktop Protocol (RDP).

Found in registry at

```
• USRCLASS.DAT\Local Settings\Software\Microsoft\Windows\Shell\BagMRU
• USRCLASS.DAT\Local Settings\Software\Microsoft\Windows\Shell\Bags
• NTUSER.DAT\Software\Microsoft\Windows\Shell\BagMRU
• HKEY_CURRENT_USER\Software\Microsoft\Windows\Shell\Bags
```

![image](https://github.com/dbissell6/DFIR/assets/50979196/f416e2e0-ee2e-4737-8310-f265b043bc66)


### Shell Bags Explorer

Looking at offline UsrClass.dat

![image](https://github.com/dbissell6/DFIR/assets/50979196/c1776763-15d8-4437-afe1-222a6364ca12)


## .lnk (Windows Shortcut) Files

.LNK files, also known as Windows shortcuts, are small files containing a reference to a target file or directory. When a user clicks on a .LNK file, it redirects them to the specified target, allowing for quick access to applications, files, or folders.

Found at 
```
C:\Users\<Username>\AppData\Local\Microsoft\Windows\Recent\
```

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

Collection of .lnk files.

Jump Lists in Windows offer quick access to recent files and common tasks for applications. From a cyber perspective, they can reveal user behavior patterns, recent file access, and priority actions. Analyzing them aids in understanding user activities and potential malicious actions associated with specific applications. Jump Lists are essential for creating a forensic timeline and identifying accessed files, making them valuable for security analysis. 

On Windows 10 stored at 
```
C:\Users\<Username>\AppData\Local\Microsoft\Windows\Recent\AutomaticDestinations
C:\Users\<Username>\AppData\Local\Microsoft\Windows\Recent\CustomDestinations
```

### JLEcmd (Jump List Explorer Command Line)

JLECmd is tailored for extracting and interpreting data from Jump List files, which can provide valuable information regarding a user's activity, including recently or frequently accessed documents, pictures, and more.

![image](https://github.com/dbissell6/DFIR/assets/50979196/2172d8e6-1844-409f-bfb4-ed18cba0f5d4)

## Application Compatibility Cache (Shimcache)

Maintains a log of program execution(before windows 10) data to aid compatibility and performance improvements. It captures data like file paths, execution timestamps, and flags denoting program execution. For investigators, Shimcache is valuable in identifying recently run programs and their respective files. Stored in the SYSTEM registry hive. Only writes on reboot or shutdown(might be able to extract current with volatility).

Found at
```
Registry: HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\Session Manager\AppCompatCache
```
### AppCompatCacheParser 

AppCompatCacheParser is another forensic tool developed by Eric Zimmerman, and it's specifically designed to parse the Application Compatibility Cache. 

![image](https://github.com/dbissell6/DFIR/assets/50979196/10942c11-789b-47c7-9ce0-c07be69df89c)

![image](https://github.com/dbissell6/DFIR/assets/50979196/ac479b6b-7fb6-4b1b-bf67-7806cf557b29)


## Userassist
Userassist keys are registry artifacts used to see what GUI-based programs the user ran, and when. 

Keys found in and ROT-13 encoded
```
NTUSER.DAT 
```

## RunMRU Lists
The RunMRU (Most Recently Used) lists in the Windows Registry store information about recently executed programs from various locations, such as the Run and RunOnce keys. These lists can indicate which programs were run, when they were executed, and potentially reveal user activity.

Found at
```
Registry: HKEY_CURRENT_USER\Software\Microsoft\Windows\CurrentVersion\Explorer\RunMRU
```

## SRUM

SRUM, which stands for System Resource Usage Monitor, is a Windows artifact that records detailed system resource usage by each application and user. It provides information about network connectivity, data usage, and application resource consumption over time.

```
C:\Windows\System32\sru\srudb.dat
```

```
C:\Windows\System32\config\SOFTWARE
```

![image](https://github.com/dbissell6/DFIR/assets/50979196/d9e968ae-f410-4aec-ba00-6c5b424ef138)


![image](https://github.com/dbissell6/DFIR/assets/50979196/ebfde46c-3d6b-4649-80e3-9a818db17dc0)

## $Logfile

The Log file is used for transaction logging by the NTFS file system. Can be used to reconstruct file system operations and recover recent changes.

### LogfileParser

```https://github.com/jschicht/LogFileParser```


Delimters is | can change it quick with this
```
$inputFile = "path\to\your\inputfile.csv"
$outputFile = "path\to\your\outputfile.csv"

(Get-Content $inputFile) -replace '\|', ',' | Set-Content $outputFile
```

We can open the CSV in timeline explorer.

![image](https://github.com/user-attachments/assets/527e28cc-f66b-4d36-89ae-17b55e1b9051)

In the above example we are trying to find the the info in shared_key before it was deleted with sdelete64.exe It says go to debug.log to see the data

![image](https://github.com/user-attachments/assets/6e724866-6bf7-4475-b87f-1195d409b094)

![image](https://github.com/user-attachments/assets/8e07212f-facb-4f97-abad-ccd24d4671f7)

This was the key used in ransomware and we can now use it to decrypt files. 

## .apmx

File type for API Monitor, a tool for monitoring and analyzing API calls made by applications on Windows systems. These files contain a record of API calls, including details such as the calling process, the APIs invoked, parameters, return values, and any errors that occurred.


In `Monitored Processes` pane, can hover over cmd and powershell processes to see commandline. In Summary pane bionoculars to find something from the strings and we can get it in the Parameters pane.

![image](https://github.com/dbissell6/DFIR/assets/50979196/e47ab520-9d30-436b-b8e0-6ae3e166e463)

## Defender

### Quarantine

Records files that were quarantined after being flagged as a threat by Defender.

Stored in ```C:\ProgramData\Microsoft\Windows Defender\Quarantine\entries```

### MP Logs – Key Points:

 Windows Defender MP logs store valuable information about files scanned by Defender, such as file paths, hashes, timestamps, and potentially signatures.
 These logs are located in the hidden directory ```C:\ProgramData\Microsoft\Windows Defender\Support```.
 MP logs can record command line arguments, observed files, and results, even if the file wasn’t flagged as suspicious.
 Common logs include MPDetection (detected threats) and MPLog (scanned files and directories).
 These logs can be pivotal in incidents where other artifacts or logs are missing, as they consolidate critical data like hashes, file paths, timestamps, and telemetry.

![image](https://github.com/user-attachments/assets/a95f9654-e570-41a3-95d4-a1dbadfd723f)

## Tasks

In Windows contains XML files that define scheduled tasks for the operating system. These tasks are automated actions that Windows or applications run at specific times or in response to specific triggers, such as system startup or user login. Each XML file typically contains details about the task, including:

    Task Name: The name of the scheduled task.
    Triggers: Events or conditions that initiate the task (e.g., time-based, event-based).
    Actions: The executable command and any arguments or scripts that the task runs.
    Conditions: Requirements that must be met for the task to run (e.g., system idle or network availability).
    Settings: Additional configurations such as retry intervals, permissions, and whether the task runs with elevated privileges.

```
C:\Windows\System32\Tasks
```

![image](https://github.com/user-attachments/assets/b7a5eb91-a295-4379-a98d-a01d912265d5)

```
exiftool * | grep -E "File Name|File Modification Date/Time|Task Actions Exec Command|Task Actions Exec Arguments"  | awk '{print} NR % 4 == 0 {print ""}'
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


# Linux 

## Logs

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


## Bash history

The `.bash_history` file is a valuable forensic artifact that records the commands entered by a user in a Linux shell. Analyzing this file can reveal critical information about user activities, such as executed commands, file access, network connections, software installations, and potential attempts to cover tracks or alter system files. Found as a hidden file in the users home, investigators can use `.bash_history` to reconstruct user actions, identify malicious behaviors, and establish a timeline of events, making it an essential tool for incident response and digital forensics.

![image](https://github.com/user-attachments/assets/4531c973-6e90-43ae-a93c-d8c56fd92189)


## system.journal

Holds logged system events and messages.

![image](https://github.com/dbissell6/DFIR/assets/50979196/735ae9c5-d3b1-4906-98e2-62f27e7870ab)

## wtmp

The wtmp file in Unix-like operating systems is a binary file that logs all logins, logouts,  reboots, and shutdowns. 

![image](https://github.com/dbissell6/DFIR/assets/50979196/6e204c99-ee16-4601-85f4-8decf2712465)

Can also use utmpdump

![image](https://github.com/dbissell6/DFIR/assets/50979196/0908748a-a6e9-4e88-9386-6921d58ed30c)


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
chmod, whoami, sudo, netstat ... typical enumeration



## Persistence 

Most persistence mechanisms found in /etc

https://github.com/dbissell6/DFIR/blob/main/WalkThroughs/Hold%20On%20Tight%20Walkthrough.pdf

### Cronjobs  

In Linux, cron is a time-based job scheduler that runs commands at specified intervals. An attacker may use cron to maintain persistence on a compromised system by creating a cronjob to execute a malicious script at regular intervals. This script could be used to create backdoors, steal data, or perform other malicious activities.

Global found in 

```
/etc/crontab
```

```/var/spool/cron```

![image](https://github.com/dbissell6/DFIR/assets/50979196/b011015a-c38a-4e41-825b-f0e564f6d422)


```/var/spool/cron/crontabs```

![Pasted image 20231122204056](https://github.com/dbissell6/DFIR/assets/50979196/ec65d879-dc6f-4703-ab6c-3ac81f2de8d8)

### LD_PRELOAD

LD_PRELOAD is an environment variable in Linux/Unix systems that allows users to specify a shared library to be loaded before other libraries. This functionality is often exploited by attackers to inject malicious code into legitimate processes.

```
/etc/ld.so.preload
```

![image](https://github.com/user-attachments/assets/f0691981-ae65-4567-ac4d-8f601c305d86)


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

Browser artifacts are crucial for profiling user activity on a system. They include history, cookies, cache, sessions, and configurations. Notably, browsers track local file access in their history, such as when viewing local PDFs or SVGs. These accesses can also be found in %LocalAppData%\Microsoft\Windows\WebCache\WebCacheV01.dat with entries like file:///X:/path/to/file, where "X" denotes the drive letter.

### Live NirLauncher

NirLauncher -> BrowsingHistoryView

![image](https://github.com/dbissell6/DFIR/assets/50979196/ecbae68b-502e-43b6-8087-7d781c9373c0)

Most databases use sqlite. Can also use bulkextract

Convert times

```
https://www.epochconverter.com/webkit
```

### Chrome 

appdata/local/google/chrome/User Data/default/History

![image](https://github.com/dbissell6/DFIR/assets/50979196/d6d87ba5-73eb-421c-b208-273fe7c90a2a)


Recover passwords

![image](https://github.com/user-attachments/assets/c9c02884-ab49-4fb3-b3e0-84b1c7b52c67)

![image](https://github.com/user-attachments/assets/d38e5c38-b271-408e-9ceb-b464d1651239)

![image](https://github.com/user-attachments/assets/74af0d10-6ea0-453e-859b-269adb023779)


#### MetaMask Vault Location

`AppData/Local/Google/Chrome/User Data/Default/Local Extension Settings/nkbihfbeogaeaoehlefnkodbefgpgknn` 

To Decrypt the Vault

`https://metamask.github.io/vault-decryptor/`

<img width="1709" height="472" alt="Pasted image 20251004174208" src="https://github.com/user-attachments/assets/640c520b-e408-4af1-95b0-a1a2d2c137af" />


### Firefox

```
Linux: ~/.mozilla/firefox/<profile_folder>/
Windows: %APPDATA%\Mozilla\Firefox\Profiles/<profile_folder>/logins.json
```

#### Places

Stores browsing history, bookmarks, and downloads.

`places.sqlite`

![image](https://github.com/user-attachments/assets/ace37d34-d817-446e-9b99-45854ccedb58)


![image](https://github.com/user-attachments/assets/6fc9cbff-f384-4a2f-a2cc-b73983ef4eab)


#### View passwords

Encrypted passwords are stored in `logins.json`

The keys to decrypt are stored in `key4.db`

![image](https://github.com/user-attachments/assets/256cfb57-921a-4916-8a07-6fe2d9850103)

```
git clone https://github.com/unode/firefox_decrypt
```

#### Session history

Open tabs and session data from the last session. Can be found in user or `sessionstore-backups`

![image](https://github.com/user-attachments/assets/3da231a9-8a82-464b-a7b2-a125e9926894)

Use `https://jsonlint.com/` to prettify json

![image](https://github.com/user-attachments/assets/8eb85739-d0ca-4d8f-a4aa-ee6f96bd92e4)

![image](https://github.com/user-attachments/assets/68c708cb-8451-43be-bea6-6370ce1fef37)


#### formhistory

Stores autocomplete form data entered by the user.

`formhistory.sqlite`

#### Downloads

Logs details of file downloads, including the source URL, download time, and save location.

`downloads.json`

#### Cookies

`cookies.sqlite`

### Edge

appdata\local\Microsoft\Edge\UserData\[Default|ProfileX]\*

appdata\local\microsoft\windows\webcache\webcacheV01.dat

## .git

Not really internet artifact, Where is better tho?

The .git directory is a goldmine of information for forensic analysts. It is the hidden folder within a Git repository that contains the entire version control history. This includes details about every commit, configuration settings, branches, and the objects that represent the filesystem of the project at every recorded point in time.

![316927808-b9eaedbe-5de4-4596-9632-846b17e4d665](https://github.com/dbissell6/DFIR/assets/50979196/89b6c490-d21f-4747-9965-09b79a765fba)

Read through all the commits and grep for specific content within them.

```
git log --format="%H" | while read commit_hash; do git show "$commit_hash"; done | grep "search_term"
```

![image](https://github.com/dbissell6/DFIR/assets/50979196/bf4f2466-26a3-41f8-9d06-f33f1db83c07)

## Email

.ost 

OST stands for Offline Storage Table. These files are used by Microsoft Outlook to store a copy of your mailbox data (emails, calendar events, contacts, etc.) when using Outlook with a Microsoft Exchange account. They allow you to work offline and synchronize changes with the Exchange server when you reconnect.

![image](https://github.com/user-attachments/assets/d920d3b3-18d0-40b3-a8d6-375290cc50ad)



# Files/Executables

[Malware Analysis](https://github.com/dbissell6/DFIR/blob/main/Blue_Book/Blue_Book.md#malware-analysis)

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

### Strings recursivly 

```
 find Users/rumi -type f -size -100M -print0 |                     
while IFS= read -r -d '' f; do
  printf '\n----- %s -----\n' "$f"
  strings -a -n 4 "$f"
  strings -a -n 4 -e l "$f"
  strings -a -n 4 -e b "$f"
done 2>/dev/null
```

### ASCII/UTF-8 (treat all files as text)

```
rg -n -F -a --hidden --no-ignore \
  'toallknownlawsofaviationthereisnowayabeeshouldbeabletofly' Users/rumi

# UTF-16LE and UTF-16BE
rg -n -F -a --encoding utf-16le \
  'toallknownlawsofaviationthereisnowayabeeshouldbeabletofly' Users/rumi
rg -n -F -a --encoding utf-16be \
  'toallknownlawsofaviationthereisnowayabeeshouldbeabletofly' Users/rumi
```
## Floss

Can also be used to get static strings from binaries

![image](https://github.com/dbissell6/DFIR/assets/50979196/30656dd6-a02a-46bd-9636-5ee644f7ec45)

## Detect It Easy (DIE)

Detect It Easy, or abbreviated "DIE" is a program for determining types of files

![image](https://github.com/dbissell6/DFIR/assets/50979196/354a1f97-d5b8-4e05-afbd-b6955cbc86b0)

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

### Windows/Macros(.docm, .docx .doc, .bin, .vba, .pptm, .one)
.docm .doc .bin .vba .pptm .one .rtf

Can sometimes using unzip or 7z on word files can reveal hidden content.

![Pasted image 20240729163554](https://github.com/user-attachments/assets/32819dd0-cfdf-4abb-9549-32dbaa9ec123)


![Pasted image 20240729163615](https://github.com/user-attachments/assets/a5498a3c-ffc0-4485-ad9d-e59907d3cd61)

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

### Python (.py, .pyc)

py Files: .py files are Python source code files. These files contain human-readable code written in the Python programming language. They can include scripts, modules, or complete applications.


Compiled Python Files: .pyc files are the result of compiling Python source code (.py files) into bytecode. 
This bytecode is a low-level, platform-independent representation of your source code that the Python interpreter can execute.

![image](https://github.com/dbissell6/DFIR/assets/50979196/0212d7ac-46fb-42da-8087-0d42d9cd3406)

```https://github.com/extremecoders-re/pyinstxtractor```


![image](https://github.com/dbissell6/DFIR/assets/50979196/6f9df92c-bb81-44d3-a337-82809eee430c)

```
# Clone the repository
git clone https://github.com/zrax/pycdc.git

# Change directory to the cloned repository
cd pycdc

# Build the tool
mkdir build
cd build
cmake ..
make
```

pylingual is an online decompiler. PyLingual makes novel use of transformer models to learn new Python bytecode specifications as they are released.

```
https://pylingual.io/
```

### Image files (.jpg, .png, .bmp)

These files can contain hidden messages or steganography, where data is hidden within the image.

#### bmp

A .bmp  file is a bitmap image file format that contains uncompressed image data. The file starts with a 14-byte header that contains information about the file format, such as the file size, offset to the pixel data, and the number of bits per pixel. After the header, there is an optional color table that maps color values to specific pixels. The pixel data follows the color table (if present) and is stored row-by-row, with each row padded to a multiple of 4 bytes. Each pixel is represented by a series of bits that indicate its color and position in the image. The size of the pixel data can be calculated based on the file size and offset values in the header. It is important to note that .bmp files do not contain any compression or encryption.

#### png

A .png file is made up of chunks of data, where each chunk contains information about the image. Each chunk starts with a 4-byte length field, which specifies the number of bytes in the chunk (excluding the length field itself). This is followed by a 4-byte type field, which identifies the type of data in the chunk. After the type field comes the chunk data, which can be of varying length depending on the type of chunk. Finally, the chunk ends with a 4-byte CRC (Cyclic Redundancy Check) field, which is used to verify the integrity of the chunk data.

The first chunk in a PNG file is always the IHDR (Image Header) chunk, which contains basic information about the image such as its dimensions, color depth, and compression method.

To summarize, each chunk in a PNG file contains 4 fields in the following order:

-    Length (4 bytes): specifies the number of bytes in the chunk (excluding the length field itself).
-    Type (4 bytes): identifies the type of data in the chunk.
-    Chunk data (variable length): the actual data contained in the chunk.
-    CRC (4 bytes): a checksum used to verify the integrity of the chunk data.

#### jpeg/jpg

Notice discrepency in size

<img width="700" height="121" alt="image" src="https://github.com/user-attachments/assets/6bd4b7cc-7c10-474d-9e0f-4f2715fd3e53" />


<img width="873" height="130" alt="Pasted image 20251004003017" src="https://github.com/user-attachments/assets/2b9c109c-d102-4de0-93c7-a10ee83b7633" />


### Email (.eml)

### PDF (.pdf)

![image](https://github.com/dbissell6/DFIR/assets/50979196/b3728cc7-9fe3-4828-a6c2-97a49ab30d85)


![image](https://github.com/dbissell6/DFIR/assets/50979196/e3a1e84d-65d7-4742-a908-002392fcab53)

![image](https://github.com/dbissell6/DFIR/assets/50979196/47d5b3fd-30d8-449f-b418-150ce7f86103)

![image](https://github.com/dbissell6/DFIR/assets/50979196/9367c509-cb76-45b5-90a9-eead548ca73c)

### Database files 

#### SQLite (.sqlite, .db, .sqlite3)

![image](https://github.com/dbissell6/DFIR/assets/50979196/0bbda057-e6fa-463b-b1f4-fab95ed736fa)

#### sqlite3

![image](https://github.com/dbissell6/DFIR/assets/50979196/103752c1-7247-4ad5-be01-e0fb226c4a7f)


#### sqliteBrowser

![image](https://github.com/dbissell6/DFIR/assets/50979196/e68043f9-c3f3-44c3-a41a-d6d9a9407873)

Browse data

![image](https://github.com/dbissell6/DFIR/assets/50979196/6e9338ef-3f88-4228-9431-6bf87e5f85a3)


#### MySQL Database (.sql)

#### keepass (.kdbx)

Keepass is a password manager to allow users to securely store their passwords in a single database, which is locked with one master key or a key file.
Typically need a pawword to read it, can be cracked with keepass2john + john.

Open with

![Pasted image 20240323011307](https://github.com/dbissell6/DFIR/assets/50979196/30907313-2a87-4db4-a7da-a1994cc302a1)

### Bitcode Formats (.o,)

#### llvm

![image](https://github.com/user-attachments/assets/5f33836e-2ac2-4358-930b-50e6635a60f3)


### Audio files (e.g., MP3, WAV)
Information can be hidden in the frequency spectrum of the audio signal, in unused space within the file, or by modifying the phase of the audio waveform.  
### Video files (e.g., MP4, AVI)
Information can be hidden within the individual frames of the video, in unused space within the file, or by modifying the motion vectors of the video stream.



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


#### Decompressing

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
#### Unzipping ZipCrypto

ZipCrypto is one of the encryption methods used in ZIP file formats. It's been around for a while and is considered weak because it uses a stream cipher that's not cryptographically strong by modern standards. The algorithm's design flaws, such as the way encryption keys are derived and the cipher's susceptibility to known-plaintext attacks, make it vulnerable.

Known Plaintext: The attacker must have some portion of the plaintext of one of the files in the encrypted ZIP archive. This could be a standard file header, any predictable content, or previously extracted unencrypted files from the archive.

![image](https://github.com/dbissell6/DFIR/assets/50979196/1b06beb8-581d-459b-bd66-11cdd779dec1)

To exploit 

1) Reconstruct file (svg).
2) Run bkcrack to get keys
3) Recreate zip with password of your choice
4) Open

![image](https://github.com/dbissell6/DFIR/assets/50979196/c4cc4f94-474a-4b1a-89b9-88d813532014)

Another store example

Add plaintext to file and zip it with `-0` 

![image](https://github.com/user-attachments/assets/41780e74-6b4a-4d53-8b6d-0b4c5afad430)

can run pointint at index

![image](https://github.com/user-attachments/assets/c0134c8a-ff7f-406d-b9a8-035e8b1cc99d)


Another Example, not 16 continous bytes
https://github.com/dbissell6/DFIR/blob/3eeb5a757fbe5b3bbabe088b65b4a23dc8b36726/WalkThroughs/TexSaw_CTF_2025.md#hidden-beneath-the-wavs

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

Binwalk is a popular tool used in cybersecurity for analyzing and extracting information from binary files, such as firmware images and file systems. With binwalk, analysts can identify and extract various components of a binary file, including the file system, bootloader, and kernel. Binwalk can really be used for any file.

![image](https://github.com/dbissell6/DFIR/assets/50979196/34c98f59-bb60-465e-b80e-b26d627b1986)

Two popular switches used with binwalk are:

    -e  
This switch tells binwalk to extract the identified file systems from the binary file. This is useful when you want to extract and analyze the file system components of a firmware image.

    -y 
This switch tells binwalk to suppress confirmation prompts during extraction. This can be useful when you want to automate the extraction process and don't want to be prompted for confirmation every time.

Sometimes binwalk -e doesnt work need to use

```
~/.local/bin/binwalk -e --dd='.*' pngfile
```
## xxd

xxd is a command-line utility that is used to convert binary files into hexadecimal and vice versa. It can be used to create a hexadecimal dump of a binary file, or to convert a hexadecimal dump back into a binary file. xxd is useful for analyzing binary files and for converting between different formats.

![Pasted image 20230213121602](https://user-images.githubusercontent.com/50979196/221450472-5829ddc8-15a5-4b61-ac00-240bd1ea7346.png)

## Hexedit
Hexedit is a hexadecimal editor that allows users to modify binary files directly. It can be used to view and edit the contents of binary files at the byte level, and can be particularly useful for changing specific bytes in a file. In the Pico CTF challenge "Tunnel," Hexedit was used to change the header of a .bmp file.

![image](https://github.com/dbissell6/DFIR/assets/50979196/5f1f63c2-8013-4d1d-a28a-5c1112ab3f88)

## Scalpel 

Scalpel is an open-source, high-performance file carving tool used in digital forensics and data recovery. It scans disk images for file signatures based on user-defined patterns (usually file headers and footers) and extracts files that match those signatures.

First step is to edit the conf file to select what you want

```
sudo nano /etc/scalpel/scalpel.conf
```
Uncomment the file types we want to search for

![image](https://github.com/user-attachments/assets/983dda7d-9fd1-473f-aa60-f158063278d6)

Run it

![image](https://github.com/user-attachments/assets/4d02f022-dd64-46c4-aaaf-331f990ff041)



# Malware Analysis

Please watch if first time doing this- https://www.youtube.com/watch?v=gjVmeKWOsEU

Malware analysis is the process of dissecting malicious software to understand its functionality, behavior, and purpose. 

We want to understand what the malware does. Does it encyrpt our files? Does it send a reverse shell? If so, how?

General rules
    * Dont get stuck in the weeds, you will never understand every detail of complex malware. Always start with the big picture, zoom in as needed, dont fall down a rabbit hole.




https://docs.remnux.org/ - VM Focused on malware analysis

https://www.youtube.com/@jstrosch/featured


## static vs dynamic


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






## **Static Analysis Techniques**
 Static analysis techniques involve analyzing the code of a program without actually executing it. Some techniques include disassembly, decompilation, and string analysis. Disassembly involves translating machine code into assembly code to better understand the program's behavior. Decompilation involves converting compiled code back into its original source code. String analysis involves analyzing the strings contained within a program to identify potential malicious behavior.

### Example simple .sh 


![image](https://github.com/dbissell6/DFIR/assets/50979196/38c4f389-be45-40da-849f-ff7f42103656)

Run strings on file, notice base64 encoded text 

![image](https://github.com/dbissell6/DFIR/assets/50979196/dc126fe4-5ded-40ba-82cd-34f5df32c16e)




## objdump

Disassemble binary files.

![image](https://github.com/dbissell6/DFIR/assets/50979196/67590727-a16a-4f67-b74c-7b9058f3c6f9)

## ldd

ldd is a Unix and Linux command-line utility that stands for "List Dynamic Dependencies." It's used to display the shared libraries that a binary program requires to run.

![image](https://github.com/dbissell6/DFIR/assets/50979196/11f1a938-6b99-404e-b265-e20c398a547f)


### Dogbolt

This is the Decompiler Explorer! It is an interactive online decompiler which shows equivalent C-like output of decompiled programs from many popular decompilers. It's meant to be the reverse of the amazing Compiler Explorer.

`https://dogbolt.org`


### Ghidra

Ghidra is an open-source reverse engineering framework developed by the National Security Agency, offering a suite of capabilities to analyze compiled code and decompile it into higher-level representations.

![image](https://github.com/dbissell6/DFIR/assets/50979196/02e2d697-9302-4c59-a38b-109acbfcfbd7)

#### Ghidrathon

Ghidrathon embeds your local Python 3 interpreter in Ghidra, giving it access to your database and the framework’s scripting API. You can then use modern Python, including any third-party packages you have installed, to programmatically access your Ghidra database. 

`https://github.com/mandiant/Ghidrathon/tree/main`

##### XOR + index example

There was a piece of malware that had obfuscated strings in DAT. The strings were ran through a function before being used in the exe. This script allows the user to programatically
get the bytes and run them through the function.

![image](https://github.com/user-attachments/assets/722c5807-c973-47c5-b879-92a01cd254d6)


This example works 90%. More of a basius for future scripts.
<details>

<summary>Python script</summary>


```
# Import necessary Ghidra classes
from ghidra.app.decompiler import DecompInterface
from ghidra.program.model.data import ByteDataType, ArrayDataType
from ghidra.util.task import TaskMonitor
import re  # Import regex module


def index_subtraction_and_xor(data):
    # The key 'Love_Her'
    key = "Love_Her"

    # Convert the key 'Love_Her' to its byte representation
    key = key.encode('utf-8')  # 'Love_Her' => b'Love_Her'

    result = bytearray()
    key_length = len(key)

    # Loop over the input data
    for i in range(len(data)):
        # Subtract the index from the byte
        subtracted_value = (data[i] - i) % 256
        
        # XOR the result with the corresponding byte from the key (repeated)
        xor_value = subtracted_value ^ key[i % key_length]
        
        # Append the result to the output
        result.append(xor_value)

    # Print the output as an ASCII string (ignore non-printable characters)
    try:
        ascii_output = result.decode('ascii', errors='ignore')  # Ignore non-printable characters
        print("Output (ASCII):", ascii_output)
    except UnicodeDecodeError:
        print("Output contains non-printable characters and cannot be fully converted to ASCII.")


# Define the function you're targeting
function_name = "tls_callback_0"

# Get the current program
program = getCurrentProgram()

if program:
    # Get the target function by name
    functions = getGlobalFunctions(function_name)

    if functions:
        function = functions[0]
        print(f"Function {function_name} found at address: {function.getEntryPoint()}")

        # Set up decompiler
        decomp_interface = DecompInterface()
        decomp_interface.openProgram(program)

        # Decompile the function
        decompiled = decomp_interface.decompileFunction(function, 30, TaskMonitor.DUMMY)

        if decompiled.decompileCompleted():
            decompiled_code = decompiled.getDecompiledFunction().getC()
            print(f"Decompiled code for {function_name}:\n{decompiled_code}")

            # Split decompiled code into lines and process
            lines = decompiled_code.splitlines()
            for line in lines:
                line = line.strip()

                # Identify function calls that reference `DAT_` entries
                if line.startswith("FUN_"):
                    parts = line.split(',')
                    second_arg = parts[1].strip().rstrip(");")

                    # Check for a DAT reference in the second argument
                    if "DAT_" in second_arg:
                        dat_address_str = second_arg.split('&DAT_')[-1].strip()
                        dat_address = toAddr(f"0x{dat_address_str}")

                        # Determine the byte count (default to 16 if third argument is missing)
                        byte_count = 16
                        if len(parts) >= 3:
                            try:
                                byte_count = int(parts[2].strip().rstrip(");"), 0)
                            except ValueError:
                                pass

                        # Define the data at `DAT_` as a byte array
                        byte_data_type = ArrayDataType(ByteDataType(), byte_count, 1)
                        createData(dat_address, byte_data_type)  # Define data as byte array

                        # Extract the byte array
                        defined_data = getDataAt(dat_address)
                        if defined_data and defined_data.isArray():
                            data_bytes = [defined_data.getComponent(i).getByte(0) for i in range(byte_count)]
                            data_hex = ''.join([f'{byte:02x}' for byte in data_bytes])

                            # Remove dashes, spaces, and filter only valid hex characters
                            data_hex_clean = re.sub(r'[^0-9a-fA-F]', '', data_hex)

                            print(f"Cleaned Hex data at {dat_address_str}: {data_hex_clean}")

                            # Convert the cleaned hex string to actual byte data and run the XOR operation
                            data_bytes = bytes.fromhex(data_hex_clean)
                            index_subtraction_and_xor(data_bytes)
                        else:
                            print(f"Failed to define or extract data at {dat_address_str}")
        else:
            print(f"Decompilation of {function_name} failed!")
    else:
        print(f"Function {function_name} not found!")
else:
    print("No program found!")

```

</details>




## **Dynamic Analysis Techniques**
Dynamic analysis techniques involve analyzing the behavior of a program as it executes. Techniques like debugging and sandboxing can be used to analyze malware in a controlled environment. Debugging allows analysts to step through a program and observe its behavior at runtime. Sandboxing involves running a program in an isolated environment to analyze its behavior without risking damage to the host system.


### debuggers

steps

Breakpoints

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
| `x/10x $esp`            | Examines memory, x = hexadecimal. Here, it shows 10 words starting from the ESP register. |
| `x/6gx $rsi`            | The g specifies that the memory displayed in giant words (64-bits) |
| `print $eax`                  | Displays the value of the EAX register.            |
| `set $eax=0x12345678`         | Sets the EAX register to the value `0x12345678`.   |
| `x/s $rdi`                    | Displays the string pointed to by the RDI register.|
| `display <expression>`       | Automatically prints the value of an expression every time GDB stops. |
| `undisplay <n>`              | Stops displaying the expression with the given display number `n`.    |
| `delete display`             | Stops displaying all expressions.                                     |
| `info display`               | Lists all currently displayed expressions and their display numbers.  |
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

#### Decompiling

`F5` for decompiling

#### Rebase

Sometimes using and comparing to ghidra you will notices the addresses dont match up

Compare

![image](https://github.com/user-attachments/assets/175e25e0-f181-405a-88eb-1ebd1575d7f2)

to

![image](https://github.com/user-attachments/assets/1cf1da43-070f-4d67-b2c9-791b60cf7205)

To fix this you can rebase.

`Edit -> Segments -> Rebase Program -> Set value to 0`

![image](https://github.com/user-attachments/assets/8b55899e-c88f-4f6a-a30c-3d212d1c4126)


### x64dbg

Debugger for windows exe

Some malware will check for debugger, can counteract that with `hide debugger`

![image](https://github.com/user-attachments/assets/907c993d-cce2-420d-babf-e76fa5c65804)



### dnSpy

dnSpy is a debugger and .NET assembly editor, which can be used to inspect, debug, and edit .NET assemblies. One of its powerful features is the ability to decompile .NET assemblies back to C# or VB.NET source code, providing insights into the underlying functionality of the software. dnSpy allows users to set breakpoints, step through code, and inspect variables and objects, making it a valuable tool for reverse engineering and debugging .NET applications.


![image](https://github.com/dbissell6/DFIR/assets/50979196/8881de65-03e0-437e-811c-31693517365b)

### dotPeek

dotPeek is a free .NET decompiler and assembly browser developed by JetBrains. It allows forensic analysts and reverse engineers to decompile .NET executables and libraries back into readable C# source code.

![image](https://github.com/user-attachments/assets/dc3919bf-8694-4654-b56f-5a5dbb21634e)


### Procmon

Process Monitor, commonly referred to as ProcMon, is a monitoring tool from the Sysinternals suite. It combines the features of two legacy Sysinternals utilities – Filemon and Regmon. ProcMon provides real-time file system, Registry, and process/thread activity monitoring. May also get .pml log files as forensic evidence.


![image](https://github.com/dbissell6/DFIR/assets/50979196/7a91f502-25ba-4fa1-b681-e03380bebb6d)

Can filter with process name or pid...

![image](https://github.com/dbissell6/DFIR/assets/50979196/857658bd-6246-4826-b8e9-1b435c9cf810)

Can filter type of activity (Registry, filesystem, network)

![image](https://github.com/dbissell6/DFIR/assets/50979196/7c2711d4-5f0c-4391-a62c-05322251b5f7)

Can see process tree by clicking on tree , or Tools -? Process Tree

![image](https://github.com/user-attachments/assets/10998502-e6e1-4aec-9bea-192f4970e678)

Can see more details Options -> Select Columns 

![image](https://github.com/user-attachments/assets/a963d253-9bae-44e1-87e1-13499d8615a1)


### Process Explorer

Process Explorer is another tool from the Sysinternals suite, and it provides detailed information about which handles and DLLs processes have opened or loaded. It offers a more in-depth view than the standard Windows Task Manager.




### Auditd

Linux Audit daemon, part of a system that captures detailed system-level events for monitoring and security analysis. It logs system calls, file accesses, and security changes, based on rules defined by the system administrator. Auditd does not attach to the process and will not trigger anti-debugging checking for tracerpid /prc/self/status.


Can add rules of what to monitor. In this instance I am preparing to run malware which I know will interact with the following file and direcotry.

`-k` is used to create a tag to search for

![image](https://github.com/dbissell6/DFIR/assets/50979196/b3027095-5eda-40f9-90d3-ed7c4fff1a0b)

Run the malware, wait till completion. 

`ausearch`

![image](https://github.com/dbissell6/DFIR/assets/50979196/3cd6d70a-d076-475b-bb94-4a7eeb3680ff)

Rule to track malware with all system calls tracked.
```
-a always,exit -F path=/home/kali/Desktop/download.elf -F arch=b64 -S all -k VIVIG
```


### strace

strace is a diagnostic, debugging, and instructional utility for Linux that is used to monitor interactions between processes and the Linux kernel, which include system calls, signal deliveries, and changes of process state. 

![image](https://github.com/dbissell6/DFIR/assets/50979196/a78351bb-570d-4373-b19e-99060f47c312)


### ltrace

ltrace is a utility that intercepts and records dynamic library calls (calls to shared libraries) which are executed by user-space applications.

![image](https://github.com/dbissell6/DFIR/assets/50979196/f5e4a286-df78-4c4c-9808-944be1c2af0f)

### LD_PRELOAD Trick

The LD_PRELOAD technique leverages the dynamic linker, which is part of the Linux operating system. When a dynamically linked executable runs, the linker is responsible for loading all shared libraries that the program requires. The LD_PRELOAD environment variable specifies a list of additional, user-specified, shared libraries to be loaded before all others. This method allows us to inject custom code, such as function hooks, into a program's runtime environment.

Use case, run ltrace and see variables you want, like a key and iv?

![289154479-793444e0-b33d-44fe-899b-d557c4bec9a8](https://github.com/dbissell6/DFIR/assets/50979196/4d1e3c1a-c44e-4e73-9046-8e8f54fc7697)

Create a hook and run with preload. Capture key and IV.

![288989558-1e05dbd8-e262-495a-9396-4e3b834a4309](https://github.com/dbissell6/DFIR/assets/50979196/41428800-4e61-48a5-a299-8d9dbb9fba5b)



### sysdig

Think about sysdig as strace + tcpdump + htop + iftop + lsof + ...awesome sauce.


Start sysdig, run malware, stop sysdig, read

![image](https://github.com/dbissell6/DFIR/assets/50979196/957f9e6a-002a-4d77-8ab1-f25c44aef764)



### Regshot

Regshot is an open-source (GNU GPL) tool that allows users to take a snapshot of the system registry and then compare it with a second one, made after doing system changes or installing a new software product.

Take first shot 

![image](https://github.com/dbissell6/DFIR/assets/50979196/6369f784-fabb-4267-a876-b7d0f9d1fc94)

Run malware

![image](https://github.com/dbissell6/DFIR/assets/50979196/808e22dd-29ad-4f6a-864e-58898c4cb208)

Take second shot

![image](https://github.com/dbissell6/DFIR/assets/50979196/d7c69dfb-5a69-4bef-b71a-84ba460065b9)

Compare

![image](https://github.com/dbissell6/DFIR/assets/50979196/b06f0d06-94ba-425a-a581-81598164bd7c)

## Shellcode

Shellcode is a small piece of code used to exploit software vulnerabilities. It's often written in assembly and injected into a program to execute arbitrary commands or manipulate the system, typically by attackers in memory to escalate privileges or perform malicious actions.

### scdbg

scdbg is a shellcode debugger that simulates the execution of shellcode within a controlled environment, detecting shellcode actions like API calls, memory access, and system changes to analyze its behavior without direct execution.

![image](https://github.com/user-attachments/assets/15deb55a-4758-4e3c-89d1-77242e71f7bf)


### Speakeasy

Speakeasy is a dynamic binary emulation tool that allows the execution of malware in a sandboxed environment. It’s used for analyzing and understanding malware without directly executing it, useful for reverse engineering and identifying malicious behaviors.

`https://github.com/mandiant/speakeasy`

![image](https://github.com/user-attachments/assets/64c46a42-5cb8-4643-bf0a-2a79cfa16004)


## Sandboxes

### Virus total 

More than a sandbox, can be useful to get some information from.  

![Pasted image 20230212170655](https://user-images.githubusercontent.com/50979196/221450418-70e59b66-d291-4a83-9540-d71735b7e4a5.png)


To add: Malware dropping files,

### Noriben

Noriben can be used for dynamic analysis monitoring creation of processes.

Start from command line, run executable in question, when finihed stop Noriben, get output 

![image](https://github.com/dbissell6/DFIR/assets/50979196/f3f80f0d-7a6b-4042-9219-187570dba020)


![image](https://github.com/dbissell6/DFIR/assets/50979196/a3718827-65db-4f74-8afa-b5a53e902430)


### hybrid-analysis

Web based, uses Crowdstrike Falcon Sandbox.

![image](https://github.com/dbissell6/DFIR/assets/50979196/926cf34b-9543-4a80-b394-d95ee0d9fa27)


### any.run

Any.Run is an interactive online sandbox service designed for the analysis of suspicious files and URLs. Any.Run provides real-time feedback, including network traffic, file system changes, and other system behaviors

![image](https://github.com/dbissell6/DFIR/assets/50979196/5ecd943c-278e-42e8-9499-ae86540a3d2d)


### Alien Vault

Web based, can check hashes and run in sandboxes. Crucial for linux binaries. 

![image](https://github.com/dbissell6/DFIR/assets/50979196/45f165da-48ba-4868-91ec-00c11aeb3432)

https://otx.alienvault.com

### MalwareBazaar

MalwareBazaar is an open-source threat intelligence platform developed and maintained by abuse.ch. It serves as a repository for collecting, analyzing, and sharing malware samples. Security researchers, threat analysts, and IT professionals use MalwareBazaar to submit malware samples they encounter in the wild. The platform allows users to download these samples for further analysis and study. MalwareBazaar also provides detailed metadata about each sample, including its hash values, file type, and associated indicators of compromise (IOCs). This information helps security professionals stay informed about the latest threats and enhances their ability to defend against malware.

![image](https://github.com/dbissell6/DFIR/assets/50979196/8571b5f9-3f2d-4c2f-b42d-f22633cc4b40)

```
https://bazaar.abuse.ch
```

### ThreatFox

ThreatFox is another threat intelligence platform developed by abuse.ch, focusing specifically on collecting and sharing indicators of compromise (IOCs) related to various types of cyber threats, including malware, phishing, and other malicious activities. ThreatFox aggregates IOCs from multiple sources, providing a centralized repository for threat intelligence data. Users can search for and access detailed information about IP addresses, domain names, URLs, and file hashes associated with malicious activities. ThreatFox aims to facilitate the sharing of actionable threat intelligence among the cybersecurity community, helping organizations to better detect and mitigate cyber threats.

![image](https://github.com/dbissell6/DFIR/assets/50979196/a1febc11-1f14-48cd-9fab-ddf5699e059b)

```
https://threatfox.abuse.ch
```

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

### stegseek

Crack
```
https://github.com/RickdeJager/stegseek

sudo dpkg -i stegseek_0.6-1.deb
sudo apt-get install -f # install dependencies
```

![image](https://github.com/dbissell6/DFIR/assets/50979196/4b39dbbb-2aab-455f-9000-27e15f76dbbb)


### Zsteg 
A steganography tool that can be used to detect hidden information within images. It can be used to identify the type of steganography being used, extract hidden data, and even recover lost data. Zsteg is particularly useful for identifying the presence of LSB (Least Significant Bit) steganography, which is a common technique used to hide data within images.
![Pasted image 20230221160217](https://user-images.githubusercontent.com/50979196/221450531-b66bfdf7-3c9d-4cd0-9a20-54fe3d14c5ef.png)

### Stegsolve 
A Java-based tool that can be used to analyze and manipulate images for steganography purposes. It provides a range of filters and visual aids to help users identify hidden information within images. Stegsolve is particularly useful for identifying the location and type of steganography being used within an image.
![Pasted image 20230221202426](https://user-images.githubusercontent.com/50979196/221450558-7c93ed5f-4a8a-450a-84d1-8d77d9b77458.png)

### Aperisolve

Aperi'Solve is an online platform which performs layer analysis on image. The platform also uses zsteg, steghide, outguess, exiftool, binwalk, foremost and strings for deeper steganography analysis. The platform supports the following images format: .png, .jpg, .gif, .bmp, .jpeg, .jfif, .jpe, .tiff...


`https://www.aperisolve.com`

### LSB in MP3s

<details>

<summary>Python script</summary>

```
import sys

def extract_message_from_mp3(file_path):
    bits = []
    with open(file_path, 'rb') as f:
        byte = f.read(1)
        while byte:
            byte_value = byte[0]
            lsb = byte_value & 1  # Extract the least significant bit
            bits.append(str(lsb))
            # Check if we have enough bits to form a byte
            if len(bits) % 8 == 0:
                byte_bits = bits[-8:]
                byte_str = ''.join(byte_bits)
                byte_value = int(byte_str, 2)
                if byte_value == 0:  # Null terminator
                    break
            byte = f.read(1)

    # Now convert all bits into bytes
    message_bytes = []
    for i in range(0, len(bits), 8):
        byte_bits = bits[i:i+8]
        if len(byte_bits) < 8:
            break
        byte_str = ''.join(byte_bits)
        byte_value = int(byte_str, 2)
        message_bytes.append(byte_value)

    message = bytes(message_bytes)
    try:
        decoded_message = message.decode('utf-8', errors='replace')
        print("Hidden message:")
        print(decoded_message)
    except UnicodeDecodeError:
        print("Failed to decode message")

if __name__ == "__main__":
    if len(sys.argv) != 2:
        print("Usage: python extract_message_from_mp3.py <mp3_file>")
    else:
        extract_message_from_mp3(sys.argv[1])
```
</details>

### Audio Morse code

`https://morsecode.world/international/decoder/audio-decoder-adaptive.html`

![image](https://github.com/user-attachments/assets/7871530a-a835-4dff-8cdb-70c013e7ec05)


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
-   Virtual Machine Memory file (.vmem)

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

### Processes

A process is an instance of a running program, containing the program's code, data, heap, stack, and other resources. Each process operates in its own isolated memory space, ensuring stability and security.

**Key Components of a Process:**

- Executable Code (Text Segment): Contains the machine instructions for the process.

- Data Segment: Holds global and static variables.

- Heap: Used for dynamic memory allocation.

- Stack: Contains local variables, function parameters, and return addresses.

- Memory-Mapped Files: Regions of memory mapped to files, including shared libraries (DLLs).

- Process Control Block (PCB): Contains metadata about the process, such as the process ID (PID), state, memory management information, and open files.


#### Process Memory

| **Structure/Region** | **Location**                   | **Purpose**                             | **Key Data**                                                   |
|----------------------|--------------------------------|-----------------------------------------|----------------------------------------------------------------|
| **PEB**              | User-mode address space        | Information about the process           | Image base address, startup parameters, heap pointers, modules |
| **TEB**              | User-mode address space, per thread | Information specific to each thread    | Stack base and limit, thread ID, environment pointer           |
| **Executable Code**  | User-mode address space        | Executable instructions of the process  | Machine code, read-only                                        |
| **Data Segment**     | User-mode address space        | Holds global and static variables       | Initialized data, uninitialized data (BSS)                     |
| **Heap**             | User-mode address space        | Dynamic memory allocation               | Allocated variables, runtime data, user inputs                 |
| **Stack**            | User-mode address space, per thread | Manages function calls and variables  | Function call parameters, return addresses, local variables    |
| **Memory-Mapped Files** | User-mode address space     | Maps files or libraries into memory     | DLLs, memory-mapped data files                                 |
| **Loaded Modules**   | User-mode address space        | Lists modules loaded into the process   | Base addresses, names and paths of DLLs, entry points          |
| **Handles and Resources** | Kernel and user-mode     | Manages system resources                | File handles, registry handles, network connections            |
| **PCB**              | Kernel-mode address space      | Contains process state information      | PID, process state, scheduling information                     |


**Process Environment Block (PEB):** An extremely useful structure that tells you where to find several of the other items in this list, including the DLLs, heaps, and environment variables.

Using windbg to view process dump of peb.

![image](https://github.com/dbissell6/DFIR/assets/50979196/f0098402-efd6-443d-842b-09fcb7319b56)

Also holds environment variables.

![image](https://github.com/dbissell6/DFIR/assets/50979196/f276e21b-ea68-4107-bad1-674dfc386026)

**Process heaps:** Where you can find a majority of the dynamic input that the process receives. For example, variable-length text that you type into e-mail or documents is often placed on the heap, as is data sent or received over network sockets.
Heap

![image](https://github.com/dbissell6/DFIR/assets/50979196/1674676e-ee3e-4fe7-89fe-57014bf60f79)



### Threads

A thread is the smallest unit of execution within a process. Each process has at least one thread (the main thread), and many processes create additional threads to perform tasks concurrently.

**Key Components of a Thread:**

- Thread Context: The state of the thread, including CPU registers and the program counter.

- Thread Stack: Contains local variables, function parameters, and control information.

- Thread Control Block (TCB): Contains metadata about the thread, such as the thread ID (TID), state, and pointers to the stack and thread-specific data.

### Handles

A **handle** is a reference to an open instance of a kernel object, such as a file, registry key, mutex, process, or thread.

Could show persistence if process has handle of registry files.


## Strings
It is possible to run strings on a memory dump to extract info

![image](https://github.com/dbissell6/DFIR/assets/50979196/271f4112-a784-43e3-80cf-1338872e62ad)

Grep for commands
`
strings PhysicalMemory.raw | grep -E "(cmd|powershell|bash)[^\s]+"
`

## memprocfs


![image](https://github.com/user-attachments/assets/de9224a5-c659-4d1d-a9ed-e32654d599dd)

![image](https://github.com/user-attachments/assets/26fd0157-6c44-4985-bfa0-d51e6272b0c3)


## Volatility 3

Volatility 3 is an Open-Source memory forensics tool that allows analysts to extract and analyze information from a computer's volatile memory, such as running processes, network connections, and open files. To do this, Volatility needs to know the kernel version and build of the operating system from which the memory was obtained. This is because the kernel is responsible for managing the memory and processes, and its data structures and behavior can change between different versions or builds of the operating system.

`
https://volatility3.readthedocs.io/en/latest/index.html
`

Download

```https://github.com/volatilityfoundation/volatility3```

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

```https://learn.microsoft.com/en-us/windows/win32/memory/memory-pools```

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

## Volatility 2

I hate that I have to do this, but here we are. Long story short, vol2 has some features that vol3 doesnt. There are rumors of differences 
between python2 and python3 leading to the plugins we get for each version of vol.  Some plugins of interest are cmdscan(better than cmdline), clipboard, consoles.

Download

```
git clone https://github.com/volatilityfoundation/volatility.git
cd volatility
sudo python2 setup.py install
```

First need to run info on the image. 

![image](https://github.com/dbissell6/DFIR/assets/50979196/2e5bb1c5-8aaa-43af-a01d-8413cda3c29d)

Vol3 will automatically give us a profile, in vol2 we have to explicitly state it, we can see suggested profiles loaded above.

![image](https://github.com/dbissell6/DFIR/assets/50979196/2bb7fc8d-0a8a-4c86-8537-28242a66e8e1)


For all available plugins
```
python2 vol.py -f /home/kali/Desktop/recollection.bin --profile=Win7SP1x64 --help
```

## What did they see?

Dumping process can sometimes allow us to see what was on the screen, or that processes display.

Take for instance this process mspaint pid 5116.

![image](https://github.com/dbissell6/DFIR/assets/50979196/063f0517-75c3-4bed-ad4d-27377eafe4b6)

Dump the memmap

![image](https://github.com/dbissell6/DFIR/assets/50979196/93041d19-ffcd-411c-9eab-edf3f4c82c5a)

Change the extention to .data. Open file with GIMP 

![image](https://github.com/dbissell6/DFIR/assets/50979196/44bf3026-6db2-4075-8765-b2cb6f7b6cde)

![image](https://github.com/dbissell6/DFIR/assets/50979196/33159526-fe16-4a50-8a8f-5e43ae0610e0)


Guess the width,height,offset

![image](https://github.com/dbissell6/DFIR/assets/50979196/bbdf5fc6-7816-470b-968d-9c4b012fe48e)


## yara

![image](https://github.com/dbissell6/DFIR/assets/50979196/9c18bff0-267c-4830-85c4-bf7e3286b76f)


Rules at
```
https://github.com/Yara-Rules/rules
```

![image](https://github.com/dbissell6/DFIR/assets/50979196/0db2eace-aa03-4359-abc3-c87d9d8ca107)


## Bulk_Extractor

Bulk_Extractor is a tool that will scan various types of evidence including pcaps, files, disk images but I probably get the most use from memory dumps. Computationally + Time intensive, must create an output dir.  

![image](https://github.com/dbissell6/DFIR/assets/50979196/2c7253c5-4be2-4ec2-ac98-d3fcaf248930)

![image](https://github.com/dbissell6/DFIR/assets/50979196/1edae5d4-d897-40da-83f9-6f3d0ef67d45)

Useful to find, emails, browser search terms, logs... 

![image](https://github.com/dbissell6/DFIR/assets/50979196/8ac97e75-26f9-4a41-a658-2b6ea059d5ba)

## LSASS (.DMP)

![image](https://github.com/dbissell6/DFIR/assets/50979196/bddd5970-296d-4ba7-8484-e108a8b08153)

binwalk can also be used to identify, should see Certificate or private key in DER format, mcrypt encrypt,...

LSASS (Local Security Authority Subsystem Service) is a crucial Windows system process responsible for enforcing the security policy on the system. It handles user logins, password changes, and creates access tokens. It's essentially the gatekeeper for the security realm within Windows, dealing with authentication and locally stored credentials.

LSASS Dump

An LSASS dump involves capturing the memory contents of the LSASS process. This memory can contain active credentials, such as plaintext passwords, hashed passwords, and Kerberos tickets, depending on the system's configuration and the user's state. Malware and attackers often target LSASS to extract credentials that can be used for lateral movement within a network. (can do the dumping with task manager or procdump)

![Pasted image 20240323140017](https://github.com/dbissell6/DFIR/assets/50979196/02c874cd-6bce-4a79-af05-cafc756eea68)

## hiberfil.sys

magic bytes + Ascii

![image](https://github.com/dbissell6/DFIR/assets/50979196/8f7516a5-759c-48e9-856c-70cbbd357bdf)


https://github.com/hackthebox/cyber-apocalypse-2024/tree/main/forensics/%5BInsane%5D%20Oblique%20Final


## Crash dumps

Sometimes the memory of a single program is dumped.

<img width="1431" height="98" alt="image" src="https://github.com/user-attachments/assets/a678aedc-5f4d-4056-9732-0d188b91cfc7" />

Sometimes can use volatility like on a regular memory dump. Other times must use WinDbg.


```
.symfix
.reload /f
!analyze -v
.bugcheck
kv
```


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

## EWF on Linux

The Expert Witness Format (EWF), commonly represented by .E01 files, is a forensic disk image format used to store digital evidence. It was developed by Guidance Software for EnCase and is widely used in digital forensics. EWF supports compression, encryption, and metadata storage, such as case details and hash values for verification.

![image](https://github.com/user-attachments/assets/6a55d681-7d5d-48ff-912a-e20415cbed2a)

![image](https://github.com/user-attachments/assets/2bb7c67c-237c-4d7a-9406-6dac528140c7)

![image](https://github.com/user-attachments/assets/185a30a3-c41d-4833-87d2-745b8cbb671b)

![image](https://github.com/user-attachments/assets/c0fa7686-ebbf-4055-bf7a-c2b7c5a9866c)

Can also mount with

![image](https://github.com/user-attachments/assets/68e84cba-abd3-431d-ae90-7d7f3b953501)

## WIM

WIM (Windows Imaging Format)

A WIM file is a disk image format created by Microsoft to store multiple disk images in a single file. It’s commonly used for Windows installation files or backups. The .wim file typically contains the contents of an entire disk or a partition and is used in Windows deployment scenarios.

`wimlib-imagex info budget.wim`

![image](https://github.com/user-attachments/assets/2c933b22-ed0b-4dbc-9d8f-4ba433879991)

To extract

`wimlib-imagex extract budget.wim 1 --dest-dir=./extracted`

![image](https://github.com/user-attachments/assets/b103efb7-974d-4347-9990-3ac58d824f8c)

To mount

`wimlib-imagex mount budget.wim 1 wim_mount`

![image](https://github.com/user-attachments/assets/1f727bd9-cea1-4c15-8f4d-e46735c10123)


Can also use 7z to extract everything

![image](https://github.com/user-attachments/assets/5cbc7f1c-83dc-45ce-9dd0-627120332b10)

Useful because will extract and show if files had alternate data streams.

![image](https://github.com/user-attachments/assets/e6b32940-1c77-44c0-916b-1df3878ee852)


## Example fdisk+Mount Windows vhdx

![Pasted image 20230318133623](https://user-images.githubusercontent.com/50979196/229358946-72832415-38f2-4742-ba91-c91332de8981.png)
![Pasted image 20230318133610](https://user-images.githubusercontent.com/50979196/229358957-684da311-e205-419d-a3e2-29e26e6bfc4e.png)
![Pasted image 20230318133553](https://user-images.githubusercontent.com/50979196/229358976-02560289-3226-4f8f-af22-11dc6e120430.png)
![Pasted image 20230318133535](https://user-images.githubusercontent.com/50979196/229359015-4c1dd124-6f5e-4709-9168-335a1d6ea0cf.png)
![Pasted image 20230318133520](https://user-images.githubusercontent.com/50979196/229359026-40b14558-22fb-4a98-9e80-7e52a39465e3.png)

## guestmount windows vhdx

![image](https://github.com/user-attachments/assets/2a1e9f29-39ee-4fd0-8dc3-64318f124e12)

![image](https://github.com/user-attachments/assets/8a79232c-0b86-49c4-8273-e9eeb71230ca)

![image](https://github.com/user-attachments/assets/0eae362b-6fa1-497d-b24b-bbab362de5bd)

![image](https://github.com/user-attachments/assets/bd3ada11-27a2-455c-8072-41f962a55043)

## Encrypted drive

.vhdx encrypted with bitlocker.

![image](https://github.com/user-attachments/assets/2b162ba9-68f7-47c9-a0c9-97b2bbe02a18)

bit-locker2john

![image](https://github.com/user-attachments/assets/6906fc9e-5f1b-4aa2-b7d7-43ccdf6a4c95)

![image](https://github.com/user-attachments/assets/46e8eddf-b19a-4bc6-8e90-edefdbf4c24e)


crack hash with hashcat

`.\hashcat.exe -m 22100 -a 0 C:\Users\Daniel\Desktop\bitlocker.hash C:\Users\Daniel\Desktop\SecLists-2024.3\SecLists-2024.3\Passwords\Leaked-Databases\rockyou-75.txt`

![image](https://github.com/user-attachments/assets/8d49c17e-90bb-4eae-9e26-73a9e9e693d7)


Open on windows

![image](https://github.com/user-attachments/assets/71207ce3-fac9-43dd-8a2e-ce8234f11975)

![image](https://github.com/user-attachments/assets/7c6acc7e-bfcf-4c7c-a384-50d927147dcd)

![image](https://github.com/user-attachments/assets/f4c3da31-6a65-4390-87ed-56d32ebd6491)


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

On linux can also use `7z x` to extract /parse the streams

![image](https://github.com/user-attachments/assets/bb1e2e3f-cfc5-4303-a4ed-316e87c917d0)


## Android Forensics

```
https://github.com/RealityNet/Android-Forensics-References
```

### ALEAPP

Android Logs Events And Protobuf Parser.

![image](https://github.com/dbissell6/DFIR/assets/50979196/98c7185c-a4fe-4c1f-b115-908b02807caa)


![image](https://github.com/dbissell6/DFIR/assets/50979196/c4f20dd6-7bc6-4cfa-9b47-7e47c01e0a50)


```
https://github.com/abrignoni/ALEAPP
```



## PowerForensics

PowerForensics is a powerful and flexible tool for digital forensic investigations on Windows systems. Can use on mounted systems or live systems. PowerForensics offers a suite of cmdlets that can extract a variety of forensic artifacts, such as the Master File Table (MFT), Volume Boot Record (VBR), Event Logs, and more.

Docs - https://powerforensics.readthedocs.io/en/latest/#cmdlets

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

## Photorec

Photorec is part of the TestDisk suite and is designed to recover lost files, including documents, archives, and multimedia files, from hard disks, CD-ROMs, and lost pictures (hence the name) from digital camera memory.

On linux - Select the disk -> file system type -> where to save

![image](https://github.com/dbissell6/DFIR/assets/50979196/037aae50-8f97-4d71-b785-30852c960d54)

![image](https://github.com/dbissell6/DFIR/assets/50979196/e79a68d4-78b2-4968-8203-8c6b7747f781)

![image](https://github.com/dbissell6/DFIR/assets/50979196/3f603828-4d70-44c5-be70-7b24e7ad5da6)


## foremost

Foremost is a tool that is used for file recovery and reconstruction. It can be used to recover deleted files, carve out files from disk images, and extract files from various file formats. Foremost is particularly useful for recovering files from damaged or corrupted disks, or for recovering files that have been deleted or lost.

Foremost uses a technique called file carving to recover files from disk images or other sources. It scans through the input data looking for specific file headers and footers, and then extracts the data between them. Foremost supports a wide range of file types, including images, audio files, videos, documents, and archives.

Foremost can be used in a variety of scenarios, such as when trying to recover deleted files, investigating a cybercrime incident, or recovering data from a damaged disk. It is a powerful tool for file recovery and reconstruction and can help in restoring valuable data that may have been lost or deleted.

![image](https://github.com/user-attachments/assets/695eab74-6ffe-4d78-948b-8918f9d4d2d7)


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

KAPE extracts artifacts from a system.

Comes with Targets and Modules.


`./kape.exe --tsource C: --target !SANS_Triage,ProgrameData --tdest D:\KAPEOUT`


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

## Catscale (Dump linux artifacts)

Linux CatScale is a bash script that uses live off the land tools to collect extensive data from Linux based hosts. The data aims to help DFIR professionals triage and scope incidents. An Elk Stack instance also is configured to consume the output and assist the analysis process. Note that the script will likely alter artefacts on endpoints. Care should be taken when using the script. This is not meant to take forensically sound disk images of the remote endpoints.

What does it collect?
`https://labs.f-secure.com/tools/cat-scale-linux-incident-response-collection/`

source code
`https://github.com/WithSecureLabs/LinuxCatScale/tree/master`

![image](https://github.com/dbissell6/DFIR/assets/50979196/cff36786-077e-4d47-bfdb-fcec9d32be40)



### Misc

Use `exec-perm-files.txt` to cross reference hashes on VT.

`full-timeline.csv` Can be very useful.

![image](https://github.com/dbissell6/DFIR/assets/50979196/cac3c933-bea5-4a2e-b9fe-c78a50ba9af8)

![image](https://github.com/dbissell6/DFIR/assets/50979196/11226904-f3f8-4f11-a358-2daa18e07516)


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

Get system info

![image](https://github.com/dbissell6/DFIR/assets/50979196/b657d44e-0964-4bd8-b317-f98ac2daf8c1)


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

Powershell commands

```
https://learn.microsoft.com/en-us/powershell/module/microsoft.powershell.management/?view=powershell-7.4&viewFallbackFrom=powershell-7
```

or 

```
Get-Command
```


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

## AWS (Amazon Web Services)

Amazon Web Services (AWS) is a comprehensive and widely adopted cloud platform that offers over 200 fully featured services from data centers globally. AWS provides services including computing power, storage options, networking, and databases, delivered as scalable cloud computing.

### Forensic Investigation Tips on AWS
- **AWS CloudTrail**: Logs all API calls, crucial for a trail of user and resource activity.
- **CloudTrail-Digest**: Automatically created to help you ensure the integrity of your CloudTrail logs.
- **AWS Config**: Provides inventory and configuration changes of AWS resources.
- **Access and Analyze Logs**: Use services like Amazon S3 and AWS Lambda for log storage and analysis.

### Artifacts of Interest
- **EC2 Artifacts**: Instances, snapshots, AMIs, security groups.
- **S3 Buckets**: Data, access logs, bucket policies.
- **IAM Logs**: User, group, role, and policy details.
- **VPC Flow Logs**: IP traffic information.
- **RDS Snapshots**: Database backups.

### Useful Commands & Tools
- **AWS CLI**: Command line tool for AWS services. Example: Listing S3 buckets with `aws s3 ls`.
- **EC2 Snapshots**: Create snapshots with `aws ec2 create-snapshot`.
- **DB Snapshots**: Create snapshots with `CreateDBSnapshot`.
- **CloudTrail Logs**: Access with AWS Console or `aws cloudtrail lookup-events`.
- **S3 Data Access**: Download files using `aws s3 cp s3://bucket-name/path/to/object localpath`.
- **whoami**:  Returns details about the IAM user `GetCallerIdentity`.
- **Describe**: Returns metadata about running EC2 instances `DescribeInstances`.

- 

- 

#### Using AWS CLI

![292685469-210d6bb7-a98f-4b08-b389-8b43b3847955](https://github.com/dbissell6/DFIR/assets/50979196/2cdd7876-075f-49a4-8cfe-9587e91a638f)


#### Useful search queries for json logs


Select all logs with a username

```
find . -name "*.json" -exec jq -r '.Records[] | select(.userIdentity.userName == "forela-ec2-automation")' {} +
```

![image](https://github.com/dbissell6/DFIR/assets/50979196/dbebc661-cd57-4523-88c9-fabbcbf63951)


Select event names from user `forela-ec2-automation` sorted by time

![image](https://github.com/dbissell6/DFIR/assets/50979196/d566a21f-d9dd-463d-a2e2-567fe83dac5f)


![Pasted image 20231130123929](https://github.com/dbissell6/DFIR/assets/50979196/f931dcb4-0e65-4b04-af48-5a78e1456c96)


#### Getting Cloudtrails on splunk

`https://help.splunk.com/en/splunk-enterprise/get-started/install-and-upgrade/9.2/install-splunk-enterprise-in-virtual-and-containerized-environments/deploy-and-run-splunk-enterprise-inside-a-docker-container`
`https://www.youtube.com/watch?v=TG6zBnSgf5M`

![image](https://github.com/user-attachments/assets/dca02f6e-f464-4c00-ad32-b1bf1965888b)



Copy data into docker container

![image](https://github.com/dbissell6/DFIR/assets/50979196/fc046ba5-15c1-4655-9f5a-c6e4b6d0115b)

OR ... consolatate into one .json file

```
find . -type f -name '*.json' -exec cat {} + | jq -c '.Records[]' > combined_cloudtrail_logs.json

#Get the files in the docker

sudo docker cp combined_cloudtrail_logs.json splunk:/tmp/combined_cloudtrail_logs.json

```

Download aws add-on 

Apps -> Find More Apps -> 

![image](https://github.com/dbissell6/DFIR/assets/50979196/b7456dc5-4925-4717-9027-5054d0ef1597)

Upload data -> upload -> Set source type aws:cloudtrail  

![image](https://github.com/dbissell6/DFIR/assets/50979196/a8f4c38f-d93a-4fd5-9a38-5c52ae82ef98)


## Azure

Azure is Microsoft’s cloud computing platform offering services for computing, analytics, storage, and networking. Users can develop new applications or run existing ones in the public cloud.

### Forensic Investigation Tips on Azure
- **Azure Activity Log**: Provides data on operations performed on resources.
- **Azure Monitor**: Collects and analyzes performance metrics and operational data.
- **Azure AD Investigation**: Logs sign-in activity and user account changes.
- **Azure Blob Storage**: Securely stores forensic data in the cloud.
- **Network Security Group Flow Logs**: Provides IP traffic data for network forensic investigations.
- **Disk Snapshots**: Analyze the state of VMs at specific points in time.
- **Azure Backup**: Protects data from accidental deletion or corruption.

### Artifacts of Interest
- **VM Artifacts**: Disks, snapshots, networking info.
- **Azure AD Logs**: Sign-in, audit logs, user/group info.
- **Storage Account Logs**: Blob, Queue, Table, File storage logs.
- **NSG Flow Logs**: Network traffic logs.
- **SQL Database Auditing**: Database auditing logs.

### Useful Commands & Tools
- **Azure CLI**: Azure's command line interface. Example: `az vm list` for listing VMs.
- **Disk Snapshots**: Create VM disk snapshots with `az snapshot create`.
- **NSG Flow Logs**: Manage with `az network watcher flow-log`.
- **Blob Storage Access**: Download blobs with `az storage blob download`.

### Azure Data Explorer

Azure Data Explorer (ADX) uses a query language known as Kusto Query Language (KQL).Not really a SIEM, but a resource to filter data. 


show tables

![image](https://github.com/dbissell6/DFIR/assets/50979196/cf656fd2-acc8-4aa4-9045-fa0d12d240e7)

Show columns for the tables.

![image](https://github.com/dbissell6/DFIR/assets/50979196/d1f6e081-a7fa-4254-b539-da77326a1608)


Getting a sample of data

![image](https://github.com/dbissell6/DFIR/assets/50979196/7262ae39-7674-4710-93f6-beaf6ab90fb7)


https://learn.microsoft.com/en-us/azure/data-explorer/kusto/query/kql-quick-reference

summarize 

![image](https://github.com/dbissell6/DFIR/assets/50979196/c296d631-9a22-41db-b431-87821a63b0b2)




# SIEMS

SIEM, which stands for Security Information and Event Management, is a comprehensive solution designed to provide real-time analysis of security alerts and events generated by various hardware and software entities within an IT infrastructure. Using a SIEM feels like a mix of viewing logs and see

## Splunk

Splunk is a powerful platform for searching, monitoring, and analyzing machine-generated data, which can come from web applications, sensors, devices, or any data that an organization's IT infrastructure generates. 



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


### Download install splunk docker

```
https://docs.splunk.com/Documentation/Splunk/9.2.1/Installation/DeployandrunSplunkEnterpriseinsideDockercontainers
```

If docker isn't Downloaded
```
sudo apt install docker.io
```

![image](https://github.com/dbissell6/DFIR/assets/50979196/94c5d3ae-6510-4e04-860e-2f8c7131dfa4)

![image](https://github.com/dbissell6/DFIR/assets/50979196/9cba2f07-ab1c-44c3-854b-033d30d68d16)

![image](https://github.com/dbissell6/DFIR/assets/50979196/7b423a34-fabc-44cc-b1be-37d594aed05a)

![image](https://github.com/dbissell6/DFIR/assets/50979196/4cfd485e-9b44-4ea5-b408-14be390b3e46)

## ELK

The ELK Stack, consisting of Elasticsearch, Logstash, and Kibana, is a robust suite of tools that collectively enable organizations to efficiently search, analyze, and visualize vast volumes of data in real-time.


### Discover

### controling columns

On left side can search for a feature and add it as a column by clickling blue + . 

![image](https://github.com/dbissell6/DFIR/assets/50979196/1267c1b4-aee8-44a3-9c36-159fda7eefc6)


#### Useful queries examples





# OSINT

Open Source Intelligence (OSINT) involves gathering evidence from sources like websites, social media, domain records, and other internet-based platforms.



https://dfir.blog/unfurl/

https://osintframework.com/

## Google

Google is your friend.

![image](https://github.com/dbissell6/DFIR/assets/50979196/4d1fd8aa-9b69-41fe-8585-8dbe554cab69)


### email unique identifier

## Discord

This needs to be moved

![image](https://github.com/dbissell6/DFIR/assets/50979196/42da7d72-e5bc-4440-86ca-8fb53bc55559)


![image](https://github.com/dbissell6/DFIR/assets/50979196/65475bb4-4241-4620-aa97-58bf3a6d71f3)




## Geoguesser

https://docs.google.com/spreadsheets/d/1UNvkoY-LaktF75nU_cP7-wVRAEvH3fSqVZet20HqxXA/edit?gid=0#gid=0

### Reading Japanese Utility pole plates

https://docs.google.com/document/d/17WL3aQeSvfnqymGKtV-DbSJDd7KTYCqEbWgtEsJNKFs/edit

### geohints

https://geohints.com/

### Reverse image

https://www.google.com/?authuser=0

Search by image

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





