# PCAPS (.pcap)

## Intro 

Pcap stands for packet capture and they are the events (or a log of the events) of what happenened on the network or 'over the wire'. For noobs they can be best conceptualized as text message logs.

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
## HID - USB

Some pcaps are not of a network, but keyboard commands captured by a USB. There are a couple challenges(logger, deadly arthropod) that require you to decode these commands. Doing so typically yields the flag.
There are some python scripts that will do the decoding, becareful with cases(A or a).  But they essentially map 
![image](https://user-images.githubusercontent.com/50979196/229363610-efd7635b-9467-4550-8a1d-dd93362bea65.png)

In wireshark

![image](https://user-images.githubusercontent.com/50979196/229363428-52f23471-42d6-4f72-855e-4637ce652bee.png)
Notice very bottom says usage and gives 2 symbols, those are the 2 options depending if shift or caps lock was used.

https://github.com/WangYihang/USB-Mouse-Pcap-Visualizer

## Bluetooth

`https://www.bluetooth.com/wp-content/uploads/Files/Specification/HTML/Core-54/out/en/host/security-manager-specification.html`


Key Protocols & Packets

    SBC 
    L2CAP (Logical Link Control and Adaptation Protocol) – 


`Wireless - Bluetooh Devices`

![image](https://github.com/user-attachments/assets/0901b9fb-5c9d-4609-8df4-0823e5b2de5a)


`Telephony-RTP-RTP Streams`

![image](https://github.com/user-attachments/assets/1bdf6b20-0a98-421f-a2f1-0c34012f58f9)


### LTK

https://github.com/dbissell6/DFIR/blob/main/WalkThroughs/Apoorv_CTF_2025.md#dura-lesc-sed-lesc-from-pwnme

## Drone Footage

Videos can be sent over networks

<img width="1684" height="650" alt="Pasted image 20250921113456" src="https://github.com/user-attachments/assets/df41fcf4-23c4-409b-83ac-76eb1f5a8bc5" />

<img width="961" height="60" alt="Pasted image 20250921113402" src="https://github.com/user-attachments/assets/67b5a990-6529-44d6-8479-7c5781714f3f" />

<img width="470" height="54" alt="Pasted image 20250921113422" src="https://github.com/user-attachments/assets/25acd41e-85f5-4414-b92d-627d8723b28b" />


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

### User Agent

There could be additional letters appended to the useragent

<img width="1304" height="378" alt="Pasted image 20250920214729" src="https://github.com/user-attachments/assets/0c3e6efd-ce9f-4dd6-9418-71a63395ef50" />

<img width="972" height="290" alt="Pasted image 20250920214804" src="https://github.com/user-attachments/assets/de15f709-c747-42eb-afeb-b46e5d6d1578" />

<img width="1378" height="473" alt="Pasted image 20250920214828" src="https://github.com/user-attachments/assets/f0add5b9-3a39-443d-895c-a6e44f097881" />

### NTP

`https://github.com/evallen/ntpescape`


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

