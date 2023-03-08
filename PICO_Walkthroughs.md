# Included Challenges
information = {Difficulty:10, .jpg:1}  
Matryoshka doll = {Difficulty:30, .jpg:1}  
tunn3l_v1s10n = {Difficulty:40, .bmp:1, hexedit:1}  
Glory_of_the Garden = {Difficulty:50, .jpg:1}  
Wireshark_doo_doo = {Difficulty:50, pcap:1, Wireshark:1, ROT13:1}   
MacroHard WeakEdge = {Difficulty:60, .pptm:1}  
Trivial_Flag_Transfer = {Difficulty:90, pcap:1, Wireshark:1, Protocol-FTP:1, ROT13:1, .bmp:1, steghide:1}  
Wireshark_two_two = {Difficulty:100, pcap:1, Wireshark:1, Protocol-DNS:1, Base64:1}  
advanced_potion_making = {Difficulty:100, .png:1, stegsolve:1}  
File_types = {Difficulty:100, .pdf:1, .ar:1, decompress:1}  
Enhance!= {Difficulty:100, .svg:1, strings:1}  
Lookey_here= {Difficulty:100, .txt:1, grep:1}  
Packets_Primer= {Difficulty:100, pcap:1, Wireshark:1}  
Redaction_gone_wrong= {Difficulty:100, .pdf:1,}  
Sleuthkit_intro= {Difficulty:100, .img:1, fdisk:1}  
Disk,disk,sleuth! = {Difficulty:110, .img:1, fdisk:1, mount:1}   really jsut a grep  
Milkslap = {Difficulty:120, .png:1, zsteg:1}  
Disk,disk,sleuth!2 = {Difficulty:130, .img:1, fdisk:1, mount:1}  
So_Meta = {Difficulty:150, .png:1, exiftool:1}  
shark_on_wire_1 = {Difficulty:150, pcap:1, Wireshark:1, Stream:1}  
extensions = {Difficulty:150, .txt:1, .png:1}  
What_Lies_Within = {Difficulty:150,.png:1, zsteg:1}  
Pitter,Patter,Platters = {Difficulty:200, dd.sda1:1, fdisk:1, mount:1, xxd:1}  
WPA-ing_Out = {Difficulty:200,pcap:1, Wireshark:1, aircrack-ng:1}  
Sleuthkit_Apprentice = {Difficulty:200,.img:1, fdisk:1, mount:1}  
WhitePages = {Difficulty:250,.txt:1, hexedit:1, SMPythonScript:1}  
like1000 = {Difficulty:250, .tar:1, SMPythonScript:1}  
c0rrupt = {Difficulty:250, .png:1, hexedit:1}  
shark_on_wire_ = {Difficulty:300,pcap:1, Wireshark:1, SMPythonScript:1}  
very_very_hidden = {Difficulty:300, pcap:1, Wireshark:1,.png:1, SMPythonScript:1,XOR:1}  
Eavesdrop = {Difficulty:300,pcap:1, Wireshark:1, openssl:1, des3:1}  
Operation_Oni = {Difficulty:300, .img:1, fdisk:1, mount:1, id_rsa:1, ssh:1}  
St3g0 = {Difficulty:300, .png:1, zsteg:1}  
webnet0 = {Difficulty:350, pcap:1, Wireshark:1, RSA_Key:1, Protocol-TLS:1}  
OP_Orchid = {Difficulty:400, .img:1, fdisk:1, mount:1, openssl:1, Encrypted_AES:1}  
SideChannel = {Difficulty:400, elf:1, SMPythonScript:1}  
Torrent_Analyze = {Difficulty:400, pcap:1, Wireshark:1, Torrent:1, Hash:1}  
webnet1 = {Difficulty:450,pcap:1, Wireshark:1, RSA_Key:1, Protocol-TLS:1, .jpg:1, exiftool:1}  

scrambled-bytes = {Difficulty:200,}#NF
m00nwalk = {Difficulty:250,}#NF
Surfing the Waves = {Difficulty:250,}#NF
m00nwalk2 = {Difficulty:300,}#NF
B1g_Mac = {Difficulty:500,}#NF

# information
Given .jpg of a cat  
Can run strings on it  
![image](https://user-images.githubusercontent.com/50979196/223497620-0cc541bb-02f2-4844-9329-0582bc30514a.png)  
Base64 resource to yield flag

# Matryoshka doll
Given .jpg  

```
binwalk -e -M dolls.jpg
```
This will recursivly search the file+output for additional files
# tunn3l_v1s1on
Given .bmp  
![Pasted image 20230213131653](https://user-images.githubusercontent.com/50979196/223185060-c0376adf-52f4-4bd0-a490-433ef5b3cf5e.png)
![Pasted image 20230213131322](https://user-images.githubusercontent.com/50979196/223185943-68f0724a-8610-4881-9bca-2c8e77a46957.png)

```
hexedit tunn3l_v1s10n.bmp
```
![Pasted image 20230213131714](https://user-images.githubusercontent.com/50979196/223185163-d3ca6a91-a808-4025-909a-f900f30a0122.png)
Then view image

# Glory_of_the Garden
Given .jpg

# Wireshark doo dooo
Given pcap  


start by looking at the http traffic 
![Pasted image 20221229162224](https://user-images.githubusercontent.com/50979196/223185547-39a199f8-b32b-4ac6-9f95-cd2bded955b2.png)

Take to cyberchef and run ROT13 on it

# MacroHard WeakEdge
Given .pptm  
![image](https://user-images.githubusercontent.com/50979196/223500570-7b710320-9e25-4156-976b-02636d254993.png)

![image](https://user-images.githubusercontent.com/50979196/223500653-a959d878-c570-46e0-b115-54feec994614.png)

Remove spaces and abse64 decode for flag


# TFTP
Given Pcap  
![Pasted image 20230113161433](https://user-images.githubusercontent.com/50979196/223304014-e147809e-1b3f-44e4-99b1-eb2a1677bf74.png)
![Pasted image 20221229174855](https://user-images.githubusercontent.com/50979196/223304100-a9b4db6a-3d15-4750-95c0-fa0a6dce5520.png)
![Pasted image 20230113161053](https://user-images.githubusercontent.com/50979196/223304154-504cce6e-ca93-488d-bff7-20cfb52825b0.png)


![Pasted image 20230113161036](https://user-images.githubusercontent.com/50979196/223304189-c8e151ca-6a00-4b73-84d7-0cbd169c7bf6.png)


![Pasted image 20230113161249](https://user-images.githubusercontent.com/50979196/223304225-d52cd2f5-0799-45b3-bc65-0b7be8183bce.png)  

steghide  
![Pasted image 20230113161316](https://user-images.githubusercontent.com/50979196/223304379-50b9f942-52c8-43e1-9e62-8436f1b63a7e.png)  
use password DUEDILIGENCE  



# Wireshark two two
![Pasted image 20221229162904](https://user-images.githubusercontent.com/50979196/223304664-563efc32-ab6e-4931-a223-50d4f91a1e82.png)

![Pasted image 20221229163440](https://user-images.githubusercontent.com/50979196/223304719-9254fe30-b24b-42bc-bbd3-67c3638e5eb7.png)

first /flag is a bunch of decoys  
notice that 18.217.1.57 has a wierd connection with DNS  
![Pasted image 20221229165224](https://user-images.githubusercontent.com/50979196/223304789-2f415b32-b2b0-4b83-b43a-9a11f8fbbab6.png)

![Pasted image 20221229165310](https://user-images.githubusercontent.com/50979196/223304828-d68daf1e-83ec-4309-a549-9aa99ebbc230.png)

These segments ran through a base 64 decoder will yeild the flag.  
# advanced potion making

start with a corrupted png, used a normal png to compare the header and footer to fix. the loaded into stegsolve red 0

  
# Enhance

given svg, image was a black cirlce, like a music record, ran strings on file  
![Pasted image 20230222092406](https://user-images.githubusercontent.com/50979196/223305379-30afd591-6ce6-4c74-ac79-f1703e0735bb.png)


# File types
Given pdf that is really a shell. Shell executes and creates a flag. Flag is a compressed file, of a compressed file. Finally Hex of flag


```
binwalk -e flag
binwalk -e 64
lzip -d -k flag
lz4 -d flag.out flag2.out
lzma -d -k flag2.lzma
lzop -d -k flag2.lzop -o flag3
lzip -d -k flag3
xz -d -k flag4.xz

```
Decompress each output will yiled a hex string

# Lookey Here
Given large .txt file  

# Packets Primer

Given pcap  
![Pasted image 20221229170104](https://user-images.githubusercontent.com/50979196/223475514-df5d0bc4-5db9-40bc-bbb7-6d9b1bf07e5e.png)



# Redaction gone wrong
given pdf file, some text redacted properly others not, can just open document and hightlight to reveal flag


# Slueth Intro
given img
fdisk to determine sectors length

# Slueth1
given .img  

![image](https://user-images.githubusercontent.com/50979196/223307422-2c354d63-3864-43bc-b93c-d47f84af973a.png)

The way you are supposed to do it is mount the disk, then grep



# MilkSlap

![[Pasted image 20230226193015.png]]
![[Pasted image 20230226193100.png]]

zsteg errored out for me, other walk throughs it worked for them, online tools take too long to upload, must revist.

# Slueth2
given .img

![Pasted image 20230224131740](https://user-images.githubusercontent.com/50979196/223309891-6596661e-36a3-4e1f-bedc-5abc5b4e265f.png)
![Pasted image 20230224131801](https://user-images.githubusercontent.com/50979196/223309962-a9c8ca7d-9fac-4a40-807c-cc20661f12f0.png)

![image](https://user-images.githubusercontent.com/50979196/223310065-ff40f79e-7c5c-4f90-b4b1-18cfe953f2af.png)


# So Meta
Given .png

# shark on the wire 1
Given pcap, check streams

# extentions
.png saved as .txt, change to .png then view

# What lies within
Given .png  
zsteg  
![image](https://user-images.githubusercontent.com/50979196/223476206-d2bef411-10ab-49f4-989d-a055d2ee9b0a.png)




# Pitter Patter
Given .dd.sda1  
![Pasted image 20230222093051](https://user-images.githubusercontent.com/50979196/223476393-c9adf0e6-087b-49b6-8c0d-7398119934bb.png)

![Pasted image 20230222162114](https://user-images.githubusercontent.com/50979196/223476429-c3c7c915-c4c5-4f0e-af52-40bb9a7dc6dc.png)



![[Pasted image 20230113170105.png]]
can also use exiftool on vulture.jpeg to get flag 
![[Pasted image 20230113170137.png]]




# Scrambled
given pcap and python code  

python code shows udp ports are randomized and bytes are scrambled  
![Pasted image 20230214124724](https://user-images.githubusercontent.com/50979196/223480564-07ac6525-a911-4c62-9117-eff607277933.png)

![Pasted image 20230214124302](https://user-images.githubusercontent.com/50979196/223480663-6edb1d8e-b88d-420b-a94a-11b6ed8eef4c.png)

this should isolate the scrabmbled message
```
!(_ws.expert) && ip.src == 172.17.0.2 && ip.src!=172.17.0.3
```

```
tshark -r capture.pcapng -T fields -e data -Y "!(_ws.expert) && ip.src == 172.17.0.2 && ip.src!=172.17.0.3" > output 
```



# WPAing Out
given pcap of wifi password exchange
```
aircrack-ng -w rockyou capture.pcap
```
# Sluethkit_apperentice
given .img

![Pasted image 20230222130428](https://user-images.githubusercontent.com/50979196/223188743-78453def-e9ef-4963-921a-de391e603fba.png)


![Pasted image 20230222130804](https://user-images.githubusercontent.com/50979196/223188759-e850df34-99f5-477d-9d80-85917acdf2aa.png)


![Pasted image 20230222130718](https://user-images.githubusercontent.com/50979196/223188784-f0f21426-6459-4dab-9de7-b494e6bccc91.png)

```
sudo mount -o loop,ro,offset=184549376 disk.flag.img test 
```
Can find flag in root 


# Whitepages

blank txt file, open with hexedit see a pattern, use python to convert bytes to binary then binary back to ascii
2  
they are being sent as single len=1 data  
![[Pasted image 20230213173514.png]]
![[Pasted image 20230213173523.png]]
```
tshark -r capture.pcap -T fields -e udp.srcport -Y "udp.port == 22" > output
```
create python script to handle output. The key was to see the src port would always start with 5 and be 4 nums long, the last 3 nums were ascii characters
![[Pasted image 20230213175847.png]]

# C0rrupt

https://github.com/Dvd848/CTFs/blob/master/2019_picoCTF/c0rrupt.md

# Like1000
this is a 1000 deep tar file. Created python script to automate it.

# very very hidden

![Pasted image 20230113142415](https://user-images.githubusercontent.com/50979196/223189539-7edf5a54-3e64-4b6a-8771-0033d17be1de.png)

using a python script on the evil_duck.png image
![Pasted image 20230113153109](https://user-images.githubusercontent.com/50979196/223189589-a9b312d3-d0c4-4541-b6fc-07dad50b4494.png)

xor encoded

![image](https://user-images.githubusercontent.com/50979196/223191633-d279ae26-19a5-44e1-a637-f0c596bdff7c.png)


# eavesdrop
![Pasted image 20230222083155](https://user-images.githubusercontent.com/50979196/223190317-359173ff-d8a7-4d15-964c-ac9fcaf3a8f6.png)

```
openssl des3 -d -salt -in file.des3 -out file.txt -k supersecretpassword123
```

![Pasted image 20230222083932](https://user-images.githubusercontent.com/50979196/223190372-3ad0d5e4-66c1-4b1d-b511-892ad4b1c593.png)
File -> export packet bytes


![Pasted image 20230222084016](https://user-images.githubusercontent.com/50979196/223190440-93de414f-b48b-401f-bc2b-65994f6759f8.png)

Produces flag

# ST3g0
![image](https://user-images.githubusercontent.com/50979196/223190683-2d90b990-8f26-4a00-8309-08439d31cc6b.png)


# webnet0
given pcap and rsa key
from G, but TLS instead of SSL
![Pasted image 20230113164502](https://user-images.githubusercontent.com/50979196/223189032-f842bfa3-001e-4025-869d-38f2e4f84ccf.png)

![Pasted image 20230113164429](https://user-images.githubusercontent.com/50979196/223189070-68a5d33c-6fd3-491b-bbe9-0fa991ea22df.png)

Can now find flag in stream

# OP Orchid
given .img

calculate offset
mount disk img
```
sudo mount -o loop,ro,offset=210763776 disk.flag.img /mnt/

```


![Pasted image 20230213195911](https://user-images.githubusercontent.com/50979196/223191046-d7ae37b1-82f3-45b2-8e10-8e580d9c10b5.png)

```
openssl aes256 -d -salt -in flag.txt.enc -out flag -k unbreakablepassword1234567
```



# SideChannel
Timing based attack. Can use python script to interact with pin checker binary to determine password from diffrerence in timing of responses

# Torrent_Analyze
Given pcap  
Tasked to look for file name, not file contents  

In a BitTorrent network, files are broken down into small chunks, which are distributed among the peers participating in the network. Each chunk is identified by a unique hash value, which is calculated using a cryptographic hashing algorithm.

The info_hash is a specific type of hash value that is used to uniquely identify a specific torrent file in the BitTorrent network. This hash value is calculated based on the metadata associated with the file, including its name, size, and the hashes of its constituent chunks.

When a client wants to download a file from the BitTorrent network, it sends a request to the tracker server, which responds with a list of peers that are currently seeding the file. The client then contacts these peers and requests the chunks of the file that it needs, using the info_hash value to specify which file it is requesting.

In the context of a CTF challenge involving a pcap of torrent traffic, the info_hash value can be a valuable piece of information for forensic analysts. By examining the traffic and identifying the info_hash values associated with specific files, analysts can gain insights into the types of files that were being downloaded or shared on the network. This can be useful for identifying potential intellectual property violations, tracking the spread of malware, or investigating other types of cybercrime.

Once you find the info_hash, you can search for the hash in google. it will return the file name

# webnet1
rsa key is the same
![Pasted image 20230113165754](https://user-images.githubusercontent.com/50979196/223191318-90aeafef-ef08-49b5-9588-9b7dd096ea61.png)

can also use exiftool on vulture.jpeg to get flag 
