# Included Challenges
information= {Difficulty:10,.jpg:1}  
Matryoshka doll= {Difficulty:30,.jpg:1}  
tunn3l_v1s10n= {Difficulty:40,.bmp:1,hexedit:1}  
Glory_of_the Garden= {Difficulty:50,.jpg:1}  
Wireshark_doo_doo= {Difficulty:50,pcap:1, Wireshark:1,ROT13:1}   
MacroHard WeakEdge= {Difficulty:60,.pptm:1}  
Trivial_Flag_Transfer= {Difficulty:90,pcap:1,Wireshark:1,Protocol-FTP:1,ROT13:1,.bmp:1,steghide:1}  
Wireshark_two_two= {Difficulty:100,pcap:1, Wireshark:1,Protocol-DNS:1,Base64:1}  
advanced_potion_making= {Difficulty:100,.png:1,stegsolve:1}  
File_types= {Difficulty:100,.pdf:1,.ar:1,decompress:1}  
Enhance!= {Difficulty:100,.svg:1,strings:1}  
Lookey_here= {Difficulty:100,.txt:1,grep:1}  
Packets_Primer= {Difficulty:100,pcap:1,Wireshark:1}  
Redaction_gone_wrong= {Difficulty:100,.pdf:1,}
Sleuthkit_intro= {Difficulty:100,.img:1,fdisk:1}  
Disk,disk,sleuth!= {Difficulty:110,.img:1,fdisk:1,mount:1}   really jsut a grep
Milkslap= {Difficulty:120,.png:1,zsteg:1}  
Disk,disk,sleuth!2= {Difficulty:130,.img:1,fdisk:1,mount:1}  
So_Meta= {Difficulty:150,.png:1,exiftool:1}  
shark_on_wire_1= {Difficulty:150,pcap:1, Wireshark:1,Stream:1}  
extensions= {Difficulty:150,.txt:1,.png:1}  
What_Lies_Within= {Difficulty:150,.png:1,zsteg:1}  
Pitter,Patter,Platters= {Difficulty:200,dd.sda1:1,fdisk:1,mount:1,xxd:1}  
WPA-ing_Out= {Difficulty:200,pcap:1, Wireshark:1,aircrack-ng:1}  
Sleuthkit_Apprentice= {Difficulty:200,.img:1,fdisk:1,mount:1}  
WhitePages= {Difficulty:250,.txt:1,hexedit:1,SMPythonScript:1}  
like1000= {Difficulty:250,.tar:1,SMPythonScript:1}  
c0rrupt= {Difficulty:250,.png:1,hexedit:1}  
shark_on_wire_2= {Difficulty:300,pcap:1, Wireshark:1,SMPythonScript:1}  
very_very_hidden= {Difficulty:300,pcap:1, Wireshark:1,.png:1,SMPythonScript:1,XOR:1}  
Eavesdrop= {Difficulty:300,pcap:1, Wireshark:1,openssl:1,des3:1}  
Operation_Oni= {Difficulty:300,.img:1,fdisk:1,mount:1,id_rsa:1,ssh:1}  
St3g0= {Difficulty:300,.png:1,zsteg:1}  
webnet0= {Difficulty:350,pcap:1, Wireshark:1,RSA_Key:1,Protocol-TLS:1}  
OP_Orchid= {Difficulty:400,.img:1,fdisk:1,mount:1,openssl:1,Encrypted_AES:1}  
SideChannel= {Difficulty:400,elf:1,SMPythonScript:1}  
webnet1= {Difficulty:450,pcap:1, Wireshark:1,RSA_Key:1,Protocol-TLS:1,.jpg:1,exiftool:1}  

scrambled-bytes= {Difficulty:200,}#NF
m00nwalk= {Difficulty:250,}#NF
Surfing the Waves= {Difficulty:250,}#NF
m00nwalk2= {Difficulty:300,}#NF
Torrent_Analyze= {Difficulty:400,}#NF
B1g_Mac= {Difficulty:500,}#NF

# information

# Matryoshka doll
 
# Glory_of_the Garden

# tunn3l_v1s1on
 ![Pasted image 20230213131653](https://user-images.githubusercontent.com/50979196/223185060-c0376adf-52f4-4bd0-a490-433ef5b3cf5e.png)
![Pasted image 20230213131322](https://user-images.githubusercontent.com/50979196/223185943-68f0724a-8610-4881-9bca-2c8e77a46957.png)

```
hexedit tunn3l_v1s10n.bmp
```
![Pasted image 20230213131714](https://user-images.githubusercontent.com/50979196/223185163-d3ca6a91-a808-4025-909a-f900f30a0122.png)
Then view image

# Wireshark doo dooo
given pcap


start by looking at the http traffic 
![Pasted image 20221229162224](https://user-images.githubusercontent.com/50979196/223185547-39a199f8-b32b-4ac6-9f95-cd2bded955b2.png)

Take to cyberchef and run ROT13 on in

# MacroHard WeakEdge

# TFTP
![[Pasted image 20230113161433.png]]
![[Pasted image 20221229174855.png]]
![[Pasted image 20230113161053.png]]
![[Pasted image 20230113161036.png]]

![[Pasted image 20230113161249.png]]
steghide
![[Pasted image 20230113161316.png]]
use password DUEDILIGENCE
![[Pasted image 20230113161350.png]]
# very very hidden

![[Pasted image 20230113142415.png]]
using a python script on the evil_duck.png image
![[Pasted image 20230113153109.png]]

xor encoded
![[Pasted image 20230113153402.png]]

# Wireshark two two
![[Pasted image 20221229162904.png]]
![[Pasted image 20221229163440.png]]
first /flag is a bunch of decoys
notice that 18.217.1.57 has a wierd connection with DNS
![[Pasted image 20221229165224.png]]
![[Pasted image 20221229165310.png]]
![[Pasted image 20221229165144.png]]

# advanced potion making

start with a corrupted png, used a normal png to compare the header and footer to fix. the loaded into stegsolve red 0

  
# Enhance

given svg, image was a black ciurlce, like a record, ran strings on file
![[Pasted image 20230222092406.png]]

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

![[Pasted image 20230224124736.png]]

# Lookey Here

# Packets Primer

![[Pasted image 20221229170104.png]]
![[Pasted image 20221229170138.png]]

# Redaction gone wrong
pdf file, some text redacted properly others not, can just hightlight to reveal flag
![[Pasted image 20230222091926.png]]

# Slueth Intro
given img
fdisk to determine sectors length

# Slueth1
given .img

![[Pasted image 20230224133208.png]]
![[Pasted image 20230224133350.png]]



# MilkSlap

![[Pasted image 20230226193015.png]]
![[Pasted image 20230226193100.png]]

zstep errored out for me, other walk throughs it worked for them, online tools take too long to upload, must revist.

# Slueth2
given .img
![[Pasted image 20230224131740.png]]
![[Pasted image 20230224131801.png]]
![[Pasted image 20230224131717.png]]

# So Meta

# shark on the wire 1
	![[Pasted image 20221229172520.png]]

# extentions
.png saved as .txt, change to .png then view

# What lies within
![[Pasted image 20230221160303.png]]
zsteg


# Pitter Patter
![[Pasted image 20230222093051.png]]

![[Pasted image 20230222162114.png]]


![[Pasted image 20230113170105.png]]
can also use exiftool on vulture.jpeg to get flag 
![[Pasted image 20230113170137.png]]




# Scrambled
given pcap and python code

python code shows udp ports are randomized and bytes are scrambled
![[Pasted image 20230214124724.png]]
![[Pasted image 20230214124302.png]]
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

![[Pasted image 20230222130428.png]]

![[Pasted image 20230222130804.png]]

![[Pasted image 20230222130718.png]]
```
sudo mount -o loop,ro,offset=184549376 disk.flag.img test 
```
![[Pasted image 20230222130320.png]]


# Whitepages

blank txt file, open with hexedit see a pattern, use python to convert byes to binary then binary back to ascii
2
they are being sent as single len=1 data
![[Pasted image 20230213173514.png]]
![[Pasted image 20230213173523.png]]
```
tshark -r capture.pcap -T fields -e udp.srcport -Y "udp.port == 22" > output
```
create python script to handle output. The key was to see the src port would always start with 5 and be 4 nums long, the last 3 nums were ascii characters
![[Pasted image 20230213175847.png]]


# Like1000
this is a 1000 deep tar file. Created python script to automate it.


# eavesdrop
![[Pasted image 20230222083155.png]]
```
openssl des3 -d -salt -in file.des3 -out file.txt -k supersecretpassword123
```

![[Pasted image 20230222083932.png]]
File -> export packet bytes

![[Pasted image 20230222084016.png]]
![[Pasted image 20230222084027.png]]

# ST3g0
![[Pasted image 20230222090751.png]]



# webnet0
given pcap and rsa key
from G, but TLS instead of SSL
![[Pasted image 20230113164502.png]]
![[Pasted image 20230113164429.png]]
![[Pasted image 20230113164557.png]]

# OP Orchid

mount disk img

calculate offset
```
sudo mount -o loop,ro,offset=210763776 disk.flag.img /mnt/

```

![[Pasted image 20230213195911.png]]
```
openssl aes256 -d -salt -in flag.txt.enc -out flag -k unbreakablepassword1234567
```



# SideChannel
Timing based attack. Can use python script to interact with pin checker binary to determine password from diffrerence in timing of responses


# webnet1
rsa key is the same
![[Pasted image 20230113165754.png]]


