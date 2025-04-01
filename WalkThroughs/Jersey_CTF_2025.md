# Jersey CTF 2025

![Pasted image 20250330142437](https://github.com/user-attachments/assets/c6190475-b617-4af8-9265-57d1c5faa6ab)

## evtx

![Pasted image 20250329145248](https://github.com/user-attachments/assets/7fc65f87-c93c-484f-a513-0ba1a152b645)


Given windows event logs evtx. Run Chainsaw

![Pasted image 20250329145053](https://github.com/user-attachments/assets/6a30ece7-75b3-41fa-a45a-a554b7f5f0e6)


![Pasted image 20250329145026](https://github.com/user-attachments/assets/08eb2701-d759-4bb0-8b8c-ecaaaa3fb878)


## The-Veiled-Backtrace


![Pasted image 20250329145327](https://github.com/user-attachments/assets/ff500fd1-f724-4a7a-ae8f-797a9d1eae3c)

Given archive of jpgs

![Pasted image 20250330153838](https://github.com/user-attachments/assets/96bf5523-8c41-4d35-901a-72f45c5d2416)

Notice one hidden file

![image](https://github.com/user-attachments/assets/f4ff6805-f474-4ae7-88e4-f07f5da651a5)

Get ip and port converting from base64 on cyberchef

![image](https://github.com/user-attachments/assets/0d664dcd-3d56-4d48-8169-f2ee238f22aa)


## Frequencies-of-Deception

![Pasted image 20250329145349](https://github.com/user-attachments/assets/5122a077-4dff-4171-84b3-a82a838f4b1c)

Given unknown.wav

Looking for DTMF

![image](https://github.com/user-attachments/assets/7eadfb69-5cac-4605-8ea0-ea09af0a80a7)


![image](https://github.com/user-attachments/assets/b35a5d05-7820-463a-b364-9772c34d406d)


![image](https://github.com/user-attachments/assets/c28905b0-b38b-49af-8647-a7578d80df49)


![image](https://github.com/user-attachments/assets/ee317b3b-b267-463c-8d16-776d2a2a78a0)


## path-finder


![Pasted image 20250329151649](https://github.com/user-attachments/assets/00f24e18-5801-409c-ae6c-1a984c46dd18)

Given some jpgs. Have to extract a base64 encoded strong from each, in the order of the map.

![Pasted image 20250329152546](https://github.com/user-attachments/assets/26fe4239-944a-4e69-b32c-6a80b0a0e48f)

![Pasted image 20250329152846](https://github.com/user-attachments/assets/d533e4fb-a4c7-4465-84e5-dcd51a2450b0)




![Pasted image 20250329153817](https://github.com/user-attachments/assets/8677cf11-c83a-4f6f-886d-ffd6d222f872)




![Pasted image 20250329152835](https://github.com/user-attachments/assets/4720f278-ca48-4c28-8a6e-7b2b839428d8)



![Pasted image 20250329153101](https://github.com/user-attachments/assets/cb1c8e3a-6cda-4291-acf4-3050f72c896c)

![Pasted image 20250329153039](https://github.com/user-attachments/assets/aab0b749-0ecc-4f72-97dc-00681b87ffd6)


Last one we see there is an error in the magic bytes.

![Pasted image 20250329152826](https://github.com/user-attachments/assets/a6ad5009-e184-4b09-af6c-f942a5b40a75)


Example of correcting the bytes based on the bytes of the map jpg.

![Pasted image 20250329153228](https://github.com/user-attachments/assets/440957d4-4a09-4e8a-9f9e-0bbcfe6aa522)

![Pasted image 20250329153255](https://github.com/user-attachments/assets/ea3bdc58-8c2d-4b0b-a113-80b7b1ae9676)

`jctfv{n01r_cr1m3_4mb1guity_isol4ti0n}`

## DoN't See Me?

![Pasted image 20250329151801](https://github.com/user-attachments/assets/607f65f0-6d9a-466d-b983-583f2d8de68d)


![Pasted image 20250329154458](https://github.com/user-attachments/assets/198f6ec9-500c-4a92-bc90-784a47de677e)

Given pcap, python code and windows logs. 

The python code shows there are base64 encoded commands in the dns prefix.

![image](https://github.com/user-attachments/assets/31cc31c3-d3e2-44ca-abc8-147c449df9e0)


Windows logs show the flag.txt file was compressed as a cab.

![image](https://github.com/user-attachments/assets/56b50ee9-26cb-4522-821c-99f48091be2b)


pcap has the actual transfer.

![image](https://github.com/user-attachments/assets/6d0f3c88-9b09-43c0-9e7a-9d74152b9739)


```
tshark -r firewall-packet-capture.pcap  -Y "(ip.dst == 172.16.0.50) && (ip.src == 1.1.1.1) && dns" -T fields -e dns.qry.name 

```


Cyber chef to clean up. Notice magic bytes arnt cab.

![image](https://github.com/user-attachments/assets/1a94bfd9-d965-4933-92ff-c604bc5dc92e)

Replace with proper magic bytes and extract

![image](https://github.com/user-attachments/assets/d6d8cfe6-c518-455a-bac6-8453841a9568)


![image](https://github.com/user-attachments/assets/4d90ed5d-d1e3-4f5e-a698-7f56c8e85e44)

## Ransom-in-the-Shadows


![Pasted image 20250329152120](https://github.com/user-attachments/assets/87e0cc9e-9fea-42ab-9f8e-cfd9c187472c)



## Dollhouse

![Pasted image 20250329161214](https://github.com/user-attachments/assets/af4c2f71-bbab-4104-9823-1694973c6201)


Given memory dump. mem.dmp

![Pasted image 20250329161202](https://github.com/user-attachments/assets/28af100d-6fe9-492f-ac50-a5dd5b58973e)

![Pasted image 20250329161454](https://github.com/user-attachments/assets/f862961a-1489-4e5c-bc36-9da49d6af788)

Running file scan notice these sus files.

```
0x8f05b2c85180  \Users\johndoe\Downloads\EvilUnknown.txt
0x8f05b2c86c10  \Users\johndoe\Downloads\EvilUnknown.txt
```

![Pasted image 20250329173233](https://github.com/user-attachments/assets/a3164da1-40cd-41ba-aadc-ad4d52eb741c)

![image](https://github.com/user-attachments/assets/b1b85ae9-aebd-49b9-9935-5bfad484e5bd)


Wireshark can read them?

![Pasted image 20250330105250](https://github.com/user-attachments/assets/77cd70b6-28ca-4a5c-8cd9-c5c0043b127a)

 Find a sus image upload.

![Pasted image 20250330105235](https://github.com/user-attachments/assets/ebd83bcc-afbc-4cdd-8fb4-1408054176a5)

Run stegseek with rockyou 

![Pasted image 20250330142027](https://github.com/user-attachments/assets/e030cce5-b010-413e-bc50-8d3ad28b079d)

## The Ungraspable Phantom of Life

![Pasted image 20250329180401](https://github.com/user-attachments/assets/c23fe015-7cf6-4858-afe9-32ef1f378fb7)

hub.docker

![Pasted image 20250329180722](https://github.com/user-attachments/assets/d5b6e9bc-0c59-48a5-83f9-9b7f792feb49)


![Pasted image 20250329181634](https://github.com/user-attachments/assets/d2891957-8f29-40b5-9d19-87ee2109e7e2)



![Pasted image 20250329181655](https://github.com/user-attachments/assets/9498719b-eb1a-4ee2-99cf-da9166fbef60)


![Pasted image 20250329181610](https://github.com/user-attachments/assets/59b96a98-1dc3-4e72-8e2e-3dd51b7de450)

![Pasted image 20250329181546](https://github.com/user-attachments/assets/2370adc5-3a87-4604-9f54-9fe273fd2826)

`Flag_PartOne_jctfv{1n_h15`


![Pasted image 20250329190738](https://github.com/user-attachments/assets/8ca1174e-9b8f-46e3-a9c3-434586241d5b)

`FLAG_PART2=_1nfallibl3_wak3}`

`jctfv{1n_h15_1nfallibl3_wak3}`



## linux-live-response 

![image](https://github.com/user-attachments/assets/654767a1-df2d-49ea-9064-53b638c62993)


![image](https://github.com/user-attachments/assets/ccc95f50-2a82-4ed1-bf57-87efcdb28a92)







