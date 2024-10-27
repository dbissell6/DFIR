![Pasted image 20241027052912](https://github.com/user-attachments/assets/f61d7154-6a30-419f-a33a-f4c6cdc18658)

# Corrupted Hard Drive

![Pasted image 20241027040000](https://github.com/user-attachments/assets/4ba8f544-b222-4718-920c-6d48a635792e)

Given .vhd

![image](https://github.com/user-attachments/assets/c4d0a45b-2263-4978-9e3e-389900273677)


![image](https://github.com/user-attachments/assets/6de05fb3-0c63-4c1b-aa6e-abfc6ed65f77)

## Tampered OEM ID

The OEM ID in the boot sector is located at offset 0x03 and is 8 bytes long. The standard OEM ID for NTFS is 'NTFS ' (with 'S' as 0x53). Here, the 'S' (0x53) has been tampered with and replaced by 0x00.

```
dd if=Deleted.vhd bs=1 skip=$((0x10000)) count=64 2>/dev/null | hexdump -C

00000000  eb 52 90 4e 54 46 00 20  20 20 20 00 02 08 00 00  |.R.NTF.    .....|
00000010  00 00 00 00 00 f8 00 00  3f 00 ff 00 80 00 00 00  |........?.......|
00000020  00 00 00 00 80 00 80 00  ff 07 03 00 00 00 00 00  |................|
00000030  55 20 00 00 00 00 00 00  02 00 00 00 00 00 00 00  |U ..............|
00000040
```

Fixed byte

![image](https://github.com/user-attachments/assets/2c7b3aa5-ff26-4375-9202-a829671f4694)


To mount

```
# Map the partitions within the VHD file
sudo kpartx -av fixed.vhd

# Create a mount point
sudo mkdir -p /mnt/vhd

# Mount the partition (replace loop0p1 with the correct partition if needed)
sudo mount -o ro /dev/mapper/loop0p1 /mnt/vhd

# Access the mounted filesystem
ls /mnt/vhd
```


`sudo fls -r -o 0 /dev/mapper/loop0p1`

![Pasted image 20241025215710](https://github.com/user-attachments/assets/b622bc82-7b34-441b-ab3b-c1c91fcd494c)

Can recover MFT USNJrnl to answer. Use zone identifier to find time of download of .pdf

```
Welcome to the FORENSIC challenge!
Answer all the questions correctly to get the flag!
[1]. What is the starting address of the LBA address? Format (0xXXXXX)
0x10000
[+] Correct!
[2]. What is the tampered OEM ID? Format (0xXXXXXXXXXXXXXXXX)
0x4E54460020202020
[+] Correct!
[3]. After Fixing the disk, my friend downloaded a file from Google, what is the exact time when he clicked to download that file? Eg: 2024-01-01 01:01:01
2024-10-22 21:51:13
[+] Correct!
[4]. How much time did that file take to for download (in seconds)?? Format  (XXX)
126
[+] Correct!
[5]. The first directory he moved this file to?
best
[+] Correct!
[6]. Last directory the suspicious move the file to?
MustRead
[+] Correct!
[7]. The time he of the deletion?? Eg: 2024-01-01 01:01:01
 2024-10-22 22:20:28
[+] Correct!
[+] Congrats! You have successfully completed the test.
Here's your reward: ISITDTU{https://www.youtube.com/watch?v=yqp61_Wqm-A}
```



![Pasted image 20241025230448](https://github.com/user-attachments/assets/fc7b278a-5476-4d0a-a030-c0f0e77df96a)




# Unexpected

Given eml that contained a .zip and a password. Zip contained pcapng, process dump and sslkeylog.



![Pasted image 20241027050304](https://github.com/user-attachments/assets/fb8749af-7ff1-4618-b12a-e9831cf35dc2)


## Part 1

First part requires us to extract the exe and open it up in dotPeek.


![Pasted image 20241026005204](https://github.com/user-attachments/assets/03cb719b-7988-4bd8-9f77-7f78223a3eec)


![Pasted image 20241026005303](https://github.com/user-attachments/assets/4cacbe46-f03c-4ef5-8665-c2c86a0b96f3)

## Part 2 

![Pasted image 20241027050441](https://github.com/user-attachments/assets/ef79a89a-f59f-4b5f-8cf5-c2da2c8bf3f2)

`https://www.youtube.com/playlist?list=PL8rua6xfypCAiqEdvoKs006WPvBMQF9-G`

Find a playlist of QR codes

![Pasted image 20241027052444](https://github.com/user-attachments/assets/482f50ef-639f-40f6-8783-d0833bf021f9)


![Pasted image 20241027052502](https://github.com/user-attachments/assets/efb495a0-3b5f-4fd3-a3c1-911029e5c4c5)


Remembering the Key and iv from the exe and part 1.
key = `c4530e2eeb9ea61d57910fe9ec86f47e25359840bf430c3ce78e4c363c5d24ef`
iv = `6c44f45102fdd739cbc6b572ed8698db`


![Pasted image 20241027052307](https://github.com/user-attachments/assets/afc85c2e-33e6-4577-bee3-377ed4f31b8f)

or could use this ps1

![Pasted image 20241027052654](https://github.com/user-attachments/assets/bc2d2cfe-d918-41a3-a9cf-d96ebaea7802)


## Part 3


Finding the key from Bulk Extractor

```
# BANNER FILE NOT PROVIDED (-b option)
# BULK_EXTRACTOR-Version: 2.1.1
# Feature-Recorder: aes_keys
# Filename: MaliciousPID.DMP
# Feature-File-Version: 1.1
2996744 7c 00 a8 28 33 d8 ae 19 b2 d8 e4 22 2d 5e f7 99 AES128
2999296 7c 00 a8 28 33 d8 ae 19 b2 d8 e4 22 2d 5e f7 99 AES128
8192408 c4 53 0e 2e eb 9e a6 1d 57 91 0f e9 ec 86 f4 7e 25 35 98 40 bf 43 0c 3c e7 8e 4c 36 3c 5d 24 ef AES256
*** 8235212 1f 68 7a 50 da 70 e4 74 1e 7d 2b a4 2e 0a 1b 9c d4 56 71 79 d7 8a c6 55 af a3 29 7e 50 7c fb c8 AES256
13923928        0d be 59 14 ab af c9 b8 57 6f 92 9d 9a 5c 83 78 AES128
13926480        0d be 59 14 ab af c9 b8 57 6f 92 9d 9a 5c 83 78 AES128
13930648        28 4d b8 20 75 95 00 89 f1 ac b2 4c 39 81 b9 20 AES128
13933200        28 4d b8 20 75 95 00 89 f1 ac b2 4c 39 81 b9 20 AES128
14167256        22 ac c8 a2 7b f3 0e e5 e2 29 7a 51 9c 8c a7 cb AES128
14169808        22 ac c8 a2 7b f3 0e e5 e2 29 7a 51 9c 8c a7 cb AES128

```

Finding the ciphertext from the pcap dns exfiltration



![Pasted image 20241027051841](https://github.com/user-attachments/assets/236ea4cf-fc70-4c59-8ab4-64b85cf25bc1)

Using these in a python script. The iv is the last 16 bytes, the rest of the data is the ciphertext.

![Pasted image 20241027051932](https://github.com/user-attachments/assets/b0c8c886-f517-4b4d-91cb-c2555fff472e)

![Pasted image 20241026010427](https://github.com/user-attachments/assets/b291e689-c95a-4090-833c-ad13704abe05)



Final Flag

`ISITDTU{3vEry7h!n9_c0uLd_B3_u5ed_4s_c2-chAnNe|~}`

# Swatted 

Given vmdk


![Pasted image 20241026113118](https://github.com/user-attachments/assets/216e4171-7190-461e-9323-5db26a4bd2dd)

![Pasted image 20241026113156](https://github.com/user-attachments/assets/a4c26db6-dc42-4ad6-ad92-a871436f46b8)


![Pasted image 20241026131935](https://github.com/user-attachments/assets/87062d34-6925-4b84-aaad-cb1f86b9b991)


![Pasted image 20241026124057](https://github.com/user-attachments/assets/eac39cc2-b131-476f-9b52-67d34edabb3a)


![Pasted image 20241026140011](https://github.com/user-attachments/assets/e91f0748-704c-427f-bfcf-1187857753cb)

```
    └─$ nc 152.69.210.130 1259

     

    Welcome to ISITDTU CTF 2024 - Forensics Challenge!
    Most of the answers are case-insensitive. If not, it will be mentioned in the question.
    You have to answer 10/10 questions correctly to get the flag. Good Luck!

	
[1]. What is the credential used to login to the machine?
Format: username:password                                                                                                                                    
==> imsadboi:qwerty
CORRECT!
[2]. The criminal used a messaging app to communicate with his partner. What is the name of the app?
Format: AppName                                                                                                                                              
==> wire
CORRECT!
[3]. What is the username of the criminal (The app username)?
Format: username                                                                                                                                             
==> anonymous69420
CORRECT!
[4]. What is his partner's username?
Format: username                                                                                                                                             
==> clowncz123
CORRECT!
[5]. His partner sent him a file. What is the URL used to download the file?
Format: URL                                                                                                                                                  
==> https://file.io/lIPzLAvhF5n4
CORRECT!
[6]. What is the timestamp of the file sent by his partner (UTC)?
Format: YYYY-MM-DD HH:MM:SS                                                                                                                                  
==> 2024-10-24 09:59:12
CORRECT!
[7]. What is the timestamp when the criminal downloaded the file (UTC)?
Format: YYYY-MM-DD HH:MM:SS                                                                                                                                  
==> 2024-10-24 10:01:12
CORRECT!
[8]. His partner accidentally leaked his email. What is the email address?
Format: email@domain.com                                                                                                                                     
==> theclownz723@gmail.com
CORRECT!
[9]. Luckily, we caught the criminal before he could send the sensitive information. How many credentials did he manage to steal?
Format: XX. Example 1: 01. Example 2: 42.                                                                                                                    
==> 23
CORRECT!
[10]. What is the email address and the password of user 'blistery'?
Format: email:password                                                                                                                                       
==> blistery@yahoo.com:HDTSy0C7ZBCj
CORRECT!
Congrats! Here is your flag: ISITDTU{https://www.youtube.com/watch?v=H3d26v9TciI}
 

```
# CPUsage

Given Windows Event Trace Log



![Pasted image 20241027045801](https://github.com/user-attachments/assets/1242ffb4-b3ba-4871-bfb8-95331044f469)


![Pasted image 20241026144340](https://github.com/user-attachments/assets/d19adbb6-4dba-406e-ae82-8ebc35c0124b)


![Pasted image 20241026143929](https://github.com/user-attachments/assets/2af430fd-daf2-4406-98c4-f146332ab2eb)


![Pasted image 20241026144310](https://github.com/user-attachments/assets/9195a367-8ffd-44f9-aad0-be5f0c915c48)

psscan

![Pasted image 20241026144149](https://github.com/user-attachments/assets/68167aac-b64e-416d-ad8f-544a4a4928ae)



![Pasted image 20241026143827](https://github.com/user-attachments/assets/4e4c7aec-5f53-4d8e-a91f-c006ba6c7a7c)



`ISITDTU{dlIhost.exe-C:\Users\m4shl3\AppData\Roaming\DLL\dlIhost.exe-264_45.77.240.51-harharminer`


# Initial

Stupid

Given registry


![Pasted image 20241027045716](https://github.com/user-attachments/assets/21bed4c6-3265-422b-a50f-b7a51974ea51)


![Pasted image 20241027045423](https://github.com/user-attachments/assets/ea32e16e-7f35-4480-af35-1f9ae78e43ff)



```

[HKEY_CURRENT_USER\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\WordWheelQuery] "MRUListEx"=hex:00,00,00,00,ff,ff,ff,ff "0"=hex:4a,00,6b,00,30,00,78,00,30,00,69,00,66,00,57,00,51,00,4b,00,59,00,38,\   00,6c,00,5a,00,65,00,57,00,63,00,39,00,52,00,57,00,51,00,62,00,71,00,34,00,\   4f,00,76,00,4f,00,6b,00,75,00,76,00,54,00,7a,00,6c,00,71,00,6f,00,71,00,38,\   00,50,00,79,00,67,00,79,00,4e,00,6c,00,68,00,67,00,4c,00,37,00,00,00


```

`ISITDTU{N0w_I_kn0w_about_search-ms}`
