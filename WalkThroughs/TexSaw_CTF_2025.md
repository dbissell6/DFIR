# TexSawCTF 2025

![Pasted image 20250411114021](https://github.com/user-attachments/assets/8fc595ca-5872-4d92-a975-51c35e1a7432)




## Hidden beneath the wavs

![Pasted image 20250411130152](https://github.com/user-attachments/assets/88be67bc-fa96-45dc-a644-09b81dd75efc)

Given a password protected zip. John provided a hash but it didnt crack. The challenge lets us know there is a wav file in the zip.
It is using zipcrypto and stored so we can use bkcrack. Only thing that makes this unique is we dont know 12 bytes in a row. We know the first 4, dont know 4, then know 8.

![Pasted image 20250411170536](https://github.com/user-attachments/assets/537a0eff-aa45-40c0-8761-4ac0d400d53b)


bkcrack command

![Pasted image 20250411153815](https://github.com/user-attachments/assets/ff094590-9052-40ce-9430-cf786cf6808c)

unzip with password and run strings on wav file 

![Pasted image 20250411153750](https://github.com/user-attachments/assets/afda9da6-4bc8-410a-bdbe-9c075255ba69)


## Freaky Flower


![Pasted image 20250411144132](https://github.com/user-attachments/assets/e84e66e9-a8fb-4143-8ffa-2b0333cff4f8)

given an image, run strings

![Pasted image 20250411144117](https://github.com/user-attachments/assets/7f97420c-3911-416f-8494-1e1ce3b59c32)


## Deleted Evidence


![Pasted image 20250411130323](https://github.com/user-attachments/assets/6990bd74-356f-492a-baed-1a8c868317b2)

Given a windows memory dump. 

![Pasted image 20250411170855](https://github.com/user-attachments/assets/ab8a3d9e-bfee-4b5e-8689-9b70571c5186)

![Pasted image 20250411171316](https://github.com/user-attachments/assets/d35c049e-7b29-4f63-824a-373e369c6592)


![Pasted image 20250411171700](https://github.com/user-attachments/assets/129ef6b1-56cf-4376-af51-f133a6bc9a5b)

I thought i was going to need to run the generator with the seed? idk.
```
0xe78e758b8a60  \Users\user\Documents\Flags\libcrypto-3-x64.dll
0xe78e757c07c0  \Users\user\Documents\Flags\generator.exe
0xe78e757c0c70  \Users\user\Documents\Flags\generator.exe

```

The part of the seed we actually need is the time, we can search the MFT for this.

```
python3 ~/Tools/volatility3/vol.py -f evidence.mem windows.mftscan.MFTScan | grep -i seed | grep txt
```

```
`seed_89.txt` = **actual data file**, created at `2025-03-26 02:08:23`
```


![Pasted image 20250411221403](https://github.com/user-attachments/assets/3648af6e-64e8-4beb-8d77-c1b9f36788cb)

I got lucky i didnt even notice there were different flags

Append the time to that top flag for the final flag.



## Scrambled Packets


![Pasted image 20250411132727](https://github.com/user-attachments/assets/d120fd69-5f9d-4eff-93a0-3730d2bf3472)

Given pcap. Open in wireshark and notice icmp packets not in proper order. 

```
tshark -r cap.pcap -Y "icmp" -T fields -e icmp.seq -e data.data | \ 
  awk 'length($2) >= 2 { printf "%d %c\n", $1, strtonum("0x" substr($2,1,2)) }' | \
  sort -n

```

Run, order and extract the data from the icmp packets. 

![Pasted image 20250411140508](https://github.com/user-attachments/assets/3f033b3b-1d9e-4456-ab0d-6e80ef1a2506)


## String Symphony

![Pasted image 20250411162647](https://github.com/user-attachments/assets/73cb0ea1-2177-498e-9079-b0c797306a57)



![Pasted image 20250411162600](https://github.com/user-attachments/assets/ffdef806-bd4e-4786-a1ca-9251f78bea17)





`psx` see some instruments

![Pasted image 20250411174241](https://github.com/user-attachments/assets/777b93a6-d6de-4ca0-bbd5-d1f929122208)

`cmdline`

![Pasted image 20250411174345](https://github.com/user-attachments/assets/16547500-ba7b-4632-a42d-231ea23506d8)


![Pasted image 20250411230625](https://github.com/user-attachments/assets/2c786a86-fbf7-404e-b1ef-79de5d49f05a)

![Pasted image 20250412182333](https://github.com/user-attachments/assets/34563f2f-8418-4236-bc71-1533837470cc)

K so we have 4 string instruments. Extracting the executables show each one has 2 base64 encoded strings. 1) a series of 10 notes. 2) a part of a registry path

![Pasted image 20250412203906](https://github.com/user-attachments/assets/acb117f9-f338-435f-aca8-a866a0933f2d)


![Pasted image 20250412204035](https://github.com/user-attachments/assets/514afba3-4b10-4f67-9f8a-0b5d94e41de8)

in total, the parts in this path `SOFTWARE/ORGANIC/SCORES` led to the keys - values, something like CEGC - I. The idea is the 4 instruments playing together form a series of 10 chords. Each chord can be represented as a roman numerial,
and this is held in the registry.

Looking at an example key in the registry

![Pasted image 20250412204400](https://github.com/user-attachments/assets/f6ecb872-aaf2-46d7-a3f9-c674cd14e0d9)


Extracting the notes from each instrument gives us.

```
Cello.exe
C E F G A F G G G C
viola.exe
C C C B C D G G F E
violin1.exe
E C F D E F E D D C
Violin2.exe
G G A G A A C B B C
```


Linking each on of these in order gives us.

```

G E C C - I
G C C E - I6
A F C F - IV
G D B G - V
A E C A - vi
A F D F - ii6
C E G G - I64
B D G G - V
B D F G - V7
C C E C - I64 

```

`texsaw{I_I6_IV_V_vi_ii6_I64_V_V7_I}`





