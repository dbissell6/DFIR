# The Blue Book


<img width="1402" height="1122" alt="vivi_bluebook" src="https://github.com/user-attachments/assets/49316c34-b4a8-496d-b3c9-11cfa425a6d1" />


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
