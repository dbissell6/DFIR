# ApoorvCTF

## Phantom Connection

![Pasted image 20250228120956](https://github.com/user-attachments/assets/8232b61c-514a-499b-b7f8-85ce7e887f3a)


Given bcache24.bmc and Cache0000.bin.

![Pasted image 20250228122426](https://github.com/user-attachments/assets/3abaae1c-0a1b-4933-93d7-9163209cb21d)


Run strings notice rdp.

![Pasted image 20250228122451](https://github.com/user-attachments/assets/c12d43b9-c59b-4c55-b2fe-1be08f08535c)


Use bmc-tools

![Pasted image 20250228122357](https://github.com/user-attachments/assets/efa1df16-39ce-450c-a089-f1d7484a5c04)


![Pasted image 20250228122346](https://github.com/user-attachments/assets/8f2f408a-06a5-4dd5-bae6-a5963314c703)


## Ramen lockdown


![Pasted image 20250228121011](https://github.com/user-attachments/assets/d0f3114b-d27a-4e24-b576-3eb393c71f11)

Given password protected zip


![Pasted image 20250228122545](https://github.com/user-attachments/assets/121ae5a7-4be9-44d2-ad08-d5ad0afae817)

![Pasted image 20250228122517](https://github.com/user-attachments/assets/41d9751c-ced8-42ef-aebc-ea57b2ebcb62)


Zipcrypto in with store compression. We can use bkcrack if we know 12 bytes


![Pasted image 20250228123136](https://github.com/user-attachments/assets/50dba5e4-124b-4565-921e-5f958f9eb6e3)

The issue is for pngs the first 16 bytes contain 12 bytes that are static. 8-12 can change

![image](https://github.com/user-attachments/assets/fb6bb088-76a1-4f52-8319-7a6d5efd340e)


Running bkcrack

![Pasted image 20250301131802](https://github.com/user-attachments/assets/38005809-936c-4915-b37e-6a44c2c6c16f)

key - `7cfefd6a 4aedd214 970c7187`

![Pasted image 20250301132310](https://github.com/user-attachments/assets/cd08421d-12bb-4f83-9107-cd4aa3aaf8f1)

![Pasted image 20250301132257](https://github.com/user-attachments/assets/f4993b6b-903b-47b2-84d1-258f5123caac)



## Samurais Code

![Pasted image 20250301091837](https://github.com/user-attachments/assets/15d5c459-cb12-4337-9126-4ff18bd962f8)


![Pasted image 20250301090441](https://github.com/user-attachments/assets/80a313d5-57a1-431d-9694-392d416a79b0)


Run strings on file, notice `BrainFuck`.

![Pasted image 20250301102705](https://github.com/user-attachments/assets/8bed44eb-ed06-4933-9753-bc0b24352ac9)

Find a google drive link. 

![Pasted image 20250301102621](https://github.com/user-attachments/assets/1689d1f8-db2a-4a20-8871-3414f858e657)

`https://drive.google.com/file/d/1JWqdBJzgQhLUI-xLTwLCWwYi2Ydk4W6-/view?usp=sharing`

The jif was distorted, can swap endianness to fix it.

![Pasted image 20250301103251](https://github.com/user-attachments/assets/ce093424-f729-4542-9f39-a654d2add745)



## ArchFTW

![image](https://github.com/user-attachments/assets/73c4b311-81ad-4442-ad09-748f80e37475)

Given pcap and two txt files.

![Pasted image 20250301103513](https://github.com/user-attachments/assets/b5016f04-dcb6-4af0-b648-5195c4d511ef)

Pcap is a keyboard hid.

![Pasted image 20250301191453](https://github.com/user-attachments/assets/a6ba4117-4000-4491-83a8-8ba767b197c1)

The user opened neovim and ran some subsitituion commands.

![Pasted image 20250301232432](https://github.com/user-attachments/assets/83e6d759-eb65-44cf-a8e3-817b48a13ccf)

`awk 'NR % 2 == 0 {print $0, "0"} NR % 2 == 1 {print $0, "1"}' synoonyms.txt > mapping.txt`


![Pasted image 20250301232741](https://github.com/user-attachments/assets/71d6dff1-b322-4256-a2c5-183752aed777)

`awk 'NR==FNR {map[$1]=$2; next} {for(i=1;i<=NF;i++) if ($i in map) printf "%s", map[$i]; print ""}' mapping.txt flag.txt > binary_flag.txt`


![Pasted image 20250301232409](https://github.com/user-attachments/assets/80c3368c-118e-403d-b101-20ca6551d937)


`apoorvctf{ne0v1m_1s_b3tt3r}`


## Whispers of the Forgotten


![Pasted image 20250301091824](https://github.com/user-attachments/assets/43ec92eb-4d89-46c7-a202-607721b5a46d)

Given mem dump.


![Pasted image 20250301093735](https://github.com/user-attachments/assets/c7cdda8f-1138-4107-819a-5f399f79aed1)


![Pasted image 20250301094224](https://github.com/user-attachments/assets/1cc84814-7765-4fce-9542-3b55c935a817)

Running `psscan` notice lots of chrome tabs opened.

find the chrome history file
`python3 ~/Tools/volatility3/vol.py -f memdump.mem windows.dumpfiles --virtaddr '0xd50f11b607a0'`

extract, try to open in sqlitebrowser, buts its corrupt, so run strings.


![Pasted image 20250301105147](https://github.com/user-attachments/assets/2fa007c4-f702-4618-bb0c-231e93ce35e5)

Looking over search history see some sus questions and a pastebin url.

![Pasted image 20250301105129](https://github.com/user-attachments/assets/c849fba7-e4c4-49c8-a6f3-e53d8de5e7b5)

## Broken Tooth

![Pasted image 20250301091918](https://github.com/user-attachments/assets/5162f105-d280-4e7c-aed6-69fa6c6a8417)

Given Bluetooth pcap

![image](https://github.com/user-attachments/assets/ba631cb3-e6d5-4c14-9a79-ddb82088a199)


`Wireless- Bluetooth Devies`

![Pasted image 20250301093113](https://github.com/user-attachments/assets/a039d811-169b-4681-9067-9d66a8d3b367)

`Telephony-TRP-RTPStreams`

![Pasted image 20250301212430](https://github.com/user-attachments/assets/30941905-48be-463e-9db3-92c7af1a28c2)

Song is some billie eyelash. 

## Dura Lesc Sed Lesc (From PwnMe)

![Pasted image 20250228125940](https://github.com/user-attachments/assets/07f13694-af46-47fe-894d-399134e6fa02)

Given Bluetooth pcap.

See raspberrypi source.

![image](https://github.com/user-attachments/assets/2851ef9e-7c81-4cd8-876c-0fb437a7f04e)

Currently encrypted

![image](https://github.com/user-attachments/assets/f4a15085-c04d-4ec5-ab03-616e7c01f135)


Bluetooth Documentation

`https://www.bluetooth.com/wp-content/uploads/Files/Specification/HTML/Core-54/out/en/host/security-manager-specification.html`

We need the LTK. To create it we need 3 sets of info and a private key.

1) X/Y public key coords

2) Random pairings

3) mac addresses


Below we can see most of what we need

![Pasted image 20250228200246](https://github.com/user-attachments/assets/d07b7f0a-924e-4829-8518-83ac774d85f5)

X/Y public key coords

![image](https://github.com/user-attachments/assets/d0249676-3385-43bd-85b6-5ce72b850785)


Random pairings

![image](https://github.com/user-attachments/assets/94c71f72-791e-4531-be55-38dae4558a21)

![image](https://github.com/user-attachments/assets/dbfcaa9c-44dd-49ca-a79c-dd11d0a8631f)

mac addresses

![Pasted image 20250228151154](https://github.com/user-attachments/assets/6c84960d-2fc9-460a-9af8-c77085a5be45)

So we have everything but the private key. However, becasue we see debug key we know it is well known private key. Find the private key here.


![image](https://github.com/user-attachments/assets/4882b871-bd29-448b-ab10-4804f9de06f9)

`https://community.onsemi.com/s/article/KB-How-to-use-Bluetooth-LE-security-manager-in-debug-mode`

Notice the x, y is the same from what we have.

![image](https://github.com/user-attachments/assets/d147afa5-45ea-40a5-b4df-b3c12651bb92)


Can now use python script to get the LTK and use crackle to decrypt the pcap

![image](https://github.com/user-attachments/assets/f4026d79-14f6-4ff6-9645-238d77c0a102)


Final view of previously encrypted traffic.

![image](https://github.com/user-attachments/assets/e5a7b21a-9d02-4d46-a4fc-b059092d12db)


## Holy Rice


![Pasted image 20250301233622](https://github.com/user-attachments/assets/84defe72-3a1b-4a44-b84a-9ecc68a0ec84)


Given dynamically linked elf

![image](https://github.com/user-attachments/assets/81c536f2-5e0e-4fa0-a70a-3ac84ed9a8de)

Running ltrace notice there are 3 pretty simple looking transformations. 1) string is changed 2) `!` is added 3) string is reversed.

![Pasted image 20250301213037](https://github.com/user-attachments/assets/631101f5-2d22-4d73-8778-58d815e95906)

Trying it with 2 more strings notice that the transformations are static and more symbols are added ever 3rd character.


![Pasted image 20250301213129](https://github.com/user-attachments/assets/22e89737-b162-4307-a3b7-c16f13423f99)

Here i enter every symbol into the binary to get its transformation

![Pasted image 20250301223924](https://github.com/user-attachments/assets/ec2ec4b1-2027-44fd-bf03-486816efdc1d)

So to get the flag, I need to reverse it, remove the added symbols then apply the transformations

![image](https://github.com/user-attachments/assets/1b68175a-bbcf-49bc-8240-22403ee2ab33)

5 become {, 6 is }

![Pasted image 20250301223859](https://github.com/user-attachments/assets/c91c2fdf-56b4-418c-b64f-f5e56f18b753)
