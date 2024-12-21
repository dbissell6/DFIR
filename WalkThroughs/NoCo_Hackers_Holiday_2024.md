# NoCo Hackers Holiday 2024



![Pasted image 20241215164209](https://github.com/user-attachments/assets/89d3c287-d88b-46bb-8da7-0fe2d61de606)


Most of the downloadable content was found in this.

![image](https://github.com/user-attachments/assets/383d0899-8fd9-4959-854b-a32aa0e96abd)


![image](https://github.com/user-attachments/assets/52988264-8a77-4ca1-8f4b-b23ba38b4034)



After solving `Inode I missed something` the player has access to a private key that allows them to ssh onto a jumpbox and
find some hidden infrastructure challenges.

Once getting on the host i started to enumerate and found other hosts that ended up being the rest of the challenges. 

![Pasted image 20241215132749](https://github.com/user-attachments/assets/e6e37191-d522-4245-975c-f71c10bd8770)


# Steganography

## It's literally right here

Given no downloadable and the challenge name, figure it's hidden on the web page.

![Pasted image 20241215101638](https://github.com/user-attachments/assets/5747343d-add8-4ade-b00d-7cccbf80e849)

Right Click -> Inspect

use find to search for flag

![Pasted image 20241215102228](https://github.com/user-attachments/assets/667e23fe-76c1-48f6-9e02-3677d550f012)


## Look at this Photograph

![Pasted image 20241215101703](https://github.com/user-attachments/assets/6875ab4c-786f-44f4-af52-a917070b5e08)

![Pasted image 20241215101753](https://github.com/user-attachments/assets/14472018-00a9-41d0-a0c1-c7a9d69da345)

Take a quick look at the image.

![Pasted image 20241215101958](https://github.com/user-attachments/assets/9ab79ed1-57ec-494a-bbbb-8edd219ecb85)

Found it running strings.

![Pasted image 20241215101908](https://github.com/user-attachments/assets/c0edcb31-8c57-42a5-952b-a3536b8c494c)

## Linkedin Park


![Pasted image 20241215122601](https://github.com/user-attachments/assets/b4b27570-669b-4348-bec5-de4e33955421)

Run `file` and see it's a jpg as advertised. 

![Pasted image 20241215122920](https://github.com/user-attachments/assets/cfa424ea-b1d7-4baa-9428-d9437b11ada8)


![Pasted image 20241215122546](https://github.com/user-attachments/assets/ed975447-31cb-4e47-a0ad-763aa3d7a362)

Run `stegoveritas`

![Pasted image 20241215122853](https://github.com/user-attachments/assets/e74c4281-fa33-47c2-a5cd-06557d295d82)

Looking through the output see some QR codes

![Pasted image 20241215122821](https://github.com/user-attachments/assets/ba83af00-d9bf-4bb7-9abd-2acf31bfdcd3)

Take the QR Code to get scanned.

![Pasted image 20241215122757](https://github.com/user-attachments/assets/f2da84de-9138-443a-9a0f-3ddd1b4d58ae)


# Cloud - Attack

## whoami


![Pasted image 20241215133855](https://github.com/user-attachments/assets/5dac85ba-d2e9-43ea-b616-cfbf3e386d65)



![Pasted image 20241215134125](https://github.com/user-attachments/assets/3758b43d-c265-469e-b8ef-cc0a17d33280)


## I Just want to belong


![Pasted image 20241215134342](https://github.com/user-attachments/assets/6c38442a-77ad-44ed-9d2d-f1bc15445f8d)

![Pasted image 20241215134402](https://github.com/user-attachments/assets/fb6f44e3-3587-4f84-a7ed-9e67b57b6021)

## Group Policy


![Pasted image 20241215134451](https://github.com/user-attachments/assets/eae970e1-9f32-4d7f-bbdd-80db18ec3d55)

![Pasted image 20241215134821](https://github.com/user-attachments/assets/0ffdf786-5ae5-444e-9040-e84ea58de6a7)


## S3 Actions


![Pasted image 20241215134907](https://github.com/user-attachments/assets/f849b086-dd0b-4859-960a-bd2bbf8d6ea7)

![Pasted image 20241215135229](https://github.com/user-attachments/assets/647f64b3-958c-4029-92d8-a09cccddf442)

![Pasted image 20241215135334](https://github.com/user-attachments/assets/54af038a-0556-4cb9-9d5a-6898cbbf8647)

## I'm a little pail today!

![Pasted image 20241215135744](https://github.com/user-attachments/assets/dbf4f704-f6de-4f2e-9872-54712aaa2192)


![Pasted image 20241215135828](https://github.com/user-attachments/assets/ffb063bd-b405-4967-b843-fdd02b8c06b3)


## Signal in the Noise


![Pasted image 20241215135903](https://github.com/user-attachments/assets/cdb0258b-2752-4600-8ec3-98666ec6cd04)

![Pasted image 20241215141149](https://github.com/user-attachments/assets/6b9c7787-74f2-4378-9507-033594e0746e)

![Pasted image 20241215141246](https://github.com/user-attachments/assets/3a54b278-5b0e-45aa-8b3c-250748be456f)

![Pasted image 20241215141620](https://github.com/user-attachments/assets/dc8ec902-9594-416d-a380-67dd8e00a52c)

## whoamthis

![Pasted image 20241215141653](https://github.com/user-attachments/assets/5232b7c8-a771-4178-83c4-83411b14fe65)

![Pasted image 20241215141933](https://github.com/user-attachments/assets/faf3233e-1767-4a19-aca3-35a99c6f68ff)


# Cracking

## Call me maybe?

![Pasted image 20241215101211](https://github.com/user-attachments/assets/6c719c69-9bee-4737-a461-adbb7249f25c)


Referencing the original directory structure find the contacts as a locked pdf. Use `pdf2john` to create a hash.

![Pasted image 20241215101339](https://github.com/user-attachments/assets/69f31aa3-9025-4496-9330-d20c5996d7a8)

![Pasted image 20241215101404](https://github.com/user-attachments/assets/c35cf4c2-e4d0-4ad9-8c59-9551de5a1598)

Hashcat to crack.

![Pasted image 20241215101316](https://github.com/user-attachments/assets/9ff3a376-fe80-4cb1-9df7-a9a2c0871720)

Use the password to open the pdf and see the flag on top of the page.

![Pasted image 20241215101129](https://github.com/user-attachments/assets/cccab523-cbc4-4b96-86b9-c748e58f9624)

# Crypto

## Greatest Hits vol 1

![Pasted image 20241215143102](https://github.com/user-attachments/assets/0691703d-ebbf-4893-937e-8147eddff537)

![Pasted image 20241215142844](https://github.com/user-attachments/assets/93b6bec2-fd53-43b1-8967-5551b13782d7)

Use Cisco Password Cracker

![Pasted image 20241215142719](https://github.com/user-attachments/assets/ff4289d9-a2bc-4366-af1d-c855e1b46aee)


`noco{980431c3eac00}`

# Forensics

## FTP: For The Plunder

![Pasted image 20241215103257](https://github.com/user-attachments/assets/40011269-5d60-419a-bea3-5f8eb015f523)

![Pasted image 20241215103356](https://github.com/user-attachments/assets/1007bebd-1c6f-4b86-a315-77cd27afb672)

Given a pcap

![Pasted image 20241215103419](https://github.com/user-attachments/assets/71a7a3b5-b5d1-4235-af2e-456edc602662)

from the challenge name look up the FTP protocol, nothing comes up. Try searching for `ftp` string.  

![Pasted image 20241215103723](https://github.com/user-attachments/assets/f06ca04d-3839-40d7-bf7f-f41cb40d240a)

Follow this stream and notice there is a zip being transfered over the python ftb library.


![Pasted image 20241215103627](https://github.com/user-attachments/assets/f718a677-1359-4aa8-8db1-0ff7569c79d8)

Use binwalk extract the pcap

![Pasted image 20241215103811](https://github.com/user-attachments/assets/f1674334-29e9-4a72-95b2-fbec8aa0206d)

`zip2john` to get the hashes of the password protected compressed file.

![Pasted image 20241215201920](https://github.com/user-attachments/assets/9b09c7f9-b1f8-4505-9829-f784d7bc7d58)

Use Hashcat on mode `-m 13600` to crack the hash. 

![Pasted image 20241215201849](https://github.com/user-attachments/assets/ad6260ba-7c9c-4505-873c-5ce04aadef3c)

Use 7-Zip to open the file with  password `TH3tr!foco`

![Pasted image 20241215202445](https://github.com/user-attachments/assets/e1ec84db-3495-43f8-acb2-efaa914b1cc8)

Get the flag.

![Pasted image 20241215202334](https://github.com/user-attachments/assets/341d2c8d-72a2-4998-b574-07012ef79092)

## Inode I missed something

![Pasted image 20241215102943](https://github.com/user-attachments/assets/3b7b5ff7-baa8-4f0c-b186-bc58c6214826)

![Pasted image 20241215103044](https://github.com/user-attachments/assets/010fa78c-1c4f-4313-bf2f-aaf9336fb26b)

Going to our mounted drive see the `.ssh` directory is missing. 

![Pasted image 20241215103116](https://github.com/user-attachments/assets/6e7eb041-9d9d-4960-b795-f27b564c4eef)

![Pasted image 20241215102929](https://github.com/user-attachments/assets/32c11302-6a24-49e8-93cb-58053487ba7c)

## Out of your RADIUS

![Pasted image 20241215111120](https://github.com/user-attachments/assets/004dc095-2eaf-4e62-8246-d970f9da8109)

![Pasted image 20241215111105](https://github.com/user-attachments/assets/af07f9f1-8417-4ea0-b641-c1b04a624aad)

Capture these in a pcap,


![Pasted image 20241215173647](https://github.com/user-attachments/assets/754db3e7-e054-4337-9696-3d7ac77b678e)

First get shared key, then take locally to decrypt

![Pasted image 20241215174738](https://github.com/user-attachments/assets/c4e5a167-b51d-4a6e-9694-32ec4dc65ae9)

![Pasted image 20241215174806](https://github.com/user-attachments/assets/eaded8c1-c7d8-4248-a797-cd2818841605)

`RaDS3cW0uldB3gUd3H_51fbf40dc`

Take locally into Wireshark to decrypt.

`Edit -> Preferences -> Protocols -> RADIUS`

![Pasted image 20241215174445](https://github.com/user-attachments/assets/b2a99f79-ea77-473f-b731-bbef8fcb436b)


# Command injection - Vulnerable Infrastructure

## What's in a Name?


![Pasted image 20241215180349](https://github.com/user-attachments/assets/6eaf31bf-b8f1-40e1-bef6-99f9b7888f91)

notice this log is showing ubuntu user and group which is not a user on my system. I guess the script is running something like
`for f in dir: file $f`



![Pasted image 20241215175918](https://github.com/user-attachments/assets/4831f4f1-41eb-4ceb-bfcd-00e7d795db41)


I next notice the autosync folder will get transfered to the other host and create `$(id) hoping that show command injection in the sync.log

![Pasted image 20241215175838](https://github.com/user-attachments/assets/47dad231-509c-4fdc-ab46-414bb3ac4ec9)

We got it.

Random new command to check network

![Pasted image 20241215203549](https://github.com/user-attachments/assets/a77650ce-aefe-477c-84c7-6c6fdb1020ba)

![Pasted image 20241215203448](https://github.com/user-attachments/assets/ea0da594-59d2-40ae-910a-91c0a1e89bb5)

I tried to get SSH to work for a while and gave up. Next goal was to get a reverse shell with Netcat. 
So I moved Netcat into the autosync folder so it would get sent to the victim. Then created a reverse shell
that would exploit the command execution.

![Pasted image 20241216130314](https://github.com/user-attachments/assets/2608cb6c-76ab-4894-8c43-ca9e55cc7236)

I create the exploit then set up a listener. Soon after i get a connection and see that im actually root.

![Pasted image 20241216125815](https://github.com/user-attachments/assets/bdae2113-7a13-4ad9-be1c-14c3ebe3b961)


Moving to the `ubuntu` user's home directory I find the flag.

![Pasted image 20241216125959](https://github.com/user-attachments/assets/3597752d-6c60-4fbe-baac-096ad227392c)


# Web

## Confused Fox


![Pasted image 20241215143626](https://github.com/user-attachments/assets/265feaf8-0ea0-4c53-a921-10bf6df45627)


![Pasted image 20241215143836](https://github.com/user-attachments/assets/a9e92248-01f8-49c7-beb4-31692df223c7)

Drop down had question about secrets, asked it, mentioned something about admin panel. 
Later on doing the other challenges I noticed in the js references of this functionality and buzzwords including admin.

![Pasted image 20241215143708](https://github.com/user-attachments/assets/e51de7a7-f3bc-465d-aa38-481e4ce3da15)

## Rookie Mistake


![Pasted image 20241215144110](https://github.com/user-attachments/assets/81dda5ab-5451-4c25-921c-0f643cec6a77)


Cheesed this one




![Pasted image 20241215145914](https://github.com/user-attachments/assets/75a1e86b-7004-4c7e-89f9-5dc5971456c4)

That didnt work, but maybe he changed it or something?


Search for panda in the in the word list they gave us, see the same string without the second `_`. Try that and it works.

![Pasted image 20241215145956](https://github.com/user-attachments/assets/288e8613-c998-4229-93c5-79155d7984c2)


The real way to get this was look at a different page.


![Pasted image 20241215160123](https://github.com/user-attachments/assets/dbef6995-086c-408b-90fb-86c147846bc5)

Crack it with Hashcat.

![Pasted image 20241215160145](https://github.com/user-attachments/assets/2475f713-1144-45ae-8352-92f4d0c06d1a)


![Pasted image 20241215160054](https://github.com/user-attachments/assets/636acaab-a90e-4c5e-b5ae-dcbf1c8b2f96)

## Late Night Easter Egg


![Pasted image 20241215144442](https://github.com/user-attachments/assets/faeba072-8a7d-488a-8969-a8f230edcdee)

I found this on accident trying to solve the previous challenge. There was some self maintenance page, I click diagnose or fix or something and the flag popped up.

![Pasted image 20241215144504](https://github.com/user-attachments/assets/03b11ce8-9dc0-45e0-b7ad-2c8b9df8f3ba)
