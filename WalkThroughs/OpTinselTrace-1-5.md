# OpTinselTrace Walkthrough

![image](https://github.com/dbissell6/PWN_Practice/assets/50979196/387100e3-e261-4b9a-bb8c-4454ec3166c8)


HTB 2023

Hack The Box Sherlocks. 


[OpTinselTrace-1](https://github.com/dbissell6/PWN_Practice/blob/main/OpTinselTrace-1-5.md#optinseltrace-1)

[OpTinselTrace-2](https://github.com/dbissell6/PWN_Practice/blob/main/OpTinselTrace-1-5.md#optinseltrace-2)

[OpTinselTrace-3](https://github.com/dbissell6/PWN_Practice/blob/main/OpTinselTrace-1-5.md#optinseltrace-3)

[OpTinselTrace-4](https://github.com/dbissell6/PWN_Practice/blob/main/OpTinselTrace-1-5.md#optinseltrace-4)

[OpTinselTrace-5](https://github.com/dbissell6/PWN_Practice/blob/main/OpTinselTrace-1-5.md#optinseltrace-5)



The Hack The Box's Sherlock CTF challenges, collectively titled "OpTinselTrace," presented a series of digital forensics and incident response scenarios that tasked participants with investigating and mitigating a multi-faceted cyber attack on Santa's North Pole operations. Through five distinct but interconnected modules, participants navigated complex security breaches involving email communications, cloud storage, networked printers, and critical server infrastructure. The challenges required a blend of technical skills to uncover evidence of insider threats, credential compromise, lateral movement, and ransomware deployment, all orchestrated by the infamous Grinch and his accomplices.


# OpTinselTrace-1

![image](https://github.com/dbissell6/PWN_Practice/assets/50979196/dd66259c-9c36-413e-a3dc-150c50e8b2ff)


## Sherlock Scenario

An elf named "Elfin" has been acting rather suspiciously lately. He's been working at odd hours and seems to be bypassing some of Santa's security protocols. Santa's network of intelligence elves has told Santa that the Grinch got a little bit too tipsy on egg nog and made mention of an insider elf! Santa is very busy with his naughty and nice list, so he’s put you in charge of figuring this one out. Please audit Elfin’s workstation and email communications.

## Abstract

Given

![image](https://github.com/dbissell6/PWN_Practice/assets/50979196/210762b8-2b37-40b1-a930-a41c2b0a405c)

A little annoying because i was going back between `conversations.dat` and `mail_fti.dat`.

## Task 1

### Question

`What is the name of the email client that Elfin is using?`

### Answer

`eM client`

### Explanation

![image](https://github.com/dbissell6/PWN_Practice/assets/50979196/03d47c1d-364a-47d7-9515-be91918d0f37)

## Task 2

### Question

`What is the email the threat is using?`

### Answer
`definitelynotthegrinch@gmail.com`

## Task 3

### Question
`When does the threat actor reach out to Elfin?`

### Answer
`2023-11-27 17:27:26`

### Explanation

![image](https://github.com/dbissell6/PWN_Practice/assets/50979196/2e7c143d-16d2-47af-8fd4-81d98c7eae69)

## Task 4

### Question
`What is the name of Elfins boss?`

### Answer
`elfuttin bigelf`

### Explanation

We can see elfuttin refered to a couple times in emails. This screenshot is nice becasue it ties a couple names to addresses.

![image](https://github.com/dbissell6/PWN_Practice/assets/50979196/800521a3-2390-4295-8812-1698733fb873)


## Task 5

### Question
`What is the title of the email in which Elfin first mentions his access to Santas special files?`

### Answer
`Re: work`

## Task 6

### Question
`The threat actor changes their name, what is the new name + the date of the first email Elfin receives with it?`

### Answer
`wendy elflower, 2023-11-28 10:00:21`

### Explanation

![image](https://github.com/dbissell6/PWN_Practice/assets/50979196/2eeb0c1d-950a-4d31-8bb9-7eb0013d5565)


## Task 7

### Question
`What is the name of the bar that Elfin offers to meet the threat actor at?`

### Answer

`SnowGlobe`

### Explanation

![image](https://github.com/dbissell6/PWN_Practice/assets/50979196/88dd1739-be63-49d0-9348-a950c80b9b7a)


## Task 8

### Question
`When does Elfin offer to send the secret files to the actor?`

### Answer
`2023-11-28 16:56:13`

## Task 9

### Question
`What is the search string for the first suspicious google search from Elfin? (Format: string)`

### Answer
`how to get around work security`

### Explanation

Google History

![image](https://github.com/dbissell6/PWN_Practice/assets/50979196/24df9af1-b05a-408e-9232-d41d5c05127b)


## Task 10

### Question
`What is the name of the author who wrote the article from the CIA field manual?`

### Answer
`Joost Minnaar`

## Task 11

### Question
`What is the name of Santas secret file that Elfin sent to the actor?`

### Answer
`santa_deliveries.zip`

## Task 12

### Question
`According to the filesystem, what is the exact CreationTime of the secret file on Elfins host?`

### Answer
`2023-11-28 17:01:29`

## Task 13

### Question
`What is the full directory name that Elfin stored the file in?`

### Answer
`C:\users\Elfin\Appdata\Roaming\top-secret`

### Explantion 

We saw this answering the first question.

## Task 14

### Question
`Which country is Elfin trying to flee to after he exfiltrates the file?`

### Answer
`Greece`

## Task 15

### Question
`What is the email address of the apology letter the user (elfin) wrote out but didn’t send?`

### Answer
`Santa.claus@gmail.com`

## Task 16

### Question
`The head elf PixelPeppermint has requested any passwords of Elfins to assist in the investigation down the line. What’s the windows password of Elfin’s host?`

### Answer
`Santaknowskungfu`

# OpTinselTrace-2

![image](https://github.com/dbissell6/PWN_Practice/assets/50979196/130ef1be-1cf8-4269-923d-f4c53f2c4c5f)


## Sherlock Scenario

It seems our precious technology has been leaked to the threat actor. Our head Elf, PixelPepermint, seems to think that there were some hard-coded sensitive URLs within the technology sent. Please audit our Sparky Cloud logs and confirm if anything was stolen! PS - Santa likes his answers in UTC...

## Abstract

## Task 1

### Question
`What is the MD5 sum of the binary the Threat Actor found the S3 bucket location in?`

### Answer
`62d5c1f1f9020c98f97d8085b9456b05`

## Task 2

### Question
`What time did the Threat Actor begin their automated retrieval of the contents of our exposed S3 bucket?`

### Answer
`2023-11-29 08:24:07`

## Task 3

### Question
`What time did the Threat Actor complete their automated retrieval of the contents of our exposed S3 bucket?`

### Answer
`2023-11-29 08:24:16`

## Task 4

### Question
`Based on the Threat Actor's user agent - what scripting language did the TA likely utilise to retrieve the files?`

### Answer
`python`

## Task 5

### Question
`Which file did the Threat Actor locate some hard coded credentials within?`

### Answer
`claus.py`

## Task 6

### Question
`Please detail all confirmed malicious IP addresses. (Ascending Order)`

### Answer
`45.133.193.41, 191.101.31.57`

## Task 7

### Question
`We are extremely concerned the TA managed to compromise our private S3 bucket, which contains an important VPN file. Please confirm the name of this VPN file and the time it was retrieved by the TA.`

### Answer
`bytesparkle.ovpn, 2023-11-29 10:16:53`

## Task 8

### Question
`Please confirm the username of the compromised AWS account?`

### Answer
`elfadmin`

## Task 9

### Question
`Based on the analysis completed Santa Claus has asked for some advice. What is the ARN of the S3 Bucket that requires locking down?`

### Answer
`arn:aws:s3:::papa-noel`

## Discussion

# OpTinselTrace-3

![image](https://github.com/dbissell6/PWN_Practice/assets/50979196/271c475d-d7b2-4c1c-833c-7c186fcb65e3)


## Sherlock Scenario

Oh no! Our IT admin is a bit of a cotton-headed ninny-muggins, ByteSparkle left his VPN configuration file in our fancy private S3 location! The nasty attackers may have gained access to our internal network. We think they compromised one of our TinkerTech workstations. Our security team has managed to grab you a memory dump - please analyse it and answer the questions! Santa is waiting…

## Abstract



## Task 1

### Question
`What is the name of the file that is likely copied from the shared folder (including the file extension)?`
### Answer
`present_for_santa.zip`

### Explanation

![Pasted image 20231220130351](https://github.com/dbissell6/PWN_Practice/assets/50979196/a554ce08-6e5f-4430-b5bf-3ccbe79ffbed)


## Task 2

### Question
`What is the file name used to trigger the attack (including the file extension)?`
### Answer
`click_for_present.lnk`

## Task 3

### Question
`What is the name of the file executed by click_for_present.lnk (including the file extension)?`

### Answer
`present.vbs`

## Task 4

### Question
`What is the name of the program used by the vbs script to execute the next stage?`
### Answer
`powershell.exe`

## Task 5

### Question
`What is the name of the function used for the powershell script obfuscation?`

### Answer
`WrapPresent`

## Task 6

### Question
`What is the URL that the next stage was downloaded from?`

### Answer
`http://77.74.198.52/destroy_christmas/evil_present.jpg`

## Task 7

### Question
`What is the IP and port that the executable downloaded the shellcode from (IP:Port)?`

### Answer
`77.74.198.52:445`

### Explanation

From hybrid analysis

![image](https://github.com/dbissell6/PWN_Practice/assets/50979196/f61959d6-2757-4dcd-a694-88ee77e4064e)

From wine + wireshark

![image](https://github.com/dbissell6/PWN_Practice/assets/50979196/b591bd1a-ab66-4691-91ad-3766a16d7ca7)


## Task 8

### Question
`What is the process ID of the remote process that the shellcode was injected into?`

### Answer
`724`

## Task 9

### Question
`After the attacker established a Command & Control connection, what command did they use to clear all event logs?`

### Answer
`Get-EventLog -List | ForEach-Object { Clear-EventLog -LogName $_.Log }`

## Task 10

### Question
`What is the full path of the folder that was excluded from defender?`

### Answer
`C:\users\public`

## Task 11

### Question
`What is the original name of the file that was ingressed to the victim?`

### Answer
`procdump.exe`

## Task 12

### Question
`What is the name of the process targeted by procdump.exe?`

### Answer
`lsass.exe`


## Discussion


# OpTinselTrace-4

![image](https://github.com/dbissell6/PWN_Practice/assets/50979196/0dd0e014-56c4-42b3-a789-de449ea32f48)


## Sherlock Scenario

Printers are important in Santa’s workshops, but we haven’t really tried to secure them! The Grinch and his team of elite hackers may try and use this against us! Please investigate using the packet capture provided! The printer server IP Address is 192.168.68.128

## Abstract


## Task 1

### Question

`The performance of the network printer server has become sluggish, causing interruptions in the workflow at the North Pole workshop. Santa has directed us to generate a support request and examine the network data to pinpoint the source of the issue. He suspects that the Grinch and his group may be involved in this situation. Could you verify if there is an IP Address that is sending an excessive amount of traffic to the printer server?`

### Answer
`172.17.79.133`

## Task 2

### Question

`Bytesparkle being the technical Lead, found traces of port scanning from the same IP identified in previous attack. Which port was then targeted for initial compromise of the printer?`

### Answer

`9100`

## Task 3

### Question

`What is the full name of printer running on the server?`

### Answer

`Northpole HP LaserJet 4200n`

## Task 4

### Question

`Grinch intercepted a list of nice and naughty children created by Santa. What was name of the second child on the nice list?`

### Answer

`Douglas Price`

## Task 5

### Question

`The Grinch obtained a print job instruction file intended for a printer used by an employee named Elfin. It appears that Santa and the North Pole management team have made the decision to dismiss Elfin. Could you please provide the word for word rationale behind the decision to terminate Elfin's employment?`

### Answer

`The addressed employee is confirmed to be working with grinch and team. According to Clause 69 , This calls for an immediate expulsion.`

## Task 6

### Question

`What was the name of the scheduled print job?`

### Answer

`MerryChristmas+BonusAnnouncment`

## Task 7

### Question

`Amidst our ongoing analysis of the current packet capture, the situation has escalated alarmingly. Our security system has detected signs of post-exploitation activities on a highly critical server, which was supposed to be secure with SSH key-only access. This development has raised serious concerns within the security team. While Bytesparkle is investigating the breach, he speculated that this security incident might be connected to the earlier printer issue. Could you determine and provide the complete path of the file on the printer server that enabled the Grinch to laterally move to this critical server?`

### Answer

`/Administration/securitykeys/ssh_systems/id_rsa`

## Task 8

### Question

`What is size of this file in bytes?`

### Answer

`1914`

## Task 9

### Question

`What was the hostname of the other compromised critical server?`

### Answer

`christmas.gifts`

## Task 10

### Question

`When did the Grinch attempt to delete a file from the printer? (UTC)`

### Answer

`2023-12-08 12:18:14`

## Discussion



# OpTinselTrace-5

![image](https://github.com/dbissell6/PWN_Practice/assets/50979196/ae00e4a4-c646-40d6-a300-3837fcade3b5)

## Sherlock Scenario

You'll notice a lot of our critical server infrastructure was recently transferred from the domain of our MSSP - Forela.local over to Northpole.local. We actually managed to purchase some second hand servers from the MSSP who have confirmed they are as secure as Christmas is! It seems not as we believe christmas is doomed and the attackers seemed to have the stealth of a clattering sleigh bell, or they didn’t want to hide at all!!!!!! We have found nasty notes from the Grinch on all of our TinkerTech workstations and servers! Christmas seems doomed. Please help us recover from whoever committed this naughty attack!

## Abstract



## Task 1
`Which CVE did the Threat Actor (TA) initially exploit to gain access to DC01?`

### Answer 1
`CVE-2020-1472`

### Explanation

Using chainsaw + sigma... see mimikatz

![Pasted image 20231223122056](https://github.com/dbissell6/PWN_Practice/assets/50979196/e30612d7-efd5-44c4-b5bb-13ccbb57c23f)

Google

![image](https://github.com/dbissell6/PWN_Practice/assets/50979196/51241ecc-e3ff-442a-96c8-a2d637f268fe)


## Task 2
`What time did the TA initially exploit the CVE? (UTC)`

### Answer 2
`2023-12-13 09:24:23`

## Task 3
`What is the name of the executable related to the unusual service installed on the system around the time of the CVE exploitation?`

### Answer 3

`hAvbdksT.exe`

## Task 4 
`What date & time was the unusual service start?`

### Answer 4

`2023-12-13 09:24:24`

### Explanation

Ties servicename to executable

![image](https://github.com/dbissell6/PWN_Practice/assets/50979196/76de6146-2210-49fc-a34c-11c2ae12a393)


Search for servicename, not created but running.

![image](https://github.com/dbissell6/PWN_Practice/assets/50979196/c4d62b5c-2c25-49c6-a392-231e5a0edf61)


## Task 5
`What was the TA's IP address within our internal network?`

### Answer 5

`192.168.68.200`

### Explanation

Using chainsaw + sigma...

![image](https://github.com/dbissell6/PWN_Practice/assets/50979196/f451e83d-af34-4ffb-a341-119819827f4e)



## Task 6
`Please list all user accounts the TA utilised during their access. (Ascending order)`

### Answer 6

`Administrator, Bytesparkle`

## Task 7
`What was the name of the scheduled task created by the TA?`

### Answer 7

`svc_vnc`

## Task 8
`Santa's memory is a little bad recently! He tends to write a lot of stuff down, but all our critical files have been encrypted! Which creature is Santa's new sleigh design planning to use?`

### Answer 8

`Unicorn`

### Explanation

Find ransomeware(splunk_svc.dll) and encrypted files. Open malware in ghidra. Notice it is XOR.

![image](https://github.com/dbissell6/PWN_Practice/assets/50979196/eda92b76-aed1-46dc-9612-e9ddd1bd25f9)

Can also see ransom note.

Another clue of XOR and source.

![image](https://github.com/dbissell6/PWN_Practice/assets/50979196/e5fa5e63-30e1-43e7-a378-a0e7a8cac186)


Decrypting in cyberchef. Can tell it worked from header.

![image](https://github.com/dbissell6/PWN_Practice/assets/50979196/b88d0087-fbd2-41ca-b750-68d530d84de5)

Looking at png

![image](https://github.com/dbissell6/PWN_Practice/assets/50979196/318d46d6-c892-4f4b-8525-5aa77837a775)


## Task 9
`Please confirm the process ID of the process that encrypted our files.`

### Answer 9

`5828`

### Explanation

Search for the process that encrypted the files by focusing on and searching for the file extentsion.

![image](https://github.com/dbissell6/PWN_Practice/assets/50979196/ae80e8dc-a645-40d6-848a-7e6f90b73573)



## Discussion

## Final Reflections

The "OpTinselTrace" series unfolded a narrative where the North Pole's security was under siege by a sophisticated adversary. Participants began by scrutinizing an elf named Elfin's unusual activities, including the use of eM client for suspicious communications with the Grinch. This led to the discovery of an insider threat and a compromised printer server acting as a beachhead for further attacks.

As the scenario progressed, the challenges increased in complexity, revealing a deep penetration into the North Pole's digital infrastructure. The Grinch leveraged exposed S3 buckets to exfiltrate sensitive VPN configurations and employed malicious scripts to facilitate lateral movement within the network. Detailed memory analysis was required to trace the steps of the attacker, leading to the identification of malicious processes, compromised servers, and the extent of data manipulation.

The capstone of the series involved a full-scale ransomware attack that encrypted critical files and disrupted the North Pole's operations. The incident response involved tracing the ransomware's execution path, determining the compromised user accounts, and unveiling the devious plans hidden within scheduled tasks. The series culminated in the participants' efforts to aid Santa in recovering from the attack, ensuring that Christmas was not doomed.

Throughout the challenges, the importance of vigilance, even in the most cheerful and seemingly secure environments, was underscored. From email clients to networked printers, and from cloud storage to domain controllers, every component was a potential vulnerability. The "OpTinselTrace" series not only provided an immersive learning experience for participants but also highlighted the evolving nature of cyber threats and the critical need for comprehensive security strategies to protect against them.
