# HTB Forensics Walkthroughs

## Red Miner

Very Easy chall. Given .sh

![image](https://github.com/dbissell6/DFIR/assets/50979196/74d5f8f7-f3aa-426f-bef9-c2ef87a34517)

The script starts with a function called checkTarget(), which checks if the script is running under the expected user root7654 and the hostname starts with UNZ-. If these conditions are not met, the script will exit.

Next, the script defines various variables related to a binary file, presumably a cryptocurrency miner (xmrig). It provides a download URL for the binary file and its MD5 hash. The script seems to be performing some integrity checks to ensure the downloaded binary is correct.

The bulk of the script is dedicated to terminating and removing a wide range of processes, services, and configurations. The script kills processes associated with known mining software, crypto mining pools, malware-related names, and other suspicious activities. It also disables certain services and removes specific files and directories related to known threats.

Can see some lines are bae64 encoded, decoding them reveals the flag.
![image](https://github.com/dbissell6/DFIR/assets/50979196/54eb4f06-7ced-4316-b6df-287cdeb58576)


## Scripts and Formulas
Easy chall. Given .lnk, .vbs, Windows logs + NC to answer questions.

![image](https://github.com/dbissell6/DFIR/assets/50979196/dd47abe1-031d-411d-87ae-6d5131ef9183)

First answer can be found in the lnk. 2nd in the vbs, Rest can be found using chainsaw or evtx_dump
![image](https://github.com/dbissell6/DFIR/assets/50979196/d3c3abc2-8086-4b04-ab11-4ac914d8ca87)

![Pasted image 20230714222648](https://github.com/dbissell6/DFIR/assets/50979196/cc1cde98-9ffd-477a-afad-058874d1e6e3)


![Pasted image 20230714222805](https://github.com/dbissell6/DFIR/assets/50979196/a08c0878-2fb0-4049-b8a2-7f759ef10d5f)

![Pasted image 20230714222912](https://github.com/dbissell6/DFIR/assets/50979196/c5f160cc-72ce-4836-9ebd-f640013f531f)


![Pasted image 20230714224040](https://github.com/dbissell6/DFIR/assets/50979196/69666609-eb83-4fe4-b179-3bfa259cdc9a)

![image](https://github.com/dbissell6/DFIR/assets/50979196/c0e93dfb-7d20-4963-8ed6-7c2d7850124d)



![Pasted image 20230715082338](https://github.com/dbissell6/DFIR/assets/50979196/d9848849-a669-49c0-acb4-9492a9e3b2da)


![Pasted image 20230715082352](https://github.com/dbissell6/DFIR/assets/50979196/b34f5b94-f5a8-4d97-b114-5cb951f73f26)

![Pasted image 20230715082734](https://github.com/dbissell6/DFIR/assets/50979196/41675f1b-6a8d-470c-85c3-2dfd0a25d40c)


## Hypercraft

Medium chall. Given .eml

![image](https://github.com/dbissell6/DFIR/assets/50979196/83461ecf-8e65-441a-8e1c-207ff7969dcd)

1st open eml, notice huge base64 encoded text, strip out the rest and decode.

![image](https://github.com/dbissell6/DFIR/assets/50979196/64e14b0a-c022-429f-a8e3-30acef1b596e)

This yeilds a very long html with a javascript script in it

![image](https://github.com/dbissell6/DFIR/assets/50979196/77be6789-05e5-48d3-8706-9bf914d11ca2)

I notice this pbmbiaan function and put a console.log() to print its output every time it is called.
Doing this and opening the file in firefox can find the zip in the the console. save and unzip to find a .pdf file that is really a .js similar to what we just decoded

This file will create some hex to be decoded to reveal the last step. Base64 decode and inflate the text another obfuscated powershell script.


![Pasted image 20230716150843](https://github.com/dbissell6/DFIR/assets/50979196/9844945c-f086-4bde-bb0a-78108832fcff)

Same as before change print using Write-Host to print variable names. After printing a couple variables, find the flag.

![image](https://github.com/dbissell6/DFIR/assets/50979196/4cd90bc7-de98-4561-a130-dee949480b49)



## Project RedLine

## No Start Where
