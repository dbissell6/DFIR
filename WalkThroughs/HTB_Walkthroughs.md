# HTB Forensics Walkthroughs

Some of the Difficulties might not match up, Ive noticed if a chall is a medium in the ctf, if it gets loaded to the site it will be as an easy.



## Spooky Phishing

Very Easy chall. Given .html

Phishing attacks often utilize obfuscation techniques to hide their malicious intent. In the "Spooky Phishing" challenge, we are presented with a snippet of HTML that seems to employ both Base64 and Hex encoding methods to obscure its true purpose.


![Pasted image 20231023075326](https://github.com/dbissell6/DFIR/assets/50979196/01992ce2-729b-49f8-bdbf-64b149b6c53a)


![Pasted image 20231023075404](https://github.com/dbissell6/DFIR/assets/50979196/664a91f4-6b25-4fee-89b1-e6382443801d)


![Pasted image 20231023075451](https://github.com/dbissell6/DFIR/assets/50979196/f6f58c1f-68f1-423b-9693-612eed24e125)


## Bat Problems

Very Easy chall. Given .bat. 

The set commands are defining environment variables with obfuscated values.

![Pasted image 20231023074201](https://github.com/dbissell6/DFIR/assets/50979196/b81738d0-4528-48c2-98c5-d53cb4a797ca)

Created a python script to print the command

![Pasted image 20231023074445](https://github.com/dbissell6/DFIR/assets/50979196/b0dac85b-393d-4898-aded-947f4c5deb5d)


![Pasted image 20231023073509](https://github.com/dbissell6/DFIR/assets/50979196/ae201313-5d4a-4aff-be56-0941bc2c24f5)


## Vulnerable Season

Very Easy chall. Given Linux access logs.

Search for evidence of commands being executed.

![Pasted image 20231023075008](https://github.com/dbissell6/DFIR/assets/50979196/80c911b6-eaf2-4111-ab09-92c733c5f5d0)



![Pasted image 20231023075033](https://github.com/dbissell6/DFIR/assets/50979196/29f05cc6-fa8c-4da7-976f-29dee66332e9)

Looks like a reverse shell command that tries to establish a connection to an external IP address using TCP on port 7331 and some additional obfuscated code.

```
Nz=Eg1n;az=5bDRuQ;Mz=fXIzTm;Kz=F9nMEx;Oz=7QlRI;Tz=4xZ0Vi;Vz=XzRfdDV
```

Put these in order

![Pasted image 20231023075126](https://github.com/dbissell6/DFIR/assets/50979196/f39236af-a060-4212-9724-630b19b8f3f9)

yields
```
fXIzTm4xZ0ViXzRfdDV5bDRuQF9nMEx7QlRI
```

![Pasted image 20231023075054](https://github.com/dbissell6/DFIR/assets/50979196/eef4d6eb-84e6-4b65-b896-4a3a02d15ade)


## Trick or Treat

Easy Chall. Given .lnk and pcap

Use exiftool to parse .lnk. Notice there is a command to download a file and decrypt it with hex and xor.

![Pasted image 20231026070107](https://github.com/dbissell6/DFIR/assets/50979196/6ea3fac3-aa36-40b2-88c8-367aaa4b0a47)


Get the file in question from wireshark.

![image](https://github.com/dbissell6/DFIR/assets/50979196/4f4ff8df-7fe9-4298-b806-8ccf73a3d400)


![Pasted image 20231026070930](https://github.com/dbissell6/DFIR/assets/50979196/10c51edc-a047-4c02-81d5-382d93fc3d4f)

Take to cyber chef and use the decryption found in the .lnk

![Pasted image 20231026070953](https://github.com/dbissell6/DFIR/assets/50979196/8cd70090-4315-4043-8e55-71a5770e467b)


## Valhalloween

Medium Chall. Given Windows Logs

I was able to use Chainsaw + Sigma to do ~90% of it. 

![Pasted image 20231028035926](https://github.com/dbissell6/DFIR/assets/50979196/585f71e6-e869-40b8-97f8-59431ed49504)

![Pasted image 20231028035830](https://github.com/dbissell6/DFIR/assets/50979196/1ca9d7de-f3e1-41c8-a391-2a102401c04e)

![Pasted image 20231028040210](https://github.com/dbissell6/DFIR/assets/50979196/f92f9fe2-a2b7-4303-9e3b-db83813f36b2)

![Pasted image 20231028040035](https://github.com/dbissell6/DFIR/assets/50979196/293ef886-3af0-4160-978d-570516b9df5a)

![image](https://github.com/dbissell6/DFIR/assets/50979196/1255a99c-2184-47d4-913a-5c2000dcfe50)

![Pasted image 20231028034450](https://github.com/dbissell6/DFIR/assets/50979196/6098521b-556f-4219-ba55-290caee87529)

![Pasted image 20231028034507](https://github.com/dbissell6/DFIR/assets/50979196/74ee9021-25a4-4b9f-b5b6-9316eff953fb)


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
