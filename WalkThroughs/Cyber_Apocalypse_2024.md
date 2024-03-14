# Cyber_Apocalypse_2024 - Hack The Box(HTB)

![image](https://github.com/dbissell6/DFIR/assets/50979196/f773fc8d-3c31-42f3-b955-ca52a8eba356)

# Misc

## Path of Survival

## Stop Drip and Roll

## Character

# Forensics

## It Has Begun - very easy

Given .sh

Base64 encoded strings containing the flag.

![Pasted image 20240309061317](https://github.com/dbissell6/DFIR/assets/50979196/0b74e42e-04c7-478b-bf7e-5cefdad41e1d)

## An unusual sighting - very easy

Given .log and bash_history.txt

![Pasted image 20240309213743](https://github.com/dbissell6/DFIR/assets/50979196/3b6c5e29-340d-4ac7-9e42-eb673abf6fd7)

![Pasted image 20240309214234](https://github.com/dbissell6/DFIR/assets/50979196/60d46b14-ff66-439e-be94-ceaec8e1ecd3)

![Pasted image 20240313181403](https://github.com/dbissell6/DFIR/assets/50979196/f6072925-0211-48ac-a1ee-a6e09be53dce)

## Urgent - very easy

Given .eml

![Pasted image 20240309061554](https://github.com/dbissell6/DFIR/assets/50979196/be87190b-6ecd-4a3a-b12d-d305905f5cf6)

## Pursue The Tracks - easy

Given mft

Used a mix of mft explorer and MFTEcmd -> timeline explorer. 

![Pasted image 20240309220155](https://github.com/dbissell6/DFIR/assets/50979196/97993d71-b64a-4a99-8ca8-eaad13a7adcb)

![Pasted image 20240309220114](https://github.com/dbissell6/DFIR/assets/50979196/4647438f-eef5-46e3-b797-2ecf3e2522fd)

![Pasted image 20240313181643](https://github.com/dbissell6/DFIR/assets/50979196/316e735c-0eda-475a-9210-c617b1b9dfbb)

## Fake Boost - easy 

Given pcap

pcap contained malicious script. the first part of the flag was in the script along with the algorithm to decrypt packets that had the other half of the flag.

![Pasted image 20240309224006](https://github.com/dbissell6/DFIR/assets/50979196/d864f0c7-a475-4b3e-bd1a-ac4d346d9070)

![Pasted image 20240309063750](https://github.com/dbissell6/DFIR/assets/50979196/54d18958-ee92-4f1c-86db-688aedcf7cc1)

![Pasted image 20240309063448](https://github.com/dbissell6/DFIR/assets/50979196/566872cc-3fb1-4dcb-8f9e-f33f49f340e1)

This is the big part, we see after message is encrypted, the IV is added to the beginning, then base64, then sent. We need to reverse the base64 take the first 16 bytes off and they will be our IV.

![Pasted image 20240311203313](https://github.com/dbissell6/DFIR/assets/50979196/f44a05f7-c62d-483b-95ae-53828b1f0b8c)

The pcaps in question, from the malicious script.

![Pasted image 20240311203857](https://github.com/dbissell6/DFIR/assets/50979196/2ac63975-40a8-4143-8486-3270f0ac6ff5)

![Pasted image 20240311203929](https://github.com/dbissell6/DFIR/assets/50979196/395d8bcc-8cae-4f3a-8692-edcc82cefead)

To get IV

![Pasted image 20240311203228](https://github.com/dbissell6/DFIR/assets/50979196/376bf879-a02f-4378-8843-c81b100e153c)

Get encrypted message

![Pasted image 20240311203252](https://github.com/dbissell6/DFIR/assets/50979196/a0415e81-dda0-4bb2-af58-1be960aa0f62)

![Pasted image 20240311202745](https://github.com/dbissell6/DFIR/assets/50979196/1d71741c-640b-4a63-8d52-20cddc10010f)

![Pasted image 20240311204032](https://github.com/dbissell6/DFIR/assets/50979196/3b8529df-4a5a-4a83-94fd-244281aa91ed)

## Phreaky - medium 

# Reversing 

## Packed Away

## Boxcutter
