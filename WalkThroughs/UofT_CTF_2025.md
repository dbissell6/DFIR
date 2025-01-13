# UofTCTF 2025

![Pasted image 20250110162147](https://github.com/user-attachments/assets/6f2b5eb2-6c94-4fcc-a682-e98090c0245f)


## Decrypt Me

![Pasted image 20250110171830](https://github.com/user-attachments/assets/7954e2e7-5be5-4ec6-ba77-2a256628b1db)

Given `.rar`

![Pasted image 20250110171741](https://github.com/user-attachments/assets/6001bce2-d5ee-4fc8-9519-a23e62c1eb16)


It is password protected.

![Pasted image 20250110171805](https://github.com/user-attachments/assets/23c177db-27ae-4dd7-93d0-686a366b2f4e)

I tried opening up the file with `7z` and it showed the presence of an alternate data stream.

![Pasted image 20250110172616](https://github.com/user-attachments/assets/2c6a9632-564d-47a3-a852-010c1a64fa0c)

`rar2john` then crack with `hashcat`.

![Pasted image 20250110171955](https://github.com/user-attachments/assets/bd935939-3e4e-4128-add2-5a82bec567ae)


unrar with password

![Pasted image 20250110172637](https://github.com/user-attachments/assets/ea1db1a7-64f4-4aac-9a44-34805abc1fae)

Can see contents of flag.py  The big part here is that it pcils the key based on random, BUT it seeds that with time. cannot access the alternate data stream on linux.

![Pasted image 20250110172655](https://github.com/user-attachments/assets/85924baa-d7d2-4c00-8f11-14299c3fd07f)

Looking at the time in the original rar we see `2025-01-05`. We can use that to start bruteforcing the times for the seed.

![Pasted image 20250110174058](https://github.com/user-attachments/assets/faeff464-8a05-4bad-aad8-9ea21ef728a6)


winrar and/or the get stream command failed us, why? idk, but `BreeZip` worked.

![Pasted image 20250110193746](https://github.com/user-attachments/assets/6d11eb46-f449-415b-b7b7-8a4148370aff)



![Pasted image 20250110193716](https://github.com/user-attachments/assets/0bac75e2-fd1b-4466-906d-13526735ffd5)



![Pasted image 20250110194835](https://github.com/user-attachments/assets/49fa9e05-d758-4cbc-811f-6fd7bd785193)

## POOF

![Pasted image 20250110182652](https://github.com/user-attachments/assets/f1c67f77-82c7-46f8-bdb8-836a3228d538)

Given `.pcap`.


Open up `Wireshark` and http exports. Take notice of `.ps1` and `.bin`.

![Pasted image 20250110182823](https://github.com/user-attachments/assets/edbc5344-a22f-402a-8f9c-58044ae195d8)

Download `.ps1` looks sus.

![Pasted image 20250110182737](https://github.com/user-attachments/assets/f7276f6e-b937-41ea-aee5-34455f26e34d)


`.bin` appears to be some hex-encoded data. 

![Pasted image 20250110182317](https://github.com/user-attachments/assets/939ee43d-db6c-44db-ab95-e04d79eec91c)

The `.ps1` is obfuscated but there are some parts about encryption decryption, creating a file in temp then starting it.

I run it through `any.run` to get deobfuscated PowerShell script and the key and iv.

![Pasted image 20250111000217](https://github.com/user-attachments/assets/68cacac1-f506-4ba7-a4db-befbb6771ec0)

Recreate the decryption in Cyberchef.

![Pasted image 20250110182240](https://github.com/user-attachments/assets/2b7cc5b4-7d38-4f7c-bb57-b5e3e8dd8a0e)


Can take the `.exe` to Windows and use a .net decompiler. 


![Pasted image 20250110182212](https://github.com/user-attachments/assets/19c5aa5a-3dee-497e-98b0-17cc7583da5c)



![Pasted image 20250110182937](https://github.com/user-attachments/assets/e5af88e0-5ba7-4e1e-9d00-c67ebc43e1f0)


## Walk in the Forest


![Pasted image 20250111112156](https://github.com/user-attachments/assets/48fcb670-5002-45a6-b4d6-40928c584270)

Given `.pkl`

See its an `sklearn RandomForestClassfier`


![Pasted image 20250110232318](https://github.com/user-attachments/assets/987a3261-1daa-4bf1-b398-a457336235c7)


Running `i2.py` can see 8 features in and 1 output but the 1 out can be 1-9.


![Pasted image 20250111102616](https://github.com/user-attachments/assets/68caa770-e6fa-4ade-a17b-dc38715eb586)

Looking at the tree, each branch is at `.5`, this suggests binary data as input, maybe something like `00110101`. 
One way to do this would be to work backwards starting from the leaf node(Class 1 in the example) and see in order to get this bit 8 would have to be less than .5,
or in binary 0. xxxxxxx0. Going to the next step bit 6 is 0, xxxxx0x0, and so on and so on. I am lazy so insteam I am going to have GPT create a script to get 
all the possible binary inputs, put them in the model, record the output and track it.


![Pasted image 20250111103900](https://github.com/user-attachments/assets/ac49ecd0-b16a-4346-98bd-f780a8da74cf)

Here the idea is there is a binary input that will yield an output of 1-9, if we  put it in order then convert the binary output to ASCII it should yield the flag.
There are some different inputs that track to the same output, that is an issue.


![Pasted image 20250111114331](https://github.com/user-attachments/assets/af4fb0da-a585-4a04-9cce-b7403b700623)

Organizing and converting the output start to see 

![Pasted image 20250111114217](https://github.com/user-attachments/assets/bd5a242d-98d4-421c-8189-14fb1e8687e8)


left with `br4nc?0ut` guessed an `h` and that was it. `uoftctf{br4nch0ut}`



