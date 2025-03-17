# picoCTF 2025

![image](https://github.com/user-attachments/assets/c636b25f-d000-40bb-9d65-c38913c1e044)


# Forensics

## Ph4nt0m 1ntruder

![Pasted image 20250307100409](https://github.com/user-attachments/assets/a56c516c-970b-417e-ad4f-122f4cc196d6)

Given pcap. Mainly TCP Retransmissions.

Run strings see base64 encoded strings

![Pasted image 20250307100916](https://github.com/user-attachments/assets/b2612813-f91c-4ef4-9162-833115c89a98)


![Pasted image 20250307101123](https://github.com/user-attachments/assets/35e431ed-eb80-41ee-a042-5d336941c4eb)

`tshark -r myNetworkTraffic.pcap -Y "tcp.analysis.retransmission" -T fields -e frame.time_epoch -e tcp.segment_data | sort -n | awk '{print $2}'`

![Pasted image 20250307101724](https://github.com/user-attachments/assets/fe59e347-adba-4936-bbc8-c8cf94493758)

![Pasted image 20250307101659](https://github.com/user-attachments/assets/9cecdcae-f6ba-480a-8df2-bc03fe435f54)

`1t_w4s` was somewhere else + bad decoding

`picoCTF{1t_w4snt_th4t_34sy_tbh_4r_e5e8c78d}`

## RED

![Pasted image 20250307100428](https://github.com/user-attachments/assets/25b4018d-d3f7-4014-85e8-12318990ef3e)

Given .png

![Pasted image 20250307102215](https://github.com/user-attachments/assets/6ae94a74-e162-41bf-979d-84d66d784511)

Base64 encoded string found with zsteg in aperisolve.

![Pasted image 20250307102142](https://github.com/user-attachments/assets/9f950687-8098-420b-8bcf-71ceaf952c5a)



## flags are stepic


![Pasted image 20250307100444](https://github.com/user-attachments/assets/34291658-0d66-43bf-9d29-c540123dfaff)

Given access to a website with lots of countries flags.

![Pasted image 20250307103020](https://github.com/user-attachments/assets/1659bdf1-e0e6-4f99-9e7d-34ec4b228fd1)

There is a flag of a country that doesnt really exist. Download that png. Notice it is much larger than other flags on site and
it has some messed up pixels in the top left. The size of the file broke most automated steg solvers.

![Pasted image 20250309200409](https://github.com/user-attachments/assets/b01c8e5c-0c94-49ce-a1df-6026d39fcf16)


![Pasted image 20250309202555](https://github.com/user-attachments/assets/d2a1e86a-ca05-4f12-aaac-17f777e862ec)

Build simple python script to get the RGB values for the first ~100 pixels. Convert 254 to 0 and 255 to 1. Throw away every 9th byte + from binary in Cyberchef.

![Pasted image 20250309195929](https://github.com/user-attachments/assets/0932dced-d2d7-4598-bcba-3779ef17ac13)




## Bitlocker-1

![Pasted image 20250307100459](https://github.com/user-attachments/assets/67e62475-a63c-4b5b-a569-8d0a978d1343)

Given Bitlocker dd drive.

![Pasted image 20250307111409](https://github.com/user-attachments/assets/905843c1-532c-455c-8b42-69049a663f1a)

bitlocker2john to extract hashes.

![Pasted image 20250307111043](https://github.com/user-attachments/assets/ac40963c-a168-4860-b266-40643f2ee25a)


![Pasted image 20250307111100](https://github.com/user-attachments/assets/4fa5d6ff-223c-4124-91ec-b4ffa8b9ca0c)

John to crack. 

![Pasted image 20250307110547](https://github.com/user-attachments/assets/f0549e98-e344-47b0-bb99-71b790fd9a8c)

Convert to vhdx to move to windows.

![Pasted image 20250307123612](https://github.com/user-attachments/assets/af566d30-fe74-435f-9664-fbd24d9c0cb8)

Open in windows use cracked password when prompted.

![Pasted image 20250307123719](https://github.com/user-attachments/assets/80149729-c5e1-4fea-970e-f38fa7932d93)


![Pasted image 20250307123748](https://github.com/user-attachments/assets/fef47368-c84c-47c7-a20f-1d6b47acc9ff)



## Event-Viewing

![Pasted image 20250307100516](https://github.com/user-attachments/assets/329f318c-96ca-4866-b21d-9772099731a5)

Given registry hive.

`EventID: 1033`

![Pasted image 20250312095520](https://github.com/user-attachments/assets/485e8be0-ceeb-4e02-b3f6-90324e1f1602)

Decode in Cyberchef.

![Pasted image 20250307153335](https://github.com/user-attachments/assets/8e2e15e3-f6d3-484b-93a9-974aea9cca18)

`EventID: 4657`

![Pasted image 20250312095634](https://github.com/user-attachments/assets/9f030c9f-6660-402f-8e11-73d87e9e4e31)

Decode in Cyberchef.

![Pasted image 20250307154152](https://github.com/user-attachments/assets/1c7196d1-7fa4-4ab2-8a5f-8f73054240ff)


`EventID: 1074`

![Pasted image 20250312095735](https://github.com/user-attachments/assets/0c59b9a1-fb83-4669-ae7b-a547089250b3)

Decode in Cyberchef.

![Pasted image 20250307154307](https://github.com/user-attachments/assets/a8869b8d-f895-4926-a24b-745984502a34)

## Bitlocker-2

![Pasted image 20250307100530](https://github.com/user-attachments/assets/743969f4-6190-4744-96fc-9ca72814f0b3)

Given Bitlocker dd drive and mem.dump.


github repo for a volatility plugin to extract bitlocker keys from mem dumps.

`https://github.com/breppo/Volatility-BitLocker/blob/master/bitlocker.py`

![Pasted image 20250307180731](https://github.com/user-attachments/assets/e9b1f6f7-e30c-49c0-8ad9-e18d056c926a)

```
python2 ~/Tools/volatility/vol.py -f memdump.mem --profile=Win10x64_19041 bitlocker
Volatility Foundation Volatility Framework 2.6.1

[FVEK] Address : 0x9e8879926a50
[FVEK] Cipher  : AES 128-bit (Win 8+)
[FVEK] FVEK: 5b6ff64e4a0ee8f89050b7ba532f6256

[FVEK] Address : 0x9e887496fb30
[FVEK] Cipher  : AES 256-bit (Win 8+)
[FVEK] FVEK: 60be5ce2a190dfb760bea1ece40e4223c8982aecfd03221a5a43d8fdd302eaee

[FVEK] Address : 0x9e8874cb5c70
[FVEK] Cipher  : AES 128-bit (Win 8+)
[FVEK] FVEK: 1ed2a4b8dd0290f646ded074fbcff8bd

[FVEK] Address : 0x9e88779f1a10
[FVEK] Cipher  : AES 128-bit (Win 8+)
[FVEK] FVEK: bccaf1d4ea09e91f976bf94569761654
```

Find a github issue asking how to actually use the FVEK key in Dislocker

`https://github.com/Aorimn/dislocker/issues/202`

Suggest to do something like this but it didnt work.

![Pasted image 20250308201654](https://github.com/user-attachments/assets/66b66958-1ba1-41d9-996f-2f6660817a33)



# General Skills

## FANTASY CTF

![Pasted image 20250309173145](https://github.com/user-attachments/assets/181872fc-bf9e-4150-9564-07f63743b004)

Given nc connection to answer questions about the ctfs rules.

![Pasted image 20250309173258](https://github.com/user-attachments/assets/a726e559-2e32-4f6e-9a44-78ccfa40e62b)

## Rust fixme 1

![image](https://github.com/user-attachments/assets/1319bd9a-2e10-44c8-878e-68681d832faa)

Given broken Rust code.

`Cargo build` + `Cargo run` runs broken code and gets some error

![Pasted image 20250307205113](https://github.com/user-attachments/assets/735bb8f8-15c5-4810-a192-c9efa26b6ccc)

![Pasted image 20250307205102](https://github.com/user-attachments/assets/28119f4c-2779-4ebf-8c22-b5cf5b94fd1e)

To fix

`; to end`
`return` not `ret`
`{}` for printing

Look at actual code now.

![Pasted image 20250307205520](https://github.com/user-attachments/assets/5d803f5a-ac74-46b1-9b1d-b411cfe67a8b)


![Pasted image 20250307205424](https://github.com/user-attachments/assets/16bc2227-5a35-48d7-ba39-805189cb75fd)

`picoCTF{4r3_y0u_4_ru$t4c30n_n0w?}`

## Rust fixme 2

![Pasted image 20250307205640](https://github.com/user-attachments/assets/d4c8a012-694f-452c-9638-165a44d69710)

For 2 and 3 I noticed they are using the same decryption method as 1, they just changed the cipher text, so i just copied and pasted the cipher text for 2 and 3 in 1 solver.

![Pasted image 20250307205948](https://github.com/user-attachments/assets/a693d6b9-dce3-449b-a1f0-e0a4247ece95)

`picoCTF{4r3_y0u_h4v1n5_fun_y31?}`

## Rust fixme 3

![Pasted image 20250307210303](https://github.com/user-attachments/assets/4213a2c3-1b5b-4b80-a2e1-cb7d84d4a919)

![Pasted image 20250307210242](https://github.com/user-attachments/assets/f0278955-b1c4-4b96-86d4-53afa00ea4c6)

`picoCTF{n0w_y0uv3_f1x3d_1h3m_411}`

## YaraRules0x100

![Pasted image 20250308125337](https://github.com/user-attachments/assets/c7beb83e-722a-4188-85f5-9bb512e59c40)

Given an exe.

![Pasted image 20250308125547](https://github.com/user-attachments/assets/41e1212c-11e0-429e-bdd3-e9dbc5e55694)

![Pasted image 20250308125805](https://github.com/user-attachments/assets/a8ea0439-4db8-4b3c-9f60-9c02a3d66eae)

![Pasted image 20250308125752](https://github.com/user-attachments/assets/fbf5de58-61be-4ee0-a769-e90c4b842221)

Created yara rules just from running strings on the 2 files.

![Pasted image 20250308134227](https://github.com/user-attachments/assets/13ba9a50-f90c-42ca-b228-9cce0b7755ac)

![Pasted image 20250308134100](https://github.com/user-attachments/assets/9b1c2ff2-9f93-4332-8f32-26c2e261360b)

`picoCTF{yara_rul35_r0ckzzz_d31fbfb7}`

# Web Exploitation

## Cookie Monster Secret Recipe

![Pasted image 20250309173411](https://github.com/user-attachments/assets/20e94686-4d08-438c-b6cc-5e1fa474eb4e)

Taken to login page.

![Pasted image 20250309173536](https://github.com/user-attachments/assets/dae335d3-a178-4bce-aa08-83e7e3b86e2e)

Notice cookie with base64 encoded flag.

![Pasted image 20250309173503](https://github.com/user-attachments/assets/c99d5c4b-8cc9-41c0-87ce-6395ad317770)

## head-dump

![Pasted image 20250307144842](https://github.com/user-attachments/assets/e8997a0b-4a5a-4b2d-9d6e-e32238be3cea)

Given access to a website, notice one of the links to API Docs is accessable.

![Pasted image 20250307145643](https://github.com/user-attachments/assets/4c8eb55a-9c1c-423d-ba43-59df2ca6b5ab)

API mentions a heapdump, getting the systems memory.

![Pasted image 20250307145907](https://github.com/user-attachments/assets/6caf9f7c-0fae-4bea-bbda-05c9cf0bf7f2)

Run strings on the output and get the flag.

![Pasted image 20250307145830](https://github.com/user-attachments/assets/5c19d08e-a3a0-4f09-8b00-429bf1716d17)

## n0s4n1ty

Given access to a php site with upload capabilitites. 

![Pasted image 20250307144525](https://github.com/user-attachments/assets/be0f381d-ee4b-4809-9983-a90599df5d73)

php reverse shell

![Pasted image 20250307144554](https://github.com/user-attachments/assets/e5bf540b-91ae-4fab-854a-a9105f2fa2d1)

![Pasted image 20250307144329](https://github.com/user-attachments/assets/8f0c6dac-472f-4677-aa53-23b42d759d3f)

## SSTI1

![Pasted image 20250307140618](https://github.com/user-attachments/assets/a8f91478-5b50-44c7-b636-fb7bb7c277c1)

Given access to a site with an input field vulnerable to SSTI. Go to payloadallthings to get a payload.

![Pasted image 20250307140557](https://github.com/user-attachments/assets/02fb8dd2-dc1c-4188-a32f-da32b7c645b6)

![Pasted image 20250307140638](https://github.com/user-attachments/assets/725a0c8c-c897-43f6-8b22-e9158c308d7f)

## WebSockFish

![Pasted image 20250309013017](https://github.com/user-attachments/assets/0f3ac981-6aba-4a2b-a421-e60b5dcd46f6)

Given access to a chess bot running on websockets. 

![Pasted image 20250309012954](https://github.com/user-attachments/assets/dba5fdaa-8f38-437c-befb-e408596f7ef8)

Notice socket sends a `confidence` variable as eval. Intercept and make the model ashamed.

![Pasted image 20250309012843](https://github.com/user-attachments/assets/aa80692c-e06c-4aa7-93df-94d7b0c3acfb)

## SSTI2

![Pasted image 20250307210631](https://github.com/user-attachments/assets/3cb63178-48eb-4c8b-8ae0-7411c86f93a7)

Given access to a site with an input field vulnerable to SSTI. This time there are blacklisted characters.

`https://www.onsecurity.io/blog/server-side-template-injection-with-jinja2/`

![Pasted image 20250308142636](https://github.com/user-attachments/assets/cb472ba1-5ecc-4e2f-aa06-f27bcbf347aa)

![Pasted image 20250308143010](https://github.com/user-attachments/assets/09af8164-9616-4fac-9405-8c6938ae995b)

# Cryptography

## hashcrack

![Pasted image 20250307131811](https://github.com/user-attachments/assets/64ee4c8a-446c-4651-8978-e9a64ea1f3f2)

Given nc connection to a host giving hashes to crack. Use hashcat to crack.

![Pasted image 20250307131936](https://github.com/user-attachments/assets/009e2e56-9f31-4dc9-8b2d-29894f042787)

![Pasted image 20250307131750](https://github.com/user-attachments/assets/55e28a11-1c63-4a85-889e-14a8bd0f8738)



## EVEN RSA CAN BE BROKEN???

## Guess My Cheese (Part1)

![Pasted image 20250307221024](https://github.com/user-attachments/assets/c424af9d-0209-449e-a329-05f7681b8ed8)

Given access to nc connection that wants you to decoded thier string. Input 2 guesses and the mouse encodes your strings with current encoder, 3rd attempt is to use that info to decode thier cheese. Run it a couple times and notice its a simple substitution. Plan is to pick 2 cheeses that have as many different letters as possible, map the transformation, apply that to the mouses cheese.

![Pasted image 20250307230040](https://github.com/user-attachments/assets/050d8e3e-0150-4045-8f91-f5f52114b622)

Get enough of the letters to google the rest.

![Pasted image 20250307230129](https://github.com/user-attachments/assets/092ee488-8a8e-4aff-b4fe-0d5609b3a207)

![Pasted image 20250307230108](https://github.com/user-attachments/assets/acb2bb12-d055-4bab-b1c9-e90f02e23eb4)

![Pasted image 20250307230015](https://github.com/user-attachments/assets/0a96acd1-a4c1-4c08-bc1e-52ef56668f28)



# Reverse Engineering

## Flag Hunters

![Pasted image 20250308144129](https://github.com/user-attachments/assets/4ad3ce79-07bc-44d1-8210-cafb39a0941f)

Python script to print. Notice flag is appended to a secret intro we typically never see.

![Pasted image 20250308144244](https://github.com/user-attachments/assets/5f1c04d4-4bef-452a-a017-d2cd40d65d03)

There is a match searching for `RETURN`. We can use a command injection using `;`, then returning to the secret intro. 

![Pasted image 20250308144213](https://github.com/user-attachments/assets/ade4ace4-e305-4d2d-bf75-23023b018281)


## Quantum Scrambler

![Pasted image 20250309192501](https://github.com/user-attachments/assets/a3fe9c80-98fe-4dce-8206-49d8272a7c61)

Given a python script

![Pasted image 20250309193033](https://github.com/user-attachments/assets/b3b14512-5cf9-4967-99c8-b28a5a834eea)

I first created a small script to convert the hex back to ascii

![Pasted image 20250309192656](https://github.com/user-attachments/assets/271128b1-cc1f-4a0c-8d8d-d9f0390e6b35)

My plan was to create a poc fake flag a-z1-9, then run the script on this to generate the poc-ciphertext. Becasue i know the actual order of the poc-ciphertext i will be able to map the output back the original input, then apply that same mapping to the flag-ciphertext.


![Pasted image 20250309192752](https://github.com/user-attachments/assets/05fe71bd-36b3-421c-a8a1-006d54405d55)

Small python script to get the indicies to the transformation.

![Pasted image 20250309192641](https://github.com/user-attachments/assets/ca4c96ae-8734-42fb-a7f3-6915f0468de5)

This will give us the key map


`key = [0, 1, 2, 3, 4, 7, 8, 13, 14, 23, 24, 39, 40, 65, 66, 107, 108, 175, 176, 285, 286, 463, 464, 751, 752, 1217, 1218, 1971, 1972, 3191, 3192]
`

With this mapping key we can get the indices from the flag cipher text


![Pasted image 20250309192817](https://github.com/user-attachments/assets/d0911b8f-1a65-426c-a20c-118ab89cb810)

![Pasted image 20250309192534](https://github.com/user-attachments/assets/57d6166a-5f8f-40d2-9192-b379b017ce80)


## perplexed

![Pasted image 20250309174001](https://github.com/user-attachments/assets/f79b35f4-93e9-48ae-9bc6-f1545392cec4)

Given elf

![Pasted image 20250309173943](https://github.com/user-attachments/assets/57a17a3e-cd9b-45f2-baca-8113dfb08f85)

In Ghidra looking at the main


![Pasted image 20250309174139](https://github.com/user-attachments/assets/aba52f42-f893-44fa-852b-151a92f457bf)

Check function in Ghidra

![Pasted image 20250309174241](https://github.com/user-attachments/assets/8fc0fa6f-d9e8-4576-9c50-1620afd5a181)


For some reason the real string is 26 not 27

![Pasted image 20250309182856](https://github.com/user-attachments/assets/541d7fb6-e0b9-4a8d-8f65-8f1f81f6b717)

