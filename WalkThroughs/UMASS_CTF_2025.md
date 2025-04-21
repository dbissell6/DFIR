# UMASS CTF 2025

![Pasted image 20250418113033](https://github.com/user-attachments/assets/a9854986-b842-44d4-aec8-ed87f2513c98)

## No Updates


![Pasted image 20250418120806](https://github.com/user-attachments/assets/18ee5314-aade-453d-86d0-46c1ede9470d)


Given Pcap

Run strings

![Pasted image 20250418120830](https://github.com/user-attachments/assets/e23f663f-d44a-44bd-930e-ffdb45b74ae6)

In Wireshark


![Pasted image 20250418125209](https://github.com/user-attachments/assets/04113ed3-254c-4153-8c0f-9509b6fae375)


`UMASS{n07_ag41n_d4mn_y0u_m3t4spl017}`


## Macrotrace


![Pasted image 20250418205959](https://github.com/user-attachments/assets/975c6082-c17c-4d86-9e41-077f061245e7)


![Pasted image 20250418210116](https://github.com/user-attachments/assets/e3d33a6a-acfa-44e4-8b9c-0aa924f44971)


See base64 encoded string in ScriptBlocks


![Pasted image 20250418210850](https://github.com/user-attachments/assets/830ec16d-7b55-415c-be69-1bf6cf2b0c71)




![Pasted image 20250418210828](https://github.com/user-attachments/assets/ed51a3a0-7bcf-4ff7-ac34-6bf5ff778d0f)


## Real Forensics

![Pasted image 20250419234931](https://github.com/user-attachments/assets/7adccce1-bfbf-4bc8-8da3-a05967b9f755)



Given pcap

Notice it has pdf![Pasted image 20250420004940](https://github.com/user-attachments/assets/0c6552b8-331b-40e7-815e-830ab10c4eda)


pdf has sus JavaScript.






![Pasted image 20250419235143](https://github.com/user-attachments/assets/c8d728a5-1ac1-4dc7-962b-ec735cc8eee2)




![Pasted image 20250420001423](https://github.com/user-attachments/assets/4d6cd2ac-551f-4abd-94a4-5f5b6e48ac7f)


Here we can see the full http get/post.

![image](https://github.com/user-attachments/assets/dd65e222-1bd1-4f8c-b892-a1627f31b894)

malicious PDF with javascript, downloads `helpful_tool` downloads/ decrypts bat which downloads exe thats basically a reverse shell.


`helpful_tool` get decrypted and see its rc4

![Pasted image 20250419235106](https://github.com/user-attachments/assets/135a3931-e80e-45b1-a4e5-4a1a502b636b)

Decode to find an executable.


![Pasted image 20250419235245](https://github.com/user-attachments/assets/d95f94c6-901b-4c6e-8858-f28ff50dfda6)

Running the exe, we see that it is trying to reach out to `michealsoft`. Set up /etc/hosts as local to that. Can see that it reads `network_check` as the command and send the results backs as `telemetry`.

The next issue is its try to GET `network_check`, if we provide one from the pcap we can see the command its running.





![Pasted image 20250419235328](https://github.com/user-attachments/assets/516ab195-6e84-45f1-aea1-21884cd31607)


This is the get flag command

![Pasted image 20250419203142](https://github.com/user-attachments/assets/bf36d815-9d9d-4b3e-beb5-03e406841711)



![Pasted image 20250420010448](https://github.com/user-attachments/assets/6a4e8eb4-fc33-4d44-a7ab-c270232c7735)

The last part was sending the flag in through the exe and breaking on the decryption.




















