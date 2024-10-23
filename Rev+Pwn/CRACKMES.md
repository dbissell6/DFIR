# Keygen

Given ELF, dynmaically linked

![image](https://github.com/user-attachments/assets/f69311db-eefa-4fe7-9f32-963e0615a339)

In BinaryNinja can see the first check is making sure the serial length is 0x10 or 16

![image](https://github.com/user-attachments/assets/e1dc1b25-5097-4a3b-ae5a-e5f722a177db)

The rest of code extracts or transforms the two consecutive characters using the helper function sx.d(), 
and it checks if their difference is equal to 0xffffffff (or -1).

![image](https://github.com/user-attachments/assets/ee978964-47d8-4f7e-9645-3f3a338df381)



# Vending Machine

Given ELF, dynamically linked

![image](https://github.com/user-attachments/assets/ec912ae4-29d1-4c9a-a9c6-42c25d222aca)


![image](https://github.com/user-attachments/assets/47546f6b-25dc-4ce4-b58e-9bb2e77f2d0d)

Alright lets atleast see how it was supposed to work

![image](https://github.com/user-attachments/assets/d42be244-e8be-47fa-9565-e563479025fc)

Looks like its rust?

![image](https://github.com/user-attachments/assets/ae2bb0b2-3f00-46da-83eb-06734803d651)

This looks like the functionality for the show flag. lets try switching the logic

![image](https://github.com/user-attachments/assets/32f04dab-395d-4c88-8ed9-0cff6096f6b5)

![image](https://github.com/user-attachments/assets/0eeff11d-2d55-4bd8-ace2-c40ea2774ee9)

This works, no becasue the logic is flipped we can get the flag even if we dont have enough coins(we are deep in debt tho)

![image](https://github.com/user-attachments/assets/0a23c99c-d032-457e-88e0-b258f682711d)

As expected, there was an easier way, show flag has the flag clear text.

![image](https://github.com/user-attachments/assets/82022a4a-2be3-41e2-838b-9a68678bb321)

Finally we can find it in gdb. Find the function, set rip, continue

![image](https://github.com/user-attachments/assets/218cd7d2-12c9-4595-8fa6-609a5c34fdbf)

![image](https://github.com/user-attachments/assets/2d6659fa-f89c-4058-bd2b-8e2e47706bc9)

`flag{v3nd1ng_m4ch1n3_1s_4w3s0m3}`
