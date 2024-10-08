# baby_crypt

Given - ELF, dynamically linked

![image](https://github.com/user-attachments/assets/876cb84c-688a-4e82-b41f-611b8b0a2507)

![image](https://github.com/user-attachments/assets/3163cf8d-4f2f-41c0-9296-feac3e221ba5)

From this we can tell that it is XOR and the key is 4 bytes long. A loop runs from local_44 = 0 to local_44 < 0x1a (26 iterations), where 26 bytes of data are processed(The flag will be 
26 characters long).


We know that XOR is reversible so if we know the plaintext starts as HTB{ this should return the key

![image](https://github.com/user-attachments/assets/1fba98e8-c45a-47fd-8f71-857e99869610)

Using `w0wD` as the key we get the flag.

![image](https://github.com/user-attachments/assets/ed7c286c-8526-4d31-b13b-ef4cc2020c3d)


`HTB{x0r_1s_us3d_by_h4x0r!}`

