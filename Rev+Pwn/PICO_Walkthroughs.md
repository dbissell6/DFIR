

#  Transformation

Given an encoded string and a python function. 

```chr((byte1 << 8) + byte2)```

In this case, byte1 is shifted 8 bits to the left (<< 8), making it the high byte, and byte2 remains the low byte. The combination creates a 16-bit value that represents a single character.


<details>

<summary>Code for simple reverse</summary>

You can add text within a collapsed section. 

You can add an image or a code block, too.

```
with open('enc', 'rb') as enc_file:
   encoded_data = enc_file.read()


## Original 
## ''.join([chr((ord(flag[i]) << 8) + ord(flag[i + 1])) for i in range(0, len(flag), 2)])

original_bytes = b''.join([((ord(c) >> 8) & 0xFF).to_bytes(1, 'big') + (ord(c) & 0xFF).to_bytes(1, 'big') for c in encoded_data.decode('utf-8')])

# Step 3: Convert the byte string to the original string (if needed)
original_string = original_bytes.decode('utf-8')
print(original_string)

```

</details>

# vault-door-training

Given java file with flag/password in a comment

![image](https://github.com/user-attachments/assets/7f4bbcc2-02be-43c1-91e1-5d6e103af115)


# Picker 1

Given python script and access to an instance


![image](https://github.com/user-attachments/assets/4702e653-2854-4317-96bd-a70a0428521c)

Looking at source code notice the get random number is not random and that there are 2 other functions, 1 being win.

win calls opens the flag

![image](https://github.com/user-attachments/assets/1359fd27-8cc9-4bb6-947e-99cc68eee5fe)

![image](https://github.com/user-attachments/assets/08f899d5-61d9-4c8c-90ae-20f962611725)


![image](https://github.com/user-attachments/assets/a184ad16-b9f3-4b39-a855-daef89413cd8)

# Picker 2

Given python script and access to an instance

win function exists as before but now trying to call it gives illegal input.

![image](https://github.com/user-attachments/assets/e024aa02-3b26-4147-999d-897bbc280325)

It is being defined in a basic filter function

![image](https://github.com/user-attachments/assets/493d38fb-c570-4210-9d53-77253546a5e1)

Can bypass filter using eval

![image](https://github.com/user-attachments/assets/0f531549-04bb-4f5e-8a05-d27933f57f1a)

Hex or unicode encoding would work too

![image](https://github.com/user-attachments/assets/0236c0b9-013d-4a56-b9f6-7f9ccef07c56)


![image](https://github.com/user-attachments/assets/3509c3b9-5b77-4b17-b861-9b76e0986a25)

# Picker 3

Similar to previous 2.

![image](https://github.com/user-attachments/assets/758b2268-b0f6-480d-b9ed-1204759b4483)


# GDB baby step 1

The goal of this is to find what the value of eax is at the end of the main function

break on main, disassemble main, place break at end of main

![image](https://github.com/user-attachments/assets/d1ecafbd-d21d-4bf2-bda4-bfeacfd11314)

![image](https://github.com/user-attachments/assets/a68bec62-e5c9-41c8-88d3-8e09ad738fe1)

RAX (64-bit): This is the full 64-bit register, where RAX stands for the accumulator register in 64-bit mode.
EAX (32-bit): This is the lower 32 bits of the RAX register. If you modify EAX, the upper 32 bits of RAX (bits 63-32) are automatically zeroed out.

![image](https://github.com/user-attachments/assets/0a2475f7-9beb-4b9e-b8f3-55023b5d0946)

![image](https://github.com/user-attachments/assets/4ece128f-742d-4fd2-b79f-d3b3de685125)

![image](https://github.com/user-attachments/assets/b73955f2-6398-467b-ab38-0bf9fc3bbc31)

# GDB baby step 2

The goal of this is to find what the value of eax is at the end of the main function

Exact same as before

# GDB baby step 3

Now for something a little different. 0x2262c96b is loaded into memory in the main function. Examine byte-wise the memory that the constant is loaded in by using the GDB command x/4xb addr. The flag is the four bytes as they are stored in memory. If you find the bytes 0x11 0x22 0x33 0x44 in the memory location, your flag would be: picoCTF{0x11223344}.

![image](https://github.com/user-attachments/assets/7a3f9d72-54d2-4ac6-819c-6817e46dcc3b)

![image](https://github.com/user-attachments/assets/f770da28-d5ba-4810-adb3-64c21d6c5766)

![image](https://github.com/user-attachments/assets/d1201cb3-52d2-41c4-b1b4-1da2acaff6b7)

![image](https://github.com/user-attachments/assets/f73916b9-2f60-4f66-90b1-231aa3b0a4b3)


```
Memory address = rbp− 0x4 = 0x00007fffffffdd70 − 0x4 = 0x00007fffffffdd6c
```

![image](https://github.com/user-attachments/assets/a2bff4c4-8d23-414a-b01c-f9f492220426)

```
picoCTF{0x6bc96222}
```

