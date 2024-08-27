

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


```
Memory address = rbp− 0x4 = 0x00007fffffffdd70 − 0x4 = 0x00007fffffffdd6c
```

![image](https://github.com/user-attachments/assets/a2bff4c4-8d23-414a-b01c-f9f492220426)

```
picoCTF{0x6bc96222}
```
# GDB baby step 4

main calls a function that multiplies eax by a constant. The flag for this challenge is that constant in decimal base. If the constant you find is 0x1000, the flag will be picoCTF{4096}.

![image](https://github.com/user-attachments/assets/8e86c6a7-9453-40f6-9c6f-9475310bdf18)

![image](https://github.com/user-attachments/assets/e58cbcb1-429f-41d0-8ad9-3d4c50abb79c)

![image](https://github.com/user-attachments/assets/ef95681b-20d2-4727-b507-7e9f1ef964ef)

#ASCII FTW

This program has constructed the flag using hex ascii values. Identify the flag text by disassembling the program.
Given ELF 64-bit LSB pie executable, x86-64, version 1 (SYSV), dynamically linked.

Running the program gives a hint the the flag beings with 70

![image](https://github.com/user-attachments/assets/1d2568fa-4ce6-4c2c-af2e-0e1a85e9ee3b)


Each mov instruction moves a single byte value into a specific offset from rbp

![image](https://github.com/user-attachments/assets/ee442972-be93-496c-ac3e-a82ca06d767b)

Break after the hex has been moved

![image](https://github.com/user-attachments/assets/025a01b0-9634-4496-836b-b4ab66368abe)


# unpackme

Given ELF 64-bit LSB executable, x86-64, version 1 (GNU/Linux), statically linked

See the file is packed. Use upx.

![image](https://github.com/user-attachments/assets/bc9455ae-8f48-476e-b1ac-5602fdfa2d4d)

Running the binary

![image](https://github.com/user-attachments/assets/51ad7bcc-fe1f-41bd-ab6d-905efe0225e8)

Disassembling main we can see there is a cmp and a jmp

![image](https://github.com/user-attachments/assets/c1ff88e8-54f4-4792-8ecb-6be1e1a7467b)

![image](https://github.com/user-attachments/assets/d67c97b8-f51f-4eaf-ad34-d7effcfd6b05)

![image](https://github.com/user-attachments/assets/b227722e-cc11-4820-b05f-2be03b3c7720)


# Safe Opener

Given java file, see the password is base64 encoded

![image](https://github.com/user-attachments/assets/441c6b8c-05b0-42f6-ad07-0df03245548c)

# vault-door-1

Given java file. Checking the string index match a password.

![image](https://github.com/user-attachments/assets/5886f1f5-e4d0-4b76-b6fd-a4072fe779b4)


<details>

<summary>Python script to order the string</summary>



```python3

   import re

def parse_and_construct_password(input_string):
    # Create a list of 32 empty strings to hold the characters
    password = [''] * 32
    
    # Use regex to find all occurrences of password.charAt(index) == 'char'
    matches = re.findall(r"password\.charAt\((\d+)\)\s*==\s*'(\w)'", input_string)

    # Populate the password list based on extracted indices and characters
    for match in matches:
        index = int(match[0])  # Convert index to integer
        char = match[1]  # Extract character
        password[index] = char  # Place the character in the correct position

    # Join the list into the final string
    final_password = ''.join(password)
    return final_password

# The string containing the conditions
input_string = """
password.charAt(0)  == 'd' &&
password.charAt(29) == '3' &&
password.charAt(4)  == 'r' &&
password.charAt(2)  == '5' &&
password.charAt(23) == 'r' &&
password.charAt(3)  == 'c' &&
password.charAt(17) == '4' &&
password.charAt(1)  == '3' &&
password.charAt(7)  == 'b' &&
password.charAt(10) == '_' &&
password.charAt(5)  == '4' &&
password.charAt(9)  == '3' &&
password.charAt(11) == 't' &&
password.charAt(15) == 'c' &&
password.charAt(8)  == 'l' &&
password.charAt(12) == 'H' &&
password.charAt(20) == 'c' &&
password.charAt(14) == '_' &&
password.charAt(6)  == 'm' &&
password.charAt(24) == '5' &&
password.charAt(18) == 'r' &&
password.charAt(13) == '3' &&
password.charAt(19) == '4' &&
password.charAt(21) == 'T' &&
password.charAt(16) == 'H' &&
password.charAt(27) == 'f' &&
password.charAt(30) == 'b' &&
password.charAt(25) == '_' &&
password.charAt(22) == '3' &&
password.charAt(28) == '6' &&
password.charAt(26) == 'f' &&
password.charAt(31) == '0';
"""

# Parse the input string and construct the password
constructed_password = parse_and_construct_password(input_string)
print(f"picoCTF{{{constructed_password}}}")
```

</details>


# vault-door-3

![image](https://github.com/user-attachments/assets/6b5cb330-38e7-4809-bc0d-bb1e8d79055f)

<details>

<summary>Python equivelent to reverse</summary>


```
def check_password(password):
    if len(password) != 32:
        return False

    buffer = [''] * 32

    # First loop: Direct copy of the first 8 characters
    for i in range(8):
        buffer[i] = password[i]

    # Second loop: Reverse copy from 8 to 15
    for i in range(8, 16):
        buffer[i] = password[23 - i]

    # Third loop: Copy every second character from 16 to 31
    for i in range(16, 32, 2):
        buffer[i] = password[46 - i]

    # Fourth loop: Reverse copy every second character from 31 to 17
    for i in range(31, 16, -2):
        buffer[i] = password[i]

    # Return the modified buffer (if needed for further checks)
    return ''.join(buffer)

# Example usage:
password = "jU5t_a_sna_3lpm18gb41_u_4_mfr340"  # Replace with a 32-character password
result = check_password(password)
print(result)
```

</details>


# GDB Test Drive

Given ELF 64-bit LSB pie executable, x86-64, version 1 (SYSV), dynamically linked,

Object of this is to jump over sleep. Break over sleep then jump to next instruction

![image](https://github.com/user-attachments/assets/00dd9ce6-8e79-4bf4-a208-b10b587b036b)

![image](https://github.com/user-attachments/assets/23c9e965-9ae4-4618-b376-53ef997e32f6)

![image](https://github.com/user-attachments/assets/16bb362a-842c-4d51-bc81-c91b0431e84b)

# run 

Given ELF 64-bit LSB pie executable, x86-64, version 1 (SYSV), dynamically linked,

Running strings gives flag

![image](https://github.com/user-attachments/assets/1cb5702b-14f7-47bf-9b5d-e055a5bc4b15)

or just running it

![image](https://github.com/user-attachments/assets/0085dbd9-8e47-499e-b3e1-7684c755cac4)

# Investigative Reversing 1

This is found in forensics but... you know.

Given a binary and 3 .pngs

Binary is an ELF 64-bit LSB pie executable, x86-64, version 1 (SYSV), dynamically linked

All 3 pngs look pretty similar

Trying to cheese it, it looks like the trailing data is scrambled

![image](https://github.com/user-attachments/assets/5857a5d6-173d-470b-b93a-6b4cb55e885b)

![image](https://github.com/user-attachments/assets/61c1b705-2e77-4f68-8b7e-a29093d38a42)

Examining in Ghidra

![image](https://github.com/user-attachments/assets/6e6cd655-2905-4381-be17-fc44deaaa2d9)



