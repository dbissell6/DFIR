

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

# ASCII FTW

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

# Vault Door 4

![image](https://github.com/user-attachments/assets/0d092d9b-a2a8-49ab-9d7d-97731f959ad1)

![image](https://github.com/user-attachments/assets/038b4a40-f929-4401-adba-5269d5f4696b)

![image](https://github.com/user-attachments/assets/c048d20a-bced-4ed3-8f3b-e19b5e96fe53)

![image](https://github.com/user-attachments/assets/ab888974-522c-4cb2-9707-6806861e9484)


`picoCTF{jU5t_4_bUnCh_0f_bYt3s_c194f7458e}`

# Vault Door 5

![image](https://github.com/user-attachments/assets/b5d50a1c-6772-47be-ba85-28030e1b5271)


![image](https://github.com/user-attachments/assets/0ea7578e-98fd-4270-9ef0-7b069480bbbc)


# Vault Door 6


![image](https://github.com/user-attachments/assets/8a4442e8-ed46-4886-879e-67137c893694)

![image](https://github.com/user-attachments/assets/743dd7d8-7dae-421e-acf4-f5d18df3d6ed)

Basic XOR

![image](https://github.com/user-attachments/assets/d11d2e07-f77e-4ff8-8f4c-f8d646c30f92)

`picoCTF{n0t_mUcH_h4rD3r_tH4n_x0r_948b888}`

# Vault Door 6

![image](https://github.com/user-attachments/assets/64fe318b-7199-4f6d-9145-a9d3fd079c2c)


<details>

<summary>Python equivelent to reverse</summary>


```
def int_to_hex_string(int_value):
    # Convert integer to 4-byte hex and remove '0x' prefix
    return f'{int_value:08x}'

def reverse_password():
    # Given integers from the checkPassword function
    password_integers = [
        1096770097, 1952395366, 1600270708, 1601398833,
        1716808014, 1734304867, 942695730, 942748212
    ]
    
    # Convert each integer to its corresponding 8 hex characters
    hex_parts = [int_to_hex_string(i) for i in password_integers]
    
    # Combine the hex parts into the full password
    password = ''.join(hex_parts)
    
    return password

# Output the reversed password
reversed_password = reverse_password()
print("Reversed password:", reversed_password)

```

</details>

![image](https://github.com/user-attachments/assets/c01dce0f-9389-4d0d-a141-02df9b526e29)

![image](https://github.com/user-attachments/assets/24fea603-5f5b-4d3e-89e8-afc7e65a487e)

`picoCTF{A_b1t_0f_b1t_sh1fTiNg_dc80e28124}`

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

# Investigative Reversing 0


![image](https://github.com/user-attachments/assets/82cd0654-8c31-4f4a-8db8-d01c567f36b0)

![image](https://github.com/user-attachments/assets/f2ca4802-2292-4969-b6e0-f12be9eb79c0)



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

We can see the total length of the flag was 26

The first 4 characters are taken and added to the files. There are 3 small lopps to add the rest. 

Reversing getting the p 0x85-0x15 = 0x70
We can get the o by sing the loop iterate 4 times s - 4 = o

![image](https://github.com/user-attachments/assets/727a5626-0a24-4d1c-866d-9ce009853694)

![image](https://github.com/user-attachments/assets/121d73f5-29f3-40cb-9d0b-1b0dc1f42a57)


# Bit-o-asm-1

Can you figure out what is in the eax register? Put your answer in the picoCTF flag format: picoCTF{n} where n is the contents of the eax register in the decimal number base. If the answer was 0x11 your flag would be picoCTF{17}.

![image](https://github.com/user-attachments/assets/918f5f72-e3d3-42a5-85fe-24a0cf400f47)

![image](https://github.com/user-attachments/assets/b55b4572-d059-45c5-b94b-8d7ade4e6e82)

# Bit-o-asm-2

Same prompt as above

![image](https://github.com/user-attachments/assets/ba4f81d2-0182-4a41-aa14-9b3015f26fd7)

# Bit-o-asm-3

Same prompt as 1

![image](https://github.com/user-attachments/assets/31c33654-dd42-4edd-b5e7-731653a48e4c)

    Initial Setup:
        mov DWORD PTR [rbp-0xc], 0x9fe1a moves 0x9fe1a (which is 654874 in decimal) to [rbp-0xc].
        mov DWORD PTR [rbp-0x8], 0x4 moves 0x4 (which is 4 in decimal) to [rbp-0x8].

    Move to eax:
        mov eax, DWORD PTR [rbp-0xc] moves 0x9fe1a (654874) into eax.

    Multiplication:
        imul eax, DWORD PTR [rbp-0x8] multiplies eax by 4:
    654874×4=2619496
    654874×4=2619496

    Addition:
        add eax, 0x1f5 adds 501 to 2619496:
    2619496+501=2619997
    2619496+501=2619997

    



Conclusion:
    picoCTF{2619997}

Can also recompile and debug

![image](https://github.com/user-attachments/assets/293fe585-2469-4c94-9fe4-14f9adc6da97)


```
nasm -f elf64 -o program.o program.asm
ld -o program program.o  
```


![image](https://github.com/user-attachments/assets/ec31f80b-bf61-472c-8d9c-be2b25feb211)


![image](https://github.com/user-attachments/assets/d7a5898a-7e51-44fe-9106-f2dcb23addef)

# Bit-o-asm-4

Same prompt as 1

![image](https://github.com/user-attachments/assets/14ef9707-58d8-4c0d-b08a-eca5b9c4a1d9)

Here we see a cmp and a jle(Jump if less), Here 0x9fe1a is not less than 0x2700 so we dont jump. We hit the sub and subtract 0x9fe1a - 0x65 then jump over the add to the move. 

![image](https://github.com/user-attachments/assets/c9f00d00-9d46-4482-8eb0-8316fe1f0b2a)


# Bbbloat

ELF 64-bit LSB pie executable, x86-64, version 1 (SYSV), dynamically linked

Open in Ghidra, Notice a comparison

![image](https://github.com/user-attachments/assets/5b029cff-699b-4f03-8d29-a19dc876a921)

![image](https://github.com/user-attachments/assets/d64851e8-8fe1-43a7-8d9d-d5e246ff434f)

# Forky

Given ELF 32-bit LSB pie executable, Intel 80386, version 1 (SYSV), dynamically linked,



# Checkpass

Given ELF 64-bit LSB pie executable, x86-64, version 1 (SYSV), dynamically linked

![image](https://github.com/user-attachments/assets/4e78eca4-ad7d-4aeb-b076-7f9f9a028b17)


# reverse_cipher

![image](https://github.com/user-attachments/assets/3ed5f736-6e70-4852-a89c-b14d2b7bac2b)

even index - 5
odd index + 2


# patchme.py

![image](https://github.com/user-attachments/assets/08cafb25-3eee-49c3-b2cc-6519b89321b3)

![image](https://github.com/user-attachments/assets/5ba18e3b-4ac6-4a08-b131-090bc04ca0fc)

or

![image](https://github.com/user-attachments/assets/60b35cf2-6da1-42c1-b703-3b3696e4583e)

or

Change the logic of the check

![image](https://github.com/user-attachments/assets/d70e9863-7f97-40f6-bdaf-db8235999b2a)

![image](https://github.com/user-attachments/assets/db7565fd-c8ec-4edf-94fe-23a2e0dd3e55)

# Fresh Java

Given Java class data

![image](https://github.com/user-attachments/assets/b635d803-6f01-4c75-b5e2-798251fa8bf0)

![image](https://github.com/user-attachments/assets/a74f5469-e022-46cc-be24-256cb81555c8)

Looking in Ghidra can see the flag in reverse order

![image](https://github.com/user-attachments/assets/d27d9a48-0b67-4426-90fd-26e54b7ffff1)

Can also use
```
http://www.javadecompilers.com/
```

`
picoCTF{700l1ng_r3qu1r3d_738cac89}
`

# Bloat.py

given python script and flag

![image](https://github.com/user-attachments/assets/07179e80-364a-4a57-9d0e-2818cd905635)

Just change logic

![image](https://github.com/user-attachments/assets/ac0a9d4c-5b86-43b8-9860-580ccfbec68c)

![image](https://github.com/user-attachments/assets/29d5fcef-0e79-44ac-8f61-43294cff340c)

# unpackme.py

Given python script

![image](https://github.com/user-attachments/assets/56c377b5-804f-435b-8ad5-189ee58aa978)

Easiest method to solve is place prints

![image](https://github.com/user-attachments/assets/8d0249b8-9832-4431-bc0c-1374d4b2e368)


`picoCTF{175_chr157m45_5274ff21}`

# keygen-trial.py

Given python script with 1/3 and last third of flag in plain text.

![image](https://github.com/user-attachments/assets/7b029f7a-3746-4638-b47c-026b30eed953)




# Keygenme

Given ELF, dynamically linked

![image](https://github.com/user-attachments/assets/d420d2d4-ac22-4036-a404-00793eb847bb)


# Droids1 

Given Android package (APK)

![image](https://github.com/user-attachments/assets/4abb12ea-a767-4b92-a9fc-b889e68097fe)

# Lets Get Dynamic

Given Assembler source

![image](https://github.com/user-attachments/assets/7d619eb7-13f6-4f2e-a849-b842ce264253)

# OTP Implementation

Given ELF, Dynamically Linked and flag.txt

![image](https://github.com/user-attachments/assets/0ae3e9dc-3c25-4390-957e-7f6155715546)


Looking into ghidra can see some  jumple function and the clear string of what the key should be

![image](https://github.com/user-attachments/assets/629a7677-7570-4303-b087-a66825c22413)


![image](https://github.com/user-attachments/assets/ef5bfb30-6054-4b40-a354-b065e08867ed)

<details>

<summary>Python script to brute it</summary>


```
import re
from subprocess import Popen, PIPE, DEVNULL

# Known target string from the program (for comparison)
target = "jbgkfmgkknbiblpmibgkcneiedgokibmekffokamknbkhgnlhnajeefpekiefmjgeogjbflijnekebeokpgngjnfbimlkdjdjhan"

# Create a list to store the current guess for the key
key = ['a'] * len(target)

# Iterate over the length of the target
for i in range(len(target)):
    for x in '0123456789abcdef':
        key[i] = x
        p = Popen(['ltrace', '-s', '1000', './otp', ''.join(key)], stderr=PIPE, stdout=DEVNULL)
        output = p.stderr.read().decode()
        
        # Extract the matched string from the program's output
        match = re.search(r'strncmp\("(.+)"', output)
        
        if match:
            result = match.group(1)[:len(target)]  # Compare only up to the target length
            
            # Debugging: print the current match and target comparison
            print(f"Matching at index {i}:")
            print(f"Result: {result}")
            print(f"Target: {target[:i+1]}")
            
            if target[i] == result[i]:
                print(f"Correct guess at index {i}: {x}")
                break
            else:
                print(f"Incorrect guess at index {i}: {x}")

# After constructing the key, output the final guessed key
key_string = ''.join(key)
print(f"Found key: {key_string}")

def xor_hex_strings(flag_hex, key_string):
    # Convert both hex strings to bytes
    flag_bytes = bytes.fromhex(flag_hex)
    key_bytes = bytes.fromhex(key_string)

    # XOR the bytes
    result = bytes(a ^ b for a, b in zip(flag_bytes, key_bytes * (len(flag_bytes) // len(key_bytes) + 1)))

    # Convert the result back to a string (or to ASCII if it's readable)
    return result.decode('utf-8')



# Read the flag from flag.txt
with open('flag.txt', 'r') as flag_file:
    flag_hex = flag_file.read().strip()

# XOR them together
decoded_flag = xor_hex_strings(flag_hex, key_string)

# Print the decoded flag
print(f"Decoded flag: {decoded_flag}")


```

</details>

We can see its just hex and a 1 to 1 relationship

![image](https://github.com/user-attachments/assets/ac2991f1-f125-4fd1-9040-774e2bd5ecfd)


`picoCTF{cust0m_jumbl3s_4r3nt_4_g0Od_1d3A_50869043}`
