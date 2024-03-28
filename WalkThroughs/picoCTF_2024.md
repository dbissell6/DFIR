# picoCTF 2024

![image](https://github.com/dbissell6/DFIR/assets/50979196/4de72966-4dd8-40bf-a37b-20ea64f55fb3)


## Forensics

### Scan Surprise - 50

given .png of qrcode. just need to follow to get flag. 
use ```https://webqr.com/index.html```

![Pasted image 20240312165751](https://github.com/dbissell6/DFIR/assets/50979196/2e1940b9-6aa6-4b8a-a61a-6fcb8e007415)

![image](https://github.com/dbissell6/DFIR/assets/50979196/8ad68b5a-1b86-4549-acd9-c77827a20379)


### Verify - 50

Given script that decrypts files and a folder with a bunch of files. Only thing to do was change the script to match the folders on my system.


![Pasted image 20240312170521](https://github.com/dbissell6/DFIR/assets/50979196/dc15e5d5-ce98-49ca-96c1-afdcd1ff08b4)

![Pasted image 20240312170430](https://github.com/dbissell6/DFIR/assets/50979196/019e506f-91de-49f5-bde8-c67852e61ef9)

### CanYouSee - 100

Given .jpg

![Pasted image 20240312171923](https://github.com/dbissell6/DFIR/assets/50979196/532bfcd9-e87f-444a-899a-3bd4b6df9ff0)

![Pasted image 20240312171909](https://github.com/dbissell6/DFIR/assets/50979196/0aa0b7f7-0d97-418b-b408-23cfcfd9634b)


### Secret of the Polyglot - 100

Given a file that can be read as a pdf or png. Each view shows a part of the flag

![Pasted image 20240313020611](https://github.com/dbissell6/DFIR/assets/50979196/0d64c18f-14d0-4cd2-bb16-8c1e2c2ee493)

![Pasted image 20240313020559](https://github.com/dbissell6/DFIR/assets/50979196/d477e61a-a3d1-4721-b35a-7ae5d44c9891)

### Mob psycho - 200

Given .apk. can use apktool or just unzip it.

![Pasted image 20240314221334](https://github.com/dbissell6/DFIR/assets/50979196/9222d396-c9e4-45f9-93c8-1a3b14bada06)

![Pasted image 20240314221317](https://github.com/dbissell6/DFIR/assets/50979196/71c1a02c-74b3-4e8c-b344-ce59a6894b10)


### endianness-v2 - 300

Given file of unknown type.

Take the title hint to mess around with endianness and notice image header.

![Pasted image 20240313130107](https://github.com/dbissell6/DFIR/assets/50979196/3f838ed1-0ce2-4729-9d17-a57d525c1d04)

![Pasted image 20240313130052](https://github.com/dbissell6/DFIR/assets/50979196/cb8a8106-796d-4698-94c5-994a30b5d820)


### Blast from the past - 300

Object was be given an .jpg and change the metadata timestamps to  date.  Was able to use exiv2 and exiftool to change most of the timestamps with the exeption of the last task. Biggest take away was ```exiftool -v3``` will show where in the file/hex it used to pull that metadata. This allowed me to go into the .jpg with hexedit and manually change the last time stamp.

```
exiftool '-DateTimeOriginal=1970:01:01 00:00:00' '-SubSecTimeOriginal=001' original.jpg  
```
```
exiftool '-ModifyDate=1970:01:01 00:00:00' '-SubSecModifyDate=001' original.jpg
```
```
exiftool '-SubSecCreateDate=1970:01:01 00:00:00.001' original.jpg
```
```
exiv2 -M"set Exif.Image.DateTime 1970:01:01 00:00:00.001" -M"set Exif.Photo.DateTimeOriginal 1970:01:01 00:00:00.001" -M"set Exif.Photo.DateTimeDigitized 1970:01:01 00:00:00.001" -M"set Exif.Photo.SubSecTime 001" -M"set Exif.Photo.SubSecTimeOriginal 001" -M"set Exif.Photo.SubSecTimeDigitized 001" '-CreateDate=1970:01:01 00:00:00.001' original.jpg
```

To change the last timestamp

![Pasted image 20240318164217](https://github.com/dbissell6/DFIR/assets/50979196/08a2629c-a76d-41c8-bfe7-cc6bc3fe4c86)


hexedit F4 to go to address

![Pasted image 20240318164119](https://github.com/dbissell6/DFIR/assets/50979196/d34df64a-0f70-43e4-8303-eb112ea2443f)

Have to submit file over nc.

![Pasted image 20240318164149](https://github.com/dbissell6/DFIR/assets/50979196/bbcde96d-33d5-4d8f-9f22-cacbe63be3b1)

## General Skills

### Commitment Issues - 50

Given directory and notice .git

![Pasted image 20240312165313](https://github.com/dbissell6/DFIR/assets/50979196/b9eaedbe-5de4-4596-9632-846b17e4d665)


### Time Machine - 50

Really similar to above

![Pasted image 20240312185731](https://github.com/dbissell6/DFIR/assets/50979196/7cc3ef85-dcf3-41a4-8a95-703008f43b2c)


### Blame Game - 75

Another really similar to above

![Pasted image 20240312231800](https://github.com/dbissell6/DFIR/assets/50979196/42667cc2-2c8c-4032-b66a-846cf9a02e9b)

### Collaborative Development - 75

Similar to above, this time we are using checkout on different branches.

![Pasted image 20240312232308](https://github.com/dbissell6/DFIR/assets/50979196/e4b7550d-3509-4345-83ee-14077f7179f7)

![Pasted image 20240312232251](https://github.com/dbissell6/DFIR/assets/50979196/9ec0fe3e-7978-4c29-8395-3a2d3c77f216)

### binhexa - 100

This required us to offer a series of challenges doing binary operations. Using a bitwise calculater

used this site + gpt 
https://codebeautify.org/bitwise-calculator

![image](https://github.com/dbissell6/DFIR/assets/50979196/edcf2f4f-507c-47e0-ad0d-52d7ee020fec)

![image](https://github.com/dbissell6/DFIR/assets/50979196/955ab67d-557a-49a1-904d-a86f77a75d64)

![image](https://github.com/dbissell6/DFIR/assets/50979196/3a2cf0dd-8e60-4f1d-870f-ae287d0975b1)


### Binary Search - 100

Want to play a game? As you use more of the shell, you might be interested in how they work! Binary search is a classic algorithm used to quickly find an item in a sorted list. Can you find the flag? You'll have 1000 possibilities and only 10 guesses.

Strat is to keep cutting in half. 

![Pasted image 20240312230245](https://github.com/dbissell6/DFIR/assets/50979196/7e36fac9-4795-40d3-bff2-13b8f1e7befe)

### endianness - 200

The challenge consisted in giving the player a word and having them submit the hex big and little endian.
I was able to solve it by stripping out the functions from the source code. I started the challenge, it gave me a word, and i put that into the new frankenstein function to get the answers.

![Pasted image 20240313010343](https://github.com/dbissell6/DFIR/assets/50979196/12330465-9b80-420c-a4c1-bfeb5e478f53)

![Pasted image 20240313010423](https://github.com/dbissell6/DFIR/assets/50979196/0edcedcc-eb98-456c-9450-534d27071c41)

<details>

<summary>code for little+big endian</summary>


```
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

// Function prototypes

char *find_little_endian(const char *word)
{
    size_t word_len = strlen(word);
    char *little_endian = (char *)malloc((2 * word_len + 1) * sizeof(char));

    for (size_t i = word_len; i-- > 0;)
    {
        snprintf(&little_endian[(word_len - 1 - i) * 2], 3, "%02X", (unsigned char)word[i]);
    }

    little_endian[2 * word_len] = '\0';
    return little_endian;
}

char *find_big_endian(const char *word)
{
    size_t length = strlen(word);
    char *big_endian = (char *)malloc((2 * length + 1) * sizeof(char));

    for (size_t i = 0; i < length; i++)
    {
        snprintf(&big_endian[i * 2], 3, "%02X", (unsigned char)word[i]);
    }

    big_endian[2 * length] = '\0';
    return big_endian;
}



int main(int argc, char *argv[])
{
    // Check if a word was passed as a command-line argument
    if (argc != 2) {
        fprintf(stderr, "Usage: %s <word>\n", argv[0]);
        return EXIT_FAILURE;
    }
    // Replace "pykbx" with the word given by the challenge.
    const char *challenge_word = argv[1]; // word.
    printf("Word: %s\n", challenge_word);
    fflush(stdout);

    // Find and print the little endian representation.
    char *little_endian = find_little_endian(challenge_word);
    printf("Little Endian representation: %s\n", little_endian);
    fflush(stdout);
    free(little_endian); // Don't forget to free the memory.

    // Find and print the big endian representation.
    char *big_endian = find_big_endian(challenge_word);
    printf("Big Endian representation: %s\n", big_endian);
    fflush(stdout);
    free(big_endian); // Don't forget to free the memory.

    // The rest of the code is no longer needed, since we're not checking user input.
    return 0;
}
```

</details>


### dont-you-love-banners - 300

Use nc to find ssh banner + password.

![Pasted image 20240313132655](https://github.com/dbissell6/DFIR/assets/50979196/2228472c-f99b-4238-ac01-d7fbd14a8997)

Next we are given another port to answer questions. For whatever my reason terminal kept crashing here, regardless how I entered the answers, used pwnbox to log in.(Ive noticed nc connections in general not being stable)

![Pasted image 20240313132616](https://github.com/dbissell6/DFIR/assets/50979196/caee6c85-b183-4824-a265-5e5365666d86)

Below is the last step, a classic priv esc. We can see the script is being ran as root and is printing the banner, from the file banner. The goal is to get the script to print the flag, we cant change the script but we can modify the banner file. 

![Pasted image 20240314205942](https://github.com/dbissell6/DFIR/assets/50979196/a0564b9b-c490-47e6-baa3-93a0c4040a44)

Create a symbolic link banner /root/flag.txt. Stress importance of script being ran as root here. 

![Pasted image 20240314210239](https://github.com/dbissell6/DFIR/assets/50979196/7877cade-4d3c-4448-82ec-5ace7507a8ea)

Now we can log out and log back in

![Pasted image 20240314210325](https://github.com/dbissell6/DFIR/assets/50979196/595d803f-e1c4-43e5-b77d-ac0cf3d3884b)

## Reverse Engineering

### packer - 100

Given a packed binary. Unpack it and run strings.

![Pasted image 20240312180541](https://github.com/dbissell6/DFIR/assets/50979196/c46f09fd-8c16-4bc0-a60a-ae261f29f947)

![Pasted image 20240312180454](https://github.com/dbissell6/DFIR/assets/50979196/1f193cc1-7881-4e91-ba80-a7292f078f3e)

![Pasted image 20240312180513](https://github.com/dbissell6/DFIR/assets/50979196/368012ab-5118-41f7-ba42-f05032e77bb8)

### FactCheck - 200

Given bin, dynamically linked.

Open up in ghidra looking at main can see first half of flag and a lot of nonsense.

![image](https://github.com/dbissell6/DFIR/assets/50979196/8b434046-cb54-449e-b1b5-3bc8549624fc)

We know im not doing this statically, Start debugging with gdb and set break somewhere before the bin closes itself.

break main; run; dissassemble main; b *0x0000555555555956; c

![image](https://github.com/dbissell6/DFIR/assets/50979196/351213db-1db5-4872-aa68-1823162b764d)


### WinAntiDbg0x100 - 200

given .exe must patch. 
Flip logic on this JZ to JNZ

![Pasted image 20240313142444](https://github.com/dbissell6/DFIR/assets/50979196/c5ecebb8-2600-431b-8403-b714ffeb2b3e)

### WinAntiDbg0x200 - 300

line 65 if cvar \0 should be flipped
same with 67
I also flipped like 15 up top looking for admin permissions.

![Pasted image 20240313151231](https://github.com/dbissell6/DFIR/assets/50979196/f67f7c4e-b1f9-4711-b678-4bd5341837e1)


![Pasted image 20240313152845](https://github.com/dbissell6/DFIR/assets/50979196/f68b4a8d-65ae-487b-93f9-ab87d6a4b00d)



### WinAntiDbg0x300 - 400

Given .exe, .pdb, config.bin



![image](https://github.com/dbissell6/DFIR/assets/50979196/3117f401-e17e-43a0-8e77-dea0dc503bda)

![image](https://github.com/dbissell6/DFIR/assets/50979196/084afef3-ad1d-4f99-a8ac-00de81067b4e)



### Classic Crackme 0x100 - 300

given elf dynamically linked

![image](https://github.com/dbissell6/DFIR/assets/50979196/4bb3b3c3-9e22-4d72-89f8-173e4b2f3d26)

Show basic execution and failed attempt

![image](https://github.com/dbissell6/DFIR/assets/50979196/4ba2801e-e09f-4f1a-9776-78ba76c2164e)

Use ltrace and notice some canadities for LD_PRELOAD

![image](https://github.com/dbissell6/DFIR/assets/50979196/c6e85eb8-508c-451d-b290-f095bd8eb26a)

Using LD preload can see the actual of data being compared. This is helpful becasue the string we are entering is getting transformed before being compared.

![image](https://github.com/dbissell6/DFIR/assets/50979196/613ccf07-d5aa-4787-9f6f-fb45a1273dc6)

After playing around here for a little bit i notice that they are expecting a string of length 50 and they will all be 50 lowercase. I discovered this with the first broken challenge.

![Pasted image 20240313013320](https://github.com/dbissell6/DFIR/assets/50979196/db140389-488e-46d2-8373-b8ea7b92d77c)

When i tried submitting above it failed, so i waited a couple days and a new chall was released. 

![Pasted image 20240315121650](https://github.com/dbissell6/DFIR/assets/50979196/f10add9e-d9af-4d61-9a10-ae913c4d707a)

But going back, i noticed the relationship, how did i get the actual string that needed to be submitted? I created a python script. The script works by creating a string of 50 a's and submitting it, then it goes through the trandformed list and the expected list index by index, whichever are overlaping means in our final string 'a' will need to be at that index. Do this for a-z.

<details>

<summary>python script to get string </summary>


```
import subprocess
import re
import string

# Command to run the binary
command = ['./crackme100']

# Preload the shared library
env = {'LD_PRELOAD': './memcmp_hook.so'}

# Regex pattern to find the compared data (s1)
pattern_s1 = re.compile(r'Compared data \(s1\): ([^\n]+)')

# Known hexadecimal string from the program output (replace with the actual string)
# Assuming this string is the hex representation of the 'password' s2 data.
# Convert the hex string to ASCII
known_hex_s2 = "7A7471697474777478746965796672736C67747A75786F766C66646E6272736E6C72767968687364787872666F786E6A626C"
known_s2 = bytes.fromhex(known_hex_s2).decode('utf-8')

# Dictionary to store the correct characters
correct_characters = {}

# Iterate over each letter in the lowercase alphabet
for index in range(len(known_s2)):
    for letter in string.ascii_lowercase:
        # Generate the password with the current letter at the correct position
        password = ''.join(correct_characters.get(i, letter) for i in range(len(known_s2)))

        # Run the binary and send the password
        proc = subprocess.Popen(command, env=env, stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        stdout, stderr = proc.communicate(input=password.encode())

        # Decode the output and search for the s1 data
        output = stdout.decode()
        match_s1 = pattern_s1.search(output)
        if match_s1:
            s1_data = match_s1.group(1).replace(' ', '')  # Remove spaces from the hex string
            s1_bytes = bytes.fromhex(s1_data)  # Convert the hex string to bytes
            s1_char = s1_bytes[index]  # Get the character at the current index

            # Check if the character in s1 matches the known character in s2 at the current index
            if s1_char == ord(known_s2[index]):
                # If it matches, store the letter as the correct character for this index
                correct_characters[index] = letter
                break  # Go to the next character index

# Now, construct the correct s1 based on the correct characters found
final_s1 = ''.join(correct_characters.get(i, '?') for i in range(len(known_s2)))

print(f"The constructed s1 string is: {final_s1}")
```

</details>

<details>

<summary>memcmp hook for working solution</summary>


```
#include <stdio.h>
#include <dlfcn.h>
#include <string.h>
#include <ctype.h>

typedef int (*original_memcmp_t)(const void *, const void *, size_t);

static original_memcmp_t original_memcmp;

int memcmp(const void *s1, const void *s2, size_t n) {
    // Ensure we have the original function
    if (!original_memcmp) {
        original_memcmp = (original_memcmp_t)dlsym(RTLD_NEXT, "memcmp");
    }

    // Print the compared data in hexadecimal
    printf("Compared data (s1): ");
    for (size_t i = 0; i < n; ++i) {
        printf("%02X", ((unsigned char *)s1)[i]);
    }
    printf("\n");

    printf("Compared data (s2): ");
    for (size_t i = 0; i < n; ++i) {
        printf("%02X", ((unsigned char *)s2)[i]);
    }
    printf("\n");

    // Call the original memcmp function
    return original_memcmp(s1, s2, n);
}

// Compile with:
// gcc -fPIC -shared -o memcmp_hook.so memcmp_hook.c -ldl
```

</details>

Ive include the memcmp from the broken chall becasue one is getting hex the other was getting ascii, thats the only real difference.

<details>

<summary>memcmp hook for broken chall</summary>


```
import subprocess
import re
import string

# Command to run the binary
command = ['./crackme100']

# Preload the shared library
env = {'LD_PRELOAD': './memcmp_hook.so'}

# Regex pattern to find the compared data (s1)
pattern_s1 = re.compile(r'Compared data \(s1\): ([^\n]+)')

# Placeholder for the known 'password' s2 data.
# You need to run the program once with the correct password to get this
# Or if it's provided by the challenge, replace it below.
known_s2 = "xjagpediegzqlnaudqfwyncpvkqneusycourkguerjpzcbstcc"

# Dictionary to store the correct characters
correct_characters = {}

# Iterate over each letter in the lowercase alphabet
for index, known_char in enumerate(known_s2):
    for letter in string.ascii_lowercase:
        # Generate the password of the same length as known_s2
        password = letter * len(known_s2)
        
        # Run the binary and send the password
        proc = subprocess.Popen(command, env=env, stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        stdout, stderr = proc.communicate(input=password.encode())

        # Decode the output and search for the s1 data
        output = stdout.decode()
        match_s1 = pattern_s1.search(output)
        if match_s1:
            s1_data = match_s1.group(1)

            # Check if the character in s1 matches the known character in s2 at the current index
            if s1_data[index] == known_char:
                # If it matches, store the letter as the correct character for this index
                correct_characters[index] = letter
                break  # Go to the next character index

# Now, construct the correct s1 based on the correct characters found
final_s1 = ''.join(correct_characters.get(i, '?') for i in range(len(known_s2)))

print(f"The constructed s1 string is: {final_s1}")
```

</details>
