# baby_crypt

Given - ELF, dynamically linked

![image](https://github.com/user-attachments/assets/876cb84c-688a-4e82-b41f-611b8b0a2507)

![image](https://github.com/user-attachments/assets/3163cf8d-4f2f-41c0-9296-feac3e221ba5)

From this we can tell that it is XOR and the input is 4 bytes long. A loop runs from local_44 = 0 to local_44 < 0x1a (26 iterations), where 26 bytes of data are processed(The flag will be 26 characters long). But only the first 3 bytes of the input/key are being used


We know that XOR is reversible so if we know the plaintext starts as HTB{ this should return the key

![image](https://github.com/user-attachments/assets/1fba98e8-c45a-47fd-8f71-857e99869610)

Using `w0wD` as the key we get the flag.

![image](https://github.com/user-attachments/assets/ed7c286c-8526-4d31-b13b-ef4cc2020c3d)


`HTB{x0r_1s_us3d_by_h4x0r!}`

# Baby RE

Given ELF, dynamically linked

![image](https://github.com/user-attachments/assets/f8ea03d0-f10f-4b80-9ea7-c772cfafdf12)

![image](https://github.com/user-attachments/assets/64609d78-ca4c-4fdd-820e-353dd2ae34d7)


![image](https://github.com/user-attachments/assets/7fa7da9f-8d3e-4689-a00a-c09784dd4d61)

strace

![image](https://github.com/user-attachments/assets/848b5350-4d8c-42a0-908b-6bd007d671b4)


LD preload


![image](https://github.com/user-attachments/assets/30703a0d-8415-44ac-8a76-4899c6c28d99)

<details>

<summary>strcmp_hook.c</summary>


```
   #include <stdio.h>
#include <dlfcn.h>
#include <string.h>
#include <ctype.h>

typedef int (*original_strcmp_t)(const char *, const char *);

static original_strcmp_t original_strcmp;

int strcmp(const char *s1, const char *s2) {
    // Ensure we have the original function
    if (!original_strcmp) {
        original_strcmp = (original_strcmp_t)dlsym(RTLD_NEXT, "strcmp");
    }

    // Print the compared strings as clear text characters
    printf("Compared string (s1): ");
    for (size_t i = 0; s1[i] != '\0'; ++i) {
        unsigned char c = (unsigned char)s1[i];
        putchar(isprint(c) ? c : '.'); // Print a dot for non-printable characters
    }
    printf("\n");

    printf("Compared string (s2): ");
    for (size_t i = 0; s2[i] != '\0'; ++i) {
        unsigned char c = (unsigned char)s2[i];
        putchar(isprint(c) ? c : '.'); // Print a dot for non-printable characters
    }
    printf("\n");

    // Call the original strcmp function
    return original_strcmp(s1, s2);
}

// Compile with:
// gcc -fPIC -shared -o strcmp_hook.so strcmp_hook.c -ldl

```

</details>

![image](https://github.com/user-attachments/assets/6952c08d-0cb0-43cc-9bf8-cce46b653aa0)

![image](https://github.com/user-attachments/assets/c15db02a-1531-404c-b9a7-104407eb4a74)

`HTB{B4BY_R3V_TH4TS_EZ}`

# Eat The Cake

Given .exe, UPX compressed

![image](https://github.com/user-attachments/assets/1517b7e2-9179-48f7-814e-65241a99c65b)

![image](https://github.com/user-attachments/assets/0bc74b9b-c51b-464b-8417-eb12b1e8a320)

Can find logic 

![image](https://github.com/user-attachments/assets/f2ca5a4d-f27c-4e98-afa2-6c7b00198398)

password length 10 has no checks, 15 only checks if characters are right. In the first check we only see 11 letters. Opening up the function that defines var 2 we can see the last 4 letters.

![image](https://github.com/user-attachments/assets/483bae80-6689-4b75-b775-429beeeab281)

Put these in order and have.

`HTB{h@ckth3parad1$E}`

# Find the Easy Pass

Given .exe

![image](https://github.com/user-attachments/assets/27c400ff-d6cf-42cc-9f4b-69519dd0f29b)

Testing the exe out with wrong password we see that is what is displayed if we get it wrong. So we can search these strings to find the functionality/logic to determine if our password is correct or not 

![image](https://github.com/user-attachments/assets/82693118-2d0b-4da1-bf1b-9cabcbd8db9e)

![image](https://github.com/user-attachments/assets/430df19a-24d3-46df-88dc-4150e6e2261d)


![image](https://github.com/user-attachments/assets/3ffe41d2-34c3-4ec3-9eb2-44558e7fedbb)

`HTB{fortran!}`

# HIssss

Given ELF, synamically linked

![image](https://github.com/user-attachments/assets/d2d26565-0653-4a4a-993f-2f376480b037)

Running strings notice lots of python 

![image](https://github.com/user-attachments/assets/549538e5-3568-457a-95e8-fa30c3b12e7e)

Slightly broken

![image](https://github.com/user-attachments/assets/2e931c0f-c589-4aeb-a376-4377eb30a30c)

This is better

![image](https://github.com/user-attachments/assets/ba92b453-c62d-46c7-8657-abdd21ea6e17)


![image](https://github.com/user-attachments/assets/496876da-399f-4f78-a5d7-1a123775aa03)

Little suduko like logic puzzle.

![image](https://github.com/user-attachments/assets/a1ca7891-0831-43c7-8f96-8013cb4fef4f)


![image](https://github.com/user-attachments/assets/be5e2320-1318-48fe-8bf9-4b628d441314)


`HTB{0p3n_s3sam3!}`

# Hunting License

Given ELF, dynamically linked

![image](https://github.com/user-attachments/assets/89e126b9-2d34-4bf8-ab80-1d3364b67c87)

Can use ltrace to find the passwords

![image](https://github.com/user-attachments/assets/8d109f34-aefb-448d-828c-7203438742b9)


![image](https://github.com/user-attachments/assets/f48dac2c-98c9-478f-a136-ab80dfabfcd4)

![image](https://github.com/user-attachments/assets/dc03a541-a0bd-4c25-b389-4dc7c4e4c900)


# IRCWare

Given ELF, dynamically linked

![image](https://github.com/user-attachments/assets/d60ffe3d-989e-492f-87b1-10c791eeebc3)



Check dynamically run it with wireshark on. see its reaching out to a local connection on port 8000

![image](https://github.com/user-attachments/assets/e76a3b46-31e3-4dad-8336-0fd64ffa04ca)

Can also see it reaching out with strace

![image](https://github.com/user-attachments/assets/4a40f0ac-95b9-4db5-8cb3-8eb546f7e98e)

set up a listener and run again

![image](https://github.com/user-attachments/assets/c4925f72-c63c-4fe4-9168-65a1eec33c49)


Looking at decompiled code in Ghidra see the entry function. First syscall is to connect.

![image](https://github.com/user-attachments/assets/8757b0ca-98c5-4c1b-91eb-bb41cd08cad5)

One function sticks out to be the main logic of the program. We can see there is an option for inputting a password, then either selecting a command or printing the flag.

Format for commands are `PRIVMSG #secret :@exec`

![image](https://github.com/user-attachments/assets/91d497d1-58c2-4420-9512-cc15730dc018)



![image](https://github.com/user-attachments/assets/2592a129-ccf0-46b8-9fa0-1bcf51708186)


`HTB{m1N1m411st1C_fL4g_pR0v1d3r_b0T}`

# ouija

![image](https://github.com/user-attachments/assets/4fae3cf5-abae-454d-99cb-30055e5dee11)

Looking into the binary it looks like it will give you the flag if you wait long enough. It runs the code with a bunch of sleeps. 

![image](https://github.com/user-attachments/assets/b7efcc31-ae66-4116-84d5-1c7d21526b43)

![image](https://github.com/user-attachments/assets/585a8ba3-23db-4e5c-9e24-90da62d60db4)

We can patch the sleeps out in ghidra. Or atleast set the sleep time to 0. 

![image](https://github.com/user-attachments/assets/27a7775d-465e-48cf-9014-e8197836a404)

![image](https://github.com/user-attachments/assets/0d2ab81f-3496-4e92-8b8b-3bc0db4016ba)

`HTB{Sleping_is_not_obfuscation}`

# Potion Master

Given .hs

# Secured Transfer

Given ELF, dynamically linked and pcap

![image](https://github.com/user-attachments/assets/877574ba-a823-4c04-aa2a-86b599a05807)

Running strings can see some libraries to network and encrypt

![image](https://github.com/user-attachments/assets/102c2bd0-f015-4a42-a47b-4f82c2d22e1e)

As expected pcap looks encrypted

![image](https://github.com/user-attachments/assets/667757cb-913d-4695-98f3-b65401c7961f)

Ghidra does a bad job parsing the key. I could run this again to it dyunmaically and hook the library, but its version 1.1 and we are up to 3 and i dont want to worry about reverting.

Luckily binary ninja does a good job parseing the key and iv

![image](https://github.com/user-attachments/assets/bb5b70b9-d8f0-4a18-87b2-648d5606006d)

Pull the message out out wireshark

![image](https://github.com/user-attachments/assets/991eb8fb-a668-4c7e-adbd-18e778947d77)

Decrypt in wireshark

![image](https://github.com/user-attachments/assets/a7fc3754-1f65-40d2-8aab-eaa2db59e7ac)


`HTB{3ncRyPt3d_F1LE_tr4nSf3r}`

# TearOrDear

Given .exe, .NET

![image](https://github.com/user-attachments/assets/f9eb17f7-211d-40e6-b083-6241b74775d6)

Trying to run it get a login form

![image](https://github.com/user-attachments/assets/ce53d32a-089c-4016-806b-4e8e86a6fa38)

Open it up in dotPeek


# The Art of Reversing

Given .exe

![image](https://github.com/user-attachments/assets/49f45cba-baa1-485c-8904-3870ed369356)


Run the exe see it gives us a product key after entering `name` and `Activation Days`

![image](https://github.com/user-attachments/assets/6e26f8ba-cf55-40c2-9c11-4d4a2a508ff0)

Running strings + grepping net, notice its probably .net

![image](https://github.com/user-attachments/assets/10208363-7514-4214-ae0f-1bdb4a9f8aae)




# You Cant C Me

Given ELF, dynamically linked

![image](https://github.com/user-attachments/assets/130c4cd7-6820-4f76-9722-e2a8e3e363dd)

Running it allows for input, any input replies you cant see me and kills it

![image](https://github.com/user-attachments/assets/efa6a45b-27f2-4dcb-9d21-2318ea4f1c4e)

Opening it up in ghidra we can see there is some password, maybe as a decoy? and a strcmp. We can hook that str comp

![image](https://github.com/user-attachments/assets/694e9355-6a83-40b7-a655-414889d52e7d)


![image](https://github.com/user-attachments/assets/22299287-5c22-4442-912e-31878b595d21)

LD is really more useful for memcmp becasue strcmp will show up in ltrace

![image](https://github.com/user-attachments/assets/6b274d03-329f-4f11-84e8-8fd7c512130e)


`HTB{wh00ps!_y0u_d1d_c_m3}`

