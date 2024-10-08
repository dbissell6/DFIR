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

`h@ckth3parad1$E`


