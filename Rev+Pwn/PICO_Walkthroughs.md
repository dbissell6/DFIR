

#  Transformation

Given an encoded string and a function. 

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


# 
