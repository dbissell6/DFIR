# nullcon HackIM CTF 2025



![Pasted image 20250201154511](https://github.com/user-attachments/assets/109cd4c2-2069-4e33-8611-0872e7c63c6e)

`https://ctf.nullcon.net/`

## abroad study notes

![Pasted image 20250201085632](https://github.com/user-attachments/assets/0c3d3a7d-0811-47b5-a685-8a966e4987fc)

Given .jpg



![Pasted image 20250201085714](https://github.com/user-attachments/assets/20d01443-96f5-44ff-845d-d32002197be9)

When running it see an error about a marker type, go do a little research about jpeg markers.

```
import sys

def fix_jpeg(input_file, output_file):
    with open(input_file, "rb") as f:
        data = f.read()

    # Replace all occurrences of FF 07 with FF DA
    fixed_data = data.replace(b'\xFF\x07', b'\xFF\x00')

    with open(output_file, "wb") as f:
        f.write(fixed_data)

    print(f"[+] Fixed file saved as: {output_file}")

# Run from command line: python fix_jpeg.py input.jpg output.jpg
if __name__ == "__main__":
    if len(sys.argv) != 3:
        print("Usage: python fix_jpeg.py <input.jpg> <output.jpg>")
    else:
        fix_jpeg(sys.argv[1], sys.argv[2])
                                             
```


![Pasted image 20250201085520](https://github.com/user-attachments/assets/721c0e24-3f24-45f1-a155-8d263436b12a)

![Pasted image 20250201085531](https://github.com/user-attachments/assets/1dd7fe04-ae91-43d3-b0b9-38a5472c2dc8)




## oscilloscope


came in mid way through and was given this string.

0b10100000000111010000000001001010000100100010100100111000100111100111101100101001100011000000101111100101010000100100000011000100011010100101111100011000100011010100101111100100100000011000000101011100101111100101100100011000000101010100101111100100010000011001100100001100011000000100010000011001100101111100100100100011001000100001100111110110

Taking the flag first approach, tried to find parts of the flag in the bytes.

![Pasted image 20250201140147](https://github.com/user-attachments/assets/3d916835-eb17-4b94-85fb-3ebb76937ad3)

![Pasted image 20250201140407](https://github.com/user-attachments/assets/a85d3a57-17ee-480b-9853-bffdd21cc8c1)

Skip header, delete one after every 8.


![Pasted image 20250201141900](https://github.com/user-attachments/assets/6470e2af-6fa3-4ee8-b0b8-0490d50c9029)


Going back I tried to understand why deleting every 9th. There are 8 bits sent, 1 for ACK. Repeat. 

![Pasted image 20250202230332](https://github.com/user-attachments/assets/1c2ee683-ca5d-49a8-9f1e-8816e67802a0)


![Pasted image 20250202224716](https://github.com/user-attachments/assets/2c64dc65-a62b-4256-a261-4b27f11efb83)


```
import pickle

HIGH = 3.25
LOW = 0.00

WINDOW = 8

def is_ambiguous(reading: float) -> bool:
        return LOW + 0.75 < reading and reading < HIGH - 0.75 

def is_high(reading: float) -> bool:
        return abs(HIGH - reading) <= abs(LOW - reading)

def should_sample(clk: list[float], ts: int, *, window: int = WINDOW):
    lhs = sum(clk[ts - window : ts - (window >> 1)]) / (window >> 1)
    rhs = sum(clk[ts - (window >> 1) : ts]) / (window >> 1)

    # Check if the readings are ambiguous
    if is_ambiguous(lhs) or is_ambiguous(rhs):
        return False

    return not is_high(lhs) and is_high(rhs)


def decode(clk: list[float], serial: list[float]) -> bytes:

    
    buffer = 0
    last_sample = 0
    for ts in range(0, len(clk)):
        if ts - last_sample <= WINDOW:
            continue # Guard against double sampling

        if should_sample(clk, ts):
            sample = sum(serial[ts - 2 : ts + 2]) // 4
            assert not is_ambiguous(sample)

            buffer = (buffer << 1) + int(is_high(sample))
            last_sample = ts
    print(bin(buffer))
    return str(bin(buffer))

def binary_to_ascii_skip(binary_string):
    result = []
    
    # Process every 8 bits, skipping the 9th bit
    for i in range(0, len(binary_string), 9):  # Step by 9 to skip every 9th bit
        chunk = binary_string[i:i+8]  # Get 8-bit chunk
        if len(chunk) == 8:  # Ensure it's a full byte
            ascii_char = chr(int(chunk, 2))  # Convert binary to ASCII
            result.append(ascii_char)
    
    return ''.join(result)



def main():
    with open("trace.pckl", "rb") as pickle_jar:
        trace = pickle.load(pickle_jar)
    _, clk, rxd = trace  # First element is just timestamps
    binary_input = decode(clk, rxd)
    output = binary_to_ascii_skip(binary_input[21:])
    print(output)



if __name__ == "__main__":
    main()
```

## 

Given a .jpg


![Pasted image 20250201230645](https://github.com/user-attachments/assets/59357006-2743-47cd-9bdc-67408ec4d163)

After running strings realize it may be a gif due to NETSCAPE2.0.

`https://en.wikipedia.org/wiki/GIF#Animated_GIF`

![Pasted image 20250201230246](https://github.com/user-attachments/assets/b120cf85-411c-47fb-bebe-8af3c26bc3e0)


![Pasted image 20250201230334](https://github.com/user-attachments/assets/007eb466-eb66-465f-af2a-104e5ffd2dcc)

![Pasted image 20250202000119](https://github.com/user-attachments/assets/35d9cbb5-e021-4a4f-87c1-d6b4c04cf86b)



