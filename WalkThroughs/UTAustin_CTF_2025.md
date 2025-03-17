# UTAustinCTF 2025


![image](https://github.com/user-attachments/assets/09434fd7-eee2-44b7-8b9c-1ad093d16239)


## Forgotten Footprints

![Pasted image 20250314171422](https://github.com/user-attachments/assets/1f182101-0770-4087-b44e-c9b394f47e0d)

Able to get the flag grepping for the hex string of the flag, at this point not sure the intended route. Sluethkit added support for this file type this week
, maybe more to come? Could not get it to work on linux and windows didnt yield anything interesting.

Given btrfs disk. 

![Pasted image 20250314173527](https://github.com/user-attachments/assets/a99321c0-7a4c-4b24-b7fe-ba54ae81285c)

Below just commands might be useful later

![Pasted image 20250314191450](https://github.com/user-attachments/assets/0915f420-8e49-4a46-9d11-1c8380fa8659)

![Pasted image 20250314201054](https://github.com/user-attachments/assets/4f51cd44-d55f-4fe3-a060-5a854500dea2)

`sudo btrfs inspect-internal dump-tree disk.img`

![Pasted image 20250314180517](https://github.com/user-attachments/assets/8c8b9429-aab6-4386-8bf3-d187f8445cb4)

## Streamified

![Pasted image 20250314171411](https://github.com/user-attachments/assets/e277b3a0-abfa-4b5e-adb4-25974aab14ce)

Given text file if 1 and 0, legnth of 625. typically this would be divisible by 8.

![image](https://github.com/user-attachments/assets/7f0ae306-8328-440a-9a18-e851481abe6f)


Its a 25x25 QR code 1 = black pixel, 0 = white pixel.

![Pasted image 20250314204633](https://github.com/user-attachments/assets/c8e828b7-a09a-4d59-8b4b-e2b47bd24c44)

Python script to convert bitstring to QR png.

```
from PIL import Image

# Your binary data (formatted as a single string)
binary_data = """
1111111000011110101111111
snip...
""".replace("\n", "")  # Remove newlines

# Convert binary string to a list of pixels (0 = black, 255 = white)
pixels = [0 if bit == '1' else 255 for bit in binary_data]

# Create a new 25x25 image
img = Image.new('L', (25, 25))  # 'L' mode for grayscale
img.putdata(pixels)

# Scale up the image (e.g., 10x larger for better visibility)
scale_factor = 10  # Adjust this as needed
large_img = img.resize((25 * scale_factor, 25 * scale_factor), Image.NEAREST)

# Show and save the high-resolution version
large_img.show()
large_img.save("qr_output_high_res.png")
                                               
```

![Pasted image 20250314204551](https://github.com/user-attachments/assets/3c1a5de7-f326-40de-8b92-94fc3ac61e47)


## Finally, an un-strings-able problem

![Pasted image 20250314172828](https://github.com/user-attachments/assets/fb922c8a-8fe8-42a6-9775-49448e38d865)

Given disk.img

![Pasted image 20250314173330](https://github.com/user-attachments/assets/b612e9f9-ae73-4404-8b6d-8bdde8dc54c2)

Notice bunch of random and unique permissions.

![image](https://github.com/user-attachments/assets/57ad51ca-9cee-47c5-bd8f-1b583c5490ec)

ls organize by time, reversed. awk to get first column. sed to remove first character (-/d) from each line. python script to convert rwx to 1 and - to 0.

![image](https://github.com/user-attachments/assets/e5491ab7-e8f7-43ab-9465-6fbb2dafc30a)


From binary in CyberChef

![image](https://github.com/user-attachments/assets/29c680a7-5a38-4b1d-81fd-5d54947e95ab)
