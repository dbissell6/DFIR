![Pasted image 20240929171636](https://github.com/user-attachments/assets/a75ead65-80a1-44aa-8d9e-65ff84269496)

# unknown

![Pasted image 20240928180930](https://github.com/user-attachments/assets/828d48f1-fca1-4b57-8c8e-e051b5de3a99)

Given zip

![Pasted image 20240928033007](https://github.com/user-attachments/assets/f944fcef-58bf-4561-8534-d988ef732aaa)

Inside can see it is a TAR archive. Extract the TAR archive it to get flag

![Pasted image 20240928032849](https://github.com/user-attachments/assets/9d6619ff-6ed1-4f70-92f9-4274e3ac8fb2)

Or could have just used strings on the original file

![Pasted image 20240928032946](https://github.com/user-attachments/assets/4354214b-d380-4726-b6bd-81187efce183)

# Couch Potato

![Pasted image 20240928180949](https://github.com/user-attachments/assets/8efa2102-4ee9-4752-a615-b9d27416d2ac)

Given .wav file

![Pasted image 20240928180115](https://github.com/user-attachments/assets/e7a64455-e010-432e-9602-b36106c29920)

`https://github.com/colaclanth/sstv`

![Pasted image 20240928180054](https://github.com/user-attachments/assets/023570fa-d462-4c7c-b465-a5798d8917d9)


![Pasted image 20240928180037](https://github.com/user-attachments/assets/ba71c292-d469-42d2-9aa0-20f0412e6129)

# wreck

![Pasted image 20240928181049](https://github.com/user-attachments/assets/4f42eb64-467b-485d-a212-59e678b28452)

Given a `dump: ELF 64-bit LSB core file, x86-64, version 1 (SYSV), SVR4-style, from 'python3 wreck.py'`

![Pasted image 20240929121846](https://github.com/user-attachments/assets/709a6614-60ff-42ef-b2b4-17c3fb6b8c68)

Ran strings on the dump and saw `flag.jpg`

![Pasted image 20240929122002](https://github.com/user-attachments/assets/d08c05da-8d58-4e43-8c69-aa63069b35d2)

Use binwalk extract the files.

![Pasted image 20240929122448](https://github.com/user-attachments/assets/f7eb1c93-8b11-423e-91b0-46b51f311b13)

![Pasted image 20240929122151](https://github.com/user-attachments/assets/74bafc8c-d71f-4904-b2d7-aa72c0857321)

![Pasted image 20240929122238](https://github.com/user-attachments/assets/0317acaa-21aa-4777-98be-8f69d2ad1e0f)

# duck-pics

![Pasted image 20240928181034](https://github.com/user-attachments/assets/1376d40e-1cf9-40f3-9c86-c9dfebd9629f)

Given pcacp and can see its probably some hid data from a keyboard

![Pasted image 20240929121318](https://github.com/user-attachments/assets/1611dbd8-2ced-4751-855f-b4ee11d43cc0)


```
https://github.com/TeamRocketIst/ctf-usb-keyboard-parser/blob/master/usbkeyboard.py
```

Extract data and add colons to fit the format needed by the script

```
 tshark -r capture.pcapng -Y 'usb.src == "1.1.1"' -T fields -e usbhid.data |sed 's/../:&/g2' > output
```

```
python3 convert.py output 
```

![Pasted image 20240928034347](https://github.com/user-attachments/assets/d40dde77-d43e-4043-9138-4d375cbe38e3)

A couple tweaks and we got the flag

# reduce_recycle

![Pasted image 20240928181012](https://github.com/user-attachments/assets/ff3fc277-bb96-4182-b1d0-6e740ae59d1a)

Given a .zip and a 7z

![image](https://github.com/user-attachments/assets/e9d4bae5-5ddb-427c-9872-1dbac9b459dd)

Running bkcrack we can see the encryption method was Zipcrypto
```
https://github.com/kimci86/bkcrack
```

![image](https://github.com/user-attachments/assets/9fc5945d-7630-4098-9b83-4102e926c345)

The challenge description mentions both files were protected with the same password so if we can crack the .zip we should be able to open the 7z

Create the plaintext and run bkcrack

![Pasted image 20240927185225](https://github.com/user-attachments/assets/798c9d91-f094-461b-94c9-b4d1c123350f)

It cracks, just for fun a pick of a dog

![Pasted image 20240928180744](https://github.com/user-attachments/assets/76b5c495-4627-4bfa-a552-5336b7eaab24)

What we really want tho is the password to open up the 7z

![Pasted image 20240927185434](https://github.com/user-attachments/assets/b8dd4b0b-5c0a-4a8c-8512-7811185c2a31)

We can also use hashcat 

![image](https://github.com/user-attachments/assets/fb15de4f-2b1c-4366-8a54-e6949040cd0b)


`7z x important_flags.7z`

![Pasted image 20240928180658](https://github.com/user-attachments/assets/4cf830c0-e602-4529-81f1-97da3bfc4ee2)


# the_CIA

![Pasted image 20240928181108](https://github.com/user-attachments/assets/c2b42179-5b3b-4db9-806a-2e038211bdbd)

Given a pdf file.

![Pasted image 20240929122613](https://github.com/user-attachments/assets/b83b73ba-080b-49f3-ad96-a9c19210138a)

It is password protected and partially encrypted. We can still get some information about the file and see its using 40-bit encryption. 

![Pasted image 20240927235257](https://github.com/user-attachments/assets/67c8821b-d5bf-484d-8b46-2d298747b000)

![Pasted image 20240927235337](https://github.com/user-attachments/assets/953e00a0-4a90-4eda-90c0-e75233553367)

Reading this series of blog posts gives us all we need to crack it. The key to the challenge is.... the key. 

`https://blog.didierstevens.com/2017/12/28/cracking-encrypted-pdfs-part-3/`

First step is to get the hash with john. Hashcat doesnt want the title at the front so we have to take that out.

![image](https://github.com/user-attachments/assets/0f450f95-829a-419e-b22a-a243ea7c475a)

Should look like

![image](https://github.com/user-attachments/assets/bf1cb0d1-0bd2-4259-9af3-58e09cac9ad0)

The hint in the description tells us that the first byte in the key is `d8`. Using hashcat with this info it cracked in a couple minutes.
Without that first byte hint it was expected to take over aday.

![Pasted image 20240928171501](https://github.com/user-attachments/assets/894f3c68-5025-45b4-919a-9b5ba36b19c3)

![Pasted image 20240928171542](https://github.com/user-attachments/assets/0c4a622d-4d02-46ba-9e59-0d9fa5eee849)

The key is `b895821f14`

Now with this key we can keep reading the blog post and Mr Stevens explains he forked and modded `qpdf` to be able to decrypt pdfs with the key instead of the password.

![Pasted image 20240928151700](https://github.com/user-attachments/assets/6dad7dbe-88f2-4145-b200-7fb09133c5be)

OG qpdf was updated. Could have also used

```
qpdf --password=b895821f14 --password-is-hex-key --decrypt here.pdf unlocked.pdf 
```
Additionally, with the key and hash it is also possible to get the password.

![image](https://github.com/user-attachments/assets/9e077a24-5dd4-4fdb-a688-f26e6b31f099)

Open the pdf

![Pasted image 20240928150822](https://github.com/user-attachments/assets/2f766108-8ff9-495a-bea4-54cfd2435e27)

Take text into cyberchef for the rot 47 and base64 decoding. 

![Pasted image 20240928151359](https://github.com/user-attachments/assets/357fc186-f3bd-47f8-a0a8-70bb706165cc)

# hall-effect

![Pasted image 20240928181132](https://github.com/user-attachments/assets/599a82d4-4d69-4f9e-bd6f-8cd32e853dbe)


![image](https://github.com/user-attachments/assets/3d6edcab-e32a-41b5-8a4f-2869d502efe5)


![Pasted image 20240929123209](https://github.com/user-attachments/assets/43b1d201-8537-4f32-9f10-f7c2f06c49d6)

![Pasted image 20240929123554](https://github.com/user-attachments/assets/03b3edb8-2106-4342-a703-d30b40eff708)

Extract hid data with tshark

`
tshark -r capture.pcapng -Y 'usb.src == "1.6.2"' -T fields -e usbhid.data > data
`
Keymap

https://github.com/Keychron/qmk_firmware/blob/a576a0b47be74851efb5eb7771fd86b006199704/keyboards/keychron/q1_he/iso_encoder/keymaps/default/keymap.c#L45

Create the solve script

Command Detection:

    The first byte of the HID packet (data[0] == 0xA9) indicates a valid command.
    The second byte (cmd = data[1]) represents the specific command. The command ID is looked up in the cmds dictionary to determine what type of action it represents.
    If the command is AMC_SET_TRAVAL, the script begins processing keypresses by looking at the row_mask data.

HID Keypress Mapping:

    The HID data uses a matrix-based system, where the keyboard is represented as rows and columns in MAP_MATRIX. Each key on the keyboard is mapped to a specific row and column.
    The row_mask stores which keys have been pressed. The script iterates through each row and column using nested loops (for r in range(6) and for c in range(15)).
    For each key that has been pressed (row_mask[r] & (0x01 << c)), the corresponding key from MAP_MATRIX is retrieved and appended to final_message.

<details>

<summary>Python script for HID pcap keyboard</summary>

```
   cmds = {
    "AMC_GET_VERSION": 0x01,
    "AMC_GET_PROFILES_INFO": 0x10,
    "AMC_SELECT_PROFILE": 0x11,
    "AMC_GET_PROFILE_RAW": 0x12,
    "AMC_SET_PROFILE_NAME": 0x13,
    "AMC_SET_TRAVAL": 0x14,
    "AMC_SET_ADVANCE_MODE": 0x15,
    "AMC_CLEAR_PROFILE": 0x1D,
    "AMC_SAVE_PROFILE": 0x1F,
    "AMC_GET_CURVE": 0x20,
    "AMC_SET_CURVE": 0x21,
    "AMC_GET_GAME_CONTROLLER_MODE": 0x22,
    "AMC_SET_GAME_CONTROLLER_MODE": 0x23,
    "AMC_GET_REALTIME_TRAVEL": 0x30,
    "AMC_CALIBRATE": 0x40,
    "AMC_GET_CALIBRATE_STATE": 0x41,
    "AMC_GET_CALIBRATED_VALUE": 0x42,
}

packets = open("./data").readlines()

MAP_MATRIX = [
    ["ESC", "F1", "F2", "F3", "F4", "F5", "F6", "F7", "F8", "F9", "F10", "F11", "F12", "DEL", "MUTE"],
    ["GRV", "1", "2", "3", "4", "5", "6", "7", "8", "9", "0", "-", "=", "BSPC", "PGUP"],
    ["TAB", "q", "w", "e", "r", "t", "y", "u", "i", "o", "p", "[", "]", "PGDN"],
    ["CAPS", "a", "s", "d", "f", "g", "h", "j", "k", "l", ":", "'", "NUHS", "ENT", "HOME"],
    ["LSFT", "NUBS", "z", "x", "c", "v", "b", "n", "m", ",", ".", "/", "RSFT", "UP"],
    ["LCTL", "LGUI", "LALT", "SPC", "RALT", "WIN_FN", "RCTL", "LEFT", "DOWN", "RGHT"],
]

SHIFTED_SYMBOLS = {
    "1": "!",
    "2": "@",
    "3": "#",
    "4": "$",
    "5": "%",
    "6": "^",
    "7": "&",
    "8": "*",
    "9": "(",
    "0": ")",
    "-": "_",
    "=": "+",
    "[": "{",
    "]": "}",
    ":": ":",
    "'": "\"",
    ",": "<",
    ".": ">",
    "/": "?",
}

final_message = []
previous_key = None

for pkt in packets:
    pkt = pkt.strip()
    data = bytes.fromhex(pkt)
    if data and data[0] == 0xA9:
        cmd = data[1]
        cmd_id = list(cmds.keys())[list(cmds.values()).index(cmd)]
        if cmd_id == "AMC_SET_TRAVAL":
            profile = data[2]
            mode = data[3]
            act_pt = data[4]
            sens = data[5]
            rls_sens = data[6]
            entire = data[7]
            row_mask = [0] * 6
            matrix = [[0] * 15 for _ in range(6)]

            if not entire:
                for i in range(6):
                    j = 8 + i * 3
                    row_mask[i] = int.from_bytes(data[j : j + 3], byteorder="little")

                for r in range(6):
                    for c in range(15):
                        try:
                            if row_mask[r] & (0x01 << c):
                                key = MAP_MATRIX[r][c]
                                if key == "LSFT":
                                    # Capitalize or modify the last appended key
                                    if previous_key and previous_key.isalpha():
                                        final_message[-1] = previous_key.upper()
                                    elif previous_key in SHIFTED_SYMBOLS:
                                        final_message[-1] = SHIFTED_SYMBOLS[previous_key]
                                else:
                                    final_message.append(key)
                                    previous_key = key
                        except IndexError:
                            print(f"Error accessing MAP_MATRIX at row {r}, col {c}")

final_string = ''.join(final_message)
print(final_string)
                               
```

</details>

Output + a couple tweaks and we get the flag.

![Pasted image 20240929170041](https://github.com/user-attachments/assets/79599239-7414-4daa-93d1-288fadc99a2b)
