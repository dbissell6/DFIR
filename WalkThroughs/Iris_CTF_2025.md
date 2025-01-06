# IrisCTF 2025

![image](https://github.com/user-attachments/assets/362c861b-3107-408b-a6fe-3d47fed3857b)


# Tracem 1

![Pasted image 20250103170046](https://github.com/user-attachments/assets/500672ff-1b6f-4ab4-a7f3-700027d01af0)

Given log file in json format. Log file contains; RADIUS, SSO, DNS, DHCP and Active Directory sources.

![Pasted image 20250103174935](https://github.com/user-attachments/assets/f6a8962b-0bf9-4d49-bd32-88ccc58e46aa)

![Pasted image 20250103184843](https://github.com/user-attachments/assets/43e84ef3-deec-47dc-8193-c291aad69778)

The DNS logs contained sites visited, one site sticks out as being off limits at work.

![Pasted image 20250103200751](https://github.com/user-attachments/assets/caa3cfdb-1f34-41ee-a64e-3f9d698f6053)

![Pasted image 20250103200840](https://github.com/user-attachments/assets/808c448d-87f5-4cf7-91d0-70045bde5dae)

![Pasted image 20250103200714](https://github.com/user-attachments/assets/18040fae-3337-41ad-a153-509f2c28e759)

# Tracem2 

Given same file type and structure as first, new data.

![Pasted image 20250103201320](https://github.com/user-attachments/assets/2bbe1ba0-0174-41d2-9a05-32be1fb70fb9)

```
jq -r '                                                 
  .data
  | ((.queries // []) + (.answers // []))[].name
' logs.json \
| sort \
| uniq -c | sort -k1,1nr

```

Using similar command find simlar bad sites.

![Pasted image 20250104101241](https://github.com/user-attachments/assets/0b8615c2-95ad-46f8-bd40-cff775221b9d)

![Pasted image 20250104101551](https://github.com/user-attachments/assets/e09ed40c-ea35-4f13-a6bd-4a3747499c66)

Filtering through the data find that a single mac address has multiple ips associated with it.



# deldeldel

![Pasted image 20250103171228](https://github.com/user-attachments/assets/72e5025a-5418-4ec5-b100-95a0d83f8477)

Given pcap of hid keyboard usb data. Run the generic keyboard script on it. Given the output and title figure the script doesnt delete and I need to clean the output up.

![Pasted image 20250103171315](https://github.com/user-attachments/assets/d1e1b4ef-9cdb-4749-8cd2-233dcad0d675)

# Windy Day

![Pasted image 20250103171404](https://github.com/user-attachments/assets/261e5483-b555-4a58-8677-f6fc4ed5d23d)

Given memdump

![Pasted image 20250104171147](https://github.com/user-attachments/assets/a625bd23-81ac-4281-a47f-34e49e116fab)

Running a `psscan` notice many instances of Firefox running. Dump the process and search through it. Can find base64 of flag in browser history.

![Pasted image 20250105105152](https://github.com/user-attachments/assets/b22c1b2b-5756-4772-85e6-5295ac81215b)

![Pasted image 20250105105039](https://github.com/user-attachments/assets/265c1f91-c5c0-47fb-8b61-b22391aa1665)


# RIP Art

Given mouse usb pcap.

![Pasted image 20250103171548](https://github.com/user-attachments/assets/f543ae61-b9d8-4b1e-a74b-4422c6383aa6)

![Pasted image 20250103174742](https://github.com/user-attachments/assets/d1fbe3b0-555a-471c-b72f-912b8e5143c8)

```tshark -r art.pcapng -T fields -e usb.src -e us.dst -e usb.capdata -Y 'usb.capdata' > usbcap.out```

```
#!/usr/bin/env python3
import sys
import matplotlib.pyplot as plt

def parse_mouse_report(raw_hex):
    """
    Convert 16 hex chars (8 bytes) into X/Y deltas.
    Adjust or swap X/Y if you see mirrored or upside-down text.
    """
    report_bytes = bytes.fromhex(raw_hex)
    # Example: we invert Y to fix 'upside-down' effect
    x_delta = int.from_bytes(report_bytes[2:4], 'little', signed=True)
    y_delta = -int.from_bytes(report_bytes[4:6], 'little', signed=True)
    return x_delta, y_delta

def ascii_preview(byte_data, max_len=80):
    """
    Return a quick ASCII-ish preview of the bytes:
      - Print ASCII if 32 <= byte <= 126
      - Else print '.'
    Just for a quick look at the content.
    """
    preview = []
    for b in byte_data[:max_len]:
        if 32 <= b < 127:
            preview.append(chr(b))
        else:
            preview.append('.')
    return "".join(preview)

def main(input_file):
    x, y = 0, 0  # track cumulative mouse movement
    mouse_coords = [(x, y)]

    with open(input_file, 'r') as f:
        for line in f:
            line = line.strip()
            if not line:
                continue

            parts = line.split()
            if len(parts) < 3:
                continue

            # The raw hex is presumably in column 3
            raw_hex = parts[2]

            # Distinguish small lines (mouse) from big lines (bulk data, etc.)
            if len(raw_hex) == 16:
                # This is likely an 8-byte mouse HID report
                print(parts[0])
                dx, dy = parse_mouse_report(raw_hex)
                x += dx
                y += dy
                mouse_coords.append((x, y))

            elif len(raw_hex) >= 128:
                # This is some large bulk data
                # Let's decode and show a quick ASCII preview
                big_bytes = bytes.fromhex(raw_hex)
                preview_str = ascii_preview(big_bytes)
                # Print the line length and an ASCII snippet
                print(f"[BIG] HexLen={len(raw_hex)} Bytes={len(big_bytes)} Preview: {preview_str}")

                # If you suspect it might contain coordinate pairs, you could parse them here
                # For now, we just show a snippet and move on.

            else:
                # Medium-sized lines or anything else
                pass

    # Done parsing. Now plot the mouse coordinates
    if len(mouse_coords) > 1:
        xs, ys = zip(*mouse_coords)
        plt.figure(figsize=(6,6))
        plt.plot(xs, ys, marker='.', linestyle='-')
        plt.title("Mouse Movement from HID Reports")
        plt.xlabel("X position")
        plt.ylabel("Y position")
        plt.grid(True)
        plt.axis('equal')
        plt.show()
    else:
        print("No small (16-hex-char) mouse lines found to plot.")

if __name__ == "__main__":
    if len(sys.argv) < 2:
        print(f"Usage: {sys.argv[0]} <tshark_output.txt>")
        sys.exit(1)
    main(sys.argv[1])

```

