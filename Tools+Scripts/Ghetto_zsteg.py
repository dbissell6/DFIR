from PIL import Image
import sys
import itertools

def extract_lsb(image_path, mode='RGB', bit_plane=0, channel_order=('R', 'G', 'B'), combine_channels=False):
    img = Image.open(image_path)
    img = img.convert('RGB')  # Always load as RGB first
    pixels = list(img.getdata())
    
    # Reorder channels if needed
    channel_idx = {'R': 0, 'G': 1, 'B': 2}
    order_indices = [channel_idx[c] for c in channel_order]

    bits = ''
    if combine_channels:
        for pixel in pixels:
            for idx in order_indices:
                channel_value = pixel[idx]
                bits += str((channel_value >> bit_plane) & 1)
    else:
        for idx in order_indices:
            bits = ''
            for pixel in pixels:
                channel_value = pixel[idx]
                bits += str((channel_value >> bit_plane) & 1)
            decoded = bits_to_text(bits)
            if decoded.strip():
                print(f"[+] Bit {bit_plane} Channel {channel_order[idx]} (first 100 chars): {decoded[:100]}")
    
    if combine_channels:
        decoded = bits_to_text(bits)
        if decoded.strip():
            order_str = ''.join(channel_order)
            print(f"[+] Bit {bit_plane} Combined {order_str} (first 100 chars): {decoded[:100]}")

def bits_to_text(bits):
    chars = []
    for i in range(0, len(bits), 8):
        byte = bits[i:i+8]
        if len(byte) == 8:
            chars.append(chr(int(byte, 2)))
    return ''.join(chars)

if __name__ == "__main__":
    if len(sys.argv) < 2:
        print("Usage: python3 brute_zsteg.py dogpicture.png")
        sys.exit(1)

    image_path = sys.argv[1]

    channel_orders = list(itertools.permutations('RGB', 3))
    max_bit_plane = 3  # bits 0 to 3

    for bit_plane in range(0, max_bit_plane+1):
        for order in channel_orders:
            extract_lsb(image_path, bit_plane=bit_plane, channel_order=order, combine_channels=False)
            extract_lsb(image_path, bit_plane=bit_plane, channel_order=order, combine_channels=True)
                                                                                                          
