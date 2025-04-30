import wave
import sys

def extract_lsb(wav_file, output_file=None):
    # Open the wav file
    with wave.open(wav_file, 'rb') as wav:
        frames = wav.readframes(wav.getnframes())
    
    # Extract LSBs from each byte
    bits = ''
    for byte in frames:
        bits += str(byte & 1)  # Take only the least significant bit

    print(f"[+] Extracted {len(bits)} bits.")

    # Optional: Save bits to a file
    if output_file:
        # Group bits into bytes
        bytes_out = bytearray()
        for i in range(0, len(bits), 8):
            byte = bits[i:i+8]
            if len(byte) == 8:
                bytes_out.append(int(byte, 2))
        
        with open(output_file, 'wb') as f:
            f.write(bytes_out)
        print(f"[+] Output saved to {output_file}")
    else:
        # Just print bits (truncated for display)
        print(bits[:256] + ('...' if len(bits) > 256 else ''))

if __name__ == '__main__':
    if len(sys.argv) < 2:
        print(f"Usage: {sys.argv[0]} input.wav [output.bin]")
        sys.exit(1)

    wav_file = sys.argv[1]
    output_file = sys.argv[2] if len(sys.argv) > 2 else None
    extract_lsb(wav_file, output_file)
                                        
