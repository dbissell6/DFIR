#!/usr/bin/env python3
import sys

#
# USB HID scancode maps for a typical US QWERTY keyboard
# when NumLock is on. Adjust as needed for your challenge!
#
# - non_shift_map: Keys when no Shift is pressed
# - shift_map: Keys when Shift is pressed (left or right)
# - For reference, Byte 0 of the 8-byte HID report has bits
#   that indicate whether left Shift (0x02) or right Shift
#   (0x20) is held down.
#

non_shift_map = {
    0x04: 'a',  0x05: 'b',  0x06: 'c',  0x07: 'd',  0x08: 'e',  0x09: 'f',
    0x0a: 'g',  0x0b: 'h',  0x0c: 'i',  0x0d: 'j',  0x0e: 'k',  0x0f: 'l',
    0x10: 'm',  0x11: 'n',  0x12: 'o',  0x13: 'p',  0x14: 'q',  0x15: 'r',
    0x16: 's',  0x17: 't',  0x18: 'u',  0x19: 'v',  0x1a: 'w',  0x1b: 'x',
    0x1c: 'y',  0x1d: 'z',
    0x1e: '1',  0x1f: '2',  0x20: '3',  0x21: '4',  0x22: '5',  0x23: '6',
    0x24: '7',  0x25: '8',  0x26: '9',  0x27: '0',
    0x28: '\n',       # Enter
    0x29: '[ESC]',    # Escape
    0x2a: '\b',       # Backspace
    0x2b: '\t',       # Tab
    0x2c: ' ',        # Space
    0x2d: '-',  0x2e: '=',  0x2f: '[',  0x30: ']',  0x31: '\\', 
    0x33: ';', 0x34: '\'', 0x36: ',',  0x37: '.',  0x38: '/',
    # Arrow keys, etc. (optional):
    0x4f: '[RIGHT]', 0x50: '[LEFT]',  0x51: '[DOWN]',  0x52: '[UP]',
    # Keypad (when NumLock = ON):
    0x54: '/', 0x55: '*', 0x56: '-', 0x57: '+', 0x58: '\n', # Keypad Enter
    0x59: '1', 0x5a: '2', 0x5b: '3', 0x5c: '4', 0x5d: '5',
    0x5e: '6', 0x5f: '7', 0x60: '8', 0x61: '9', 0x62: '0', 0x63: '.'
}

shift_map = {
    0x04: 'A',  0x05: 'B',  0x06: 'C',  0x07: 'D',  0x08: 'E',  0x09: 'F',
    0x0a: 'G',  0x0b: 'H',  0x0c: 'I',  0x0d: 'J',  0x0e: 'K',  0x0f: 'L',
    0x10: 'M',  0x11: 'N',  0x12: 'O',  0x13: 'P',  0x14: 'Q',  0x15: 'R',
    0x16: 'S',  0x17: 'T',  0x18: 'U',  0x19: 'V',  0x1a: 'W',  0x1b: 'X',
    0x1c: 'Y',  0x1d: 'Z',
    0x1e: '!',  0x1f: '@',  0x20: '#',  0x21: '$',  0x22: '%',  0x23: '^',
    0x24: '&',  0x25: '*',  0x26: '(',  0x27: ')',
    0x28: '\n',
    0x2d: '_',  0x2e: '+',  0x2f: '{',  0x30: '}',  0x31: '|', 
    0x33: ':',  0x34: '"',  0x36: '<',  0x37: '>',  0x38: '?',
    # Shift + keypad often yields the same as unshifted. Adjust if needed.
    0x59: '1',  0x5a: '2',  0x5b: '3',  0x5c: '4',  0x5d: '5',
    0x5e: '6',  0x5f: '7',  0x60: '8',  0x61: '9',  0x62: '0',  0x63: '.'
}

def decode_hid_report(hid_hex: str) -> str:
    """
    Given a single line of 8-byte USB HID data in hex (e.g. "00 00 04 00 00 00 00 00"),
    decode all pressed keys. Return a string of the typed characters.
    
    Byte layout (8 bytes total):
      Byte0 = Modifier bits (e.g. SHIFT)
      Byte1 = Reserved
      Byte2..Byte7 = up to 6 scancodes (keys) pressed simultaneously
    """
    # Remove spaces or colons, then convert to bytes
    hid_hex = hid_hex.replace(' ', '').replace(':', '')
    data = bytes.fromhex(hid_hex)
    if len(data) != 8:
        return ''  # Invalid length

    # Check if SHIFT is pressed: left shift = 0x02, right shift = 0x20
    # Combine them in a mask 0x22 => either left or right shift.
    is_shift = (data[0] & 0x22) != 0

    # We will accumulate characters from any pressed scancodes in bytes 2..7
    result = []
    for scancode in data[2:]:
        if scancode == 0:
            continue  # No key pressed in this slot
        if is_shift:
            char = shift_map.get(scancode, '')
        else:
            char = non_shift_map.get(scancode, '')

        # If it's unknown scancode, we just skip it or mark it
        result.append(char)

    return ''.join(result)


def main():
    """
    Reads lines of HID data from stdin (e.g. from tshark),
    decodes them, and prints the full recovered string.
    """
    output = []
    for line in sys.stdin:
        line = line.strip()
        if not line:
            continue
        chars = decode_hid_report(line)
        output.append(chars)

    # Print the final recovered text
    print(''.join(output))


if __name__ == '__main__':
    main()
    
