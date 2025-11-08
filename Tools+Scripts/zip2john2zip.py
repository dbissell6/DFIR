#!/usr/bin/env python3
"""
hash_content.py

Rebuild a minimal ZIP from a zip2john / $pkzip2$ inline-data hash line,
then try to open/decrypt entries using a supplied password.

Features:
 - Accepts hash lines from a file (--hashfile) or stdin.
 - Accepts password on CLI (-p/--password) or prompts.
 - Does not assume a fixed filename; enumerates entries and tries each one.
 - Optionally choose entry by index or name (--entry).
"""
from __future__ import annotations
import re
import binascii
import io
import struct
import zipfile
import zlib
import argparse
import sys
import getpass
from typing import Optional, Dict, Any

PKZIP_RE = re.compile(r'\$pkzip2\$(.+?)\$/pkzip2\$')

def parse_pkzip2(line: str) -> Dict[str, Any]:
    """
    Parse a single line containing $pkzip2$...$/pkzip2$ and return the DT=2 blob fields.
    Raises ValueError if no DT=2 item is found.
    """
    m = PKZIP_RE.search(line)
    if not m:
        raise ValueError("No $pkzip2$ core found in line")
    core = m.group(1)
    parts = core.split('*')

    if len(parts) < 2:
        raise ValueError("Malformed pkzip2 core")

    # C and B not used except for validation in some contexts; parse defensively
    def to_int(tok: str):
        if re.fullmatch(r'[0-9a-fA-F]+', tok):
            return int(tok, 16)
        return int(tok)

    C = to_int(parts[0])
    B = to_int(parts[1])

    i = 2
    while i < len(parts):
        # skip until plausible DT token
        DT_tok = parts[i]; i += 1
        if DT_tok not in ('1', '2', '3'):
            # sometimes stray whitespace or weird items; continue scanning
            continue
        DT = int(DT_tok)

        if i >= len(parts):
            break
        MT = to_int(parts[i]); i += 1

        CL = UL = CR = OF = OX = 0
        if DT != 1:
            # CL UL CR OF OX
            if i + 4 >= len(parts):
                break
            CL = to_int(parts[i]); i += 1
            UL = to_int(parts[i]); i += 1
            CR = to_int(parts[i]); i += 1
            OF = to_int(parts[i]); i += 1
            OX = to_int(parts[i]); i += 1

        # CT, DL, CS, TC, DA
        if i + 4 >= len(parts):
            break
        CT = to_int(parts[i]); i += 1
        DL = to_int(parts[i]); i += 1
        CS = parts[i]; i += 1
        TC = parts[i]; i += 1
        DA = parts[i]; i += 1

        if DT == 2:
            if not re.fullmatch(r'[0-9a-fA-F]+', DA):
                raise ValueError("DA field is not hex")
            blob = binascii.unhexlify(DA)
            return {
                'MT': MT, 'CL': CL, 'UL': UL, 'CR': CR,
                'OF': OF, 'OX': OX, 'CT': CT, 'DL': DL,
                'CS': CS, 'TC': TC, 'DA_bytes': blob,
                'C': C, 'B': B
            }

    raise ValueError("No DT=2 item found in $pkzip2$ array")

def build_min_zip_from_blob(entry_name: str, fields: Dict[str, Any]) -> bytes:
    """
    Build a minimal ZIP file (bytes) containing one encrypted member whose encrypted
    data is the inline blob (fields['DA_bytes']).
    """
    nameb = entry_name.encode('utf-8')
    ver_needed = 20
    flags = 0x0001  # encrypted
    method = fields['CT']  # compression method: 0=stored, 8=deflate
    mtime = 0
    mdate = 0
    crc   = fields['CR'] & 0xffffffff
    comp  = len(fields['DA_bytes'])
    uncomp= fields['UL'] & 0xffffffff

    # Local file header (little-endian)
    # struct: signature, ver_needed, flags, method, mtime, mdate, crc, comp_size, uncomp_size, name_len, extra_len
    lh = struct.pack("<IHHHHHIIIHH",
                     0x04034b50, ver_needed, flags, method, mtime, mdate,
                     crc, comp, uncomp, len(nameb), 0)
    local = lh + nameb + fields['DA_bytes']

    # Central directory header (we keep offsets simple: local header is at offset 0)
    # Fields sequence chosen to match typical central directory (not all fields strictly needed here)
    # struct used earlier: "<IHHHHHHIIIHHHHHII"
    # We'll supply placeholder values; many zip readers (including zipfile) accept it for small test zips.
    ch = struct.pack("<IHHHHHHIIIHHHHHII",
                     0x02014b50,    # central file header signature
                     0x0314,        # version made by (arbitrary)
                     ver_needed,
                     flags,
                     method,
                     mtime,
                     mdate,
                     crc,
                     comp,
                     uncomp,
                     len(nameb),
                     0,             # extra len
                     0,             # file comment len
                     0,             # disk number start
                     0,             # internal attrs
                     0,             # external attrs
                     0)             # relative offset of local header (0 here)
    central = ch + nameb

    # End of central directory record
    eocd = struct.pack("<IHHHHIIH",
                       0x06054b50,
                       0,    # disk number
                       0,    # cd start disk
                       1,    # number of central directory records on this disk
                       1,    # total number of central directory records
                       len(central),  # size of central directory
                       len(local),    # offset of start of central directory (we used 0-local size)
                       0)    # comment length

    return local + central + eocd

def try_decrypt_zip(zbytes: bytes, password: Optional[str], try_inflate: bool = True) -> None:
    """
    Try to open rebuilt ZIP and attempt to read entries using the password.
    Prints diagnostics and the head of successfully decrypted content.
    """
    bio = io.BytesIO(zbytes)
    with zipfile.ZipFile(bio, "r") as zf:
        names = zf.namelist()
        print("ZIP entries:", names)
        if not names:
            print("No entries found in rebuilt ZIP.")
            return

        # If user supplied a password use it; else None/empty will be tried
        pwd = password.encode("utf-8") if password is not None else None

        # If user didn't select a specific entry, try each one until success
        for idx, nm in enumerate(names):
            print(f"\nTrying entry {idx}: {nm!r}")
            try:
                # zipfile allows reading with pwd; if it fails raises RuntimeError or BadZipFile or zlib.error
                data = zf.read(nm, pwd=pwd)
                print(f"  Decrypted payload length: {len(data)} bytes (raw)")

                # If compressed (method 8 == deflate), zipfile already returns decompressed data
                # but in our minimal rebuild we may have stored raw deflate bytes; handle both
                method = None
                try:
                    info = zf.getinfo(nm)
                    method = info.compress_type
                except Exception:
                    # fallback: use fields content later if needed
                    pass

                # If returned data looks like compressed deflate (and user asked), try inflate
                if try_inflate and data:
                    # Attempt raw deflate if it fails try normal zlib wrapper
                    inflated = None
                    # heuristic: if compress_type indicates DEFLATE (8), attempt inflate; else still try as raw
                    tried_inflate = False
                    if method == zipfile.ZIP_DEFLATED or method is None:
                        tried_inflate = True
                        try:
                            inflated = zlib.decompress(data, -zlib.MAX_WBITS)
                            print(f"  Inflated length: {len(inflated)}")
                        except zlib.error:
                            try:
                                inflated = zlib.decompress(data)
                                print(f"  Inflated (zlib) length: {len(inflated)}")
                            except zlib.error:
                                inflated = None
                    if inflated is not None:
                        head = inflated[:400]
                        try:
                            print("  Head (UTF-8):", head.decode("utf-8", errors="replace"))
                        except Exception:
                            print("  Head (bytes):", head)
                    else:
                        # treat 'data' as plaintext
                        head = data[:400]
                        try:
                            print("  Head (UTF-8):", head.decode("utf-8", errors="replace"))
                        except Exception:
                            print("  Head (bytes):", head)
                else:
                    head = data[:400]
                    try:
                        print("  Head (UTF-8):", head.decode("utf-8", errors="replace"))
                    except Exception:
                        print("  Head (bytes):", head)

                # success: break (unless user wants to try all)
                return
            except RuntimeError as e:
                # This often means "Bad password for file" from zipfile
                print("  RuntimeError while reading (likely bad password or corrupt):", e)
            except zipfile.BadZipFile as e:
                print("  BadZipFile:", e)
            except zlib.error as e:
                print("  zlib.error while decompressing:", e)
            except Exception as e:
                print("  Exception while trying entry:", type(e).__name__, e)

        print("\nTried all entries but none decrypted successfully with the provided password.")

def read_first_pkzip2_line_from_file(path: str) -> str:
    with open(path, "r", encoding="utf-8", errors="ignore") as fh:
        for ln in fh:
            if PKZIP_RE.search(ln):
                return ln.strip()
    raise ValueError("No $pkzip2$ line found in file")

def read_first_pkzip2_line_from_stdin() -> str:
    for ln in sys.stdin:
        if PKZIP_RE.search(ln):
            return ln.strip()
    raise ValueError("No $pkzip2$ line found on stdin")

def main():
    ap = argparse.ArgumentParser(description="Rebuild minimal ZIP from zip2john $pkzip2$ inline-data and try to decrypt it.")
    ap.add_argument("--hashfile", "-f", help="Path to file containing one or more zip2john/$pkzip2$ lines. If omitted, read from stdin.")
    ap.add_argument("--password", "-p", help="Cracked password to try (if omitted, prompt).")
    ap.add_argument("--entry", help="Optional: entry index (0-based) or entry name to try first.", default=None)
    ap.add_argument("--entry-try-all", action="store_true", help="Try all entries until success (default).")
    args = ap.parse_args()

    # read hash line
    try:
        if args.hashfile:
            line = read_first_pkzip2_line_from_file(args.hashfile)
        else:
            print("Reading from stdin; please pipe or paste a line containing $pkzip2$...$/pkzip2$ and newline, then Ctrl-D.")
            line = read_first_pkzip2_line_from_stdin()
    except Exception as e:
        print("Error reading hash line:", e)
        sys.exit(1)

    # password resolution
    pwd = args.password
    if pwd is None:
        # prompt
        try:
            pwd = getpass.getpass("Password (leave empty for none): ")
            if pwd == "":
                pwd = None
        except Exception:
            pwd = None

    try:
        fields = parse_pkzip2(line)
    except Exception as e:
        print("Error parsing $pkzip2$:", e)
        sys.exit(1)

    print(f"Parsed pkzip2: CT={fields['CT']} (0=stored,8=defl), CL={fields['CL']} UL={fields['UL']} CRC=0x{fields['CR']:08x}")
    print(f"Inline blob bytes: {len(fields['DA_bytes'])}")

    # Build a sensible entry name - we don't use any external filename; user can override with --entry
    default_entry_name = "file.bin"
    zbytes = build_min_zip_from_blob(default_entry_name, fields)

    # Try to open rebuilt ZIP and list entries; if user provided --entry as index or name, try to use that
    bio = io.BytesIO(zbytes)
    try:
        with zipfile.ZipFile(bio, "r") as zf:
            names = zf.namelist()
            print("Rebuilt ZIP contains entries:", names)
            if names:
                chosen_zbytes = zbytes
                # if user wants a specific entry (index or name), attempt to rebuild with that name so namelist matches
                if args.entry is not None:
                    # if entry is integer index, map to name
                    try:
                        idx = int(args.entry)
                        if 0 <= idx < len(names):
                            # rebuild using that entry name (so central/local name match)
                            chosen_name = names[idx]
                            zbytes = build_min_zip_from_blob(chosen_name, fields)
                        else:
                            print("Entry index out of range; ignoring.")
                    except ValueError:
                        # treat as literal name: rebuild zip with that provided name
                        zbytes = build_min_zip_from_blob(args.entry, fields)

                # Finally attempt decrypt/read
                try_decrypt_zip(zbytes, pwd)
            else:
                print("No entries present after rebuild.")
    except zipfile.BadZipFile:
        # If zipfile can't parse the central directory we still try to read with our single-entry assumption
        print("zipfile couldn't parse central directory; trying single-entry read using default name.")
        try_decrypt_zip(zbytes, pwd)

if __name__ == "__main__":
    main()
           
