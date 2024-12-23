# BackdoorCTF2024

![Pasted image 20241222075459](https://github.com/user-attachments/assets/59ca0a94-5dd9-4b0d-80d2-991376a002d1)


## Cursed Credentials


![Pasted image 20241222075526](https://github.com/user-attachments/assets/98737a90-b52e-4f95-be87-42d9f437047d)

Given firefox configuration files. 

![Pasted image 20241222075540](https://github.com/user-attachments/assets/f24aa0be-0510-43c4-926d-6d4387dfda0b)



![image](https://github.com/user-attachments/assets/c6394b06-5aa2-474a-ba7b-3a4a43536048)



<details>

<summary>Python code to get firefox key4.db</summary>


```
import argparse
import binascii
import hashlib
import hmac
import os
import sqlite3
import struct
import sys
from Crypto.Cipher import AES, DES3
from pyasn1.codec.der import decoder


class MasterPasswordInfos:
    def __init__(self, mode, global_salt, entry_salt, cipher_text, no_master_password, iteration=None, iv=None):
        if mode not in ['aes', '3des']:
            raise ValueError('Invalid mode. Supported modes are: aes, 3des.')

        self.mode = mode
        self.global_salt = global_salt
        self.entry_salt = entry_salt
        self.cipher_text = cipher_text
        self.no_master_password = no_master_password
        self.iteration = iteration
        self.iv = iv


def read_bsd_db(db_filepath):
    """Read key3.db (legacy) database."""
    with open(db_filepath, 'rb') as f:
        header = f.read(4 * 15)

        magic = struct.unpack('>L', header[0:4])[0]
        if magic != 0x61561:
            raise ValueError('Invalid magic number in database header.')

        version = struct.unpack('>L', header[4:8])[0]
        if version != 2:
            raise ValueError('Unsupported database version.')

        pagesize = struct.unpack('>L', header[12:16])[0]
        nkeys = struct.unpack('>L', header[56:60])[0]

        readkeys = 0
        page = 1
        db1 = []

        while readkeys < nkeys:
            f.seek(pagesize * page)
            offsets = f.read((nkeys + 1) * 4 + 2)

            offset_vals = []
            i = 0
            while True:
                key = struct.unpack('<H', offsets[(2 + i):(2 + i + 2)])[0]
                val = struct.unpack('<H', offsets[(4 + i):(4 + i + 2)])[0]
                nval = struct.unpack('<H', offsets[(8 + i):(8 + i + 2)])[0]
                if nval == val:
                    break

                offset_vals.extend([key + (pagesize * page), val + (pagesize * page)])
                readkeys += 1
                i += 4

            offset_vals.append(pagesize * (page + 1))
            val_key = sorted(offset_vals)

            for j in range(len(val_key) - 1):
                f.seek(val_key[j])
                data = f.read(val_key[j + 1] - val_key[j])
                db1.append(data)

            page += 1

        return {db1[i + 1]: db1[i] for i in range(0, len(db1), 2)}


def decrypt_mozilla_3des(global_salt, entry_salt, cipher_text):
    """Attempt to decrypt using 3DES."""
    hp = hashlib.sha1(global_salt).digest()
    chp = hashlib.sha1(hp + entry_salt).digest()
    pes = entry_salt + b'\x00' * (20 - len(entry_salt))
    k1 = hmac.new(chp, pes + entry_salt, hashlib.sha1).digest()
    tk = hmac.new(chp, pes, hashlib.sha1).digest()
    k2 = hmac.new(chp, tk + entry_salt, hashlib.sha1).digest()
    key = k1 + k2
    iv = key[-8:]
    return DES3.new(key[:24], DES3.MODE_CBC, iv).decrypt(cipher_text) == b'password-check\x02\x02'


def decrypt_pbe_aes(global_salt, entry_salt, iteration, iv, cipher_text):
    """Attempt to decrypt using AES."""
    key = hashlib.pbkdf2_hmac('sha256', hashlib.sha1(global_salt).digest(), entry_salt, iteration, dklen=32)
    return AES.new(key, AES.MODE_CBC, iv).decrypt(cipher_text) == b'password-check\x02\x02'


def extract_master_password_infos(db_filepath, db_version):
    """Extract encryption details for master password."""
    if db_version == 3:
        db_values = read_bsd_db(db_filepath)
        global_salt = db_values[b'global-salt']
        pwd_check = db_values[b'password-check']
        entry_salt = pwd_check[3:3 + pwd_check[1]]
        cipher_text = pwd_check[-16:]
        no_master_password = decrypt_mozilla_3des(global_salt, entry_salt, cipher_text)
        return MasterPasswordInfos('3des', global_salt, entry_salt, cipher_text, no_master_password)
    elif db_version == 4:
        db = sqlite3.connect(db_filepath)
        c = db.cursor()
        c.execute('SELECT item1, item2 FROM metadata WHERE id = "password"')
        global_salt, encoded_item2 = c.fetchone()
        decoded_item2 = decoder.decode(encoded_item2)
        pbe_algo = str(decoded_item2[0][0][0])

        if pbe_algo == '1.2.840.113549.1.12.5.1.3':  # 3DES
            entry_salt = decoded_item2[0][0][1][0].asOctets()
            cipher_text = decoded_item2[0][1].asOctets()
            no_master_password = decrypt_mozilla_3des(global_salt, entry_salt, cipher_text)
            return MasterPasswordInfos('3des', global_salt, entry_salt, cipher_text, no_master_password)
        elif pbe_algo == '1.2.840.113549.1.5.13':  # AES
            entry_salt = decoded_item2[0][0][1][0][1][0].asOctets()
            iteration = int(decoded_item2[0][0][1][0][1][1])
            iv = b'\x04\x0e' + decoded_item2[0][0][1][1][1].asOctets()
            cipher_text = decoded_item2[0][1].asOctets()
            no_master_password = decrypt_pbe_aes(global_salt, entry_salt, iteration, iv, cipher_text)
            return MasterPasswordInfos('aes', global_salt, entry_salt, cipher_text, no_master_password, iteration, iv)
    raise ValueError("Unsupported database version")


def get_hashcat_format(mp_infos):
    """Generate hashcat-compatible string."""
    if mp_infos.no_master_password:
        return 'No Primary Password is set.'
    if mp_infos.mode == '3des':
        return f'$mozilla$*3DES*{binascii.hexlify(mp_infos.global_salt).decode()}*' \
               f'{binascii.hexlify(mp_infos.entry_salt).decode()}*' \
               f'{binascii.hexlify(mp_infos.cipher_text).decode()}'
    return f'$mozilla$*AES*{binascii.hexlify(mp_infos.global_salt).decode()}*' \
           f'{binascii.hexlify(mp_infos.entry_salt).decode()}*{mp_infos.iteration}*' \
           f'{binascii.hexlify(mp_infos.iv).decode()}*{binascii.hexlify(mp_infos.cipher_text).decode()}'


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description="Extract master password info for hashcat")
    parser.add_argument('db_path', help='Path to key3.db or key4.db')
    args = parser.parse_args()

    if not os.path.exists(args.db_path):
        print("Database file not found!")
        sys.exit(1)

    db_type = 3 if 'key3.db' in args.db_path else 4
    mp_infos = extract_master_password_infos(args.db_path, db_type)
    print(get_hashcat_format(mp_infos))
    
```
</details>



Using hashcat to crack the hash


![Pasted image 20241222101911](https://github.com/user-attachments/assets/74c78ccb-6647-4e39-85db-f411a92b43a4)


![Pasted image 20241222101648](https://github.com/user-attachments/assets/a435b7a0-73bf-4962-bcc2-24c36cca9292)



## My boss's boss's boss?

![Pasted image 20241222093304](https://github.com/user-attachments/assets/4372adef-f2ec-491d-946a-1f8a4904ac16)

Given a .pdf.


![Pasted image 20241222093354](https://github.com/user-attachments/assets/22ca2156-19e2-43ed-b542-d9ded8d0af7e)

Take a look, seems like a normal pdf.

![Pasted image 20241222093530](https://github.com/user-attachments/assets/b54c8180-9cad-4929-8ab7-f8b8fe3fcdf9)


pdf-parser notice object 999


![Pasted image 20241222172534](https://github.com/user-attachments/assets/eadd20fc-4852-412f-a055-d560176cbf2a)

Notice the directory had a weird string.

![Pasted image 20241222172618](https://github.com/user-attachments/assets/73985ee0-49e4-4c73-842f-c5158bcc8527)

Concat all the bytes from the object and xor with `57`.

![Pasted image 20241222172458](https://github.com/user-attachments/assets/04009982-d978-4d0e-a519-3b400961e5cf)

See we get a zip

![Pasted image 20241222172157](https://github.com/user-attachments/assets/c7d603f7-1968-4319-9af7-c9f0d4405a79)

Get the hash with john. Convert to the hashcat format

![image](https://github.com/user-attachments/assets/e45a422d-3eb3-4c02-b6b2-0cf8facdbc63)

Remember the decription said something about `d3ad0ne` and `ruleset`, and use that as a `ruleset`.

![Pasted image 20241223074118](https://github.com/user-attachments/assets/06a51bcc-8859-413c-a0a7-af8341e4dff5)

Use firefox decrypt to get the password and flag.

![Pasted image 20241223074228](https://github.com/user-attachments/assets/53ee5c37-95c0-4508-97f4-af912ca77a79)


## Torrent Tempest



![Pasted image 20241222084326](https://github.com/user-attachments/assets/5d549ce9-bf53-42b0-982e-86260b3c11c1)

Given pcap. 

![Pasted image 20241222085749](https://github.com/user-attachments/assets/ca526036-b27c-445c-a6aa-99aa8651b3d1)

Running strings on the pcap get a `secret.wav`. Running **binwalk** also see `key.txt`


![Pasted image 20241222085924](https://github.com/user-attachments/assets/c9330ca4-624c-448f-8848-4d29254f2276)

Find one of the streams conintaing that info in **Wireshark**.

![image](https://github.com/user-attachments/assets/9fc1735a-76e5-4352-838d-9e03e3043987)

Extract the ZIP file, extract and recover both files. Take the contents of `key.txt` to **CyberChef**.

![image](https://github.com/user-attachments/assets/ef21a00a-21b5-4de4-8d55-c358365b515d)

Now that we have a password we can take both to **DeepSound** to extract files.

![Pasted image 20241222105410](https://github.com/user-attachments/assets/d7ac9fd6-bdd6-4203-8ddf-5668a07396b5)


`https://github.com/Jpinsoft/DeepSound`

Click on extract secret files. Put in password.


![Pasted image 20241222110154](https://github.com/user-attachments/assets/2755ca2f-d5d7-47f3-adbe-04d9d418b9b2)



## American Spy


![Pasted image 20241222092607](https://github.com/user-attachments/assets/008ceea4-7ccb-4261-90af-f130b08532ff)


![Pasted image 20241222092659](https://github.com/user-attachments/assets/7f540fac-93cc-47db-b913-f846fb5146a4)


Hint about VC notice lime and voip, find SIP traffic


![Pasted image 20241222124513](https://github.com/user-attachments/assets/a711bded-3b26-4a7f-b46f-87f2740de9e5)

![Pasted image 20241222183127](https://github.com/user-attachments/assets/02ebdcce-1816-43cd-9e4e-ab2dbb174b90)

![Pasted image 20241222183015](https://github.com/user-attachments/assets/688fa5f4-800d-4b05-80a8-96f18b83c924)

![Pasted image 20241222182952](https://github.com/user-attachments/assets/a3d467de-7e55-45f5-854e-a4bc984c5cd6)


![Pasted image 20241222121244](https://github.com/user-attachments/assets/4a30d07a-51f0-48f7-9f04-aeda6c9bd7e9)

None of these cracked

also found rtp traffic

Telephony -> RTP -> RTP Streams

![Pasted image 20241222125634](https://github.com/user-attachments/assets/3f4f58b0-f2bd-4eb1-8249-a6b8e223eca4)


![Pasted image 20241222192307](https://github.com/user-attachments/assets/21b5a169-4cf8-44cc-84d7-da438097ce2b)

Can hear something here, ends with tell me kid the key is `I will come home` ?

## Roman-Xor.png

![Pasted image 20241222083719](https://github.com/user-attachments/assets/6f03f2a3-34c9-4a5c-9a5a-6290f474987c)


![Pasted image 20241222085308](https://github.com/user-attachments/assets/c4d4b53b-b8e4-4c74-8e9a-6ce7c22a8eb6)

![Pasted image 20241222083816](https://github.com/user-attachments/assets/f8a9f621-752a-4ef6-a435-f7817650f8c2)

![Pasted image 20241222084055](https://github.com/user-attachments/assets/92bfb442-853a-43d0-a3bd-8a0dfb989019)



