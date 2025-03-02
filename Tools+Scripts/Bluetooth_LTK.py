from cryptography.hazmat.primitives.asymmetric.ec import SECP256R1, \
    derive_private_key

# Made by Discord Prince 2 lu

from whad.ble.crypto import *


# MANUALLY PARSED FROM THE PCAP using wireshark


x = int.from_bytes(bytes.fromhex("7f4a0d4eedf73a1490536d479d1f6f2a2605ccd0f15c9f39002a614324682ceb"), "little")
y = int.from_bytes(bytes.fromhex("085af95fc20b80035627611e949265a528408ef842a75884c30d2d0d6c55d3e2"), "little")
public_key = generate_public_key_from_coordinates(x, y)

#### based on Core Specification 4.2 Vol 3. Part H 2.3.5.6.1
private_int = int.from_bytes(bytes.fromhex("3f49f6d4a3c55f3874c9b3e3d2103f504aff607beb40b7995899b8a6cd3c1abd"), "big") # The private key from the bluetooth specification

private_key = derive_private_key(private_int, SECP256R1())
dhkey = generate_diffie_hellman_shared_secret(private_key, public_key)

initrand = bytes.fromhex("0ce71a94e1005bb725c06f88452f4ad4")[::-1] # init rand
resprand = bytes.fromhex("1bc6b08c35c24af6d02cd0adc388d643")[::-1] # resp rand
chanin = bytes.fromhex("2ccf670738a8") # just the macaddr of the initier
chanresp = bytes.fromhex("08f9e0d260cc") # just the macaddr of the responder

ltk = f5(
    dhkey,
    initrand,
    resprand,
    b"\x00"+chanin, # 0 for type public
    b"\x00"+chanresp # 0 for type public
)[:16].hex()
print(f"LTK: {ltk}")
print(f"Just use crackle -i capture.pcapng -o output.pcap -l {ltk}")
print("https://github.com/mikeryan/crackle")
                                              
