import random
import math
import threading
from scapy.all import rdpcap, TCP
from cryptography import x509
from cryptography.hazmat.backends import default_backend
from Crypto.PublicKey import RSA
from Crypto.Util.number import inverse

def pollards_rho(n, stop_event):
    if n % 2 == 0:
        return 2
    x = random.randrange(2, n)
    y = x
    c = random.randrange(1, n)
    d = 1
    while d == 1 and not stop_event.is_set():
        x = (pow(x, 2, n) + c) % n
        y = (pow(y, 2, n) + c) % n
        y = (pow(y, 2, n) + c) % n
        d = math.gcd(abs(x - y), n)
    if d != 1 and d != n:
        return d
    return None

def fermat_factor(n, stop_event):
    a = math.isqrt(n)
    if a * a < n:
        a += 1
    b2 = a*a - n
    while not stop_event.is_set():
        b = math.isqrt(b2)
        if b*b == b2:
            p = a + b
            q = a - b
            if p * q == n:
                return p
        a += 1
        b2 = a*a - n
    return None

def multi_factor(n):
    stop_event = threading.Event()
    result = {}

    def run_pollards():
        d = pollards_rho(n, stop_event)
        if d:
            result['p'] = d
            stop_event.set()

    def run_fermat():
        d = fermat_factor(n, stop_event)
        if d:
            result['p'] = d
            stop_event.set()

    threads = [
        threading.Thread(target=run_pollards),
        threading.Thread(target=run_fermat)
    ]

    for t in threads:
        t.start()

    for t in threads:
        t.join()

    if 'p' in result:
        p = result['p']
        q = n // p
        if p * q != n:
            raise ValueError("Factoring failed: p * q != n")
        return p, q
    else:
        raise ValueError("Factoring failed: no method succeeded")

def parse_pcap(pcap_path):
    print(f"[+] Parsing PCAP: {pcap_path}")
    packets = rdpcap(pcap_path)
    for pkt in packets:
        if pkt.haslayer(TCP):
            if pkt[TCP].dport == 443 or pkt[TCP].sport == 443:
                payload = bytes(pkt[TCP].payload)
                if payload.startswith(b'\x16\x03'):  # TLS Handshake
                    if b'\x0b' in payload:  # Certificate message
                        cert_start = payload.find(b'\x30\x82')  # DER start
                        if cert_start != -1 and cert_start + 4 < len(payload):
                            length_bytes = payload[cert_start+2:cert_start+4]
                            cert_len = int.from_bytes(length_bytes, 'big')
                            cert_end = cert_start + 4 + cert_len
                            cert_der = payload[cert_start:cert_end]
                            
                            server_ip = pkt[0][1].src
                            server_port = pkt[TCP].sport
                            print(f"[+] Found certificate from {server_ip}:{server_port}")
                            return server_ip, server_port, cert_der
    raise ValueError("[-] No certificate found in PCAP.")

def extract_rsa(cert_der):
    print(f"[+] Extracting RSA public key...")
    cert = x509.load_der_x509_certificate(cert_der, backend=default_backend())
    pubkey = cert.public_key()
    numbers = pubkey.public_numbers()
    return numbers.n, numbers.e

def build_private_key(n, e, p, q, filename):
    print(f"[+] Building private key...")
    phi = (p - 1) * (q - 1)
    d = inverse(e, phi)
    key = RSA.construct((n, e, d, p, q))
    with open(filename, "wb") as f:
        f.write(key.export_key("PEM"))

def smart_int(x):
    x = x.strip()
    if x.startswith('0x') or all(c in '0123456789abcdefABCDEF' for c in x):
        return int(x, 16)
    else:
        return int(x)

def main(pcap_file, output_pem):
    ip, port, cert_der = parse_pcap(pcap_file)
    n, e = extract_rsa(cert_der)

    print("\n[*] Modulus (n):")
    print(hex(n))
    print("\n[*] Exponent (e):")
    print(e)

    print("\n[+] Attempting to factor modulus automatically...")

    try:
        p, q = multi_factor(n)
        print("[+] Factoring successful!")
    except Exception as err:
        print(f"[-] Automatic factoring failed: {err}")
        print("[!] Manual input fallback...")
        p_hex = input("[?] Enter p (hex or decimal): ").strip()
        q_hex = input("[?] Enter q (hex or decimal): ").strip()
        p = smart_int(p_hex)
        q = smart_int(q_hex)
        if p * q != n:
            raise ValueError("Manual p * q does not match n!")

    build_private_key(n, e, p, q, output_pem)

    print("\n[+] Done. Private key written to:", output_pem)
    print("[!] You can now import this into Wireshark for decryption.")

if __name__ == "__main__":
    import sys
    if len(sys.argv) != 3:
        print(f"Usage: {sys.argv[0]} <input.pcap> <output_key.pem>")
        sys.exit(1)

    main(sys.argv[1], sys.argv[2])
