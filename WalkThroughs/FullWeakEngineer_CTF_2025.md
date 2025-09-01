# Full Weak Engineer CTF 2025

<img width="610" height="438" alt="Pasted image 20250831102334" src="https://github.com/user-attachments/assets/20f0956e-871f-4110-bf37-a860c654978d" />

## SharkShop

<img width="455" height="666" alt="Pasted image 20250831102414" src="https://github.com/user-attachments/assets/892c5d17-795d-4abd-87be-33d519a57aaf" />


This challenge featured TLS 1.3 end-to-end, so the private key couldn’t decrypt packets, but the app leaked a size-oracle through ciphertext lengths. By exporting TLS record sizes with tshark and clustering responses into small vs big, we mapped them to booleans and ran a binary search to recover the admin password. The walkthrough shows how to spot and exploit length side-channels over TLS—and how to mitigate them (fix SQLi, normalize response size, consider TLS 1.3 padding).


Looking into the provided artifacts we see we are given

1) a server 
2) a pcap

<img width="466" height="319" alt="Pasted image 20250830114549" src="https://github.com/user-attachments/assets/3238d2c6-d301-4c65-9e5e-2b402b05248c" />


Looking into the pcap we see it is TLS 1.3, so even if we found the `key.pem` it wouldn't be much help(forward secrecy). A quick win would be if we were able to find the `SSLKEYLOGFILE`, however that isn't accessible to us. 

<img width="1718" height="916" alt="Pasted image 20250830114620" src="https://github.com/user-attachments/assets/755081ec-663d-454a-8a9f-4223a1f61e75" />


One of the first packets in the dump shows the method the attacker used to get the password.  It is using SQL injection with binary search on the `coupon` endpoint. 

The check condition looks for the string `You can enter coupons after the offiical launch`. If it contains that string it means the character is Greater than the guess, if not the character is less than the guess.

It goes character by character until the full password is leaked.

<img width="1144" height="788" alt="Pasted image 20250830114649" src="https://github.com/user-attachments/assets/cdfa4c55-8017-4792-a15c-57b4be546f93" />

Now even though the TLS 1.3 traffic is encrypted, we can still infer the contents of the response, due to the length of the packet. 

To start our attack, we can use a tshark command to pull the relevant parts out of the pcap into a csv. 

<img width="699" height="188" alt="Pasted image 20250830114753" src="https://github.com/user-attachments/assets/5185fba6-21e9-49c3-aad0-331341f6f873" />

This will yield a csv like the one shown below.

<img width="553" height="251" alt="Pasted image 20250831113657" src="https://github.com/user-attachments/assets/c2cffc77-01e6-483c-b1dc-5b0054cd2889" />

Now we can use a python script that will look for the client and server and length of the response.  Below is a table that shows step by step how the first character of the password was derived. Take notice how the `New Range` shrinks after each round.


|Step|mid = ⌊(low+high)/2⌋|Response|Action|New range|last_true|
|--:|--:|:-:|---|---|---|
|1|79|**T**|char ≥ 79 → search higher|80…126|79|
|2|103|**T**|char ≥ 103 → search higher|104…126|103|
|3|115|**F**|char < 115 → search lower|104…114|103|
|4|109|**F**|char < 109 → search lower|104…108|103|
|5|106|**T**|char ≥ 106 → search higher|107…108|106|
|6|107|**T**|char ≥ 107 → search higher|108…108|**107**|
|7|108|**F**|char < 108 → search lower|108…107 (stop)|**107**|

Finally, after 7 rounds, we see the `last_true` was `107`. 

<img width="548" height="92" alt="Pasted image 20250831115229" src="https://github.com/user-attachments/assets/948d170b-1524-4069-a8f1-5ba4ff40221b" />



Full python code.

```
#!/usr/bin/env python3
import csv, statistics, sys

CLIENT = "192.168.224.2"
SERVER = "34.84.101.79"
CSV = "tls_records.csv"
LOW, HIGH = 32, 126

def load_rows():
    rows=[]
    with open(CSV, newline="") as f:
        for t,src,dst,L in csv.reader(f):
            rows.append((float(t),src,dst,int(L)))
    rows.sort(key=lambda x:x[0])
    return rows

def bucket_responses(rows):
    # sum server->client payload until next client->server payload
    resp, cur = [], 0
    for _,src,dst,L in rows:
        if src==CLIENT and dst==SERVER:
            if cur>0: resp.append(cur); cur=0
        elif src==SERVER and dst==CLIENT:
            cur += L
    if cur>0: resp.append(cur)
    return resp

def threshold(vals):
    mid = statistics.median(vals)
    for _ in range(6):
        g1=[v for v in vals if v<=mid]; g2=[v for v in vals if v>mid]
        m1=statistics.mean(g1) if g1 else mid
        m2=statistics.mean(g2) if g2 else mid+1
        mid=(m1+m2)/2
    return mid

def decode(bools):
    out = []
    it = iter(bools)
    while True:
        low, high = LOW, HIGH     # ← correct init
        last_true = None
        while low <= high:
            mid = (low + high) // 2
            try:
                ok = next(it)     # True => condition met => move low up
            except StopIteration:
                return "".join(out)
            if ok:
                last_true = mid
                low = mid + 1
            else:
                high = mid - 1
        if last_true is None:
            break
        out.append(chr(last_true))
        print(f"[+] {len(out):02d}: {out[-1]!r}  -> {''.join(out)}", flush=True)


def run(skip=0):
    rows=load_rows()
    resp=bucket_responses(rows)
    print(f"[i] buckets total: {len(resp)}")
    # keep only full page responses; drop the ~1378 “stub”
    pages=[v for v in resp if v>2000]
    if skip: pages=pages[skip:]
    print(f"[i] page buckets (>{2000}): {len(pages)}")
    print("[i] first 20 pages:", pages[:20])
    thr=threshold(pages)
    small=[v for v in pages if v<=thr]; big=[v for v in pages if v>thr]
    print(f"[i] thr≈{thr:.1f} small={len(small)} mean={statistics.mean(small):.1f}  "
          f"big={len(big)} mean={statistics.mean(big):.1f}")

    for label, true_is_big in [("big==True",True), ("small==True",False)]:
        print(f"\n[>] {label}")
        bools=[(v>thr) if true_is_big else (v<=thr) for v in pages]
        print(f"[i] decisions: {len(bools)} (~{len(bools)//7} chars)")
        pwd=decode(bools)
        print(f"[✓] candidate ({label}): {pwd!r}\n")

if __name__=="__main__":
    s=int(sys.argv[1]) if len(sys.argv)>1 else 0
    run(skip=s)
     
```

We can run the script and see the password get created as the attacker would have.

<img width="1685" height="918" alt="Pasted image 20250830114836" src="https://github.com/user-attachments/assets/e0b01c23-48c0-4c46-87a9-9193f431cd6c" />


Now we can take this password to login. 

From looking at the source code, we also know the flag will be on the admin page.


<img width="773" height="230" alt="Pasted image 20250830115023" src="https://github.com/user-attachments/assets/99b35708-3524-4a5e-ac9c-6d23a7755b65" />

<img width="707" height="349" alt="Pasted image 20250830115147" src="https://github.com/user-attachments/assets/08e17199-5f18-4f19-8768-a4a67410454b" />


Going to that endpoint we get the flag.

<img width="1483" height="483" alt="Pasted image 20250830114414" src="https://github.com/user-attachments/assets/6c770150-9cd7-4e07-91a2-e22d58a893ed" />












