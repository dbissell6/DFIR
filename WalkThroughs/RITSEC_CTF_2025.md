# RITSECCTF2025


![Pasted image 20250322133001](https://github.com/user-attachments/assets/0a0db06c-1bd5-452e-806f-1b3b2e403fcc)


## Pentest Forensics

![Pasted image 20250321152007](https://github.com/user-attachments/assets/21fae041-f44f-40ba-a807-21c6579ff6ef)

Given a mem dump.raw


![Pasted image 20250321152958](https://github.com/user-attachments/assets/b0f8c170-adf2-4240-a899-365677d79a94)

![Pasted image 20250321153356](https://github.com/user-attachments/assets/1101f83c-52e3-4f9e-9b6b-59d83417d079)



![Pasted image 20250321154219](https://github.com/user-attachments/assets/f7aac626-75bb-406f-b493-7d0884981354)

The key is seeing there was a pcap being captured while the smb auth was happening. Use the capture the to reassemble the parts and crack the hash.


Get parts from smb transfer.

![Pasted image 20250322105150](https://github.com/user-attachments/assets/263510e2-01f4-4a1e-8b4e-388515abfd19)


## ROPE


![Pasted image 20250321152114](https://github.com/user-attachments/assets/30468b95-e8dc-47f3-9a08-b915a321c43e)


Given .png and run strings.

![Pasted image 20250321152245](https://github.com/user-attachments/assets/628280e6-ed15-4370-a533-d9c538c5fba6)


## Intercepted Transmission


![Pasted image 20250321152344](https://github.com/user-attachments/assets/81aa7f41-a352-4635-a511-c0d629aee620)

Given a pcap can find data in icmp packet data. 


![Pasted image 20250322181553](https://github.com/user-attachments/assets/e76dbc12-3af5-490c-8681-c30caf736025)

Use tshark to extract the data.

![Pasted image 20250322181842](https://github.com/user-attachments/assets/d2feb1d3-864b-4322-8b0d-381e9127f1a3)


## Aliens Actually Listen To this

![Pasted image 20250322113438](https://github.com/user-attachments/assets/425408c4-22a7-4b81-92d7-8095d4368891)

Given an MPEG mps and MIDI

![Pasted image 20250322113411](https://github.com/user-attachments/assets/18e00104-d301-4931-9514-ef886e8693e3)

Opening Audacity, Suvoni speaks alien

![Pasted image 20250322132658](https://github.com/user-attachments/assets/c7c1f5bb-d02b-4a59-995c-ec937e2f6ce1)

## BANKSMAN

![Pasted image 20250322132325](https://github.com/user-attachments/assets/181b16d5-f385-40b5-8d0c-d1f46071ab0c)

Given a pdf

![Pasted image 20250322132306](https://github.com/user-attachments/assets/89170c47-eb83-4d1d-9c27-df2cb4d3bebc)


![Pasted image 20250322132223](https://github.com/user-attachments/assets/c29385f7-a0a7-4f30-9375-a6d267e226a3)

Can see some sus with `pdf-parser`.

![Pasted image 20250323134312](https://github.com/user-attachments/assets/138e1f8f-d4c0-4244-9461-a98607cfcb37)

![Pasted image 20250323134334](https://github.com/user-attachments/assets/30f57649-7068-4d81-a57d-fac345f0379c)

Looking at it in CyberChef `From Hex`.

![Pasted image 20250322132352](https://github.com/user-attachments/assets/6fbf9e1a-1d50-4733-9cb2-c705526ea11f)

Convert this from base64 notice some signs of an exe.


![Pasted image 20250322132423](https://github.com/user-attachments/assets/6a1f0490-8533-4f4c-9fde-0e98cc67aadf)

At the bottom of the exe can see the flag

![Pasted image 20250322132439](https://github.com/user-attachments/assets/ac9f4d2b-f2f5-4463-9ea0-0e51cc1fc382)

## Hashcrack

![Pasted image 20250323113938](https://github.com/user-attachments/assets/a1c773b5-37a6-4be6-b540-01422e9319f9)

`.\hashcat.exe -m 0 .\3.hash.txt .\rockyou.txt`

![Pasted image 20250322133818](https://github.com/user-attachments/assets/4328687b-14f4-4e76-bd2f-1445819d8f19)

`.\hashcat.exe -m 0 .\3.hash.txt .\rockyou.txt -r rules/best64.rule`

![Pasted image 20250322133934](https://github.com/user-attachments/assets/4f6c7ee8-4c26-446c-a8c2-22d06bc3d0d8)

` .\hashcat.exe -m 0 .\3.hash.txt .\rockyou.txt -r .\rules\d3ad0ne.rule`

![Pasted image 20250322134336](https://github.com/user-attachments/assets/9f894a4d-c40f-449a-bf5a-42666eb3e743)


![Pasted image 20250322134500](https://github.com/user-attachments/assets/856223ee-28a6-4a43-9c6d-92450e8066b6)

```
PS C:\Users\Daniel\Desktop\hashcat-6.2.6\hashcat-6.2.6> .\hashcat.exe -m 0 .\3.hash.txt  --show
2879b0bf1c0f0cf7640bd7f0979f273d:3uRopA24
ec77ff156c178c0c1537eba873ddbcdd:4neptune
c84abfa5ddbaa91011582d1c50d9b53d:m1LkYw4y62
0ecfc8ea245300b44a4d0ede3c049d43:17JUPITER
68834fdcdff2a84a2844bd794aa9bcdf:mars
78ea73e4f2fc8765f5b520ec602ef948:plut0
b16f0cf232f30e6fb91a369b12d53c57:Andr0m3d4!
5b9727bb9358137b79f6f8ccfd6fd5a4:saturn94
1d3404bcf57b2e7e6cba61a3318736ad:Mercury86
795e0bd1427a7713c93bfc049fc1e7a3:5aG1Tt@rius
ecde9e21b759490adcdcb06a8c8a4145:ku!p3r_b3l7!
98006665f5bfa7ec359b09775fc0943d:_v0y@g3r_
```













