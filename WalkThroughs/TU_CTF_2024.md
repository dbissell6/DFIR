# TUCTF24

![Pasted image 20250126095406](https://github.com/user-attachments/assets/40db8069-76ad-47e2-b0b0-abec56b4fe42)

## Mystery Presentation

![Pasted image 20250126095129](https://github.com/user-attachments/assets/8f0d4c52-a016-46ed-b47a-5e0c4cbc624a)

Given .pptx

![Pasted image 20250126102028](https://github.com/user-attachments/assets/aef22fbc-c675-47e5-8c0e-d5ce7ff36dc5)

![Pasted image 20250126102051](https://github.com/user-attachments/assets/51b8770b-a0f2-40fd-8fa6-526fd5c7db97)

Run 7z to extract contents.


![Pasted image 20250126102129](https://github.com/user-attachments/assets/2709cca6-2102-4189-a8f4-25d6fee071f7)

![Pasted image 20250126102226](https://github.com/user-attachments/assets/f5ceeeea-0c4a-407e-b848-3fc9498baaff)

`https://github.com/angea/pocorgtfo` ?

`TUCTF{p01yg10+_fi1e5_hiddin9_in_p1@in_5i9h+}`


## Security Rocks


![Pasted image 20250126095139](https://github.com/user-attachments/assets/b0d3ae09-8e18-41b4-a9e4-2751d03b91d0)

Given pcap

Looking over it it `Wireshark`, nothing sticks out but see some Wi-Fi info.

Use `aircrack-ng`

![Pasted image 20250126103329](https://github.com/user-attachments/assets/04e22082-1039-4e99-87b6-0444354aaa36)

It cracked

![Pasted image 20250126103255](https://github.com/user-attachments/assets/314c8ff9-648f-4092-88ef-3488247a1da8)

Going back into wireshark see some new FTP traffic

![Pasted image 20250126104948](https://github.com/user-attachments/assets/59fd160c-b72e-4ebe-886a-5faaa8f0d26a)

Using the password to decrypt traffic in wireshark.

Yellow box is under `Protocols`

![Pasted image 20250126104624](https://github.com/user-attachments/assets/9f3eb6cf-5f88-4582-8810-3576923416c1)

File - Export Objects - FTP

![Pasted image 20250126104113](https://github.com/user-attachments/assets/120da2a0-d338-481e-ba45-07194bccef4b)

![Pasted image 20250126104734](https://github.com/user-attachments/assets/afcee7ee-c085-4833-8ff3-f1b63f2a64d4)

![Pasted image 20250126105341](https://github.com/user-attachments/assets/317d169a-4214-47c1-b464-46e065329567)

## Bunker

![Pasted image 20250126095213](https://github.com/user-attachments/assets/63d606fa-f8e2-4bdd-aa43-0007bf2baaad)

![Pasted image 20250126105559](https://github.com/user-attachments/assets/48ee2459-a0ed-460f-81f4-c7db76ff4de2)

Given Keepass database and dmp.

Find POC of getting password from Keepass dump.

`https://github.com/vdohney/keepass-password-dumper`

`dotnet run Bunker_DMP`

![Pasted image 20250126115451](https://github.com/user-attachments/assets/45078815-c746-4558-ab7e-33559acf5cc6)

`keepassxc`

![Pasted image 20250126120435](https://github.com/user-attachments/assets/4bdf3b3a-15c1-4bcb-a6ee-21e57d9f3539)

![Pasted image 20250126115432](https://github.com/user-attachments/assets/3415754c-3de0-450c-a647-67fe5491c4a5)


The password has been redacted, but going into the history of the file we can restore a previous version.

![Pasted image 20250126123243](https://github.com/user-attachments/assets/f5e52aa6-5073-4e52-943b-fe4d9f092ee8)

`TUCTF{Th1s_C4nn0T_ConT1nu3}`

## Packet Detective

![Pasted image 20250126095153](https://github.com/user-attachments/assets/a678243d-d3aa-4ec2-81de-1453b4f08945)

Given pcap. Run strings.

![Pasted image 20250126103130](https://github.com/user-attachments/assets/de672451-3125-4fce-aaf8-237a606ae72d)

## XOR-Dinary

![Pasted image 20250126143852](https://github.com/user-attachments/assets/32bcd4ab-f648-49de-8820-7bf5d91fc18a)

Given .txt told to from hex then bruteforce XOR

![Pasted image 20250126143927](https://github.com/user-attachments/assets/512684ea-d848-41a5-8de4-91f6d8b8f27e)

![Pasted image 20250126143946](https://github.com/user-attachments/assets/ddf51934-cd8a-41e0-8608-6799de641b3e)

















