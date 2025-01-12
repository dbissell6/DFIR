# CyberLeague CTF 2025

![Pasted image 20250111230446](https://github.com/user-attachments/assets/7cd2fe4f-aada-4857-bd9c-e0fd9a36af39)

Forensics challenges

## Uncover Me

![Pasted image 20250111221722](https://github.com/user-attachments/assets/463db058-bd06-4d83-9d56-fd54f2731150)

Given `.7z`.

zip2john

![Pasted image 20250111221902](https://github.com/user-attachments/assets/491142d8-fc1c-40ea-8313-97ebecb801cb)

hashcat

![Pasted image 20250111221818](https://github.com/user-attachments/assets/38a86845-c7b7-424b-a965-f99309d60030)

![Pasted image 20250111221752](https://github.com/user-attachments/assets/e567141a-a742-4900-88b3-50e066f834ec)

![Pasted image 20250111221742](https://github.com/user-attachments/assets/76f0c962-77be-4504-a29a-d417951af017)


## Baby Pcap

![Pasted image 20250111222010](https://github.com/user-attachments/assets/aba1e14a-d094-418f-9a60-48a2c453068b)

Given `.pcap`.

Find sus file in exports

![Pasted image 20250112093352](https://github.com/user-attachments/assets/319b298d-4603-4cd8-9b43-facf06450aff)


Python exfiltrator. Can see xor key highlighted.

![Pasted image 20250112093430](https://github.com/user-attachments/assets/c8c53822-73a0-426c-98af-6b77fd096cff)

Other important part is to determine where in the message the encrypted data is.

![Pasted image 20250112093506](https://github.com/user-attachments/assets/0f1b05ce-3f3a-4338-aa78-beccb1e9740e)


`tshark -r capture.pcap -Y "ip.src == 172.18.0.2 && dns.qry.name contains \"result.\"" -T fields -e dns.qry.name`

Run tshark command. Get back some base64 encoded strings.

![Pasted image 20250112093208](https://github.com/user-attachments/assets/1615e48c-cd4c-4ccd-a523-157deb428152)

Take to cyber chef and decode, see root, a good sign.

![Pasted image 20250112093140](https://github.com/user-attachments/assets/016ba1c0-0a6c-4681-8cdd-54516eab7fd3)



![Pasted image 20250112093319](https://github.com/user-attachments/assets/45304a1b-d4e5-49d2-ac9c-c7107c8ada7c)



## More RAM Part 1


![Pasted image 20250111230130](https://github.com/user-attachments/assets/2e0d4abc-3f27-4209-aabc-eff55a40ffee)


Given a `.zip` with a `.lime`.



![Pasted image 20250111230416](https://github.com/user-attachments/assets/a220e6b4-6d78-4394-94ce-909fe1c06570)

Just running strings


![Pasted image 20250111230909](https://github.com/user-attachments/assets/2a29d990-0423-43c4-90e3-9c14f5c4aeb3)


## More RAM Part 2


![Pasted image 20250111231532](https://github.com/user-attachments/assets/65659799-c808-461b-8c97-6c9840f8a7f7)








