![image](https://github.com/user-attachments/assets/6e9b2f4f-953e-4ee1-911d-f229bbde0906)



# industrialspy3

![Pasted image 20240908061603](https://github.com/user-attachments/assets/e121bb87-650b-4e94-88c3-3855609cd057)


Given Pcap.

![Pasted image 20240908062853](https://github.com/user-attachments/assets/8bd07b0b-7171-44ec-9245-30f3e8a0d947)

```
tcp.flags.syn == 1 && tcp.flags.ack == 1
```

Moving down we can see log of failed login attempts


![Pasted image 20240908063108](https://github.com/user-attachments/assets/763f5d84-630f-4903-9a5a-ed08a339036b)


The last login attempt before accessing the database

![Pasted image 20240908063545](https://github.com/user-attachments/assets/e57b2ad9-015f-4633-8e78-218476a2882f)


![Pasted image 20240908063613](https://github.com/user-attachments/assets/a9aa488c-287e-49a4-8ca1-c3015effd145)


![Pasted image 20240908063418](https://github.com/user-attachments/assets/1f88b9df-330c-4bb5-a248-ea509e81cf8b)



![Pasted image 20240908061948](https://github.com/user-attachments/assets/038df9b4-87b4-4ac7-96bc-f005e8a2f125)

![Pasted image 20240908062514](https://github.com/user-attachments/assets/f994a33c-bb03-4d48-8374-aad735a4963d)



![Pasted image 20240908062607](https://github.com/user-attachments/assets/44d53cce-94bd-41b7-b118-5112500dfe44)



![Pasted image 20240908061924](https://github.com/user-attachments/assets/c6d98d4d-2330-4faa-9ed7-0876c9a68109)

![Pasted image 20240907182046](https://github.com/user-attachments/assets/a240d894-029d-4ccd-bc42-a8c3f590a24e)

# the dumb hacker

![Pasted image 20240908061707](https://github.com/user-attachments/assets/96a0c0d9-21ac-44bd-9773-337b5b8e434b)


![Pasted image 20240908072001](https://github.com/user-attachments/assets/918ccd84-43a7-476c-adb5-5171c1bc3582)


Given windows registry file, an ASCII version tho? This isn't normal.


![Pasted image 20240908072051](https://github.com/user-attachments/assets/5f58004a-2fcb-4d15-a903-f3553368e279)

It broke all the normal tools so we had to look through it manually. Look at RecentDocs find secret and something.

![Pasted image 20240908191412](https://github.com/user-attachments/assets/051f8d53-0e0d-405e-88a3-6b4c881fab31)


![Pasted image 20240908191445](https://github.com/user-attachments/assets/91a336e6-76a4-4e03-9dae-67d96b351077)

![Pasted image 20240908191612](https://github.com/user-attachments/assets/ba1e3cd8-be90-4ef0-81ef-483ffd53f765)


![Pasted image 20240908192257](https://github.com/user-attachments/assets/c01bd369-fc94-4d2c-bb65-e1d163656895)

```
COMPCTF16{h4ck3r_l3ft_4_N0t3_sA1d_tH4t_sm00thcr1m1nal_w4s_h3re_4dff1d3627}
```


# head's up


![Pasted image 20240908061728](https://github.com/user-attachments/assets/5c8a64e6-5445-49bd-87f8-3543ab64aa1a)


![Pasted image 20240908064910](https://github.com/user-attachments/assets/01f3fe41-a4b6-4a23-9d46-9e61f7f3b12d)


![Pasted image 20240908065203](https://github.com/user-attachments/assets/180be7fa-77d8-4089-98db-b4c01b8cf02f)


![Pasted image 20240908065642](https://github.com/user-attachments/assets/1ae313aa-b709-4a7a-8f5b-abc6f897369f)

Running strings on the file there are 2 things that stick out

1) Contains IHDR and IDAT but binwalk didn't find a png. This almost 100% means there is a png in there but the magic bytes have been removed.


![Pasted image 20240908065257](https://github.com/user-attachments/assets/3aff86f0-94af-4d2f-afdc-01958dcb6b2e)

2) Towards the bottom there is info about a font with the same name as our random string meong.txt

![Pasted image 20240908065556](https://github.com/user-attachments/assets/e5705518-3fd2-4f98-8bcc-e5a472144385)


Fixing the png

Bytes before

![Pasted image 20240908065854](https://github.com/user-attachments/assets/85dbc944-aec4-403d-b5fb-5e1cdebad89e)


Bytes After


![Pasted image 20240908065817](https://github.com/user-attachments/assets/421f284b-42bb-4aed-901c-235cca91b3fb)

Running binwalk again we can see it is able to detect the png. 



![Pasted image 20240908065940](https://github.com/user-attachments/assets/4d6b0083-6f07-40dc-a5df-be745e14d2a2)

Extracting the png and opening it up.

![Pasted image 20240908064341](https://github.com/user-attachments/assets/98092b53-6e6f-4c16-9fec-4241f9d12abe)

Next we need to do the same for the ttf. The IEND is the trailer of the png. 


![Pasted image 20240908070323](https://github.com/user-attachments/assets/d4e56696-4663-4bfe-9784-2f23926d5471)

A little research shows what we need to change the magic bytes of the ttf to. 

![Pasted image 20240908070657](https://github.com/user-attachments/assets/00d67940-c5e7-4665-837c-890c028f8ef5)


Cleaned up .tff header.


![Pasted image 20240908070517](https://github.com/user-attachments/assets/d72ddc10-3f74-4e50-9238-9a50b1e0f21c)

Binwalk still didn't recognize the .tff so had to extract it manually. 

Now that we have the clean .ttf we can open it up in fontforge



![Pasted image 20240908064504](https://github.com/user-attachments/assets/dc859669-3b97-41d7-a5b4-31fba5b00406)


![Pasted image 20240908063913](https://github.com/user-attachments/assets/b80f29f2-1aa2-4331-b49f-1c3ca33936a2)

Remembering our meong.txt we can recall it was the Greek alphabet characters. It looks like those will be replaced these regular characters to create the third part of the flag. 

To do the translation for us we can open,
``` Window -> New Metrics Window. ```

Then we can load the text by hitting the `v` to see the translation


![Pasted image 20240908064023](https://github.com/user-attachments/assets/659ff5ad-e113-4983-8084-68319a17475b)

![Pasted image 20240908064632](https://github.com/user-attachments/assets/868168f2-0341-4236-b0ee-ffff7ee3874b)

There are a couple broken parts but it should be trivial to fix.


Final flag

```
COMPFEST16{lO0kS_l1k3_u_k3pt_Ur_hE4D_uP!_22a4b9bdf7}
```
# loss


![Pasted image 20240908061750](https://github.com/user-attachments/assets/49b08faf-9eef-4dfd-afcf-09f82716cebb)

Given .e01


![Pasted image 20240908111337](https://github.com/user-attachments/assets/09553f9b-6e0c-4356-ace4-d8ff44e8029d)

So should be easy lets go into secret project and get the flag.  We see a hint there is a dev branch we don't have access to it.


![Pasted image 20240908110258](https://github.com/user-attachments/assets/f9cb5da8-7546-4698-96b5-59dea0b1f8b0)

A commit where we should find the flag


![Pasted image 20240908112531](https://github.com/user-attachments/assets/1db5388f-5f92-4990-9ecf-a4c7bb7803f9)

Keep looking and see there is a server. 

![Pasted image 20240908111435](https://github.com/user-attachments/assets/c59816ea-3007-4a47-a992-4c4e1cb3e96c)

The server is still up!

![Pasted image 20240908111651](https://github.com/user-attachments/assets/9baf9e4f-3e9c-4d87-a544-f73ac6c11516)

So there are a couple tools to extract exposed gits. These tools gave us issues. First issue is there was a rate limit. The current speed would not be able to extract all of the objects. The second issue was it wasnt pulling the dev branch.

To fix

Download gitdumper

```
git clone https://github.com/internetwache/GitTools.git
```

Slow it down

![Pasted image 20240908112325](https://github.com/user-attachments/assets/28f4fe3b-9dcd-4efc-8a71-57c98041a718)


Get the dev branch


![Pasted image 20240908112225](https://github.com/user-attachments/assets/961ad9f5-c88c-4e81-98d7-5de7209c61b2)

Now let it run




![Pasted image 20240908112134](https://github.com/user-attachments/assets/eed165b5-2079-4cc2-a787-e04f5a63a6b6)

Yee!


![Pasted image 20240908112346](https://github.com/user-attachments/assets/78169d5a-f5af-4402-81e7-30c8609f2537)

```
git clone out/.git my-working-directory
git checkout dev (but was already dev) - This is what I wanted to read
```

Now all the objects are z compressed, open them up in cyberchef.
![Pasted image 20240908105917](https://github.com/user-attachments/assets/dc6de86c-f31e-4c71-9e80-f10a1c18bbe8)
