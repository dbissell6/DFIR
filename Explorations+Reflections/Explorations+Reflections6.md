3/14/2024

![image](https://github.com/dbissell6/DFIR/assets/50979196/45f2905e-d540-4d9e-8032-ba8fbd730b10)
![image](https://github.com/dbissell6/DFIR/assets/50979196/35ff1857-185b-49c3-bd2d-b34d78200b79)

# Introduction

Another cycle complete. Just as last year HTB and PICO held their spring CTFs at the same time. 

This started ~18 months ago as a way to learn DFIR through CTFs. The focus has slowly expanded but still retains that objective at its heart. When this process began it felt like these challs were used for training, now the CTF feels more like a yearly check up. A diagnostic tool. 

# Overview of Challenges

Just like last year focused on the forensics and misc challs. PICO misc challs had a bunch of challs related to git.  PICO only had one stego chall which was a relief. HTB removed the machine learning category. 

Towards the end of last year I got on an anti-anti-debugging vibe and PICO had a series of challenges for this.

# Deep Dive on Selected Challenges

## Path of survival - HTB

This challenge consisted of creating a graph and finding the shortest path from a start node and target node. It had a similar vibe to last years 'calibration' challenge in terms of tools used, having to constantly interact with a server and having to get the correct answer 100 times. 

## WinAntiDbgXx100 - PICO

This was a set of 3 challenges attempting to get past a debugger to get a flag. The first 2 challs felt very similar to the excersise I did to explore this concept late last year. The main difference which was nice was it all focused on windows exes where I was looking at linux binaries.

The 3rd chall brought a whole host of problems I hadnt encountered or thought of. 

1) The exe came with a config.bin and ?
2) The exe was packed and when unpacked wouldnt run
3) the antidebugging mechanism was much more sophisticated
   
## ClassicCrackMe100 - PICO  

This was another reversing chall that I was able to solve due to the lessons learned from the malware analysis rabbit hole. This chall was like a password but the input is manipulated. I was able to use the LD preload trick to see what value the crack me was expecting and how the value I was inputting was being transformed. After a couple minutes messing around i realized there was a one to one mapping, only lowercase letters were used and the expected input was a length of 50. From here i was able to create a script to brute force the password.



## Fake Boost + Containment - HTB

These are 2 challs that i thought was neat. Fake Boost becasue it contained the IV in the transmitted message. Containment becasue it showed where to find malware that windows defender had quarentined and how to extract it.

# Struggles

There are times I wish I had a bigger team. There are times Im thankful that I have to solve every chall because I get more exposure.

I saw the vbs code and didnt even try.

Cryptography, pwn, blockchain. 

Volatility is still annoying me.

GPT is starting to annoy me. Still doing a really good job with general code creation help. Cyber related tasks have too many guard rails almost to the point of becoming useless.

# Success + Leveling Up

Although I still hate it and avoid it like the plauge I have become much more profieient in doing anything DFIR related on a windows machine. 

The venture into anti-debugging malware led me into reversing. The overlap of challenges is interesting could create a graph. It is the intersection of reversing and crypto that I hate.  

# Takeaways and Future Goals

Overall I am happy with the progress. The BlueBook has been a useful reference. 

The additions to the Blue Book have become less frequent. It will soon be time to go back and write some intros and playbooks.

To get better at crypto i need to go down a rabbit hole like i did with malware analysis. I need to start to create simple reverse mes and thier solution. I need to understand what can be reversed and what cant. Most common seems like xor. 

The note taking + learning process. Notes being an extention of my brain. Notes from solving the problem -> a write up of the solution -> extracting componets from the previous to add to main corpus(bluebook in my case)-> meta analysis comparing contrasting challs -> using the corpus or re reading previous walkthroughs . The consolidation.

I am getting a better perspective of how CTFs can be used as a training mechanism. Now that HTB is providing 'very easy' challs the difference in difficulty is eroding and the content difference between the two are becoming more evident.

compare and contrast the learning in ctfs vs sherlocks+cyberdefenders
