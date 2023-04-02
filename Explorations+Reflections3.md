# Everything All At Once

The PICO and HTB CTFs both took place in spring 2023 and included approximately 17 forensics challenges that tested a wide range of skills,
from steganography to memory forensics. In this review, we'll be exploring the forensics challenges in both CTFs, gathering new insights and trying to answer,
'was the previous research useful?'

## Results
![image](https://user-images.githubusercontent.com/50979196/228352276-6d08169a-1763-4c04-81ae-6fc73bcc52c0.png)
![image](https://user-images.githubusercontent.com/50979196/228352213-a5636f23-8bc5-4bf1-8a06-52bebdcbfd23.png)
![image](https://user-images.githubusercontent.com/50979196/228352123-8c59b824-7ebf-48e7-ab7f-eb9541960b86.png)
![image](https://user-images.githubusercontent.com/50979196/228352187-2d068fb4-4363-42d9-8fad-22b817fdc0c9.png)


## New Expectations
As expected, the PICO CTF featured a heavy emphasis on steganography and PNG challenges,
which have been a staple of PICO challenges in previous years. On the other hand,
HTB's forensics challenges included problems dealing with .evtxs, windows scripts(.bat,ps1) and memory dumps.

## Something New
One notable aspect of the 2023 HTB CTF's forensics challenges was the inclusion of some very easy problems.
These challenges were accessible to new players and had a similar feel to the ones typically found in PICO CTF.
This was a nice touch that made the forensics category more approachable and well-rounded.

## New Concepts + Lessons + Tools
One new tool we used was Chainsaw, which proved to be a useful tool for analyzing Windows logs. 
I still need to explore its capabilities more to fully understand its potential.

I also learned how to mount a Windows drive. Relic maps used a .one file.

One PICO challenge involved analyzing an .eml file to uncover the identity of the sender and using WHOIS data to trace the origin of a suspicious email.

## Gripes

While we enjoyed the 2023 PICO and HTB forensics challenges overall, there were a few aspects that we found frustrating.
One issue we encountered was that some of the PICO challenges could be solved simply by using grep or other simple tools to find the flag.
In our opinion, understanding the story behind a challenge is key to making it engaging and educational. When challenges can be solved without this understanding,
it can feel like a missed opportunity to learn something new.

In contrast, HTB's easy challenges often provided a pcap and a netcat connection that asked 10 questions about the pcap.
This approach helped to guide the player towards a deeper understanding of the story behind the challenge,
and we found it to be a much more effective way of introducing players to forensics concepts.

Another issue we had was with the steganography challenges. While we recognize that these challenges can teach important lessons about how data can be hidden in plain sight,
we didn't find them to be particularly fun or engaging. In many cases, it felt like we were simply guessing which tool to use rather than solving a meaningful puzzle.

## Struggles

It was unfortunate that the spring CTFs came so soon after completing the analysis. I predicted I would struggle deobfuscating windows executables and for the next 2 weeks I struggled with just that. Challenges that incorporate above medium difficulty cryptography, reversing, will become problematic.  

### Resources I used to finish

https://github.com/BlackAnon22/BlackAnon22.github.io/blob/main/posts/CTF%20Competitions/picoCTF_2023.md  
https://forensicskween.com/ctf/hack-the-box/htb-cyber-apocalypse-2023-forensics/

## Success
I had several successes during the 2023 PICO and HTB forensics challenges. I was able to solve around 2/3 of the problems,
which felt like a win, especially considering that I made significant progress on the challenges I couldn't complete.
Having some expectations going into the challenges was helpful, as it allowed us to follow familiar paths and achieve the right answers more quickly.
For example, the Relic Maps challenge was very similar to a previous HTB problem that involved getting a file from a netcat connection,
so knowing this path helped us solve it more easily.

Another significant success was being able to solve every challenge in the MISC category for both CTFs. 
This was the first time I was able to solve a hard problem in an HTB CTF.
The Misc categorys easier challenges involved general container escapes, 
the harder ones were more like questions on Hackerrank or Leetcode interview questions.
One in particular, called "Calibration," involved finding the center of a circle in a coordinate system.
The player is presented with the challenge 47 times and must guess the center of the circle correctly each time.
Writeup can be found here()

## Next Steps

For forensics the focus will be windows executables and getting volitility to work.  

I like being good at the Misc category, not sure how to leverege that tho lol. Before the next HTB CTF I will venture into the ML category, should be a low hanging fruit. 

I need to find a couple people or a team that specializes in my weaknesses(cyrpto,reversing,pwning,web).

## Updated Statistics
Finally with the addition of new challenges the dataset becomes more robust and the relations become more refined. Moving forward I have decided to compute the stats
of both CTF challenges together. I feel confident of the overview so this will be the last graph. The devils in the details.  

There are ~90 forensics challenges included.  
![image](https://user-images.githubusercontent.com/50979196/229377994-74fac043-1d9e-468e-8466-63d748ab8a39.png)
![image](https://user-images.githubusercontent.com/50979196/229378012-159c503a-e5bc-463c-82cf-15fd595f34b0.png)

## Graph of challenges

![image](https://user-images.githubusercontent.com/50979196/229378172-380216e6-07d9-4519-b02b-32af3ce8802c.png)

## Graph of relations
![image](https://user-images.githubusercontent.com/50979196/229371465-0d26beb3-cd6a-4330-a7d6-98aed5785d80.png)

The graph provides a useful starting point for anyone interested in exploring the DFIR CTF landscape, by highlighting some of the key types of evidence, tools, and challenges that are available. While the graph may not capture all the nuances and complexities of the field, it does provide a helpful way of orienting oneself to the overall landscape, and can serve as a useful reference for further exploration and analysis.


