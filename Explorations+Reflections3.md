# Everything All At Once

The PICO and HTB CTFs both too place in spring 2023 and included approximately 17 forensics challenges that tested a wide range of skills,
from steganography to memory forensics. In this review, we'll be taking a closer look at the forensics challenges in both CTFs,
highlighting the types of challenges that were presented and offering our take on the level of difficulty.

## New Expectations
As expected, the PICO CTF featured a heavy emphasis on steganography and PNG challenges,
which have been a staple of PICO challenges in previous years. On the other hand,
HTB's forensics challenges included  problems dealing with .evtxs, windows scripts(.bat,ps1) and memory dumps.

## Something New
One notable aspect of the 2023 HTB CTF's forensics challenges was the inclusion of some very easy problems.
These challenges were accessible to new players and had a similar feel to the ones typically found in PICO CTF.
This was a nice touch that made the forensics category more approachable and well-rounded.

## New Concepts + Lessons + Tools
One new tool we used was Chainsaw, which proved to be a useful tool for analyzing Windows logs. 
We still need to explore its capabilities more to fully understand its potential.

We also learned how to mount a Windows drive, which was particularly useful in some of the HTB challenges. 
This skill is a fundamental one in digital forensics and provides an effective way to access data on a suspect's machine.

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

## Success
I had several successes during the 2023 PICO and HTB forensics challenges. I was able to solve around 2/3 of the problems,
which felt like a win, especially considering that I made significant progress on the challenges I couldn't complete.
Having some expectations going into the challenges was helpful, as it allowed us to follow familiar paths and achieve the right answers more quickly.
For example, the Relic Maps challenge was very similar to a previous HTB problem that involved getting a file from a netcat connection,
so knowing this path helped us solve it more easily.

Another significant success was being able to solve every challenge in the MISC category. 
This was the first time I was able to solve a hard problem in an HTB CTF.
The Misc categorys easier challenges involved general container escapes, 
the harder ones were more like questions on Hackerrank or Leetcode interview questions.
One in particular, called "Calibration," involved finding the center of a circle in a coordinate system.
The player is presented with the challenge 47 times and must guess the center of the circle correctly each time.
Writeup can be found here()

## Updated Statistics
Finally with the addition of new challenges the dataset becomes more robust and the relations become more refined. Moving forward I have decided to compute the stats
of both CTF challenges together. 
