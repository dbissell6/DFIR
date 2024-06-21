A reflection anomaly. Summer time. 

As always I must start with, these past 3 months have felt like another lifetime, each time if feels more cliche but no less true.

Joining L3ak
Hosting a CTF
Creating challenges
Winning and Studying for sec+
Looking back at trying to incorporate more aspects of knowledge that would be useful when doing certificate testing

incorporating these ideas into designing future ctf challs, what would be useful to kill these 2 birds with one stone?


# Joining L3AK

Not too long after the winter sherlock collection (OPTinselTrace) someone reached out saying the writeup was dope and asked if I wanted
to join a CTF team on the forensics branch. In the last post I was lamenting on the struggles of being alone so i did some research found they were a top team and accpeted.

The experience has been completly different. Before I would try out a most east and medium taking ~50% of the time in the competition. I would eventually get to some hard and insane in the
forensics and misc category and solve maybe 1 or 2. Working with a good large team almost all time is dedicated to hard forensics problems. There have been differences in the 
process of solving problems too. One that sticks out post right now is I found a some suspicious powershell logs, when sharing them with the team smoeone else was able to notice exactly what
they were and the next steps to solving. Thinking back to doing it on my own, it was a huge disk, many users and while knowing it was suspicious I may still have started to look
for other pieces of evidence maybe eventually even just getting stuck. 

Now it isnt rare for us to finish the forensics category in the first day without me seeing more than half of the challenges. 

# L3AKCTF

After a month or two of being on the team I got notice the team was going to host a CTF. ofcourse i got excited and wanted to join. they had been planning it for almost a year and it
was set to take place in just a couple months. I was mainly focused on creating the challenges which was a great experience. however most of the knowledge and value I gained was getting
to see behind the scences of how the infrastructure was created. 

## Creating challenges

The goal I had was to create easy challenges that would give players a tool to solve more advanced challenges later. The first challenge I made dealt with linux peristence
mechanisms found in the /etc directory. There was a hint that each mechanism referenced a backdoor.sh and the users could look for variations of that string or look in common
locations of linux peristence. The idea came from a recently released paper on the topic and could easily be found with google. I think this is really the blueprint for making challenges.
This is especially true with trying to show a new variant of something or technology. 

The second challenge i made was a misc challenge trying to find a point on a coordinate plane. I again wanted to make something simple and gave the
player more attempts than were needed and more of a margin for error and ensured the hidden point never spawned near an edge, but the algorithm was probably too hard and not many solved it.
I wanted something easy that would show them how to build a tool to communicate with the netcat servers,I was better off having players calculate the area of rectangles or simple addition.

The final challenge I made was suppose to be another easy one that not many solved. A malware analysis that if the player sets up a vm with the IP the beacon is reaching out to
would be guided with hints to solve to problem. I think the main issue was one one got to that part of recieving the inital beacon. I made the program as cursed as possible to try to debug statically or walk through it
in a debugger. The fact no one solved it means not many were able to do it that way which sort of makes me happy. I had a fear that people would find the flag instantly statically.
In the first iteration the flag was printed to virustotal.

## The challenge of creating challenges

I think the linux persistence was the challenge both in execution and applicable knowledge moving forward. There could have been more hints in the mini flags to guide them to the next mini-flag

There is usch a range of cybersecurity knowdlge in a ctf. you want to try to find the goldielocks area for a majority of players. not too easy, not too hard.
there is also a disticntion between a learning environemnt and a testing environment. 
There is also the cannonical knowledge vs the new thing. It is easy to focus on new things when creating challenges. This is becasue most people creating challenges are thinking about
pushing the limits, forgetting players with no experience also have no foundation. applying a simple variation to a simple exploit can be very difficult for someone with no expierence.
I think that creating a challenge beginers like might mean some people think it was stupid and easy, but thats ok. 


## Infrustructure



# Winning the sec+ voucher and studying

Part of joining the team that is also new is that we finish in top 3 in the ctf more times than not. This means prizes! One of the prizes our team got was a voucher for a 
CompTIA cert. I dont like the idea of paying for the classes and certs and the CTFs were meant to get and demonstrate the knowledge needed for the DFIR field. But getting
the voucher and forcing me to study (I just so happened to get a free month of linkedin and some reccomended a video series that covers the material on linkedinlearning) has again
forced me consider the knowledge of these domains(Real world, CTFs, certificates). 

It is frustrating that the certs are so expensive and behind a paywall(SANS actually does a good job at providing a syllabus).
```http://www.comptia.org/training/resources/exam-objectives```
Currently it is $404 to just take the test, that is stupid. I cant find what the actual knowldge needed to pass
test is, so they are also selling you study guides.To get the study guide and test combined package!! it is almost $1000, this is stupid.

<img width="1277" alt="Screen Shot 2024-06-20 at 9 49 03 AM" src="https://github.com/dbissell6/DFIR/assets/50979196/08b17eb1-58e2-48c9-82b1-3978e313ceeb">

<img width="899" alt="Screen Shot 2024-06-20 at 9 49 48 AM" src="https://github.com/dbissell6/DFIR/assets/50979196/8980b674-72d9-4821-8b04-d580e21aa716">

Each SANS course is similarliy priced and they offer ~15 FORENSICS courses. 


## Insights for future challenges

Even with my failures in challenges, overall the CTF was a success. I will be making more challenges in the future. The journey continues. 

It seems that the best place to create new challenges is the things found in certificate curriculum and labs but not recently seen in a CTF, especially if that thing is
currently being used in the real world. The white papers from vx-underground or dfirreport are great inspiration, again especially if they overlap with SANS cert material.

## Direction for the BlueBook

The bluebook started as notes to help me steps in DFIR challenges. The completion of DFIR challeges began as a way to learn the material being offered from places like SANS and CompTIA
for free. The SANS classes and certificates are supposed to be indicators of the competency in a real life sceario. 


Steps of mounting a windows drive or using chainsaw sigma rules. While the practice knowlege of knowing
was invaluable the BlueBook 

## What would it take?

What would it take to create something more valuable than the knowledge given from these courses. Ive said before and still believe the value comes from the combination of the knowlege
and the ability to let the person practice in a lab.This is what people are paying for. But the parts do exist in the wild for free.

I imagine a wikipedia of digital forensics. open source driven by community contributions.




