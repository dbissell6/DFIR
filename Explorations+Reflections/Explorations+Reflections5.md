Winter 2023 (December 27thish) 


Each time I write one of these it feels crazy how fast time passes. This entry then has double significance, it marks a new quarter and the completon of the first year.


Last time we met I had just discovered cyberdefenders and completed HackTheBoo. Since then HTB released 'Sherlocks', DFIR challenges, the inital batch and the 
holiday challs. SANS kringlecon released.

## Full reflection on cyberdefenders. 

Cyberdefenders is a site to learn DFIR. Contains a large set of diverse challenges. One of this types of chalenges it excels in compared to HTB is giving
the player a SIEM. Other than that the site contains content in the form you would expect(with the exeption of E01s). I dont like how it forces the player to use a web broswer on each challenge. I spend so much time and money getting my environment ready for analysis, dont force me to use a lagging environment with no tools.

Cyberdefenders differed from the original ctfs in that they clearly labeled the evidence that was to be analyzed in the description. Was nice to just filter challs that had pcaps or whatever. Decresed utility of graph. 


## Compare to what I've seen in sherlocks.

Sherlocks have the same setup. One difference between the two sites is all of the sherlocks generate their content from the same infrastructure.  Doing a pcap one week you maybe recognize an ip from a piece of evideice you did the previous week. This gives a more cohesive feel. One of the phrases SANS uses on thier threat hunting cheatsheet is 'Find Evil - Know Normal'. We of course know this is important for something like processes running, but there is also a larger context not often seen in challenge like cyberdefenders, What is normal for this system?


## Sherlocks vs cyberdefender

Its really not a contest. VIP for HTB ~= 14 per month. Sub to cyberdefender ~=20 per month. Even if you concluded the blue team content is the same on both sites,
HTB VIP will also give you access to red team content for 40% of the price.



## Fell down malware analysis rabbit hole dynamic analysis, anti-anti-debugging

There was a series of sherlocks that contained some ransomware that needed to be understood. Im not sure exactly what happened but something in me changed during this. The challenges were categorized as hard and insane difficulties. I struggled to get through them but eventually succeeded. After this I revisited them for the next month trying to find ways to ease my previous pains. During this time something clicked. I find it odd becasue of how much i hated the idea of cryto, pwn and reversing when i made the inital choice of the path to go down. I am interested to see how i do with these categories during the next pico.

There is a piece of malware, you debug it to understand it better. The TA doesnt want you to understand their malware so they implement anti-debugging measures. to get around these we anit-anti-debug. Its like going so blue you pop out on the red side. It feels like hacking the hackers. 


## Since this time last year

This whole DFIR journey started a year ago. I was competing in CTFs still struggling with easy questions and decided i need to focus on one of the 5 categories
(web,pwn,reversing,cryptography,forensics). Specific early struggles. 

I was able to open up pcaps and logs with wireshark or event viewer but quickly realized it wasnt practical to manually read through these. I developed simple python tools to parse the data and look for suspect strings. a couple months after i found out about tools like chainsaw and zeek. While I dont use the python tools as much i do feel it was proably valuable to go that route and make them. 

Another thing i listed as struggling with in the first year was understanding windows languages. I hated deobfuscating vbs scripts and still do. In that complaint I can see the seed of my love of dynamic analysis, who cares what it says, what does it do?

The final problem I wrote in that inital stretch was getting volatility to work. Since then I have noticed a steady improvement in the tool with each version that has been released. Ease of loading dumps, increase of plugins and developing a framework to guide me has made memory dumps one of my favorite pieces of evidence to analyze.

## GPT 

Its hard to imagine what the journey looks like without the navigator. 



## Short commings? Successess? Desires? Goals? Predictions?


### Success

#### Bloods
I got my first bloods on a site. After a couple weeks grinding on Cyberdefenders i decided to try and got one. I was so juiced, sooo juiced. I said something changed in me when i did the malware analysis anti-anti-debugging, this was an instance of that too. I explained earlier how each CTF it felt nice to finish harder and harder challenges. This was like that * 10000. It was a validation the work was paying off.

But... during the next week I started to get doubts. Was it a fluke? Getting blood that week for the second time in a row helped to solidy some things internally. I was really close the 3rd week, felt some disapointment, but no doubt. 

The bloods felt good but they were on cyberdefenders, I think there are more and better players on HTB. I anticipate i will get that same rush again if I get a blood on HTB. After that HTB dropped sherlocks and havent been back to cyberdefender since.

#### Submitted first walkthrough
At the end of the year HTB sherlocks released 5 christmas themed challenges. Each blood got a prize and the best write up will get one too. Idk why but i decided to submit. 

### Veni, Vidi, Vivi in the box

When i began i had set a goal of being able to do the easys year one, med year 2, hard 3, insane 4. The year began with me meeting my goal, and exceeding it sometimes. It hasnt been easy, but i have been able to complete every sherlock. During the tinsel challenge I was close to blooding 2 of the challs. My confidence is higher, still not 100% tho, similar to the week after I got the first blood, has it been a fluke? 

### Help 

#### no jq

I need a better way to parse these sherlocks aws cloudtrail logs. I feel like I did with pcaps and evtx, at least i had wireshark for pcaps tho. I um under the impression that i could set up an ELK stack, but part of me whats to start with a python program. 

UPDATE: It took a day or two but i started a tool to vizualize AWS logs, started to apply it to chainsaw sigma output too, we will see where it goes


#### KAPE file dump

bulkextractor can do well here but i need more. At the very least a command to run to see the user/roaming/.../powershell for each user would be nice. Does yara work for these files? 

#### Doing it on windows

I still hate it, although for now i have to do it. There are windows artifacts like MTF and prefetch that i have not been able to do on linux. I like zimmermans tools with the execption of mftexplorer taking 2 hours to load. The other issue i have is alternate data streams. I cant find these when analyzing from linux. I am still unsure difference in this realm from getting the disk image and that KAPE output. Sort of noobish like when i didnt understand mounting the drive wasnt actually being on that host. 

## Goals

### complete every sherlock + Writeups

I imagine ~50 over the year. 

abstracts should have evidence given, expectations, 

discussions summary of attack, what was learned, 

### Research + Create

I want to do research on new malware and create content showcasing the findings. I also have some ideas for a red box. 

### The BlueBook 

The BlueBook has come a long way but needs some work. As a quick reference it provides tools for most files/binaries but it does so at a very superficial level. sections need better overviews. Tools could have installs. The malware analysis section needs to be restructured. It is getting too big, Each section of evidence should become its own file. 
