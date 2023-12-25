Winter 2023 (December 27thish) 


Each time I write one of these it feels craxy how fast time passes. This entry then has double significance, it marks a new quarter and the completon of the first year.


Last time we met I had just discovered cyberdefenders and completed HackTheBoo. Since then HTB released 'Sherlocks', DFIR challenges, the inital batch and the 
holiday challs. SANS kringlecon released.

## Full reflection on cyberdefenders. 

Cyberdefenders is a site to learn DFIR. Contains a large set of diverse challenges. One of this types of chalenges it excels in compared to HTB is giving
the player a SIEM. Other than that the site contains content in the form you would expect. I dont like how it forces the player to use a web broswer on each challenge. I spend so much time and money getting my environment ready for analysis, dont force me to use a lagging environment with no tools.

## Compare to what I've seen in sherlocks.



## Sherlocks vs cyberdefender

Its really not a contest. VIP for HTB ~= 14 per month. Sub to cyberdefender ~=20 per month. Even if you concluded the blue team content is the same on both sites,
HTB VIP will also give you access to red team content for 40% of the price.



## Fell down malware analysis rabbit hole dynamic analysis, anti-anti-debugging

## Since this time last year(compare to what i wrote about this time last year)

Short commings? Successess? Desires? Predictions?




Struggles

While analyzing data in DFIR is helpful, the struggles encountered while completing the challenges also provided valuable knowledge. The following are the key struggles encountered and insights gained:

Overwhelming data: Analyzing large amounts of data, such as a 200,000-packet pcap file in Wireshark or logs after evtx_dump, can be overwhelming and require a more organized approach. A tool like Linpeas could be useful in analyzing such data.

Converting Microsoft-specific languages: Analyzing and understanding PowerShell scripts, .vbs, .exes or other Microsoft-specific languages was a challenge. The best approach could be to run the code through a Python script to try to identify the called functions, change those to prints, and run the script on a Windows virtual machine.

Reluctance of the community to move to Python 3: The community's reluctance to move to Python 3, especially in areas that deal with bytes, is a challenge. Some tools, such as Volatility, have been converted from Python 2 to Python 3 but are lacking crucial commands that were available in Python 2. [Export Challenge - Vol2 had cmdscan. V3 only has cmdline, which did not yeild the flag.]

Success

In 2 cases of drowning I was able to develop python scripts that can be found https://github.com/dbissell6/PCAP_Analysis and https://github.com/dbissell6/EVTX_analysis. Using data science techniques, I aimed to filter the packets and events to provide an overview of the data and suggest starting points for further investigation. I did manage a small victory by converting a Python 2 script to Python 3.

Things I know I missed

It was noted that this approach may overlook some aspects. The most crucial one being data acquisition. In real-world scenarios, data is rarely handed to us; rather, we may need to physically access a computer and extract the memory. Additionally, in the event of malware detection, there is the challenge of removal. Other forensic challenges on other sites cover areas such as steganography, which is included in the "Misc" category on HTB. These were some of the areas that were not covered in this approach.
