# Intro
I recently embarked on a journey to learn Digital Forensics and Incident Response (DFIR) without breaking the bank on expensive training videos. To achieve this goal, I set out to complete every retired HTB forensics challenge. After several months of hard work, I was able to complete a majority of the challenges, but I still lacked a systematic understanding of the field.

To consolidate my knowledge and gain a better understanding of the big picture, I decided to analyze the challenges and derive general principles from them. The goal of this exercise is to use data science to understand the underlying patterns in DFIR and create a roadmap for beginners. This roadmap will provide a comprehensive guide to those who are just starting their journey in DFIR

# Considerations
It is important to note that while the retired HTB forensics challenges provide a valuable opportunity to learn about DFIR, they come with several limitations. Firstly, the sample size is incredibly small, with only 33 retired challenges currently available. This limits the representativeness of the data and may not accurately reflect the current threat landscape. Additionally, the nature and skill level of the challenges offered in CTF (Capture the Flag) problems may bias the data, and the problems may not necessarily represent the general population of DFIR incidents in the real world.

Another factor to consider is my perspective while completing these challenges. As I have primarily been focused on learning red teaming techniques for the past year, I had limited exposure to DFIR prior to starting this project. This background may have influenced my interpretation of the data and artifacts left behind by the payloads used in the challenges.

# Data
The data for this study was collected from my notes on each of the retired HTB forensics challenges. I analyzed the challenges based on a set of characteristics that included the evidence being analyzed, the tools used, and the methods required to solve the challenges. These characteristics varied greatly from challenge to challenge, with some being clearly defined and others being less so. The variability of these characteristics provided a rich source of information for my analysis.

![image](https://user-images.githubusercontent.com/50979196/217050487-c160139e-65dd-41b1-9b7f-db267915e914.png)

![image](https://user-images.githubusercontent.com/50979196/217050771-663b3181-fc33-4f78-b287-3220b88ee96a.png)

# Results

![image](https://user-images.githubusercontent.com/50979196/217050896-cbf15d8b-1a63-4bfc-8cf8-fe7aca189c59.png)

![image](https://user-images.githubusercontent.com/50979196/217050962-efa5363b-b70d-4761-b852-7494d6f52a91.png)

# Graphs
## To better understand the landscape we can plot the challanges as a graph. Below what is pictured can be thought about as the challenges that contained the same evidence or tools. 
For instance look at downgrade and event horizon then look at the graph.
![image](https://user-images.githubusercontent.com/50979196/217057213-452c3169-cbb5-4284-84db-7bb2b030eecf.png)
![image](https://user-images.githubusercontent.com/50979196/217057243-8381d897-4e68-42c4-a5dc-a0f96e11e62a.png)

![image](https://user-images.githubusercontent.com/50979196/217052142-6e8e7617-2120-46e6-83ce-14293021155f.png)

## However, in most cases knowing the relationship between boxes isnt as useful and knowing the relationships of the qualities that compose the challenges.
Remembering the qualities of downgrade and event horizon we can see them as the mustard colored module.  
![image](https://user-images.githubusercontent.com/50979196/217053537-83ec1822-821e-4a85-8eef-de4c19326f4b.png)

# Reflections
What can we learn from the data collected on retired HTB forensics challenges for those new to DFIR? By analyzing the challenges, we can see the importance of understanding the basic artifacts that need to be analyzed in DFIR and the tools used to analyze them. The four basic artifacts are pcaps/network transfer (analyzed using Wireshark), macros in Windows docs (analyzed using olevba), memory dumps (analyzed using Volatility), and Windows logs/registry. Each artifact provides unique insights into the threat landscape. However, it is important to keep in mind that simply linking problems to tools is not enough and one should strive to gain a deeper understanding of each artifact and the alternative tools available.

There are a couple themes that are found central in the graph, namely methods of encryption, they can be found in pcaps, logs anything. Its a whole seperate/related realm Cryptography.

# Struggles
While analyzing data in DFIR is helpful, the struggles encountered while completing the challenges also provided valuable knowledge. The following are the key struggles encountered and insights gained:

1) Overwhelming data: Analyzing large amounts of data, such as a 200,000-packet pcap file in Wireshark or logs after evtx_dump, can be overwhelming and require a more organized approach. A tool like Linpeas could be useful in analyzing such data.

2)  Converting Microsoft-specific languages: Analyzing and understanding PowerShell scripts, .vbs, .exes or other Microsoft-specific languages was a challenge. The best approach could be to run the code through a Python script to try to identify the called functions, change those to prints, and run the script on a Windows virtual machine.

3) Reluctance of the community to move to Python 3: The community's reluctance to move to Python 3, especially in areas that deal with bytes, is a challenge. Some tools, such as Volatility, have been converted from Python 2 to Python 3 but are lacking crucial commands that were available in Python 2.

# Success
In 2 cases of drowning I was able to develop python scripts that can be found  https://github.com/dbissell6/PCAP_Analysis and https://github.com/dbissell6/EVTX_analysis. Applying data science techiques I attempted to filter the packets and events to give the user an overview of the landscape and atleast reccomened some places to start looking. The other realm where these struggles still exist for me is memory. Like pcaps and logs i have a tool(volatility) that i can access the information on linux, but it is too much to skim through.
small win in converting a python2 script to python3

# Things I know I missed

In considerations it was mentioned this path would miss some things, what were they? First and the maybe most important was the aquisition. In a real senario you probably wont just be handed some data, but instead we may have to walk over to a computer and extract the memory ourselves. After the malware is discovered how to remove? In other foreensics challenges on other sites they include stentography, wchih HTB includes in misc, so there were areas such as those missed.

# Predictions

## What a DFIR textbook will look like

Aquisition
General croptography encrpython/decryption
  Deobfuscating powershell commands/docms malware
  Compressed data
Memory/images
Registry
Logs - evtx, browser, 
Networks - Pcaps
Removal 

## What will i see in the next forensics CTF i compete in?
Pico is in mid-March(2/6/2023 now). If there are 5 forensics challenges i assume 2 will have pcaps, 1 log, and something completly neiche and random.
The easy problems I will be able to find the flag with a grep, maybe base64 encoded. 

# Next steps

As I continue to complete HTB forensics challenges I will update the dataset and maybe analyze again at 100 completions. I am excited to test my scripts on new challenges that present pcaps or evtx. I plan to make adjustments to the scripts if they 'miss' anything in the future challenges. I've also done a bunch of challeges on other sites and am considering adding that data.
In the not to distant future I also plan on getting my hands on a DFIR textbook.
