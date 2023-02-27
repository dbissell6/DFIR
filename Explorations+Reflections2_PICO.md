# Intro 

Following the success of my previous experiment in Digital Forensics and Incident Response (DFIR), where I completed every retired HTB forensics challenge and gained valuable insights into the field, I decided to embark on a new challenge. This time, I turned to picoCTF for a fresh set of forensics challenges to further expand my knowledge and understanding of DFIR.

With the same objective as before, I aim to analyze the challenges and derive general principles from them. Using data science, I intend to uncover the underlying patterns in DFIR and create a comprehensive roadmap for beginners. This exercise will provide valuable insights and a structured guide to anyone starting their journey in DFIR. Join me as I dive into picoCTF forensics challenges and uncover the secrets of DFIR.

# Limitations

While this study provides valuable insights into the world of Digital Forensics and Incident Response through the analysis of retired HTB and PicoCTF forensics challenges, there are several limitations to consider.

Firstly, it's important to recognize that the challenges in HTB and PicoCTF may not be representative of the real-world DFIR incidents. 

Furthermore, the challenges in the forensics domain may not be transferable to other domains such as web or reversing. Also, comparing challenges in PicoCTF and HTB may be different because of the overall structure of their CTFs. For instance, if HTB has a steganography challenge, it might show up in the MISC category instead of the Forensics category.

Finally,  I dont think the points for PICO challenges is that accurate, the challenges are taken from ~5 CTFs and it looks like the scoring system differed in them.

Therefore, it's important to view the findings of this study as a starting point for further research and not a definitive roadmap for learning DFIR.

# Advancements

The second experiment aims to expand on the first by increasing the sample size of problems and introducing a new source for analysis. The additional data from PicoCTF may offer new insights that were not discovered in the previous analysis due to creator bias. Moreover, there is a perception that PicoCTF is much easier than HTB, and this analysis can provide quantitative evidence to support or challenge this claim.

# Data

For this study on the data was collected from the challenges provided on the PicoCTF platform. Each challenge was analyzed based on similar characteristics such as the type of evidence being analyzed, the tools used, and the methods required to solve the challenge.

![image](https://user-images.githubusercontent.com/50979196/221474995-c4f54fa4-e13a-4584-a56d-28a2500f6983.png)

![image](https://user-images.githubusercontent.com/50979196/221475154-27031252-92d2-442e-9f2f-4ca7859cd578.png)
# Results 
![image](https://user-images.githubusercontent.com/50979196/221475216-1c53b5f6-cb28-4b61-a540-caf5c1fa6793.png)
![image](https://user-images.githubusercontent.com/50979196/221475238-e4890bfd-4bd3-41bb-a60f-2aac6f97d371.png)


# Graph

![image](https://user-images.githubusercontent.com/50979196/221667200-06dcfba6-581b-4471-b9de-c590d3c43756.png)


The graphs look similar in relation to the pcap wireshark dominance. This new PICO graph has a nice module of the disk and tools. However aside from that this graph doesnt feel as helpful as the HTB one. This could be due to PICO challenges being less complex, less steps, therefore less oppurtnities to tie to others. It could also be something related to the tuning.

# Comparison to HTB
## 
| Sample           | PICO | HTB |
|------------------|------|-----|
| PCAPs            |  11  |  11 |
| Memory Dumps     |  0   |  4  |
| .docm challenges |  1   |  6  |
| LOG(evtx)        |  0   |  2  |
| Disk/.imgs       | 6 | 1 |
| Image files(.png, jpg, ...)| ~15  |  0  | 

Another key difference has to be the difficulty each organization assigns to the challenges. HTB is easy,med hard. PICO 10,30,40,50,60,60,10,110,130....500

Reflecting on my past struggles and limitations (decoding .vbs/powershell scripts) + mem.dump/volatility I found it interesting that these were the things PICO were missing.
This seems like some of the reasons for difference in difficulty is difference in content. 
On top of missing these harder types there were some challenges that could be solved just by grepping a txt file or unzipping something 10 times.

One key difference that I cant account for(pngs,jpgs/STEGO are MISC HTB problems so this makes sense) is how many more disk challenges there were.  HTB didnt have many so the partion and mounting process was still slightly foriegn. However, once I was able to to mount the drive it felt very similar to enumerating a box on the red team. I was even able to run linpeas in the mount and it discovered a ssh key that solved a problem. 
HTB did have a disk challenge and ofcourse it was more difficult than any of PICOs where you first had to reconstruct the image. PICO had a problem that didnt even need to mount the disk, just find the length in sectors.

If anything I think this experiment was useful just for the fact I encountered so many disk images and am now confortable mounting and manually enumerating but I will evenutally have to learn to use sleuthkit. 

Small take home #1 regarding difficulty. I learned that any of the four categories (pcaps, logs, disks, and memory) can be equally challenging, but the easiest tasks may vary slightly. For example, anyone can open a pcap file in Wireshark, while opening logs with evtx_dump may be slightly more challenging. Mounting a disk is a bit more difficult than that, and using Volatility can be the most challenging of all. 

Small take home #2 regarding difficulty. Looking at the difficulty within PICO challenges is also useful. There is a coorlation between question difficulty needing to make a python script. as you get into the upper medium problems its almost a gureantee you will need to script/automate something. 

Swithing gears to compare the pcaps, since both samples contain about the same number of Pcaps, we ask when the content is the same is there a difference in difficulty?
PICO has a mid range problem that the flag can be found in clear text. HTB thats never the case, even easy problems the flag is base64 encoded.
Looking at the harder problems in PICO, if there was a need to use something like OPENSSL to decrypt something, PICO would provided the command, HTB not so.

# Struggles

The main issue I would like to address is my pcap analysis tool. It can find a clear text flag in data if all in one packet but if the data is transmitted one character per packet it will miss it, even clear text.  Getting stream data will probably be useful. The tool still needs to be able to do a basic analysis of objects passed in the capture. There was also a challenge that hide ascii characters in port numbers that the tool is useless at detecting.

# Predictions

## Update to prediction on what to expect on next PICO CTF
If there are 5 forensics problems: 2 Pcaps, 1 .png, 1 .img, something compressed many times

# Next Steps

Each analysis is about 75% completed. I need to finish the remaining challenges and add them to my analysis. I also need to fix inconsistencies in the tools and ideas categories and refine the edges of the graph. Additionally, I plan to create a guide for new users who are interested in solving forensics challenges in their first CTF. First showing the ideas that must be understood before entering(base64, http protocol, powershell, anything that was central in the graph). Then the problems and the tools. Finally the walkthrough and Blue Book can tie all the missing pieces together and fill in the theoretical knowledge.

HTB and PICO CTFs are both in 2 weeks. Those will be good indicators and gauges on if any of this has been useful. Additionally they will be more data points added to the analysis. There could also be oppurtunities to upgrade the tools if they encounter a challenge and fail.
