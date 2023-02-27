# Intro 

Following the success of my previous experiment in Digital Forensics and Incident Response (DFIR), where I completed every retired HTB forensics challenge and gained valuable insights into the field, I decided to embark on a new challenge. This time, I turned to picoCTF for a fresh set of forensics challenges to further expand my knowledge and understanding of DFIR.

With the same objective as before, I aim to analyze the challenges and derive general principles from them. Using data science, I intend to uncover the underlying patterns in DFIR and create a comprehensive roadmap for beginners. This exercise will provide valuable insights and a structured guide to anyone starting their journey in DFIR. Join me as I dive into picoCTF forensics challenges and uncover the secrets of DFIR.

# Limitations

While this study provides valuable insights into the world of Digital Forensics and Incident Response through the analysis of retired HTB and PicoCTF forensics challenges, there are several limitations to consider.

Firstly, it's important to recognize that the challenges in HTB and PicoCTF may not be representative of the real-world DFIR incidents. 

Furthermore, the challenges in the forensics domain may not be transferable to other domains such as web or reversing. Also, comparing challenges in PicoCTF and HTB may be different because of the overall structure of their CTFs. For instance, if HTB has a steganography challenge, it might show up in the MISC category instead of the Forensics category.

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

# Comparison to HTB
## Key noticable differences 
| Sample           | PICO | HTB |
|------------------|------|-----|
| PCAPs            |  11  |  11 |
| Memory Dumps     |  0   |  4  |
| .docm challenges |  1   |  6  |
| LOG(evtx)        |  0   |  2  |
| Image files      | ~15  |  0  | (.png, .jpg, etc.)

Another key difference has to be the difficulty each organization assigns to the challenges. HTB is easy,med hard. PICO 10,30,40,50,60,60,10,110,130....500

Reflecting on my past struggles and limitations (decoding .vbs/powershell scripts) + mem.dump and volatility I found it interesting that these were the things PICO were missing.
This seems like a difference in content that contain reasons for the differences in difficulty. On top of missing the harder content there were some easier 
challenges that could be solved be grepping a txt file.

However looking at the pcaps, since the same in both samples we can ask whenthe content is the same is there a difference in difficulty?
PICO has a mid range problem that the flag can be found in clear text. HTB thats never the case, even easy problems the flag is base64 encoded.
Looking at the harder problems in PICO, if there was a need to use something like OPENSSL to decrypt something, PICO would provided the command, HTB not so.


