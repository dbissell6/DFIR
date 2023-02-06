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

![image](https://user-images.githubusercontent.com/50979196/217052142-6e8e7617-2120-46e6-83ce-14293021155f.png)


![image](https://user-images.githubusercontent.com/50979196/217053537-83ec1822-821e-4a85-8eef-de4c19326f4b.png)

# Reflections
What can we learn from the data collected on retired HTB forensics challenges for those new to DFIR? By analyzing the challenges, we can see the importance of understanding the basic artifacts that need to be analyzed in DFIR and the tools used to analyze them. The four basic artifacts are pcaps/network transfer (analyzed using Wireshark), macros in Windows docs (analyzed using olevba), memory dumps (analyzed using Volatility), and Windows logs/registry. Each artifact provides unique insights into the threat landscape. However, it is important to keep in mind that simply linking problems to tools is not enough and one should strive to gain a deeper understanding of each artifact and the alternative tools available.
