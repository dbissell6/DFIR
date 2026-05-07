
# Disk

## Intro
Disk images are copies of an entire disk drive or a portion of it. In DFIR, disk images are an essential tool for preserving the evidence and state of the original disk. Analyzing disk images can reveal important information such as deleted files, hidden files, and other artifacts that can provide valuable insight into an incident.Some common forms of disk images include raw images, Encase images, and AFF4 images.

Typically found as: .img, .dd, .raw, ISO, EWF(Expert witness format. contains raw + metadata), .ad1

Virtual Drive Formats: .vmdk, .vhdx

Differences in the way that Linux and Windows handle disk drives, which can be relevant to forensic analysis in a CTF challenge.

-    File systems: Linux and Windows use different file systems to organize and store data on disk drives. Windows primarily uses the NTFS (New Technology File System) file system, while Linux typically uses the ext4 (Fourth Extended File System) file system. There are also other file systems used by both operating systems, such as FAT32, exFAT, and ReFS (Resilient File System). Different file systems have different structures and metadata, which can affect the way that files are stored, accessed, and recovered.

-    Permissions and ownership: Linux and Windows use different approaches to managing permissions and ownership of files and directories. Linux uses a permission model based on users, groups, and permissions bits (e.g., read, write, execute), while Windows uses a more complex permission model that includes access control lists (ACLs) and security identifiers (SIDs). This can affect the way that files and directories are accessed and modified, as well as the ability to recover deleted files or data.

-    Disk partitioning: Linux and Windows use different methods for partitioning disk drives. Windows uses the Master Boot Record (MBR) or the newer GUID Partition Table (GPT) for partitioning, while Linux typically uses the GPT partitioning scheme. Different partitioning schemes can affect the way that data is organized and accessed on the disk, as well as the ability to recover deleted files or data.

-    Forensic tools and techniques: Different forensic tools and techniques may be needed to analyze disk drives on Linux versus Windows. For example, some tools may be more effective at recovering data from a specific file system or partitioning scheme, while others may be better suited for analyzing permissions and ownership. It is important to understand the differences between Linux and Windows disk drives when selecting and using forensic tools and techniques for a CTF challenge.

**File Carving**: File carving is a technique used to extract data from a file or disk image without the use of a file system. This technique can be used to recover lost or deleted files or to analyze malware that may be hiding within a file. Some commonly used file carving tools include Scalpel, Foremost, and PhotoRec. It requires a deep understanding of the file structure and data recovery techniques.


Hard drive type

-    The capacity to recover deleted files is influenced by the type of hard drive utilized. In the case of mechanical hard drives, it's advisable to refrain from deleting data directly from the disk, as marking it as deleted prompts the hard drive to overwrite the area with fresh data. Hence, deleting the data becomes an unnecessary action. On the other hand, Solid-State Drives (SSD) face limitations in writing new data to already occupied areas. Writing data to a marked-as-deleted area on an SSD involves two operations: first, erasing the old data, and then writing the new data. SSDs often implement techniques to periodically remove data marked for deletion, enhancing their speed. Consequently, the presence of deleted files is generally lower on an SSD compared to a mechanical disk.



## FTK Imager to extract a .ad1

File -> Add Evidence Item -> Image -> source path -> Finish


Evidence Tree -> right click on root -> Export Files

![image](https://github.com/dbissell6/DFIR/assets/50979196/e16c1e2c-2de0-46bd-9d08-0763019635d3)

![image](https://github.com/dbissell6/DFIR/assets/50979196/a6837611-5839-421e-acfb-54c8d00bbb10)


## Example fdisk+Mount Linux

Mounting a file system in Linux is similar to gaining access to a victim system on platforms like Hack The Box (HTB). However, there are some key differences. Unlike a live computer, the mounted system is just a file system, and you cannot run commands like netstat to view current connections. You arnt on the system, just the file system like plugging in an external hardrive. Despite this, the process of enumeration from a pentesting perspective is similar. The advantage of mounting a file system is that you can use sudo, which grants you root access to the mounted system, allowing for more comprehensive analysis and investigation. This is useful when looking for sensitive information or and intresting executable... Other times you may only need to extract logs.

In order to mount a filesystem, you typically need to first determine the offset or starting point of the filesystem within the disk image or device file. Once you have determined the offset, you can then use the "mount" command with the "-o loop" option to mount the filesystem at the specified location.

To find offset in order to mount.
```
fdisk -l disk.img
```
![Pasted image 20230216134532](https://user-images.githubusercontent.com/50979196/221450652-341c6db0-16a0-4fec-bafc-094d9a3f56d1.png)

![Pasted image 20230216134646](https://user-images.githubusercontent.com/50979196/221450672-b00b0f20-2d3c-4326-b7f4-07564f01b4ac.png)

```
mkdir test
```
```
 sudo mount -o loop,offset=210763776 disk.flag.img test/   
```
![Pasted image 20230216101009](https://user-images.githubusercontent.com/50979196/221450698-af50833b-dc66-47a8-96d9-01d5568a69e8.png)

### automate search

Just like pentesting we can use linpeas in the mount. This has helped me to find important files in CTFs.
```
 sudo /usr/share/peass/linpeas/linpeas.sh -f ~/PICO/Forensics/Orchid/test 
```

Noob tip if you mount the system and you try to access something like root and it says permission denied, use sudo
```
sudo ls -la root
```

## EWF on Linux

The Expert Witness Format (EWF), commonly represented by .E01 files, is a forensic disk image format used to store digital evidence. It was developed by Guidance Software for EnCase and is widely used in digital forensics. EWF supports compression, encryption, and metadata storage, such as case details and hash values for verification.

![image](https://github.com/user-attachments/assets/6a55d681-7d5d-48ff-912a-e20415cbed2a)

![image](https://github.com/user-attachments/assets/2bb7c67c-237c-4d7a-9406-6dac528140c7)

![image](https://github.com/user-attachments/assets/185a30a3-c41d-4833-87d2-745b8cbb671b)

![image](https://github.com/user-attachments/assets/c0fa7686-ebbf-4055-bf7a-c2b7c5a9866c)

Can also mount with

![image](https://github.com/user-attachments/assets/68e84cba-abd3-431d-ae90-7d7f3b953501)

## WIM

WIM (Windows Imaging Format)

A WIM file is a disk image format created by Microsoft to store multiple disk images in a single file. It’s commonly used for Windows installation files or backups. The .wim file typically contains the contents of an entire disk or a partition and is used in Windows deployment scenarios.

`wimlib-imagex info budget.wim`

![image](https://github.com/user-attachments/assets/2c933b22-ed0b-4dbc-9d8f-4ba433879991)

To extract

`wimlib-imagex extract budget.wim 1 --dest-dir=./extracted`

![image](https://github.com/user-attachments/assets/b103efb7-974d-4347-9990-3ac58d824f8c)

To mount

`wimlib-imagex mount budget.wim 1 wim_mount`

![image](https://github.com/user-attachments/assets/1f727bd9-cea1-4c15-8f4d-e46735c10123)


Can also use 7z to extract everything

![image](https://github.com/user-attachments/assets/5cbc7f1c-83dc-45ce-9dd0-627120332b10)

Useful because will extract and show if files had alternate data streams.

![image](https://github.com/user-attachments/assets/e6b32940-1c77-44c0-916b-1df3878ee852)


## Example fdisk+Mount Windows vhdx

![Pasted image 20230318133623](https://user-images.githubusercontent.com/50979196/229358946-72832415-38f2-4742-ba91-c91332de8981.png)
![Pasted image 20230318133610](https://user-images.githubusercontent.com/50979196/229358957-684da311-e205-419d-a3e2-29e26e6bfc4e.png)
![Pasted image 20230318133553](https://user-images.githubusercontent.com/50979196/229358976-02560289-3226-4f8f-af22-11dc6e120430.png)
![Pasted image 20230318133535](https://user-images.githubusercontent.com/50979196/229359015-4c1dd124-6f5e-4709-9168-335a1d6ea0cf.png)
![Pasted image 20230318133520](https://user-images.githubusercontent.com/50979196/229359026-40b14558-22fb-4a98-9e80-7e52a39465e3.png)

## guestmount windows vhdx

![image](https://github.com/user-attachments/assets/2a1e9f29-39ee-4fd0-8dc3-64318f124e12)

![image](https://github.com/user-attachments/assets/8a79232c-0b86-49c4-8273-e9eeb71230ca)

![image](https://github.com/user-attachments/assets/0eae362b-6fa1-497d-b24b-bbab362de5bd)

![image](https://github.com/user-attachments/assets/bd3ada11-27a2-455c-8072-41f962a55043)


```
tar -xvf image.ova
sudo LIBGUESTFS_BACKEND=direct guestmount -a anakt-disk001.vmdk -i /mnt/vm
sudo guestunmount /mnt/vm
```

## BTRFS

Btrfs is a modern Linux copy-on-write filesystem that supports features like subvolumes, snapshots, checksumming, compression, and pooled storage. For forensics, the big thing is that data may exist across multiple subvolumes or snapshots, so enumerating only the default mount can miss older or alternate versions of files.

<img width="1214" height="106" alt="image" src="https://github.com/user-attachments/assets/f19defa3-6d3b-4c9e-bcc9-5b8f210a262b" />

Can mount and investigate

<img width="822" height="454" alt="image" src="https://github.com/user-attachments/assets/fa68a790-1447-4f2e-9856-1a4081894f88" />



## Encrypted drive

.vhdx encrypted with bitlocker.

![image](https://github.com/user-attachments/assets/2b162ba9-68f7-47c9-a0c9-97b2bbe02a18)

bit-locker2john

![image](https://github.com/user-attachments/assets/6906fc9e-5f1b-4aa2-b7d7-43ccdf6a4c95)

![image](https://github.com/user-attachments/assets/46e8eddf-b19a-4bc6-8e90-edefdbf4c24e)


crack hash with hashcat

`.\hashcat.exe -m 22100 -a 0 C:\Users\Daniel\Desktop\bitlocker.hash C:\Users\Daniel\Desktop\SecLists-2024.3\SecLists-2024.3\Passwords\Leaked-Databases\rockyou-75.txt`

![image](https://github.com/user-attachments/assets/8d49c17e-90bb-4eae-9e26-73a9e9e693d7)


Open on windows

![image](https://github.com/user-attachments/assets/71207ce3-fac9-43dd-8a2e-ce8234f11975)

![image](https://github.com/user-attachments/assets/7c6acc7e-bfcf-4c7c-a384-50d927147dcd)

![image](https://github.com/user-attachments/assets/f4c3da31-6a65-4390-87ed-56d32ebd6491)


## Autopsy on Linux

GUI to look at disk.

![image](https://github.com/dbissell6/DFIR/assets/50979196/0a786bbe-9ff6-496a-954d-9159ba36ae13)


![image](https://github.com/dbissell6/DFIR/assets/50979196/f0b23d9c-2655-4529-8980-2b7df58535af)

New Case -> Add Host -> Add Image -> Analyze -> File Analysis


![image](https://github.com/dbissell6/DFIR/assets/50979196/8c4d7c83-4111-41fe-8f79-e47c2f3b8c78)

![image](https://github.com/dbissell6/DFIR/assets/50979196/a4fcf7a2-8897-41fc-af6a-b44c82f7ad74)

![image](https://github.com/dbissell6/DFIR/assets/50979196/36734528-4de2-4deb-bb42-52b0b577b6bf)


![image](https://github.com/dbissell6/DFIR/assets/50979196/08a2ecbe-2cc1-44e9-9357-e37bfa0d0837)

In file analysis can browse directories and see All Deleted Files. 

### Autopsy on Windows

![image](https://github.com/dbissell6/DFIR/assets/50979196/95281b66-8ff0-4f22-8e5f-5f1796926074)


Open Case -> Next -> Finish

![image](https://github.com/dbissell6/DFIR/assets/50979196/19d0c14c-afda-418b-ad62-114874ab4ddf)

Start analysis, this will take a while.

![image](https://github.com/dbissell6/DFIR/assets/50979196/59681d80-b5e6-4158-bcda-d5c73b038c6d)


### Autopsy Timeline


![image](https://github.com/dbissell6/DFIR/assets/50979196/31272248-c42d-4ec8-a2c9-f173a27f712c)

## Mount Windows on Windows

```
Mount-DiskImage -Access ReadOnly -ImagePath 'C:\Users\Blue\Desktop\Artifact Of Dangerous Sighting\HostEvidence_PANDORA\2023-03-09T132449_PANDORA.vhdx'
```
![image](https://github.com/dbissell6/DFIR/assets/50979196/ce18f597-cff5-4bb5-b52f-c0791bd6ebc5)


![image](https://github.com/dbissell6/DFIR/assets/50979196/b0ada041-cf64-43bf-8a49-25b5f11aeb1a)


![image](https://github.com/dbissell6/DFIR/assets/50979196/2634f8f8-8e73-47ad-8c15-251a25da069a)


### Alternate data streams

Alternate Data Streams are a feature of the NTFS file system that allows multiple data streams to be associated with a single file. While the primary data stream contains the file's actual content, these additional streams can store metadata or even other files discreetly, often going unnoticed by standard file browsing tools, making them a potential avenue for concealing data or malicious activity.

![Pasted image 20230930155804](https://github.com/dbissell6/DFIR/assets/50979196/cb46efd3-4520-49cc-9719-6741da939656)

![Pasted image 20230930160814](https://github.com/dbissell6/DFIR/assets/50979196/0a50308f-2a19-43d0-8d59-d264c0f66c5a)

![Pasted image 20230930160904](https://github.com/dbissell6/DFIR/assets/50979196/368a57fb-5a68-402a-9c9c-8399380caf9f)

On linux can also use `7z x` to extract /parse the streams

![image](https://github.com/user-attachments/assets/bb1e2e3f-cfc5-4303-a4ed-316e87c917d0)


## Android Forensics

```
https://github.com/RealityNet/Android-Forensics-References
```

### ALEAPP

Android Logs Events And Protobuf Parser.

![image](https://github.com/dbissell6/DFIR/assets/50979196/98c7185c-a4fe-4c1f-b115-908b02807caa)


![image](https://github.com/dbissell6/DFIR/assets/50979196/c4f20dd6-7bc6-4cfa-9b47-7e47c01e0a50)


```
https://github.com/abrignoni/ALEAPP
```



## PowerForensics

PowerForensics is a powerful and flexible tool for digital forensic investigations on Windows systems. Can use on mounted systems or live systems. PowerForensics offers a suite of cmdlets that can extract a variety of forensic artifacts, such as the Master File Table (MFT), Volume Boot Record (VBR), Event Logs, and more.

Docs - https://powerforensics.readthedocs.io/en/latest/#cmdlets

`
Get-ForensicFileRecord -VolumeName E:
`

![image](https://github.com/dbissell6/DFIR/assets/50979196/3d04b74f-3f55-4891-84b3-986f5906cf8c)

`
Get-ForensicAlternateDataStream -VolumeName E:
`

Alternate Data Stream

![image](https://github.com/dbissell6/DFIR/assets/50979196/55ff5415-8af6-4a4b-9880-bb600afa9528)


Example HTB Artifact Of Dangerous Sighting

## SluethKit

SleuthKit is another popular open-source digital forensic platform that provides a set of command-line tools for analyzing disk images. It supports a wide range of file systems, including FAT, NTFS, and EXT, and can be used to recover deleted files, view file metadata, and perform keyword searches.

    mmls: The 'mmls' command is used to display the partition layout of a disk image. It identifies the start and end sectors of each partition and displays other information such as the partition type, size, and offset. This information is important for identifying the partition that contains the file system you're interested in.

    fsstat: The 'fsstat' command is used to display information about a file system, such as its size, block size, and the number of allocated and unallocated blocks. It can also display information about the file system's metadata, such as the location of the Master File Table (MFT) in NTFS file systems.

    fls: The 'fls' command is used to list the contents of a file system. It displays the files and directories in the file system along with their attributes and inode numbers. The 'fls' command can also display deleted files and directories, which can be important for recovering data that has been deleted by an attacker or lost due to a system crash.

`sudo mmls dds1-alpine.flag.img `

![image](https://github.com/dbissell6/DFIR/assets/50979196/ed23a38f-35e9-417d-9ab4-fdc8b938a3e8)


`sudo fsstat -o 2048 dds1-alpine.flag.img `

Replace '2048' with the start sector of the partition you're interested in.

![image](https://github.com/dbissell6/DFIR/assets/50979196/c05f3d8e-583e-4b4f-90d4-7973659a280e)


Use the 'fls' command to list the contents of the file system: 

`sudo fls -o 2048 -f ext3 dds1-alpine.flag.img `

![image](https://github.com/dbissell6/DFIR/assets/50979196/775bd734-5a20-4edd-930b-a70508643dab)


Search a folder recursivly by specifying inode

`sudo fls -r -o 2048 dds1-alpine.flag.img 20324`

![image](https://github.com/dbissell6/DFIR/assets/50979196/48d7d6f5-e553-45d9-a253-f9c8e4a1ed2c)

## Photorec

Photorec is part of the TestDisk suite and is designed to recover lost files, including documents, archives, and multimedia files, from hard disks, CD-ROMs, and lost pictures (hence the name) from digital camera memory.

On linux - Select the disk -> file system type -> where to save

![image](https://github.com/dbissell6/DFIR/assets/50979196/037aae50-8f97-4d71-b785-30852c960d54)

![image](https://github.com/dbissell6/DFIR/assets/50979196/e79a68d4-78b2-4968-8203-8c6b7747f781)

![image](https://github.com/dbissell6/DFIR/assets/50979196/3f603828-4d70-44c5-be70-7b24e7ad5da6)


## foremost

Foremost is a tool that is used for file recovery and reconstruction. It can be used to recover deleted files, carve out files from disk images, and extract files from various file formats. Foremost is particularly useful for recovering files from damaged or corrupted disks, or for recovering files that have been deleted or lost.

Foremost uses a technique called file carving to recover files from disk images or other sources. It scans through the input data looking for specific file headers and footers, and then extracts the data between them. Foremost supports a wide range of file types, including images, audio files, videos, documents, and archives.

Foremost can be used in a variety of scenarios, such as when trying to recover deleted files, investigating a cybercrime incident, or recovering data from a damaged disk. It is a powerful tool for file recovery and reconstruction and can help in restoring valuable data that may have been lost or deleted.

![image](https://github.com/user-attachments/assets/695eab74-6ffe-4d78-948b-8918f9d4d2d7)


## RAID Disk recovery

### RAID Intro

RAID, or Redundant Array of Independent Disks, is a technology that allows multiple hard drives to be used as a single logical unit for storing data. While RAID can provide increased performance and redundancy, it can also make data recovery more challenging in the event of a disk failure.

RAID 5 is a popular type of RAID configuration that provides both data redundancy and increased performance. However, in CTF competitions, RAID 5 arrays are often deliberately subjected to various types of failures to test the contestants' ability to recover data.

Some common types of RAID 5 failures that may be encountered in CTFs include:

-   Single Drive Failure: If a single drive in a RAID 5 array fails, the array can still function. However, the array becomes more vulnerable to additional drive failures, and the performance may be degraded.

-   Multiple Drive Failures: If multiple drives fail in a RAID 5 array, data loss can occur. The number of drive failures that can be tolerated depends on the number of drives in the array and the stripe size. In CTFs, multiple drive failures may be simulated by removing multiple drives from the array.

-   Rebuild Failure: When a failed drive is replaced in a RAID 5 array, the data is rebuilt onto the new drive from the parity data. However, if the parity data is incorrect or missing, the rebuild may fail, and data loss can occur. In CTFs, contestants may be given a partially rebuilt RAID 5 array and asked to recover the missing data.

-   RAID Controller Failure: If the RAID controller fails in a RAID 5 array, the array can become inaccessible. In CTFs, contestants may be given a faulty RAID controller and asked to recover the data without the controller.

To successfully recover data from a failed RAID 5 array in a CTF, contestants must have a deep understanding of RAID 5 configurations, data recovery techniques, and tools. By practicing and gaining experience with these challenges, contestants can become more skilled at recovering data from RAID 5 arrays and gain a competitive advantage in CTF competitions.

### XOR
In a RAID 5 array with n drives, data is striped across n-1 drives, and a parity block is stored on the remaining drive. The parity block is generated using an XOR operation on the corresponding blocks of data on the other drives. This means that if one of the drives fails, the missing data can be reconstructed using the data on the remaining drives and the parity block.

Here's an example to illustrate how XOR can be used to recover missing data in a RAID 5 array:

Suppose we have a RAID 5 array with 3 drives, A, B, and C, and a block size of 512 bytes. We write a file that is 1KB in size, which is striped across the drives as follows:

    Block 1 is written to drive A
    Block 2 is written to drive B
    Block 3 is written to drive C
    Parity block is calculated as XOR of blocks 1, 2, and 3 and written to drive A (the parity block can be written to any drive)

If drive B fails, we can recover the missing data as follows:

    Read blocks 1 and 3 from drives A and C, respectively
    Calculate the missing block 2 as the XOR of blocks 1, 3, and the parity block on drive A: Block 2 = Block 1 XOR Block 3 XOR Parity
    Write the recovered data to a new drive to rebuild the RAID array

By using XOR to calculate the missing block, we can recover the data that was lost due to the failure of one of the drives in the RAID 5 array. However, if more than one drive fails, the recovery process becomes more complex and may require specialized tools and techniques.

The following python psuedocode first simulates a file that is 1KB in size and striped across a RAID 5 array with three drives. It then simulates a single drive failure by removing drive B from the array. Finally, it uses XOR to recover the missing data from the remaining drives and the parity block.

```
# Define the RAID 5 array configuration
drives = ['A', 'B', 'C']    # Drive labels
block_size = 512            # Block size in bytes

# Simulate a file that is 1KB in size striped across the drives
data = b'0123456789' * 100  # 1KB file data
n_blocks = len(data) // block_size
stripe = [[] for _ in range(len(drives))]
parity = [0] * block_size

for i in range(n_blocks):
    block = data[i*block_size:(i+1)*block_size]
    parity = [p ^ b for p, b in zip(parity, block)]
    for j in range(len(drives)):
        if j != i % len(drives):
            stripe[j].append(block)

stripe.append(parity)

# Simulate a single drive failure (drive B)
failed_drive = 1

# Recover the missing data using XOR
recovered_data = b''
for i in range(n_blocks):
    if failed_drive == i % len(drives):
        block1 = stripe[(i+1)%len(drives)][i//len(drives)]
        block2 = stripe[(i+2)%len(drives)][i//len(drives)]
        recovered_block = bytes([b1 ^ b2 ^ p for b1, b2, p in zip(block1, block2, parity)])
        recovered_data += recovered_block
    else:
        block = stripe[i%len(drives)][i//len(drives)]
        recovered_data += block

print(recovered_data)
```


https://blog.bi0s.in/2020/02/09/Forensics/RR-HackTM/

### mdadm

mdadm is a Linux utility used for managing and monitoring software RAID devices. It allows users to create, manage, and monitor RAID devices, as well as to assemble and disassemble RAID arrays. In CTFs, mdadm can be used to reconstruct a RAID 5 array using information about the disks that make up the array. This can be helpful when trying to recover data or find hidden clues in a CTF challenge that involves a RAID 5 array.

### losetup

losetup is a Linux command used to set up and control loop devices, which are virtual block devices that allow a file to be accessed as if it were a block device. In the context of RAID 5 reconstruction in a CTF, losetup can be used to map individual disks or partitions that make up a RAID 5 array to a loop device. Once the disks are mapped to loop devices, tools like mdadm can be used to assemble the array and recover the data.

```
Scenario:
You are participating in a CTF and have been given an image of a RAID 5 array. The image consists of four disks, with one of them having failed. Your task is to reconstruct the array and recover the data. The image file is named raid5.img.

Steps:

    Determine the block size of the RAID array by inspecting the image file. You can use the fdisk command to view the partition table of the image file and note the block size. Let's assume that the block size is 512 bytes.

bash

fdisk -l raid5.img

    Create loop devices for the image file and each disk image. You can use the losetup command to associate the image files with loop devices. Let's assume that the disk images are named disk1.img, disk2.img, and disk3.img.

bash

losetup -fP raid5.img
losetup -fP disk1.img
losetup -fP disk2.img
losetup -fP disk3.img

    Use mdadm to create the RAID 5 array using the loop devices. The -C option creates a new array, -l5 specifies RAID level 5, -n4 specifies the number of disks in the array, and missing indicates that one disk is missing.

bash

mdadm -C /dev/md0 -l5 -n4 missing /dev/loop0 /dev/loop1 /dev/loop2

    Verify that the array is created successfully and check the status. The /proc/mdstat file shows the current status of the array.

bash

cat /proc/mdstat

    Use mdadm to add the failed disk to the array. The -a option adds a new device to the array.

bash

mdadm /dev/md0 -a /dev/loop3

    Once the array is reconstructed, mount it and recover the data as necessary.

bash

mount /dev/md0 /mnt/raid



```
