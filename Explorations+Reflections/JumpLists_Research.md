
# JumpList Research

## Investigating File Renaming Without Traditional Artifacts

During a recent investigation, I needed to identify a file renaming events when traditional artifacts, such as filesystem logs or journaling data, were unavailable.
In that investigation I discovered that the automaticDestinations-ms file, records metadata for frequently accessed files and folders, 
retains evidence of both the original and renamed folder names. However, this information is not readily visible using standard forensic tools, 
such as Zimmerman's Jump List parsers.

My goal here is to uncover how this information is stored and why existing tools fail to capture it, highlighting its potential forensic value.

![Pasted image 20241223113344](https://github.com/user-attachments/assets/d2181cd6-8367-4dc0-9e72-fb9445df9ee1)

However, when using Zimmerman's Jump List tools, the original name was not referenced. 

## Starting from the Beginning

To demonstrate this, I created a folder named `A_New_Folder` on the desktop and examined its presence in Recent files.

![Pasted image 20241219085907](https://github.com/user-attachments/assets/fcf0a206-3554-4568-a2a7-abac854c87d4)


Running strings confirmed that the `automaticDestinations` file contained the original folder name.

![Pasted image 20241219090031](https://github.com/user-attachments/assets/56c7c13b-d725-44c9-b042-f0bdc0a431c7)

Searching through the directory using strings, I located the folder in the `f01b4d95cf55d32a.automaticDestinations-ms` file.

![Pasted image 20241219090200](https://github.com/user-attachments/assets/ae0f6ef8-0171-436b-b655-6df5abdf0947)



## Testing Renaming Behavior

Next, I renamed the folder to `B_New_Folder`. Interestingly, the `/Recent` directory entry still referred to the old name: `A_New_Folder.lnk`.

![Pasted image 20241219090547](https://github.com/user-attachments/assets/0db7a70e-49d9-46fc-bd9d-97b71ebd1ec4)


When I re-ran strings on the Jump List file, both folder names (`A_New_Folder` and `B_New_Folder`) were present.

![Pasted image 20241219090724](https://github.com/user-attachments/assets/6982c58d-a31f-49a6-acca-a6b466cf88d2)

Running Zimmerman's Jump List parsing tool (JLECmd), however, only identified the new name (B_New_Folder) without referencing the original name.


Output from `.\JLECmd.exe -d 'C:\Users\Administrator\AppData\Roaming\Microsoft\Windows\Recent\' --fd`

```
Entry #: 66
  MRU: 1
  Path: C:\Users\Administrator\Desktop\B_New_Folder
  Pinned: False
  Created on:    2024-12-19 15:48:24
  Last modified: 2024-12-19 15:58:30
  Hostname: logging-vm
  Mac Address: 00:50:56:b0:a2:03
  Interaction count: 1

--- Lnk information ---
  Lnk target created:  2024-12-19 15:58:24
  Lnk target modified: 2024-12-19 15:58:24
  Lnk target accessed: 2024-12-19 15:58:24

--- Header ---

  Target created:  2024-12-19 15:58:24
  Target modified: 2024-12-19 15:58:24
  Target accessed: 2024-12-19 15:58:24

  File size: 0
  Flags: HasTargetIdList, HasLinkInfo, IsUnicode, DisableKnownFolderTracking, AllowLinkToLink
  File attributes: FileAttributeDirectory
  Icon index: 0
  Show window: SwNormal (Activates and displays the window. The window is restored to its original size and position if the window is minimized or maximized.)


--- Link information ---
Flags: VolumeIdAndLocalBasePath

>> Volume information
  Drive type: Fixed storage media (Hard drive)
  Serial number: B8B30D72
  Label: (No label)
  Local path: C:\Users\Administrator\Desktop\B_New_Folder

--- Target ID information (Format: Type ==> Value) ---

  Absolute path: B_New_Folder

  -Directory ==> B_New_Folder
    Short name: B_New_Folder
    Modified:    2024-12-19 15:58:26
    Extension block count: 1

    --------- Block 0 (Beef0004) ---------
    Long name: B_New_Folder
    Created:     2024-12-19 15:58:26
    Last access: 2024-12-19 15:58:26

--- End Target ID information ---

--- Extra blocks information ---

>> Tracker database block
   Machine ID:  logging-vm
   MAC Address: 00:50:56:b0:a2:03
   MAC Vendor:  (Unknown vendor)
   Creation:    2024-12-19 15:48:24

   Volume Droid:       08d1517c-f0ea-455f-a42a-7788a985fde1
   Volume Droid Birth: 08d1517c-f0ea-455f-a42a-7788a985fde1
   File Droid:         ae5813f5-be20-11ef-89ad-005056b0a203
   File Droid birth:   ae5813f5-be20-11ef-89ad-005056b0a203

>> Property store data block (Format: GUID\ID Description ==> Value)
   9f4c2855-9f79-4b39-a8d0-e1d42de1d5f3\7      App User Model Is DestList Link     ==> True
   446d16b1-8dad-4870-a748-402ea43d788c\104    Volume Id                           ==> Unmapped GUID: 1f7ffce3-063b-493e-9ec7-d18369683186

   (lnk file not present)
```

## Experimenting Further

I repeated the process with additional steps:

    Created a new folder (C_New_Folder) and added files inside it.
    Observed that C_New_Folder only appeared in Recent after interacting with its contents.
    Verified that A_New_Folder was still present in strings output, but B_New_Folder was missing.


## Findings

Through these experiments, I identified the following key behaviors:

    The automaticDestinations-ms file retains both the original and current names of a renamed object.
    A new .lnk file is not created in /Recent until the object is interacted with again, and it retains the old name.
    Current Jump List parsers, including JLECmd, do not capture the renaming history. They only parse the current metadata.


![Pasted image 20241219093033](https://github.com/user-attachments/assets/7b1cb4b2-8a1a-400f-bcdd-43a38dbdf723)

This shows the entry does not keep a log of changes, just the first and last.

## Conclusion

My analysis highlights a gap in current JumpList parsing tools, which do not account for renaming history stored in the automaticDestinations-ms file.
For forensic investigators, manually inspecting these files using tools like strings or olebrowse can provide critical insights into user activity.

Future updates to Jump List tools could incorporate this capability, making it easier to uncover renaming events automatically.



# Part 2: Understanding Why Tools Miss Renaming Artifacts

In the first part, we uncovered how the automaticDestinations-ms file retains both the original and renamed folder names, even when traditional artifacts fail to do so.
But why do tools like JLECmd overlook this information? In this section, we’ll explore the structure of Jump Lists, how existing tools parse them,
and why renaming artifacts are missed.


After my initial analysis, my environment reset, so I recreated the folders (`A_New_Folder` and `B_New_Folder`) to examine the artifacts again.
Despite some changes in identifiers like stream numbers, the core insights remained consistent.

Taking the automaticDestinations-ms file back to a Linux environment, I identified it as a Composite Document File V2 Document:

![Pasted image 20241219121405](https://github.com/user-attachments/assets/e33d1d37-a7d1-4373-b268-0fe36c465eb7)

This confirmed that Jump Lists rely on the OLE file format, a complex structure designed to store hierarchical data.
How Jump List Tools Work: A Look at JLECmd

Eric Zimmerman, the creator of JLECmd, has documented his process in detail. His blog post Jump Lists In-Depth explains how Jump List files are parsed, focusing on their primary structures:

    OLE Files:
    OLE (Object Linking and Embedding) files are composed of:
        Header: Identifies the file type and provides basic metadata.
        Sector Allocation Tables (SAT): Map the storage of data streams within the file.
        Directory Entries: Organize data streams into a hierarchical structure. Two critical entries are the Root and the DestList.

    DestList Overview:
    The DestList is a specialized directory that tracks user interactions with files or folders. This includes:
        Paths to recently accessed files.
        Metadata such as timestamps, interaction counts, and machine identifiers.

Zimmerman’s tools parse the `DestList` and `.lnk` file metadata to extract actionable data, but they do not explicitly look for historical file names.

Zimmerman's illustration of the DestList structure:
![Pasted image 20241220182417](https://github.com/user-attachments/assets/c2cdd098-4b4e-460b-8bca-07a86a2bf2eb)

Manual Analysis: Beyond JLECmd

To identify why renaming artifacts are missed, I used tools like **olebrowse** to manually inspect the automaticDestinations-ms file.

Using **olebrowse**, I found the DestList directory containing `B_New_Folde`r but no reference to `A_New_Folder`:
![Pasted image 20241219121809](https://github.com/user-attachments/assets/3315e526-2cd2-4219-95ff-5e0f9ec05244)


The renaming information was buried deeper within the file, specifically in stream 42. By saving this stream to a separate file and analyzing its contents, I confirmed it retained both folder names:

![Pasted image 20241219123458](https://github.com/user-attachments/assets/790e1412-02d8-4901-afcf-9a81b5ccbdfb)
![Pasted image 20241219122210](https://github.com/user-attachments/assets/7c4fbad2-5ea2-46c3-9995-6328e95a5dfa)
![Pasted image 20241219122700](https://github.com/user-attachments/assets/6fce3b78-737b-4295-ad50-cc2becc67fc5)


This highlighted a critical limitation: JLECmd focuses on `.lnk` metadata and DestList interactions but does not parse secondary streams where renaming artifacts are stored.
Why Do Tools Miss This?

The root cause lies in how Jump List parsers prioritize data extraction. Tools like JLECmd are designed to extract actionable metadata for forensic investigations, such as:

    Recent file interactions.
    Timestamps and interaction counts.
    Host and user details.

However, these tools do not delve into secondary streams that may contain historical names. This is because:

    Focus on Accessibility: Parsing .lnk metadata is faster and covers the majority of use cases.
    Limited Scope: Tracking renaming events is not a typical forensic requirement, so tools are not optimized for this purpose.
    File Complexity: Extracting secondary streams requires additional overhead and manual intervention, which most tools are not designed to handle.






