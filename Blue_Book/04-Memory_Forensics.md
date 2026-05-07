# Memory Dumps
## Intro
Memory dumps are a type of digital forensic artifact that can be used to analyze the state of a computer's memory at the time of a crash or system failure. Memory dumps contain a complete snapshot of the memory contents of a computer, including the contents of volatile memory such as RAM, as well as the contents of any mapped physical memory pages. Memory dumps can be used to diagnose and troubleshoot system issues, as well as to recover and analyze digital evidence related to malicious activities or other incidents.

In digital forensics and incident response (DFIR), memory dumps are considered a valuable artifact because they can provide insight into the state of a system at the time of an event of interest, including information about running processes, open network connections, and any malicious activity that may have been occurring in memory. Memory dumps can be analyzed using a variety of tools, including those specifically designed for memory analysis, as well as more general-purpose digital forensics tools.


**Fileless Malware**: Fileless malware is a type of malware that operates entirely in memory, making it difficult to detect and analyze. It can be executed through legitimate processes, such as PowerShell or WMI, and can evade traditional antivirus solutions.

Crash dump files will contain memory dump when system crashes

Page files stores data when the RAM is low on space - not a memory file

Common File formats of memory dumps 
-   Raw binary format (.bin)
-   Microsoft crash dump format (.dmp)
-   RAW (.raw)
-   Virtual Machine Memory file (.vmem)

## Kernel 

Kernels are responsible for managing system resources, such as memory, processes, and input/output operations. They provide a layer of abstraction between the hardware and the rest of the operating system, and allow applications to interact with the hardware without having to know the details of the underlying hardware.

Windows and Linux have different kernel architectures, although they share many similar concepts. The Windows kernel is a monolithic kernel, which means that all core system services are part of a single executable file (ntoskrnl.exe). The Windows kernel is responsible for managing memory, processes, threads, file systems, input/output operations, and other system services.

On the other hand, the Linux kernel is a modular kernel, which means that core system services are implemented as loadable kernel modules. This allows for greater flexibility and modularity, as system services can be loaded or unloaded dynamically as needed. The Linux kernel is responsible for managing memory, processes, threads, file systems, input/output operations, and other system services, and provides a wide range of configurable options and features.

In terms of memory forensics, the differences between Windows and Linux kernels can affect how memory is organized and accessed by memory forensics tools such as Volatility. For example, the Windows kernel uses a Virtual Address Descriptor (VAD) tree to manage process memory, while the Linux kernel uses a Virtual Memory Area (VMA) structure. The details of how the kernel manages memory can affect how memory forensics tools parse and interpret the data, and can impact the accuracy and completeness of the analysis.

Overall, understanding the kernel architecture and how it manages system resources is an important aspect of memory forensics analysis, and can help analysts to correctly interpret and analyze the data in memory. The differences between Windows and Linux kernels are important to consider when using memory forensics tools on different operating systems.

## Executive Objects

Windows is written in C and uses C structures. Some of these structures are Executive Objects. These executive objects are under the management (creation, protection, deletion, etc.) of the Windows Object Manager, a fundamental component of the kernel implemented through the NT module. Every executive object is preceded by a header in memory. Before an instance of an exectuve object is created, a memory block must be allocated. 

| Object        | Description                                                                   |
|---------------|-------------------------------------------------------------------------------|
| Event         | Synchronization object used to signal events between processes.              |
| Mutant        | Synchronization object, also known as a mutex, used for mutual exclusion.     |
| Semaphore     | Synchronization object used to control access to a common resource.           |
| Directory     | Represents a directory or folder in the file system.                          |
| Key           | Represents a key in the Windows registry.                                    |
| IoCompletion  | Used for asynchronous input/output (I/O) completion notifications.            |
| File          | Represents a file in the file system.                                        |
| WindowStation | Represents a window station used to manage windows, menus, atoms, and hooks.  |
| Process       | Represents a running process in the operating system.                         |
| Thread        | Represents a thread, the basic unit of execution within a process.            |
| Desktop       | Represents a desktop object contained within a window station.                |
| ALPC Port     | Represents an Advanced Local Procedure Call (ALPC) port.                      |
| SymbolicLink  | Represents a symbolic link in the object namespace.                           |
| Timer         | Represents a timer object used for scheduling timed notifications.            |
| KeyedEvent    | Synchronization object used to signal events between processes.              |
| Section       | Represents a memory section object, used for memory mapping and sharing.      |
| Token         | Represents an access token containing security information for a logon session.|
| Job           | Represents a job object, used to manage and track sets of processes.          |
| EtwRegistration | Used for event tracing registration.                                        |
| Type          | Represents an object type in the object manager namespace.                    |

### Processes

A process is an instance of a running program, containing the program's code, data, heap, stack, and other resources. Each process operates in its own isolated memory space, ensuring stability and security.

**Key Components of a Process:**

- Executable Code (Text Segment): Contains the machine instructions for the process.

- Data Segment: Holds global and static variables.

- Heap: Used for dynamic memory allocation.

- Stack: Contains local variables, function parameters, and return addresses.

- Memory-Mapped Files: Regions of memory mapped to files, including shared libraries (DLLs).

- Process Control Block (PCB): Contains metadata about the process, such as the process ID (PID), state, memory management information, and open files.


#### Process Memory

| **Structure/Region** | **Location**                   | **Purpose**                             | **Key Data**                                                   |
|----------------------|--------------------------------|-----------------------------------------|----------------------------------------------------------------|
| **PEB**              | User-mode address space        | Information about the process           | Image base address, startup parameters, heap pointers, modules |
| **TEB**              | User-mode address space, per thread | Information specific to each thread    | Stack base and limit, thread ID, environment pointer           |
| **Executable Code**  | User-mode address space        | Executable instructions of the process  | Machine code, read-only                                        |
| **Data Segment**     | User-mode address space        | Holds global and static variables       | Initialized data, uninitialized data (BSS)                     |
| **Heap**             | User-mode address space        | Dynamic memory allocation               | Allocated variables, runtime data, user inputs                 |
| **Stack**            | User-mode address space, per thread | Manages function calls and variables  | Function call parameters, return addresses, local variables    |
| **Memory-Mapped Files** | User-mode address space     | Maps files or libraries into memory     | DLLs, memory-mapped data files                                 |
| **Loaded Modules**   | User-mode address space        | Lists modules loaded into the process   | Base addresses, names and paths of DLLs, entry points          |
| **Handles and Resources** | Kernel and user-mode     | Manages system resources                | File handles, registry handles, network connections            |
| **PCB**              | Kernel-mode address space      | Contains process state information      | PID, process state, scheduling information                     |


**Process Environment Block (PEB):** An extremely useful structure that tells you where to find several of the other items in this list, including the DLLs, heaps, and environment variables.

Using windbg to view process dump of peb.

![image](https://github.com/dbissell6/DFIR/assets/50979196/f0098402-efd6-443d-842b-09fcb7319b56)

Also holds environment variables.

![image](https://github.com/dbissell6/DFIR/assets/50979196/f276e21b-ea68-4107-bad1-674dfc386026)

**Process heaps:** Where you can find a majority of the dynamic input that the process receives. For example, variable-length text that you type into e-mail or documents is often placed on the heap, as is data sent or received over network sockets.
Heap

![image](https://github.com/dbissell6/DFIR/assets/50979196/1674676e-ee3e-4fe7-89fe-57014bf60f79)



### Threads

A thread is the smallest unit of execution within a process. Each process has at least one thread (the main thread), and many processes create additional threads to perform tasks concurrently.

**Key Components of a Thread:**

- Thread Context: The state of the thread, including CPU registers and the program counter.

- Thread Stack: Contains local variables, function parameters, and control information.

- Thread Control Block (TCB): Contains metadata about the thread, such as the thread ID (TID), state, and pointers to the stack and thread-specific data.

### Handles

A **handle** is a reference to an open instance of a kernel object, such as a file, registry key, mutex, process, or thread.

Could show persistence if process has handle of registry files.


## Strings
It is possible to run strings on a memory dump to extract info

![image](https://github.com/dbissell6/DFIR/assets/50979196/271f4112-a784-43e3-80cf-1338872e62ad)

Grep for commands
`
strings PhysicalMemory.raw | grep -E "(cmd|powershell|bash)[^\s]+"
`

## memprocfs


![image](https://github.com/user-attachments/assets/de9224a5-c659-4d1d-a9ed-e32654d599dd)

![image](https://github.com/user-attachments/assets/26fd0157-6c44-4985-bfa0-d51e6272b0c3)


## Volatility 3

Volatility 3 is an Open-Source memory forensics tool that allows analysts to extract and analyze information from a computer's volatile memory, such as running processes, network connections, and open files. To do this, Volatility needs to know the kernel version and build of the operating system from which the memory was obtained. This is because the kernel is responsible for managing the memory and processes, and its data structures and behavior can change between different versions or builds of the operating system.

`
https://volatility3.readthedocs.io/en/latest/index.html
`

Download

```https://github.com/volatilityfoundation/volatility3```

### Creating a profile for a memory dump

First run banners to see what version

<img width="1236" height="243" alt="image" src="https://github.com/user-attachments/assets/3000cc38-06fb-441d-b3d1-0513b3dc4288" />

Next go get the

<img width="1551" height="765" alt="image" src="https://github.com/user-attachments/assets/7d369b69-5fc7-4ad3-966e-bb738659355d" />

Check sum

<img width="1326" height="94" alt="image" src="https://github.com/user-attachments/assets/efbd2311-0aca-4f31-8db1-7328c1c083ba" />

Extract

<img width="911" height="64" alt="image" src="https://github.com/user-attachments/assets/c49fc62a-ec34-47f3-955d-b57bbdbf49f3" />

Create with **Dwarf2json** 

<img width="1352" height="89" alt="image" src="https://github.com/user-attachments/assets/7c8614fb-e59e-4345-b082-23ea30fe905e" />

Move to correct folder

<img width="1059" height="74" alt="image" src="https://github.com/user-attachments/assets/2f4fb0cd-b7fc-4a22-8fd1-e095f7a261d5" />

Profit

<img width="1076" height="404" alt="image" src="https://github.com/user-attachments/assets/94fd8392-0fbe-41eb-b422-60c2470b41b5" />


### General Steps

1.    Processes
2.    DLL and Handles
3.    Network
4.    Code Injection
5.    Rootkits
6.    Dump

### Windows Commands

To see options

![image](https://github.com/dbissell6/DFIR/assets/50979196/cae9895d-1e7c-4c77-98b7-2e1627fccba5)


Get image information
```
python3 ~/Tools/volatility3-1.0.0/vol.py -f memory.raw windows.info   
```
See Process List
```
python3 ~/Tools/volatility3-1.0.0/vol.py -f memory.raw windows.pslist
```
See Process List + Hiddens

```
python3 ~/Tools/volatility3-1.0.0/vol.py -f memory.raw windows.psscan
```

Can sort by create time

![image](https://github.com/dbissell6/DFIR/assets/50979196/e2e3fa0d-75bc-45c5-bc1c-7b594af3cbf9)


![image](https://github.com/dbissell6/DFIR/assets/50979196/9ccae185-d43b-461d-ae0e-c30a6050b466)


See Process tree
```
python3 ~/Tools/volatility3-1.0.0/vol.py -f memory.raw windows.pstree
```
See all active network connections and listening programs
```
python3 ~/Tools/volatility3-1.0.0/vol.py -f memory.raw windows.netscan
```
Find all handles opened by process 3424. A handle represents an active instance of a kernel object that is currently open, like a file, registry key, mutex, process, or thread.

```
python3 ~/Tools/volatility3-1.0.0/vol.py -f memory.raw windows.handles --pid 3424
```
List all available Windows Registry hives in memory
```
python3 ~/Tools/volatility3-1.0.0/vol.py -f memory.raw windows.registry.hivelist
```
Print a specific Windows Registry key, subkeys and values
```
python3 ~/Tools/volatility3-1.0.0/vol.py -f memory.raw windows.registry.printkey --key "Software\Microsoft\Windows\CurrentVersion" --recurse
```
Print Windows Registry UserAssist
```
python3 ~/Tools/volatility3-1.0.0/vol.py -f memory.raw windows.registry.userassist
```
Dump windows registry hivelist
```
python3 ~/Tools/volatility3-1.0.0/vol.py -f memory.raw -o "dump" windows.registry.hivelist --dump
```
File Scan
```
python3 ~/Tools/volatility3-1.0.0/vol.py -f memory.raw windows.filescan | grep 'rsteven\Desktop\vlc-win32\vlc.exe'
```
Extract file
```
$ python3 ~/Tools/volatility3-1.0.0/vol.py -f memory.raw windows.dumpfiles --virtaddr 0xad81ecda9910 --dump-dir .
```
Dump Windows user password hashes
![Pasted image 20221123074049](https://user-images.githubusercontent.com/50979196/221450622-46170f92-5a13-42dd-a7ff-4b9b1479f2b1.png)

Print dlls
```
python3 ~/Tools/volatility3-1.0.0/vol.py -f memory.raw windows.dlllist
```
PoolScanner

Memory pools are regions of memory set aside for dynamic memory allocation during the execution of a program.

```https://learn.microsoft.com/en-us/windows/win32/memory/memory-pools```

![image](https://github.com/dbissell6/DFIR/assets/50979196/0f6f8df5-1462-4ff7-80b3-d03b8a6f196d)


BigPools

To print large kernel pools in a memory dump.

![image](https://github.com/dbissell6/DFIR/assets/50979196/ba4baa77-84d8-4969-bfd6-0b653e39c6b6)


memmap

Analyze memory mappings for a specific process (PID 8580) from the provided memory dump file (PhysicalMemory.raw) and extracts relevant details about these memory mappings.

![image](https://github.com/dbissell6/DFIR/assets/50979196/605b8d23-b56a-4b8c-a7f9-76a4b236a44f)


envars

Display the environment variables for processes running in the memory image

![image](https://github.com/dbissell6/DFIR/assets/50979196/b9d4d2f8-1ba9-4bba-9093-32e2691e16e0)

vadinfo

![Pasted image 20231011051428](https://github.com/dbissell6/DFIR/assets/50979196/250c46f8-c94a-47be-a1af-a565eb183210)
Virtual Address Descriptors (VAD):

The VAD tree in Windows provides metadata about the virtual memory regions allocated by a process. Each node in this tree represents a block of committed virtual memory, a memory-mapped file, or a reserved block of addresses.

1. **Memory Analysis**: It helps forensic analysts understand what regions of memory a process was using, how it was using them, and what permissions were set.
2. **Find Hidden or Injected Code**: Malware might inject code into a process's address space. By analyzing the VAD tree, you can identify anomalous or unexpected memory regions which might indicate such injections.
3. **Memory-Mapped Files**: These are areas of virtual memory that are mapped to a physical file on disk. This is common for shared libraries/DLLs. A malware might map a malicious DLL into a process's memory.
4. **Discover Protection Mechanisms**: Some software might employ anti-debugging or anti-analysis techniques, such as self-modifying code. Understanding the memory permissions can give insights into such behaviors.


Memory Permissions:

Memory permissions determine how a certain region of memory can be accessed.
- **PAGE_EXECUTE**: The memory can be executed as code. This is often seen in regions where the actual binary code of a process resides.
- **PAGE_EXECUTE_READ**: The memory can be executed as code, and can be read.
- **PAGE_EXECUTE_READWRITE**: The memory can be executed as code, read from, and written to. This permission can be concerning, as it might indicate a region where malicious shellcode could be inserted and executed.
- **PAGE_EXECUTE_WRITECOPY**: Similar to the above but can be written to if a process attempts to modify it. A new private copy is made for the process.




ldrmodules

The ldrmodules plugin in Volatility is used to list the loaded modules (DLLs) for a specific process. It is particularly valuable for detecting unlinked or hidden DLLs which can be indicative of malicious activity. 

Each module will have three columns: InLoad, InInit, and InMem. These indicate whether the module is:

    Loaded into memory (InLoad)
    Initialized (InInit)
    Present in the process memory (InMem)

If all three columns for a specific module are False, it might suggest the operation of a rootkit or malicious software trying to conceal its activities.

![image](https://github.com/dbissell6/DFIR/assets/50979196/8f738a78-e847-4c06-9cdb-ccc0eade7acc)


Modules:
The Modules plugin in Volatility examines the metadata structures linked through PsLoadedModuleList, a doubly linked list. When the operating system loads new modules, they are added to this list. By analyzing this list, the Modules plugin allows you to understand the relative temporal order of module loading. Essentially, you can determine the sequence in which modules were loaded into the system.

Modscan:
The Modscan plugin employs pool tag scanning across the physical address space, even including memory that has been freed or deallocated. Does not follow the EPROCESS list which can be useful to find hidden processes. It specifically searches for MmLd, which is the pool tag associated with module metadata. This plugin is valuable for identifying both unlinked modules and modules that were previously loaded. By scanning the pool tags, it helps uncover module-related information, contributing to a comprehensive analysis of the system's module activities.

![image](https://github.com/dbissell6/DFIR/assets/50979196/c4645d8c-9dc8-444a-8f72-1d8885987acf)

### Linux Commands

| Plugin | Description | Useful For… |
|--------|-------------|--------------|
| linux.bash.Bash | Recovers bash command history from memory. | Reconstructing attacker commands & TTPs. |
| linux.boottime.Boottime | Shows the system boot time. | Timeline building, correlating events. |
| linux.capabilities.Capabilities | Lists process capability sets. | Detecting privilege escalation without root UID. |
| linux.check_afinfo.Check_afinfo | Verifies network protocol function pointers. | Finding kernel rootkit hooks in AF structures. |
| linux.check_creds.Check_creds | Detects shared credential structures. | Spotting process masquerading / privilege abuse. |
| linux.check_idt.Check_idt | Verifies the Interrupt Descriptor Table. | Detecting low-level rootkits hooking interrupts. |
| linux.check_modules.Check_modules | Compares module list with sysfs. | Identifying hidden or unlinked kernel modules. |
| linux.check_syscall.Check_syscall | Checks syscall table for hooks. | Detecting syscall-hooking kernel rootkits. |
| linux.ebpf.EBPF | Lists loaded eBPF programs. | Finding malicious eBPF backdoors & stealth monitoring. |
| linux.elfs.Elfs | Enumerates memory-mapped ELF files. | Locating injected binaries, memory-only implants. |
| linux.envars.Envars | Extracts process environment variables. | Finding secrets, LD_PRELOAD, malicious env vars. |
| linux.graphics.fbdev.Fbdev | Extracts framebuffer images. | Capturing on-screen evidence (screenshots). |
| linux.hidden_modules.Hidden_modules | Carves memory looking for hidden modules. | Detecting kernel-level stealth modules. |
| linux.iomem.IOMem | Rebuilds `/proc/iomem`. | Finding unusual device mappings (DMA implants). |
| linux.ip.Addr | Lists interface IP addresses. | Identifying attacker network config or pivots. |
| linux.ip.Link | `ip link show` equivalent. | Enumerating NICs, virtual interfaces, tunnels. |
| linux.kallsyms.Kallsyms | Lists kernel symbol table. | Understanding kernel memory layout & offsets. |
| linux.keyboard_notifiers.Keyboard_notifiers | Lists keyboard notifier callbacks. | Detecting keyloggers. |
| linux.kmsg.Kmsg | Kernel log buffer reader. | Kernel-level logging of attacks or crashes. |
| linux.kthreads.Kthreads | Enumerates kernel threads. | Detecting malicious or unknown kthreads. |
| linux.library_list.LibraryList | Lists libraries in processes. | Detecting injected / swapped libraries. |
| linux.lsmod.Lsmod | Shows loaded kernel modules. | Basic kernel module presence check. |
| linux.lsof.Lsof | Lists open files per process. | Identifying exfil, staging, deleted binaries. |
| linux.malfind.Malfind | Finds injected memory regions. | Detecting userland malware/injected code. |
| linux.module_extract.ModuleExtract | Extracts kernel modules from memory. | Recovering malicious kernel modules for RE. |
| linux.modxview.Modxview | Consolidates module visibility checks. | Red/blue team rootkit detection overview. |
| linux.mountinfo.MountInfo | Lists mount points & namespaces. | Detecting container escapes & attacker mounts. |
| linux.netfilter.Netfilter | Lists Netfilter hooks. | Spotting firewall-hooking backdoors. |
| linux.pagecache.Files | Lists files present in page cache. | Finding deleted files attackers tried to hide. |
| linux.pagecache.InodePages | Lists & extracts inode pages. | Recovering partial or deleted file fragments. |
| linux.pagecache.RecoverFs | Recovers filesystem structure from cache. | Rebuilding a filesystem even if wiped. |
| linux.pidhashtable.PIDHashTable | Walks PID hash table. | Detecting hidden/unlinked processes. |
| linux.proc.Maps | Lists process memory maps. | Reviewing memory regions for anomalies/injection. |
| linux.psaux.PsAux | Shows processes with arguments. | Confirming exec args for attacker tools. |
| linux.pscallstack.PsCallStack | Shows call stack per task. | Analyzing what threads/functions were active. |
| linux.pslist.PsList | Lists tasks from linked lists. | Primary process enumeration. |
| linux.psscan.PsScan | Carves for process structures. | Finding hidden/unlinked processes. |
| linux.pstree.PsTree | Tree of process parent-child relationships. | Identifying attacker pivot process lineage. |
| linux.ptrace.Ptrace | Lists ptrace relationships. | Finding debugging, spying, credential-stealing. |
| linux.sockstat.Sockstat | Lists all network connections. | Identifying attacker C2, tunnels, handles. |
| linux.tracing.ftrace.CheckFtrace | Detects ftrace hooks. | Rootkit detection (ftrace-based hooking). |
| linux.tracing.perf_events.PerfEvents | Lists perf events. | Detecting perf-based snooping or injections. |
| linux.tracing.tracepoints.CheckTracepoints | Detects tracepoint hooks. | Rootkits modifying kernel tracepoints. |
| linux.tty_check.tty_check | Checks TTY hooks. | Spotting keyloggers or input hijacking. |
| linux.vmaregexscan.VmaRegExScan | Regex scan across VMA regions. | Hunting strings, IOCs, config data in RAM. |
| linux.vmayarascan.VmaYaraScan | Yara scan across VMA regions. | Pattern-matching malware in memory. |
| linux.vmcoreinfo.VMCoreInfo | Lists VMCoreInfo tables. | Understanding kernel crash dump metadata. |


### Vol Extras

https://readthedocs.org/projects/volatility3/downloads/pdf/latest/
https://dfir.science/2022/02/Introduction-to-Memory-Forensics-with-Volatility-3

## VolShell

![image](https://github.com/dbissell6/DFIR/assets/50979196/89a51b9d-eb60-4465-83b1-72ec863f77ad)

### Running plugins

![image](https://github.com/dbissell6/DFIR/assets/50979196/eb22bc11-3146-481e-823d-ca07a7e4d3ae)

Module requirement

![image](https://github.com/dbissell6/DFIR/assets/50979196/8ed04277-6635-44c6-813a-25a9a448031e)

### help

![image](https://github.com/dbissell6/DFIR/assets/50979196/e49999cb-7467-4a1a-a86d-49939ca463a6)

## Volatility 2

I hate that I have to do this, but here we are. Long story short, vol2 has some features that vol3 doesnt. There are rumors of differences 
between python2 and python3 leading to the plugins we get for each version of vol.  Some plugins of interest are cmdscan(better than cmdline), clipboard, consoles.

Download

```
git clone https://github.com/volatilityfoundation/volatility.git
cd volatility
sudo python2 setup.py install
```

First need to run info on the image. 

![image](https://github.com/dbissell6/DFIR/assets/50979196/2e5bb1c5-8aaa-43af-a01d-8413cda3c29d)

Vol3 will automatically give us a profile, in vol2 we have to explicitly state it, we can see suggested profiles loaded above.

![image](https://github.com/dbissell6/DFIR/assets/50979196/2bb7fc8d-0a8a-4c86-8537-28242a66e8e1)


For all available plugins
```
python2 vol.py -f /home/kali/Desktop/recollection.bin --profile=Win7SP1x64 --help
```

## What did they see?

Dumping process can sometimes allow us to see what was on the screen, or that processes display.

Take for instance this process mspaint pid 5116.

![image](https://github.com/dbissell6/DFIR/assets/50979196/063f0517-75c3-4bed-ad4d-27377eafe4b6)

Dump the memmap

![image](https://github.com/dbissell6/DFIR/assets/50979196/93041d19-ffcd-411c-9eab-edf3f4c82c5a)

Change the extention to .data. Open file with GIMP 

![image](https://github.com/dbissell6/DFIR/assets/50979196/44bf3026-6db2-4075-8765-b2cb6f7b6cde)

![image](https://github.com/dbissell6/DFIR/assets/50979196/33159526-fe16-4a50-8a8f-5e43ae0610e0)


Guess the width,height,offset

![image](https://github.com/dbissell6/DFIR/assets/50979196/bbdf5fc6-7816-470b-968d-9c4b012fe48e)


## yara

![image](https://github.com/dbissell6/DFIR/assets/50979196/9c18bff0-267c-4830-85c4-bf7e3286b76f)


Rules at
```
https://github.com/Yara-Rules/rules
```

![image](https://github.com/dbissell6/DFIR/assets/50979196/0db2eace-aa03-4359-abc3-c87d9d8ca107)


## Bulk_Extractor

Bulk_Extractor is a tool that will scan various types of evidence including pcaps, files, disk images but I probably get the most use from memory dumps. Computationally + Time intensive, must create an output dir.  

![image](https://github.com/dbissell6/DFIR/assets/50979196/2c7253c5-4be2-4ec2-ac98-d3fcaf248930)

![image](https://github.com/dbissell6/DFIR/assets/50979196/1edae5d4-d897-40da-83f9-6f3d0ef67d45)

Useful to find, emails, browser search terms, logs... 

![image](https://github.com/dbissell6/DFIR/assets/50979196/8ac97e75-26f9-4a41-a658-2b6ea059d5ba)

## LSASS (.DMP)

![image](https://github.com/dbissell6/DFIR/assets/50979196/bddd5970-296d-4ba7-8484-e108a8b08153)

binwalk can also be used to identify, should see Certificate or private key in DER format, mcrypt encrypt,...

LSASS (Local Security Authority Subsystem Service) is a crucial Windows system process responsible for enforcing the security policy on the system. It handles user logins, password changes, and creates access tokens. It's essentially the gatekeeper for the security realm within Windows, dealing with authentication and locally stored credentials.

LSASS Dump

An LSASS dump involves capturing the memory contents of the LSASS process. This memory can contain active credentials, such as plaintext passwords, hashed passwords, and Kerberos tickets, depending on the system's configuration and the user's state. Malware and attackers often target LSASS to extract credentials that can be used for lateral movement within a network. (can do the dumping with task manager or procdump)

![Pasted image 20240323140017](https://github.com/dbissell6/DFIR/assets/50979196/02c874cd-6bce-4a79-af05-cafc756eea68)

## hiberfil.sys

magic bytes + Ascii

![image](https://github.com/dbissell6/DFIR/assets/50979196/8f7516a5-759c-48e9-856c-70cbbd357bdf)


https://github.com/hackthebox/cyber-apocalypse-2024/tree/main/forensics/%5BInsane%5D%20Oblique%20Final


## Crash dumps

Sometimes the memory of a single program is dumped.

<img width="1431" height="98" alt="image" src="https://github.com/user-attachments/assets/a678aedc-5f4d-4056-9732-0d188b91cfc7" />

Sometimes can use volatility like on a regular memory dump. Other times must use WinDbg.


```
.symfix
.reload /f
!analyze -v
.bugcheck
kv
```
