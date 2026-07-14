# Boogeyman 2 - TryHackMe Challange

## Summary
The Boogeyman group has returned, and now with TTPs. The security teams received alerts from the HR department when an employee received an application for an open position in the company; the attachment appears to be more than a resume.

## Objectives
- Discovery the new TTPs of the threat group.
- Examine the artefacts recovered from the compromised workstation.
- Apply the knowledge acquired in the SOC L1.

## Tools used
- Linux CLI
- Olevba
- Volatility

## Metodology
To achive this investigation, we were provided with two artefacts: a copy of the phishing email and a memory dump of the victim's workstation.

![Artefacts](/Boogeyman%202/Images/Artefacts.png)

Opening the email with Evolution, we can see the sender and the recipient email addresses, the subject of the email, and the attached document

![Email](/Boogeyman%202/Images/Email.png)

Afer that, I needed the MD5 hash of the attachment, so I downloaded the file and used the `md5sum` command:

![Hash](/Boogeyman%202/Images/MD5Hash.png)

Additianlly to the challenge, I searched the MD5 hash on VirusTotal to look for any additional information, and I got that the hash was flagged by 39/62 vendors as malicious, which is a red flag by itself.

![VirusTotal](/Boogeyman%202/Images/VirusTotal.png)

Continuing the challenge, it is necessary to investigate the document. To achive this, we can find on the provided VM a Python tool called **olveba**, which "can detect and extract VBA macros from MS Office documents, XML, MHT, and ZIP files".

![Olevba](/Boogeyman%202/Images/Olevba.png)

In the image above, we can find the answers to questions to 5 to 7. The document makes a GET request to a URL and downloads a payload. The command was executed on "C:\ProgramData\", and the downloaded file is saved with the "update.js" name, so the file is located in "C:\ProgramData\update.js". After that, a new object named "wscript.exe" is created and then executes the previously downloaded file.

The answers to to the lasts questions can be found in the memory dump, so to get them, there is the ``Volatility`` tool on the VM. The provided memory comes from a Windows host; hence, it is necessary to use the Windows plugin in Volatility to extract the information.  
The challenge asks for the PID and PPID that executed the second payload, and the plugin `windows.pslist.PsList` can list all processes present in a particular Windows memory image. The result is shown in columns, with the first being the ``PID``, ``PPID``, and ``ImageFileName``. Knowing that the name of the executable of the second payload is ``wscript.exe``, we can see the process and its child processes, as shown in the image below.

![Processes](/Boogeyman%202/Images/Processes.png)

Te URL used to download the malicious binary is the same as shown previously; just changing the extension of the file from ``.png`` to ``.exe``.  
Now, knowing all the processes related to the attack, I looked for all possible connections made, and, to achive this, I used the plugin ``windows.netscan.NetScan`` filtering with the names of the processes. Finally, I got only one match: the updater.exe made some connections to a single IP using a TCP port.

![Connections](/Boogeyman%202/Images/Connections.png)

The next question asks for the full path where the original Word document was executed. To solve this, I used the plugin ``windows.cmdline.CmdLine``, which shows process command line arguments, and I filtered by the name to show only those related to the document.

![Path](/Boogeyman%202/Images/Execution.png)

Finally, it seems that the attacker scheduled a task, and it is necessary to know the complete command used. This question was really difficult for me, even using the hint, which says that I could find the answer by looking for keywords for scheduled tasks, but after trying each plugin and filtering by keyword like ``schtask``, been the most common, I finally found the command directly in the memory dump, and there was the answer:

![Scheduled](/Boogeyman%202/Images/ScheduledTasks.png)

## Findings
- The email took advantage of an open position in the company to send the malware, spoofing an applicant.
- The attacker used macros in a Word document to compromise the host.
- The malware downloaded more payloads form the Internet and executed them automatically.
- A scheduled task was created, probably as a persistence method.

## Analysis
It is necessary to disable the execution of macros in every document, especially if they come from external sources. It is also important to only open documents in safe mode.  
The challange helps me to understand more about the immpact of engineering social and the importance of the recognition phase according tho the Cyber Kill Chain; because of that, the attacker takes advantage of an open position and crafts the email and word to spoof a real applicant.
