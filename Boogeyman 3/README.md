# Boogeyman 3 - TryHackMe Challange

## Summary
The Boogeyman group has returned and is now pointing at a higher target. They have created a new phishing email and sent it to the CEO. Evan Hutchinson, the company's CEO, opened the attachment and, seeing that nothing happened, he reported the incident to the security team to initiate an investigation.

## Objectives
- Discovery the new TTPs of the threat group.
- Examine logs using a SIEM platform.
- Apply the knowledge acquired in the SOC L1 path.

## Tools used
- Elastic
- Sysmon

## Metodology
To achive this investigation, I had to use Elastic to analyze logs from various endpoints in the company; it was also presumed that the incident ocurred between August 29 and August 30, 2023.

![InitialDashboard](/Boogeyman%203/Images/InitialDashboard.png)

With this data, I could adjust the time range and filter the logs utilizing Sysmon's ID, especially ID 1 for process creation and those generated on the CEO's workstation.  
Once got the results, I organized the information to shown only the user name, process command, PID, parent process command and PPID. As shown in the image below, we can see the process executed by the CEO, and it is a file with a double extension; abusing that Windows usually does not show the real extension of the file, it pretended to be a PDF file.

![FirstQuery](/Boogeyman%203/Images/FirstQuery.png)

The stage 1 payload attempted to implant a file in another location. To uncover the command used to achive this, I followed a process tree. Taking the PID of the file executed on the CEO's workstation, I looked for its chil processes.

![Second](/Boogeyman%203/Images/Second.png)

Following the process tree, I found that the attacker executed the previous file as a second part of its attack.

![Execute](/Boogeyman%203/Images/Execute.png)

As another part of the first phase, it seems that the attacker created a scheduled task as a persistent mechanism. To find this action, I filtered using the keyword ``Schedule`` and wildcards to search for any coincidence, and I got a single match.

![Schedule](/Boogeyman%203/Images/Scheduled.png)

The next question asks for any connection that the malware could establish as part of a possible C2, and to find this, I modified the query to look for process ID 3, and I got some results that communicate with a single IP and port, as shown in the image below.

![C2](/Boogeyman%203/Images/C2Connection.png)

The next question was difficult for me. I had to look for common UAC bypass techniques and search through logs to find the answer; it took me a lot of time. After checking logs, I found a flow where the attacker executed a series of discovery commands followed by an executable named ``fodhelper``. I searched for this and found that this is a  commonly exploited tool to bypass UAC, so that was the answer.

![UAC](/Boogeyman%203/Images/UAC.png)

Once Boogeyman had enough permissions, they downloaded a tool for credential dumping, and to find the event, I filtered the logs to look for ID 1 and used the key word ``iwr``, a common comand used to invoke HTTP requests.  
The results show that the threat group has downloaded a tool names ``mimikatz``.

![DMimikatz](/Boogeyman%203/Images/DownloadMimikatz.png)

![Mimikatz](/Boogeyman%203/Images/Mimikatz.png)

With the new tool on the host, the threat actor used it to dump credentials inside the machine and could access other workstations. The first compromised account was ``itadmin``.

![itadmin](/Boogeyman%203/Images/itadmin.png)

Using the new credentials, the attacker attempted to enumerate accessible file shares. In the following image, it is possible to see the flow followed by the attacker through the files until reach the file ``IT_Automation.ps1``.

![RemoteShare](/Boogeyman%203/Images/RemoteShare.png)

After getting the contents of the remote file, the attacker used the new credentials to move laterally. By looking a the logs, I found the new set of credentials used to achive this. Allan Smith is our new compromised user on the WKSTN-1327 workstation.

![AllanSmith](/Boogeyman%203/Images/allan.smith.png)

Now, knowing that the attacker can move laterally, I changed the query to look for logs that show process creation on Allan's workstation. I found a couple of commands; the first one is the sencond's parent process, which is the discovery command ``whoami``.

![SecondMachine](/Boogeyman%203/Images/SecondMachine.png)

After executing more discovery commands, the attacker downloaded the ``mimikatz`` tool again. Using this tool, Boogeyman was able to get more credentials; this time was ``Administrator`` user.

![Administrator](/Boogeyman%203/Images/administrator.png)

Modifying the query to look for administrator logs, I found a similar behaviour at Allan Smith's workstation; the attacker executed a couple of discovery commands, downloaded the Mimikatz tool and extracted a new account.

![backupda](/Boogeyman%203/Images/backupda.png)

To finish the investigation, I had to look for more possible downloads and try to uncover if there was anthing unusual. To achive this, I created a query that looks for process ID 1 and the keyword ``iwr``, which is a common command to invoke HTTP requests. Besides the mimikatz tool, I found a URL that downloads a file called ``ransomboogey``. The name of this file is very suggestive. It is a ransomware.

![Ransomware](/Boogeyman%203/Images/Ransomware.png)

## Findings
- Boogeyman used whale phishing to compromise the CEO's workstation.
- The attachment executed processes in the background to keep stealth.
- The attacker executed credential harvesting to achive lateral movement.
- The attacker downloaded ransomware.

## MITRE ATT&CK
- T1566.001: Spearphishing attachment

## Analysis
Finishing the three challanges of Boogeyman, I can tell that the principal TTP used for this threat group as initial access is phishing. The logs found show that the attacker downloaded and executed ransomware after moving laterally and enumerating files on different workstations. It is necessary to isolate the compromised host and initiate an incident responce procedure.
