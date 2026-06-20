# Shadow Trace - TryHackMe Challange

## Summary
A suspicious program was found at the same time the EDR flagged two new critical alerts. As a SOC analyst, we have to conduct research to find the origin of the software and determine its possible impact.

## Objectives
- Anlyze a suspicious program.
- Find IOCs.
- Correlate alerts with suspicious activity.
- Perform basic SOC triage.

## Tools used
- PEStudio
- CyberChef
- VirusTotal

## Metodology
### PART 1 - Static Analysis
The software was placed on the desktop to facilitate the analysis. The first red flag I noticed was the name: **"windows-update.exe"**, which is an attempt to masquerade the malware as a legitimate native process named: **"WindowsUpdate.exe"**. This action can avoid some visual detection while looking legitimate to an employee.

![MalwareProperties](/Shadow%20Trace/Images/MalwareProperties.png)

After checking the program's properties, I decided to conduct a static analysis to get more information about it before I decided to try a dynamic analysis. To achive this, I used **PEStudio**, which can extract a program's information like hash, signatures, entropy, human-redable strings and others.

![PEStudioProperties](/Shadow%20Trace/Images/PEStudioIndicators.png)

In the image above, we can observe the SHA256 and MD5 hashes; there's also a high entropy, a URL that seems to download a second program. In another seccion, we can notice that the program creates processes, looks and deletes files, and others. These behavious match a data stealer and ransomware.

Finally, looking at strings, I found some words that confirm the program starts a connection with tryhatme[.]com to download more payloads, execute them automatically, and then deletes the files, trying not to leave artifacts and stay stealth.

![PEStudioStrings](/Shadow%20Trace/Images/PEStudioStrings.png)

### PART 2 - Alerts

Once I finished the static analysis, I looked at the alerts, which listed a program execution in PoweShell and a download from the browser. The alerts show two encoded strings, so I used CyberChef in order to decode both strings and get a better overview. The first one seems to be a Base64 encoded, while the second one has many decimal numbers.

![ShadowTraceAlerts](/Shadow%20Trace/Images/ShadowTraceAlerts.png)

![FromBase64](/Shadow%20Trace/Images/FromBase64.png)

The image above shows the result after decoding the Base64 alert, which is a URL pointing again to tryhatme[.]com and seems to download a program. The image below shows the result of decimal decoding, which points to a subdomain that also belongs to tryhatme[.]com.

![FromDecimal](/Shadow%20Trace/Images/FromDecimal.png)

To finish the investigation, I searched for the SHA256 hash in VirusTotal, where I found that 45/71 vendors flagged the initial program as malicious, confirming the threat.

![VirusTotal](/Shadow%20Trace/Images/VTShadowTrace.png)

## Findings
- The malware is masquerading as a legitimate program.
- The program has a high entropy.
- The program connects a website to download more programs.
- The program creates processes, searches, and deletes files to avoid leaving traces.
- The malware doesn´t use techniques to avoid static analysis, like obfuscation or packing.
- The alerts show encoded strings that can be easily decoded with tools like CyberChef.
- VirusTotal has flagged the attachement as malicious

## MITRE ATT&CK
- T1059.001: Command and scripting interpreter - PowerShell.
- T1204.002: User execution - Malicious file.
- T1070.004: Indicator removal - File deletion.
- T1036.004: Masquerading - Masquerade task or service.
- T1083: File and directory discovery.

## Analysis
The program seems to be a data stealer or probably a ransomware. The static analysis was enough to get information about the behaviour, so dynamic analysis is not necessary.  
The host was compromised when the malware was executed. As shown by the alerts, the program starts to download more payloads and starts a discovery on the device. This behaviour could mean the attack is in the phase of explotation, accordint to the cyber kill chain framework.  
It is recommended to isolate the affected host and start an incident response procedure.
