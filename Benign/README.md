# Benign - TryHackMe Challange

## Summary
An IDS raised an alert about a potentially malicious activity from one host belonging to the HR department. The network is divided into three logical segments with the following users:

**IT Department**
- James
- Moin
- Katrina

**HR Department**
- Haroon
- Chris
- Diana

**Marketing Department**
- Bell
- Amelia
- Deepak

Due to limit resourcer, we only have process execution logs with **Event ID: 4688**. Our goal is to discover the malicious activity and find artifacts that help us to understand the threat better.

## Objectives
- Use Splunk to investigate an alert.
- Review logs for evidence of malicious activity.

## Tools used
- Splunk

## Metodology

Once the Splunk instance was loaded, I reviewed the index where the logs were ingested: `index="win_eventlogs"`, and I found 13,959 events, but these events belong to the entire company.

![Dashboard](/Benign/Images/InitialDashboard.png)

Following the challange, I filtered and organized a table to list all the users and the total number of events done by each user using the following query:  
`index="win_eventlogs" | stats count by UserName | table UserName count`

![Users](/Benign/Images/Users.png)

As we can see in the screenshot above, there are two more users than expected in the comapny, one is the user "SYSTEM", and the other one is "Amel1a". The first onw seems to be a legitimate user who performs the activities on the hosts, but the second one is an account that mimics the legitimate user "Amelia", changing the letter "i" to the number "1". This behaviuor is a clear example of persistence. Also, in the count column, we can notice that this user has created a new process. Let's see what he did.  
Filtering the index by the user name "Amel1a", and showing in a table the time, user name, process name, and command line with the following query:  
`index="win_eventlogs" UserName="Amel1a" | table _time UserName ProcessName CommandLine`

![Amel1a](/Benign/Images/Amel1a.png)

In the screenshot, we can see that Amel1a has executed a common recognition comman, "whoami" in USERS/GROUPS, which means that the attacker is looking for their permissions.

Going back to the investigation, the alert showed that a host in HR has executed a scheduled task. With this, I could create a query that excludes users from other areas and looks for scheduled tasks:

`index="win_eventlogs" schtasks AND (UserName="Chris.fort" OR UserName="Haroon" OR UserName="Diana") | table _time UserName ProcessName CommandLine`

![Tasks](/Benign/Images/ScheduledTasks.png)

In the screenshot, we can see that there is only one match; Chris' host is responsible for executing the scheduled task. Looking at the command line, we can notice that the program was executed in the "Temp" folder, which is a common directory to execute processes and tries to leave no traces. Another important thing to highlight is the name of the program, which is **"update.exe"**; it is a clear example of **masquerading** as a legitimate process of the system.

The next thing to investigate in the challenge is a possible Living of the Land technique to download a possible malicious program. Keeping this in mind, I designed a query that searches for the "certutil.exe", which is a program commonly used by attackers to download malicious payloads, and, as in the previous query, it was limited to the HR's users.

`index="win_eventlogs" certutil.exe AND (UserName="Chris.fort" OR UserName="Haroon" OR UserName="Daina") | table _time UserName ProcessName CommandLine`

![certutil](/Benign/Images/LOLBIN.png)

There is only one match, that belongs to Haroon; the command line shows that the attacker has accessed https[://]controlc[.]com[/]e4d11035 and saved the file with the name **"benign.exe"**.

To finish the investigation, I accessed the URL to see the content of the file, which is a text file containing something similar to a code or a flag.

![Flag](/Benign/Images/Flag.png)

## Findings

- There is an account not recognized.
- There are at least two hosts in the HR department with suspicious activity.
- The scheduled task seems to be a masquerading malware.
- The attacker used a LoL technique to download more payloads.

## Analysis
The extra account is an exercise of persistence; meanwhile, the behaviour of Chris and Haroon's hosts shows that the attacker has access to the tools of the system and executed more persistence techniques, and can download more payloads. It is recommended to review logs looking for possible privilege escalations of the user "Amel1a", at the same time isolate the compromised hosts and look for traces of lateral movement.
