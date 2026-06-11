# The Greenholt Phish - TryHackMe Challange

## Summary
An employee has notified to SOC team about a suspicious email recieved from a customer. The email contains many inconsitences that should be analyzed.

## Objectives
- Analyze the suspicious email.
- Determine if the email is legitimate.

## Tools used
- Thunderbird
- VirusTotal
- sha256sum

## Metodology
At firts glance, the sender pretend to be Mr. James Jackson, who is using a legitimate email address (the employee can confirm that the customer uses the same address). The subject claims to be a funds transfer, incluiding a reference number.
![Email's header](/The%20Greenholt%20Phish/images/Header.png "Email's header")  

Looking at the email body, I found a greeting which uses the email address of the recepient, instead the employee's name. Also, there is an attachement that pretends to be a payment receip in PDF format, but looking closer, the file has a doble extension, beeing .CAB (Cabinet) the second one; the .CAB extension means that the attachement, could be a malicious file. The rest of the body contains some details about the transfer.  
![Gretting](/The%20Greenholt%20Phish/images/Gretting.png "Generic gretting")  
![Attachment](/The%20Greenholt%20Phish/images/Attachment.png "Suspicious attachment")  

Analyzing the message source, I found that the email failed the Sender Policy Framework (SPF), meaning the attacker is using a spoofed email address. I also found that Domain-Based Message Authentication, Reporting and Conformance (DMARC) validation could not be confirmed.  
![Validation](/The%20Greenholt%20Phish/images/Validations.png "Validations failed")  

Downloanding the attachement in the Virtual Machine provided by TryHackMe, I got the sha256 hash of the file for further investigation.  
Using VirusTotal, I searched for the sha256 hash of the file and found that 49/62 vendors have flagged this file as malicious.  
![VirusTotal](/The%20Greenholt%20Phish/images/VirusTotal.png "VirusTotal report")  

## Findings
- The email sender has been spoofed
- The file attached has a double extension: PDF and CAB
- SPF validation failed
- DMARC authentication could not be confirmed
- VirusTotal has flagged the attachement as malicious

## MITRE ATT&CK
- T1566.001: Spearphishing attachment

## Analysis
Based on the email header analysis, attachment inspection and VirusTotal results, the email was identified as a phishing email that contains a malicious attachment. The attacker attempted to impersonate a legitimate customer by spoofing the sender's email address and used a file with a double extension to deceive the employee.
