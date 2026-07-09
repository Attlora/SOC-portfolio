# Boogeyman 1 - TryHackMe Challange

## Summary
The finance department has been faced with a phishing attack, and an employee has opened the malicious attachment, which claims to be an invoice, and unbeknownst to her, compromised her workstation. An emergent threat group named "Boogeyman" uses the same TTPs seen in this attack, and they are known for targeting the logistics sector.
This challenge aims to identify the threat group's TTPs and evaluate the impact of this attack.

## Objectives
- Review an email sample to detect a phishing campaign.
- Examine PCAP files to detect anomalous connections.
- Analyse artifacts to identify TTPs.
- Recover the information exfiltrated to know the impact of the attack.

## Tools used
- Thunderbird
- Linux terminal
- Wireshark
- TShark
- CyberChef
- KeePass

## Metodology
On the desktop of the provided VM, there are theartefacts neede to initiate the investigation: a copy of the email, logs from the compromised machine, and a network capture file.

![Artefacts](/Boogeyman%201/Images/Artefacts.png)

Looking at the email, we can see the email addresses of the sender and recipient; the email body consists of a reminder of payment, and the threat actor tricks the employee into reviewing the content of the attachment, and can deploy the malware. Another relevant aspect is that the text says that the attached document is encrypted and needs a code to decrypt it.

![EmailHeaders](/Boogeyman%201/Images/Email.png)

![Signatures](/Boogeyman%201/Images/Signatures.png)

In the screenshot above, we can see that the email passed the validations of SPF and DKIM signatures, using a third-party relay service named "elasticmail". 

![Attachment](/Boogeyman%201/Images/Attachment.png)
![Invoice](/Boogeyman%201/Images/Invoice.png)

After saving the attachement, it is necessary to use the password to unzip the file; then we get a new document named `Invoice_20230103.lnk`, which we can open using the lnkparse tool. In this document, we can see the malicious payload that opens PowerShell to execute a Base64-encrypted command, which we can decode using the base64 command to see what it does.

![EPayload](/Boogeyman%201/Images/EncodedPayload.png)

The screenshot below shows the command found in the invoice, and this command creates a connection to download a new payload named "update".

![DPayload](/Boogeyman%201/Images/DecodedPayload.png)

Now moving to the endpoint logs, I look for more connections made by the attakcer. To achieve this, I used the jq command, which helps to show the JSON logs in a pretty way. In this part, the challenge asks for domains that the attacker uses for file hosting and C2; when I open the lnk document, the encoded command uses the command `iex` to create new connections, so I used the command `grep iex` to look for more connections, and I found three matches, the first belongs to GitHub, a well known service, so it does not belong to the threat group, the next two have the same domain bpakcaging[.]xyz, but different subdomains:

- files[.]bpakcaging.xyz is used for file hosting.
- The log shows that the host made POST requests to cdn[.]bpakcaging[.]xyz, so it is the C2 domain.

![FileHosting](/Boogeyman%201/Images/FileHosting.png)

After perfoming a search, I found the GitHub repository of Seatbelt, found in the first match of the past exercise, which is a tool to "mine interesting data about the system". So, it can be used to avoid an enumeration technique.

![Seatbelt](/Boogeyman%201/Images/Tool.png)

Once the tool is identified, it is necessary to look for the activity to know what the actions of the threat group were.  
Looking in the logs for executables, I found many commands: `sb.exe` was downloaded from the file hosting and was executed many timees. But there is a new file named `sq3.exe`, which was used on a database named `plum.sqlite` to execute a query.

![Executables](/Boogeyman%201/Images/Executables.png)

Continuing in the log analysis, I found that Boogeyman was able to access the `protected_data.kdbx` document from the `j.westcott` user; after that, they encrypted the document using hexadecimal encryption, and `.bpakcaging.xyz` was added at the end of each line. Once prepared, the information was sent to the IP address 167[.]71[.]211[.]113 using `nslookup`.

![Hex](/Boogeyman%201/Images/EncryptationMethod.png)

To finish the investigation, I opened the PCAP file with Wireshark and filtered to visualize only the packets sent to the IP address previously identified. I found some HTTP requests, but also a lot of DNS requests, which matches the behaviour of `nslookup`, and the length of these DNS requests is too long, confirming the use of the DNS tunneling technique to exfiltrate the file.

![DNS](/Boogeyman%201/Images/DNSTunneling.png)

Also, in the screenshot above, in the info field of each DNS query with a length greater than 100, we can see information in hexadecimal format.  
Opening a packet, an HTTP request in this case, I found the software that the attacker used to host the server, which is Python, as shown in the screenshot below.

![Python](/Boogeyman%201/Images/C2.png)

An important thing to look for is the response of the query executed by the attacker on the database. To do this, I filtered the PCAP to look for packets that contain "sq3", and I got five matches, and only one of them seems to be the command executed. Opening it to get more information, we can see the full query sent to the database.

![sq3](/Boogeyman%201/Images/WS-sq3.png)
![Query](/Boogeyman%201/Images/DBQuery.png)

The inspected packet is the 749 in the TCP stream, so to know the response, I looked for the 750.

![DBExfiltrated](/Boogeyman%201/Images/DBExfiltrated.png)

This packet contains a lot of pairs of numbers and looks like a decimal encryption, so I copied it into CyberChef to try to decrypt the content. The message decrypted shows an exfiltrated password.

![CyberChef](/Boogeyman%201/Images/ExfiltratedPassword.png)

The last part of the challenge asks to recover the exfiltrated file to know its content. To achive this, the challenge suggest using TShark to process the PCAP.  
This part of the challange was the most difficult because it is necessary to take small pieces of each activity and use many tools. The first one was remembering that the attacker used nslookup to exfiltrate the file, and the PCAP examined in Wireshark shows DNS tunneling, so I opened and filtered the PCAP to get only the DNS requests.

`tshark -r capture.pcapng -Y 'dns.qry.type==1'`

![TShark](/Boogeyman%201/Images/TShark.png)

The screenshot above shows the result of all DNS A requests. As we can see, there are many results with complete information about each packet. To remove the unnecesary fields of each packet, it is necessary to remember some important aspects:
- In Wireshark, we see the hexadecimal content in the query name.
- The command found in the logs added the termination "bpakcaging.xyz" at the end of the encypted string.

``tshark -r capture.pcapng -Y 'dns.qry.type==1 -T fields -e 'dns.qry.name' | grep bpakcaging.xyz | grep -v -E "files|cdn | cut -f1 -d '.' | uniq | tr -d '\n'"``

- The first part of the command above opens the PCAP, filters the packets to get only DNS queries, and shows only the query name field.
- With `gerp bpakcaging.xyz`, I looked only for the encrypted strings that the attacker prepared to exfiltrate.
- The query showed additinal results beyond the expected, so using grep with `-v` and `-E` flags, I removed those additional results.
- As we know, the attacker added additional characters at the end of the encrypted part, I used `cut -f1 -d '.'` to get the first field, stopping it at the first dot.
- There could be some duplicate packets due to retransmissions, so with `uniq` I remove them.
- Lastly, the packets were separated with a line break, so to get the entire file, I deleted them using `tr -d '\n'`.

With the command explained above, I got the result shown in the screenshot below, that is, the entire encrypted file exfiltrated in DNS queries.

![EncryptedFile](/Boogeyman%201/Images/EncryptedFile.png)

Knowing that the file was hexadecimal encrypted, I used the tool ``xxd`` to decrypt it. The result previously shown was processed and saved in a file named "protected_data.kdbx", the same name as the original file.

![File](/Boogeyman%201/Images/DNSQueries.png)

Opening the recovered file with KeePass and using the exfiltrated password found with Wireshark, we can see the content of the file exfiltrated by Boogeyman.

![RFile](/Boogeyman%201/Images/RecoveredFile.png)
![EFile](/Boogeyman%201/Images/ExfiltratedFile.png)

## Findings
- An employee has downloaded and opened a malicious attachement from an email that compromised her workstation.
- The malicious attachment created connections with file hosting site and C2 to download more payload.
- The attacker found and exfiltrated sensitive information and files.

## Analysis
The Boogeyman group access through a phishing campaing that unfolded a complex exfiltration operation, and they got sensitive financial information. They used a DNS tunneling technique to exfiltrate a file previously encrypted using hexadecimal encryption; it is necessary to check if the company has an IDS/IPS solution that can help to detect this type of behaviour. Early detection is key to stopping future exfiltrations.
