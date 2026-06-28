# ItsyBitsy - TryHackMe Challange

## Summary
A SOC member found an alert from an IDS showing a potential C2 connection from a device in the HR department. This connection has downloaded a file, and we only have the connection logs from the user's host from a week ago.  
Our goal is to discover the server that the host has connected to and identify the downloaded file.

## Objectives
- Get familiarized with Kibana stack.
- Look for suspicious activity by reviewing network connections in a SIEM solution.

## Tools used
- Kibana

## Metodology
In the discovery panel of Kibana, I had 1,482 hits; there were a lot of web requests to many domains in different destination IP addresses. I filtered by status code 200 to try to delete possible noise, but all of the requests were successful, so it didn't work very well.

![InitialDashboard](/ItsyBitsy/Images/InitialDashboard.png)

When I look for the source IP address, I noticed that it only shows a unique IP in 500 records, so I decided to expand all the possible addresses, and I found there was a second IP address `(192[.]166[.]65[.]54)` responsible for only two connections. It was a very discreet connection.

![SourceIP](/ItsyBitsy/Images/SourceIP.png)

Looking at the method request, I noticed that one request was a HEAD method, and the second was a GET method, so in essence, both belong to the same request.

![HTTPRequests](/ItsyBitsy/Images/HTTPRequests.png)

Accesing the URL found in Kibana `pastebin[.]com/yTg0Ah6a`, I found the original file downloaded and its content, confirming that the HR endpoint has communicated with an external server to download a payload that could be potentially malicious.

![File](/ItsyBitsy/Images/SuspiciousFile.png)

## Findings
- A suspicious connection from the HR department was found.
- The C2 channel was able to download a file from the Internet.

## Analysis
The IDS flagged a malicious activity correctly as belonging to a C2 channel, downloading a suspicious file. This action could be the first phase of an attack, where a threat actor is testing their capabilities to download a payload to the host target host to pass to the next phase, and take action on their objectives.
