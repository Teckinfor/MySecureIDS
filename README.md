# MySecureIDS - msids
IDS based on kernel Linux.\
Project carried out as part of the development lesson in computer systems security studies.\
The IDS should listen for network traffic and warn if a packet is suspicious by adding an entry in the syslog.
```
Created by WALLEMME Maxime & SENECHAL Julien
aka maxWLM & Teckinfor
```
##Prerequisite
> apt-get install libpcap-dev

##Compile command
> gcc main.c populate.c rules.c protocol.c -o msids -lpcap -Wall

##What's included
- [x] TCP
- [x] UDP
- [x] HTTP
- [x] HTTPS
- [ ] FTP 
- [x] Save all frames that match the rules
- [x] Alert on syslog all frames that match the rules
- [x] -help
- [x] Option to display all frames
- [x] Option to show HTTP's data
- [x] Option for the direction file ids.rules
- [x] Option to print all alert
- [x] Option for the interface
- [x] Option the number of frames (number of "loop")
