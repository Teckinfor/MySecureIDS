# MySecureIDS - msids
## Description
IDS based on kernel Linux.\
Project carried out as part of the development lesson in computer systems security studies.\
The IDS should listen for network traffic and warn if a packet is suspicious by adding an entry in the syslog.
```
Created by WALLEMME Maxime & SENECHAL Julien
aka maxWLM & Teckinfor
```
## Prerequisite
> apt-get install libpcap-dev

## Compile command
> gcc main.c populate.c rules.c protocol.c -o msids -lpcap -Wall

## What's included
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

## How ids.rules works
You can choose another file than ids.rules, but the rules have to be written in the same way.\
There are 2 actions possible with msids : alert & save
### Example :
> **alert [protocol] [IP SOURCE] [PORT SOURCE] -> [IP DESTINATION] [PORT DESTINATION] (msg:"This is the message for the rule";content:"content in the payload";)**\
> **save [protocol] [IP SOURCE] [PORT SOURCE] -> [IP DESTINATION] [PORT DESTINATION] ()**\
> **save [protocol] [IP SOURCE] [PORT SOURCE] -> [IP DESTINATION] [PORT DESTINATION] (file:"/home/user/msids/example";)**\
