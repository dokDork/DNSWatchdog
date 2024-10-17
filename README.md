# DNSWatchdog
[![License](https://img.shields.io/badge/license-MIT-_red.svg)](https://opensource.org/licenses/MIT)  
<img src="https://raw.githubusercontent.com/dokDork/DNSWatchdog/refs/heads/main/images/DNSWatchguard.jpg" width="250" height="250">  

## Description
**DNSWatchdog** analyzes TCP and UDP packets that have been captured by a wireshark session during a DNS spoofing attack. This allows us to understand which hostnames our target is trying to connect to and which are the target ports. This is the first step to then be able to sniff the traffic between our target and its destination.

## Example Usage
 ```
python analyze-dns-pcap.py my.pcap 192.168.1.133
 ``` 
<img src="https://raw.githubusercontent.com/dokDork/DNSWatchdog/refs/heads/main/images/01.jpg" width="250" height="250">  
and this is a possible result:
<img src="https://raw.githubusercontent.com/dokDork/DNSWatchdog/refs/heads/main/images/02.jpg" width="250" height="250">  

## Command-line parameters
```
python analyze-dns-pcap.py <pcap file> <target IP>
```

| Parameter | Description                          | Example       |
|-----------|--------------------------------------|---------------|
| `pcap file`      | pcap file from wireshark during a DNS spoof session on Target IP | `my.pcap`, `mypcapng`, ... |
| `target IP`      | IP you are trying to analyze to understand which hostname and port it is connecting to  | `http://www.example.com`          |

  
## How to install it on Kali Linux (or Debian distribution)
It's very simple  
```
cd /opt
```
```
pip install pyshark
```
```
git clone https://github.com/dokDork/DNSWatchdog.git
```
