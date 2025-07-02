<-----------------------------------------<NETWORK PACKET SNIFFER (SCAPY-BASED)/>--------------------------------------------->
This is a CodeAlpha project created as part of a fulfilment their internship program.

The project is a lightweight Python packet sniffer that captures and logs TCP and UDP traffic on your local network using Scapy. 
It has been customised to filters out your own device's traffic to enable reading of packets in the same network as your device, logs raw payloads, and stores sniffed packets in a file.

---

FEATURES
- Automatically detects and excludes your IP address
- Captures TCP, UDP, and Other packets
- Logs packet metadata (IP, ports, protocol) and raw payload (where an attempt is made to decode it)
- Saves logs to a file with a timestamp
- Multiplatform support (Linux, Windows, macOS)

---

REQUIREMENT TO RUN
- Python 3.6+
- scapy
