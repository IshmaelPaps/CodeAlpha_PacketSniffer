from scapy.all import sniff, IP, TCP, UDP
from datetime import datetime
import socket
import re

#------------------<Create the log file>--------------------

LOG_FILE = "Sniffed Packet.txt"  # Output file for logs

#-------------------<Create the log file/>--------------------


#------------------<This automatically gets your local IP address>--------------------
def get_IP():
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        s.connect(("8.8.8.8", 80))
        My_IP = s.getsockname()[0]
        s.close()
        return My_IP
    
    except Exception as exp:
        print(f"Could not get your local IP: {exp}")
        return None

whisper = get_IP()
#------------------<This automatically gets your local IP address/>--------------------


#------------------<Packet Sniffer Function>--------------------
def P_sniffer(pakt):
    info = {}
    if IP in pakt:
        info['src_ip'] = pakt[IP].src
        info['dst_ip'] = pakt[IP].dst
        info['proto'] = pakt[IP].proto

#---------------------<Your IP Address Check>-----------
    if info.get('src_ip') == whisper or info.get('dst_ip') == whisper: 
        return
#------------------<Your IP Address Check/>--------------------
# useful for catching other packets than 
# yours (broadcast, multicast, etc.)


#-------------------<Check type of protocol (TCP/UDP/Other)--------------------
    if TCP in pakt:
        info['layer'] = 'TCP Packet'
        info['src_port'] = pakt[TCP].sport
        info['dst_port'] = pakt[TCP].dport
    elif UDP in pakt:
        info['layer'] = 'UDP Packet'
        info['src_port'] = pakt[UDP].sport
        info['dst_port'] = pakt[UDP].dport
    else:
        info['layer'] = 'Other Packet'
#--------------------<Check type of protocol (TCP/UDP/Other)/>--------------------


#--------------------<Print & Store Sniffed Packet information>------------------------
    timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S") # Catch timestamp of sniff

    if TCP in pakt and pakt[TCP].dport:
        pakt_content = bytes(pakt[TCP].payload)

        try:
            prwn_pakt_content = pakt_content.decode("utf-8", errors="replace")
        except:
            prwn_pakt_content = str(pakt_content)
        
        sniffed = (
            f"------------------------------------<PACKET INFO>-----------------------------\n"
            f"PACKET INFO: {timestamp} {info['layer']} | {info.get('src_ip')}:{info.get('src_port')} => "
            f"{info.get('dst_ip')}:{info.get('dst_port')} | proto={info['proto']}\n\n"
            f"PACKET CONTENT: {pakt_content}\n\n"
            f"PRAWNED PACKET CONTENT: {prwn_pakt_content}\n\n\n")
        
                
    elif UDP in pakt and pakt[UDP].dport:
        pakt_content = bytes(pakt[UDP].payload)

        try:
            prwn_pakt_content = pakt_content.decode("utf-8", errors="replace")
        except:
            prwn_pakt_content = str(pakt_content)

        sniffed = (
            f"------------------------------------<PACKET INFO>-----------------------------\n"
            f"PACKET INFO: {timestamp} {info['layer']} | {info.get('src_ip')}:{info.get('src_port')} => "
            f"{info.get('dst_ip')}:{info.get('dst_port')} | proto={info['proto']}\n\n"
            f"PACKET CONTENT: {pakt_content}\n\n"
            f"PRAWNED PACKET CONTENT: {prwn_pakt_content}\n\n\n")
        
        
        # Store in the to log file
        with open(LOG_FILE, "a", encoding="utf-32") as f: 
            f.write(sniffed)


        # Print to terminal | Remove this if you wanna compile into .exe
        print(sniffed)

        
#--------------------<Print Sniffed Packet information/>------------------------
    

sniff(prn=P_sniffer, filter="ip", count=50, iface="Wi-Fi", store=0) 
# Adjust the interface as needed;
# filter="ip" captures all IP packets, UDP and TCP packets will be processed in the callback function.
# count = number of packets to capture, 0 for infinite, 
# store=0 to not store packets in memory
# iface = the network interface to sniff on, e.g., "Wi-Fi", "any", "en0"

#------------------<Packet Sniffer Function/>--------------------