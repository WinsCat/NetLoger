from scapy.all import sniff
from scapy.layers.inet import TCP, IP
import time

def packet_callback(packet):
    if packet.haslayer(IP) and packet.haslayer(TCP):
        ip_src = packet[IP].src
        ip_dst = packet[IP].dst
        port_src = packet[TCP].sport
        port_dst = packet[TCP].dport
        timestamp = time.strftime("%Y-%m-%d %H:%M:%S", time.localtime())

        print(f"Time: {timestamp}, Source IP: {ip_src}, Source Port: {port_src}, "
              f"Destination IP: {ip_dst}, Destination Port: {port_dst}")


# 监听80和443端口（HTTP和HTTPS）
sniff(filter="tcp port 80 or tcp port 443", prn=packet_callback, store=0)