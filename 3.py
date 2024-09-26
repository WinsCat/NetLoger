from scapy.all import *
from datetime import datetime
import re


# 处理捕获的数据包
def packet_callback(packet):
    if IP in packet:
        ip_src = packet[IP].src
        ip_dst = packet[IP].dst
        src_port = packet[TCP].sport
        dst_port = packet[TCP].dport


        timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")

        # HTTP 流量处理（TCP 80端口）
        if TCP in packet and packet[TCP].dport == 80:  # 80端口是HTTP
            if Raw in packet:  # 判断数据包是否包含负载
                try:
                    http_payload = packet[Raw].load.decode('utf-8')
                    # 提取HTTP请求头中的URL
                    request = http_payload.split("\r\n")[0]
                    url = re.search(r'(?i)(GET|POST) (.*?) HTTP', request)
                    # method = url.group("method")
                    if url:
                        print(f"[{timestamp}] HTTP Source IP: {ip_src} Source Port: {src_port}, Destination IP: {ip_dst} URL: {url.group(2)} Destination Port: {dst_port}")
                        # 将数据写入日志文件
                        with open("network_log_3.txt", "a") as logfile:
                            logfile.write(f"Time: {timestamp}, URL: {url.group(2)}, "
                                          f"Source IP: {ip_src}, Source Port: {src_port}, "
                                          f"Destination IP: {ip_dst}, Destination Port: {dst_port}\n")
                except:
                    pass

        # HTTPS 流量处理（TCP 443端口）
        elif TCP in packet and (packet[TCP].dport == 443 or packet[TCP].sport == 443):
            if Raw in packet:
                payload = packet[Raw].load
                # 检查是否为TLS客户端Hello消息，并尝试解析SNI
                if payload[0] == 0x16:  # TLS Content Type = 0x16 (Handshake)
                    try:
                        # 找到SNI的起始位置
                        sni_start = payload.find(b'\x00\x00') + 5
                        sni_length = payload[sni_start - 2:sni_start]
                        sni_length = int.from_bytes(sni_length, 'big')
                        sni = payload[sni_start:sni_start + sni_length].decode()

                        print(f"[{timestamp}] HTTPS Source IP: {ip_src} Source Port: {src_port}, Destination IP: {ip_dst} SNI/Domain: {sni} Destination Port: {dst_port}")
                        # 将数据写入日志文件
                        with open("network_log_3.txt", "a") as logfile:
                            logfile.write(f"Time: {timestamp}, URL: {sni}, "
                                          f"Source IP: {ip_src}, Source Port: {src_port}, "
                                          f"Destination IP: {ip_dst}, Destination Port: {dst_port}\n")
                    except:
                        pass


# 开始捕获数据包，捕获 HTTP 和 HTTPS 流量
sniff(prn=packet_callback, filter="tcp port 80 or tcp port 443", store=0)