from scapy.all import sniff, IP, TCP, Raw
import re
import time

# 定义过滤条件，只捕获 HTTP 和 HTTPS 流量
# HTTP 通常在 80 端口，HTTPS 在 443 端口
FILTER = "tcp port 80 or tcp port 443"

def extract_http_info(packet):
    """ 从数据包中提取HTTP请求的URL和其他信息 """
    if packet.haslayer(Raw):  # 检查是否有原始数据负载
        payload = packet[Raw].load.decode(errors='ignore')

        # 使用正则表达式查找HTTP请求的URL
        request_line = re.search(r'(?P<method>GET|POST|HEAD|PUT|DELETE|OPTIONS|PATCH) (?P<url>\S+) HTTP', payload)
        if request_line:
            method = request_line.group("method")
            url = request_line.group("url")
            timestamp = time.strftime("%Y-%m-%d %H:%M:%S", time.localtime())

            # 获取源 IP 和目的 IP 地址
            src_ip = packet[IP].src
            dst_ip = packet[IP].dst
            src_port = packet[TCP].sport
            dst_port = packet[TCP].dport

            # 打印并记录请求信息
            print(f"Time: {timestamp}, Method: {method}, URL: {url}, "
                  f"Source IP: {src_ip}, Source Port: {src_port}, "
                  f"Destination IP: {dst_ip}, Destination Port: {dst_port}")

            # 将数据写入日志文件
            with open("network_log_2.txt", "a") as logfile:
                logfile.write(f"Time: {timestamp}, Method: {method}, URL: {url}, "
                              f"Source IP: {src_ip}, Source Port: {src_port}, "
                              f"Destination IP: {dst_ip}, Destination Port: {dst_port}\n")

# 监听并捕获数据包
def start_sniffing():
    sniff(filter=FILTER, prn=extract_http_info, store=0)

if __name__ == "__main__":
    print("Starting HTTP packet capture...")
    start_sniffing()