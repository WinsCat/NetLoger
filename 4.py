import psutil
import gzip
from cryptography.fernet import Fernet
import requests
import schedule
import time
import pydivert
import win32serviceutil
import win32service
import win32event
import servicemanager
import os
from datetime import datetime


# 捕获网络访问日志 (包括端口和URL)
def capture_network_packets():
    packet_info = []
    # 使用 pydivert 捕获所有 TCP 流量
    with pydivert.WinDivert("tcp.DstPort == 80 or tcp.DstPort == 443") as w:
        for packet in w:
            if packet.tcp:
                # 记录源地址，目的地址，端口等信息
                packet_info.append({
                    'source_ip': packet.src_addr,
                    'destination_ip': packet.dst_addr,
                    'source_port': packet.src_port,
                    'destination_port': packet.dst_port
                })
            # 这里只捕获10个包用于测试，可以根据需要调整数量
            print(packet_info)
            if len(packet_info) >= 10:
                break
    return packet_info


# 获取当前所有连接的网络端口
def get_network_connections():
    connections = psutil.net_connections()
    connection_info = []
    for conn in connections:
        if conn.status == psutil.CONN_ESTABLISHED:
            connection_info.append({
                "local_address": f"{conn.laddr.ip}:{conn.laddr.port}" if conn.laddr else None,
                "remote_address": f"{conn.raddr.ip}:{conn.raddr.port}" if conn.raddr else None,
                "status": conn.status,
                "pid": conn.pid
            })
    return connection_info


# 生成加密密钥
def generate_key():
    return Fernet.generate_key()


# 加密数据
def encrypt_data(data, key):
    fernet = Fernet(key)
    encrypted = fernet.encrypt(data)
    return encrypted


# 压缩数据
def compress_data(data):
    return gzip.compress(data)


# 存储日志到本地文件
def save_to_local_file(data, filename):
    with open(filename, 'wb') as f:
        f.write(data)


# 上传日志到服务器
def upload_to_server(file_data):
    url = 'http://your-server-address/upload'  # 替换为实际服务器地址
    headers = {'Content-Type': 'application/octet-stream'}

    try:
        response = requests.post(url, data=file_data, headers=headers)
        response.raise_for_status()  # 检查响应状态码
        print("Upload successful:", response.status_code)
    except requests.exceptions.RequestException as e:
        print("Failed to upload:", e)


# 定时任务
def job():
    print("no")
    # 获取网络日志
    network_logs = get_network_connections()
    packet_logs = capture_network_packets()

    if not packet_logs:  # 如果没有获取到数据，则不继续执行
        return

    # 打包数据
    logs = str(network_logs + packet_logs).encode('utf-8')
    compressed_logs = compress_data(logs)
    encrypted_logs = encrypt_data(compressed_logs, key)

    # 生成本地文件名 (按日期命名)
    timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
    local_filename = f"network_log_{timestamp}.log"

    # 存储到本地文件
    save_to_local_file(encrypted_logs, local_filename)

    # 上传加密后的日志
    upload_to_server(encrypted_logs)


# 生成加密密钥（可以存储和复用）
key = generate_key()

# 设置定时任务：每天凌晨1点执行
schedule.every().day.at("01:00").do(job)

job()

# 定义服务类
class NetworkLogService(win32serviceutil.ServiceFramework):
    _svc_name_ = "NetworkLogService"
    _svc_display_name_ = "Network Log Capture and Upload Service"

    def __init__(self, args):
        win32serviceutil.ServiceFramework.__init__(self, args)
        self.hWaitStop = win32event.CreateEvent(None, 0, 0, None)
        self.is_running = True

    def SvcStop(self):
        self.is_running = False
        win32event.SetEvent(self.hWaitStop)

    def SvcDoRun(self):
        servicemanager.LogMsg(
            servicemanager.EVENTLOG_INFORMATION_TYPE,
            servicemanager.PYS_SERVICE_STARTED,
            (self._svc_name_, '')
        )
        self.main()

    def main(self):
        while self.is_running:
            schedule.run_pending()
            time.sleep(1)


if __name__ == '__main__':
    win32serviceutil.HandleCommandLine(NetworkLogService)