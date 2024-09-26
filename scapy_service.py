import os
import time
import shutil  # 用于复制文件到网络共享路径
import socket
import servicemanager
import win32serviceutil
import win32service
import win32event
from scapy.all import *
from datetime import datetime
import re


class ScapyService(win32serviceutil.ServiceFramework):
    _svc_name_ = "ScapyNetworkCaptureService"
    _svc_display_name_ = "Scapy Network Capture Service"
    _svc_description_ = "A service that captures HTTP and HTTPS traffic using Scapy and uploads logs to network share"

    def __init__(self, args):
        win32serviceutil.ServiceFramework.__init__(self, args)
        self.hWaitStop = win32event.CreateEvent(None, 0, 0, None)
        self.stop_requested = False
        self.log_file = "network_log8888.txt"
        self.upload_interval = 3600  # 每小时上传一次
        self.network_share_path = r"\\network\shared\logs"  # 网络共享路径，确保用户有写入权限

    def SvcStop(self):
        self.stop_requested = True
        self.ReportServiceStatus(win32service.SERVICE_STOP_PENDING)
        win32event.SetEvent(self.hWaitStop)

    def SvcDoRun(self):
        servicemanager.LogMsg(servicemanager.EVENTLOG_INFORMATION_TYPE,
                              servicemanager.PYS_SERVICE_STARTED,
                              (self._svc_name_, ''))
        self.main()

    def packet_callback(self, packet):
        if IP in packet:
            ip_src = packet[IP].src
            ip_dst = packet[IP].dst
            timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
            log_entry = None

            # HTTP 流量处理
            if TCP in packet and packet[TCP].dport == 80:
                if Raw in packet:
                    try:
                        http_payload = packet[Raw].load.decode('utf-8')
                        request = http_payload.split("\r\n")[0]
                        url = re.search(r'(?i)(GET|POST) (.*?) HTTP', request)
                        if url:
                            log_entry = f"[{timestamp}] HTTP Source IP: {ip_src} Destination IP: {ip_dst} URL: {url.group(2)}\n"
                    except:
                        pass

            # HTTPS 流量处理
            elif TCP in packet and (packet[TCP].dport == 443 or packet[TCP].sport == 443):
                if Raw in packet:
                    payload = packet[Raw].load
                    if payload[0] == 0x16:
                        try:
                            sni_start = payload.find(b'\x00\x00') + 5
                            sni_length = payload[sni_start - 2:sni_start]
                            sni_length = int.from_bytes(sni_length, 'big')
                            sni = payload[sni_start:sni_start + sni_length].decode()
                            log_entry = f"[{timestamp}] HTTPS Source IP: {ip_src} Destination IP: {ip_dst} SNI: {sni}\n"
                        except:
                            pass

            # 如果捕获到数据，写入日志文件
            if log_entry:
                with open(self.log_file, 'a') as log:
                    log.write(log_entry)

    def upload_logs(self):
        # 上传日志文件到网络共享路径
        try:
            if os.path.exists(self.log_file):
                # 复制日志文件到网络共享路径
                shutil.copy(self.log_file, self.network_share_path)
                print(f"Logs copied successfully to {self.network_share_path} at {datetime.now()}")
            else:
                print("Log file does not exist")
        except Exception as e:
            print(f"Failed to copy logs: {e}")

    def main(self):
        last_upload_time = time.time()

        # 捕获流量，直到服务停止
        while not self.stop_requested:
            # 定期上传日志
            current_time = time.time()
            if current_time - last_upload_time >= self.upload_interval:
                self.upload_logs()
                last_upload_time = current_time

            # 捕获数据包
            sniff(prn=self.packet_callback, filter="tcp port 80 or tcp port 443", store=0, timeout=1)
if __name__ == '__main__':
    win32serviceutil.HandleCommandLine(ScapyService)