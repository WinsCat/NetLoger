# Copyright (C) 2023-2024 iSeeNEw Studio, Inc. All Rights Reserved
#
# @Time    : 9/10/24 PM8:40
# @Author  : Wins
# @Email   : cn.lazycat@gmail.com
# @File    : NetLogerService.py
# @Software: PyCharm
# @Desc    :
import sys

import win32serviceutil
import win32service
import win32event
import servicemanager
import socket
from scapy.all import sniff, IP, TCP, UDP
from scapy.layers.http import HTTPRequest
from datetime import datetime, timedelta
import os
import zipfile
import shutil


class NetworkLogService(win32serviceutil.ServiceFramework):
    _svc_name_ = "NetworkLogService"
    _svc_display_name_ = "Network Logger Service"
    _svc_description_ = "融汇Turing小组出品，客户端网络访问日志获取。"

    def __init__(self, args):
        win32serviceutil.ServiceFramework.__init__(self, args)
        self.hWaitStop = win32event.CreateEvent(None, 0, 0, None)
        socket.setdefaulttimeout(60)
        self.log_file = None
        self.log_file_path = None
        self.last_compression_time = datetime.now()
        self.log_dir = "C:\\network_logs"  # 日志存储目录

    def SvcStop(self):
        self.ReportServiceStatus(win32service.SERVICE_STOP_PENDING)
        win32event.SetEvent(self.hWaitStop)
        if self.log_file:
            self.log_file.close()

    def SvcDoRun(self):
        servicemanager.LogMsg(servicemanager.EVENTLOG_INFORMATION_TYPE,
                              servicemanager.PYS_SERVICE_STARTED,
                              (self._svc_name_, ''))
        self.log_file = self.create_log_file()
        self.main()

    def create_log_file(self):
        """创建新的日志文件，按小时保存"""
        current_time = datetime.now().strftime('%Y-%m-%d_%H')
        folder_path = os.path.join(self.log_dir, current_time.split('_')[0])  # 按天建立文件夹
        os.makedirs(folder_path, exist_ok=True)
        file_path = os.path.join(folder_path, f"log_{current_time}.txt")
        self.log_file_path = file_path
        return open(file_path, "a")

    def extract_http_url(self, packet):
        """从 HTTP 请求中提取 URL"""
        if packet.haslayer(HTTPRequest):
            http_layer = packet.getlayer(HTTPRequest)
            host = http_layer.Host.decode() if http_layer.Host else ""
            path = http_layer.Path.decode() if http_layer.Path else ""
            return f"http://{host}{path}"
        return None

    def extract_sni(self, packet):
        """从 HTTPS 流量中提取 SNI"""
        try:
            if packet.haslayer('TLS Client Hello'):
                tls_layer = packet['TLS Client Hello']
                if tls_layer.sni:
                    return tls_layer.sni.decode()
        except:
            pass
        return None

    def packet_callback(self, packet):
        """处理捕获的数据包，记录IP、端口、URL、SNI信息"""
        if packet.haslayer(IP):
            ip_src = packet[IP].src
            ip_dst = packet[IP].dst

            # 提取端口信息（TCP 或 UDP）
            src_port = packet[TCP].sport if packet.haslayer(TCP) else (
                packet[UDP].sport if packet.haslayer(UDP) else "Unknown")
            dst_port = packet[TCP].dport if packet.haslayer(TCP) else (
                packet[UDP].dport if packet.haslayer(UDP) else "Unknown")

            # 处理 HTTP 请求中的 URL
            url = self.extract_http_url(packet)
            if url:
                self.log_file.write(
                    f"Time: {datetime.now()}, Source IP: {ip_src}:{src_port}, Destination IP: {ip_dst}:{dst_port}, URL: {url}\n")

            # 处理 HTTPS 流量中的 SNI
            sni = self.extract_sni(packet)
            if sni:
                self.log_file.write(
                    f"Time: {datetime.now()}, Source IP: {ip_src}:{src_port}, Destination IP: {ip_dst}:{dst_port}, Domain: {sni}\n")

            # 如果没有 URL 和 SNI，记录IP和端口信息
            if not url and not sni:
                self.log_file.write(
                    f"Time: {datetime.now()}, Source IP: {ip_src}:{src_port}, Destination IP: {ip_dst}:{dst_port}, No URL info\n")

            self.log_file.flush()

        # 检查是否需要压缩日志
        self.check_and_compress_log()

    def check_and_compress_log(self):
        """每小时压缩一次日志"""
        current_time = datetime.now()
        # 如果时间间隔超过一小时，则压缩日志文件
        if current_time - self.last_compression_time >= timedelta(hours=1):
            self.compress_log_file()
            self.log_file.close()
            self.log_file = self.create_log_file()  # 创建新的日志文件
            self.last_compression_time = current_time

        # 每次数据包到达时，执行日志清理操作
        self.clean_old_logs()

    def compress_log_file(self):
        """压缩日志文件为.zip格式"""
        if self.log_file_path and os.path.exists(self.log_file_path):
            zip_file_path = self.log_file_path.replace('.txt', '.zip')
            with zipfile.ZipFile(zip_file_path, 'w', zipfile.ZIP_DEFLATED) as zipf:
                zipf.write(self.log_file_path, os.path.basename(self.log_file_path))
            os.remove(self.log_file_path)  # 删除原始日志文件

    def clean_old_logs(self):
        """删除7天前的日志文件"""
        current_time = datetime.now()
        for folder in os.listdir(self.log_dir):
            folder_path = os.path.join(self.log_dir, folder)
            if os.path.isdir(folder_path):
                folder_date = datetime.strptime(folder, '%Y-%m-%d')
                if current_time - folder_date >= timedelta(days=7):
                    shutil.rmtree(folder_path)  # 删除整个文件夹及其内容

    def main(self):
        """捕获所有端口的网络数据包"""
        sniff(prn=self.packet_callback, store=0)

if __name__ == '__main__':
    if len(sys.argv) == 1:
        try:
            evtsrc_dll = os.path.abspath(servicemanager.__file__)
            servicemanager.PrepareToHostSingle(NetworkLogService)
            servicemanager.Initialize('NetworkLogService', evtsrc_dll)
            servicemanager.StartServiceCtrlDispatcher()
        except win32service.error as details:
            import winerror
            if details == winerror.ERROR_FAILED_SERVICE_CONTROLLER_CONNECT:
                win32serviceutil.usage()
    else:
        win32serviceutil.HandleCommandLine(NetworkLogService)