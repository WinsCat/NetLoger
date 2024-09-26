import win32serviceutil
import win32service
import win32event
import servicemanager
from scapy.all import *
from datetime import datetime, timedelta
import re
import socket
import os
import shutil

class NetworkMonitorService(win32serviceutil.ServiceFramework):
    _svc_name_ = "NetworkMonitorService"
    _svc_display_name_ = "Network Monitor Service"
    _svc_description_ = "Monitors network usage (HTTP/HTTPS) and logs it."

    def __init__(self, args):
        win32serviceutil.ServiceFramework.__init__(self, args)
        self.hWaitStop = win32event.CreateEvent(None, 0, 0, None)
        socket.setdefaulttimeout(60)
        self.is_running = True
        self.base_log_dir = r"c:\logs"  # 修改为你实际需要的路径
        self.max_log_size = 5 * 1024 * 1024  # 每个日志文件的大小上限为5MB
        # self.max_logs_per_day = 5  # 每个日期目录中最多保存5个日志文件
        self.log_retention_days = 180  # 日志文件保留天数为6个月（180天）
        self.upload_interval_days = 7  # 自定义上传到服务器的间隔天数（默认每7天）

    def SvcStop(self):
        self.is_running = False
        self.ReportServiceStatus(win32service.SERVICE_STOP_PENDING)
        win32event.SetEvent(self.hWaitStop)

    def SvcDoRun(self):
        servicemanager.LogMsg(servicemanager.EVENTLOG_INFORMATION_TYPE,
                              servicemanager.PYS_SERVICE_STARTED,
                              (self._svc_name_, ''))
        self.main()

    def packet_callback(self, packet):
        try:
            if IP in packet:
                ip_src = packet[IP].src
                ip_dst = packet[IP].dst
                src_port = packet[TCP].sport
                dst_port = packet[TCP].dport
                timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")

                # HTTP 流量处理（TCP 80端口）
                if TCP in packet and packet[TCP].dport == 80:
                    if Raw in packet:
                        try:
                            http_payload = packet[Raw].load.decode('utf-8')
                            request = http_payload.split("\r\n")[0]
                            url = re.search(r'(?i)(GET|POST) (.*?) HTTP', request)
                            if url:
                                log_entry = (f"[{timestamp}] HTTP Source IP: {ip_src} Source Port: {src_port}, "
                                             f"Destination IP: {ip_dst} URL: {url.group(2)} Destination Port: {dst_port}")
                                servicemanager.LogInfoMsg(log_entry)
                                print(log_entry)
                                self.log_to_file(log_entry)
                        except Exception as e:
                            servicemanager.LogErrorMsg(f"Error processing HTTP packet: {str(e)}")

                # HTTPS 流量处理（TCP 443端口）
                elif TCP in packet and (packet[TCP].dport == 443 or packet[TCP].sport == 443):
                    if Raw in packet:
                        payload = packet[Raw].load
                        if payload[0] == 0x16:  # TLS Content Type = 0x16 (Handshake)
                            try:
                                sni_start = payload.find(b'\x00\x00') + 5
                                sni_length = payload[sni_start - 2:sni_start]
                                sni_length = int.from_bytes(sni_length, 'big')
                                sni = payload[sni_start:sni_start + sni_length].decode()

                                log_entry = (f"[{timestamp}] HTTPS Source IP: {ip_src} Source Port: {src_port}, "
                                             f"Destination IP: {ip_dst} SNI/Domain: {sni} Destination Port: {dst_port}")
                                servicemanager.LogInfoMsg(log_entry)
                                print(log_entry)
                                self.log_to_file(log_entry)
                            except Exception as e:
                                servicemanager.LogErrorMsg(f"Error processing HTTPS packet: {str(e)}")
        except Exception as e:
            servicemanager.LogErrorMsg(f"General error in packet callback: {str(e)}")

    def get_log_dir(self):
        """获取当前日期的日志目录，并创建目录（如果不存在）"""
        current_date = datetime.now().strftime("%Y-%m-%d")
        log_dir = os.path.join(self.base_log_dir, current_date)
        if not os.path.exists(log_dir):
            os.makedirs(log_dir)
        return log_dir

    def get_log_file_path(self):
        """生成当前日志文件的路径，以日期时间命名"""
        log_dir = self.get_log_dir()
        timestamp = datetime.now().strftime("%Y-%m-%d_%H%M%S")
        logfile_path = os.path.join(log_dir, f"network_log_{timestamp}.txt")
        return logfile_path

    def clean_old_logs(self):
        """删除超过保留天数的日志文件夹"""
        retention_date = datetime.now() - timedelta(days=self.log_retention_days)
        for log_folder in os.listdir(self.base_log_dir):
            folder_path = os.path.join(self.base_log_dir, log_folder)
            if os.path.isdir(folder_path):
                try:
                    folder_date = datetime.strptime(log_folder, "%Y-%m-%d")
                    if folder_date < retention_date:
                        shutil.rmtree(folder_path)
                        servicemanager.LogInfoMsg(f"Deleted old log folder: {folder_path}")
                except ValueError:
                    # 如果文件夹名不符合日期格式，不处理
                    pass

    def log_to_file(self, message):
        try:
            logfile_path = self.get_log_file_path()
            self.clean_old_logs()  # 清理超过6个月的日志文件夹
            # self.clean_old_logs_in_day()  # 每日日志清理

            # 写入日志文件
            with open(logfile_path, "a") as logfile:
                logfile.write(message + "\n")

            # 检查日志文件大小并清理
            if os.path.getsize(logfile_path) > self.max_log_size:
                servicemanager.LogInfoMsg(f"Log file {logfile_path} reached max size and will be rotated.")
                self.clean_old_logs()  # 确保不会超出日志文件数量限制
        except Exception as e:
            servicemanager.LogErrorMsg(f"Error writing to log file: {str(e)}")

    def upload_logs(self):
        """自定义上传日志到服务器"""
        # 这里实现你上传到服务器的逻辑
        # 可以是通过FTP、SFTP、HTTP、API等方式上传
        try:
            servicemanager.LogInfoMsg("Starting to upload logs to the server.")
            # 上传逻辑
            # 示例：shutil.copyfile(logfile_path, "ftp://yourserver/path/")
            # 完成上传
            servicemanager.LogInfoMsg("Successfully uploaded logs to the server.")
        except Exception as e:
            servicemanager.LogErrorMsg(f"Error uploading logs to the server: {str(e)}")

    def schedule_log_upload(self):
        """根据设定的间隔时间上传日志"""
        last_upload_date_file = os.path.join(self.base_log_dir, "last_upload.txt")
        today = datetime.now().date()

        # 检查上次上传时间
        if os.path.exists(last_upload_date_file):
            with open(last_upload_date_file, "r") as f:
                last_upload_date_str = f.read().strip()
                try:
                    last_upload_date = datetime.strptime(last_upload_date_str, "%Y-%m-%d").date()
                except ValueError:
                    last_upload_date = today - timedelta(days=self.upload_interval_days)
        else:
            last_upload_date = today - timedelta(days=self.upload_interval_days)

        # 检查是否需要上传日志
        if (today - last_upload_date).days >= self.upload_interval_days:
            self.upload_logs()

            # 记录本次上传时间
            with open(last_upload_date_file, "w") as f:
                f.write(today.strftime("%Y-%m-%d"))

    def main(self):
        # 开始捕获数据包，捕获 HTTP 和 HTTPS 流量
        servicemanager.LogInfoMsg("Network monitor service started, sniffing for HTTP/HTTPS traffic.")
        try:
            sniff(prn=self.packet_callback, filter="tcp port 80 or tcp port 443", store=0)
            # 定期上传日志到服务器
            self.schedule_log_upload()
        except Exception as e:
            servicemanager.LogErrorMsg(f"Error in main sniff loop: {str(e)}")


if __name__ == '__main__':
    win32serviceutil.HandleCommandLine(NetworkMonitorService)