import sys
import win32serviceutil
import win32service
import win32event
import servicemanager
import logging
import os
import time
import zipfile
import schedule
import socket
from threading import Thread, Event
from queue import Queue, Empty
from logging.handlers import TimedRotatingFileHandler
from scapy.all import sniff, IP, TCP, UDP
from ftplib import FTP

# 基本配置
LOG_DIR = "C:\\netLogs\\"  # 日志存储目录
LOG_EXTENSION = ".log"
COMPRESSED_EXTENSION = ".zip"
FTP_SERVER = "192.168.110.166"
FTP_USER = "ftp_user"
FTP_PASSWORD = "ftp_password"
FTP_REMOTE_DIR = "/logs/"
UPLOAD_RETRY_LIMIT = 3  # 上传失败时的重试次数
UPLOAD_RETRY_DELAY = 5  # 每次重试的初始延迟时间（秒）
MAX_CONCURRENT_UPLOADS = 4  # 最大同时并发上传数量
MAX_LOG_RETENTION_DAYS = 7  # 日志保留的天数
MAX_LOG_SIZE = 5 * 1024 * 1024  # 5MB

upload_queue = Queue()
stop_event = Event()


# 获取终端名称
def get_terminal_name():
    return socket.gethostname()


# 创建日志文件夹
def get_log_file_path():
    current_day = time.strftime('%Y-%m-%d')
    folder_path = os.path.join(LOG_DIR, current_day)
    if not os.path.exists(folder_path):
        os.makedirs(folder_path)
    return folder_path


# 压缩文件
def compress_file(file_path):
    timestamp = time.strftime('%Y%m%d_%H%M%S')
    compressed_file = file_path + f"_{timestamp}" + COMPRESSED_EXTENSION
    with zipfile.ZipFile(compressed_file, 'w', zipfile.ZIP_DEFLATED) as zipf:
        zipf.write(file_path, os.path.basename(file_path))
    os.remove(file_path)
    logging.info(f"Compressed log file {file_path} to {compressed_file}")
    return compressed_file


# FTP上传
def create_ftp_directory(ftp, path):
    dirs = path.split('/')
    current_dir = ''
    for directory in dirs:
        if directory:
            current_dir += f'/{directory}'
            try:
                ftp.cwd(current_dir)
            except Exception:
                ftp.mkd(current_dir)
                ftp.cwd(current_dir)


def upload_file(log_file_path):
    terminal_name = get_terminal_name()
    remote_dir = os.path.join(FTP_REMOTE_DIR, terminal_name, time.strftime('%Y-%m-%d'))

    attempt = 0
    delay = UPLOAD_RETRY_DELAY

    while attempt < UPLOAD_RETRY_LIMIT:
        try:
            with FTP(FTP_SERVER) as ftp:
                ftp.login(user=FTP_USER, passwd=FTP_PASSWORD)
                create_ftp_directory(ftp, remote_dir)
                with open(log_file_path, 'rb') as f:
                    ftp.storbinary(f'STOR {os.path.basename(log_file_path)}', f)
            logging.info(f"Uploaded {log_file_path} to FTP: {remote_dir}")
            os.remove(log_file_path)
            break
        except Exception as e:
            logging.error(f"Failed to upload {log_file_path}, attempt {attempt + 1}/{UPLOAD_RETRY_LIMIT}: {e}")
            attempt += 1
            time.sleep(delay)
            delay *= 2  # 增加重试间隔


# 处理日志压缩和上传
def compress_and_upload():
    folder_path = get_log_file_path()
    for file_name in os.listdir(folder_path):
        if file_name.endswith(LOG_EXTENSION):
            file_path = os.path.join(folder_path, file_name)
            compressed_file = compress_file(file_path)
            upload_file(compressed_file)


# 清理过期日志
def clean_old_logs():
    current_time = time.time()
    for folder in os.listdir(LOG_DIR):
        folder_path = os.path.join(LOG_DIR, folder)
        if os.path.isdir(folder_path):
            for file in os.listdir(folder_path):
                file_path = os.path.join(folder_path, file)
                file_time = os.path.getmtime(file_path)
                if (current_time - file_time) // (24 * 3600) >= MAX_LOG_RETENTION_DAYS:
                    os.remove(file_path)
                    logging.info(f"Deleted old log file: {file_path}")


# 记录数据包
def log_packet(packet):
    if IP in packet:
        timestamp = time.strftime('%Y-%m-%d %H:%M:%S', time.localtime())
        local_ip = packet[IP].src
        remote_ip = packet[IP].dst

        if TCP in packet:
            local_port = packet[TCP].sport
            remote_port = packet[TCP].dport
            if packet[TCP].dport == 80 and packet.haslayer('Raw'):
                http_data = packet['Raw'].load.decode(errors='ignore')
                logging.info(f"HTTP Request: {local_ip}:{local_port} -> {remote_ip}:{remote_port} at {timestamp}")
            elif packet[TCP].dport == 443:
                logging.info(f"HTTPS Connection: {local_ip}:{local_port} -> {remote_ip}:{remote_port} at {timestamp}")
            else:
                logging.info(f"TCP: {local_ip}:{local_port} -> {remote_ip}:{remote_port} at {timestamp}")

        elif UDP in packet:
            local_port = packet[UDP].sport
            remote_port = packet[UDP].dport
            logging.info(f"UDP: {local_ip}:{local_port} -> {remote_ip}:{remote_port} at {timestamp}")


# 捕获网络数据包
def capture_packets():
    sniff(filter="tcp or udp", prn=log_packet, store=0)


# 日志配置
def configure_logging():
    log_folder = get_log_file_path()
    log_file = os.path.join(log_folder, f"logfile_{time.strftime('%H')}{LOG_EXTENSION}")
    logger = logging.getLogger()
    logger.setLevel(logging.INFO)

    handler = TimedRotatingFileHandler(log_file, when="H", interval=1, backupCount=24)
    handler.rotator = lambda source, dest: shutil.move(source, dest)
    handler.setFormatter(logging.Formatter('%(asctime)s - %(message)s', datefmt='%Y-%m-%d %H:%M:%S'))
    logger.addHandler(handler)


# Windows服务类
class NetworkLoggerService(win32serviceutil.ServiceFramework):
    _svc_name_ = "NetworkLoggerService"
    _svc_display_name_ = "Network Logger Service"
    _svc_description_ = "融汇Turing小组出品，客户端网络访问日志获取。"

    def __init__(self, args):
        win32serviceutil.ServiceFramework.__init__(self, args)
        self.hWaitStop = win32event.CreateEvent(None, 0, 0, None)

    def SvcStop(self):
        self.ReportServiceStatus(win32service.SERVICE_STOP_PENDING)
        win32event.SetEvent(self.hWaitStop)
        stop_event.set()

    def SvcDoRun(self):
        servicemanager.LogMsg(
            servicemanager.EVENTLOG_INFORMATION_TYPE,
            servicemanager.PYS_SERVICE_STARTED,
            (self._svc_name_, '')
        )
        self.main()

    def main(self):
        configure_logging()

        # 启动网络数据包捕获线程
        capture_thread = Thread(target=capture_packets)
        capture_thread.daemon = True
        capture_thread.start()

        # 定时任务
        schedule.every().hour.do(compress_and_upload)  # 每小时压缩并上传日志
        schedule.every(24).hours.do(clean_old_logs)  # 每24小时清理旧日志

        while not stop_event.is_set():
            schedule.run_pending()
            time.sleep(5)


if __name__ == '__main__':
    if len(sys.argv) == 1:
        try:
            evtsrc_dll = os.path.abspath(servicemanager.__file__)
            servicemanager.PrepareToHostSingle(NetworkLoggerService)
            servicemanager.Initialize('NetworkLoggerService', evtsrc_dll)
            servicemanager.StartServiceCtrlDispatcher()
        except win32service.error as details:
            import winerror

            if details == winerror.ERROR_FAILED_SERVICE_CONTROLLER_CONNECT:
                win32serviceutil.usage()
    else:
        win32serviceutil.HandleCommandLine(NetworkLoggerService)