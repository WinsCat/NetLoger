import sys

import win32serviceutil
import win32service
import win32event
import servicemanager
import logging
import os
import time
import shutil
import stat
import schedule
import zipfile
from threading import Thread, Event
from queue import Queue, Empty
from logging.handlers import RotatingFileHandler
from scapy.all import sniff, IP, TCP, UDP

# 基本配置
LOG_DIR = "C:\\netlogs\\"  # 根目录
MAX_LOG_SIZE = 10 * 1024 * 1024  # 10MB
LOG_EXTENSION = ".log"
RETRY_LIMIT = 3  # 上传失败时的重试次数
RETRY_DELAY = 5  # 每次重试的延迟时间（秒）
COMPRESSED_EXTENSION = ".zip"

queue = Queue()
stop_event = Event()


# 按天创建文件夹，按小时创建日志文件
def get_log_file_path():
    current_day = time.strftime('%Y-%m-%d')  # 生成当天日期的字符串
    current_hour = time.strftime('%H')  # 获取当前小时
    folder_path = os.path.join(LOG_DIR, current_day)

    if not os.path.exists(folder_path):
        os.makedirs(folder_path)  # 如果文件夹不存在则创建

    log_file_path = os.path.join(folder_path, f"logfile_{current_hour}{LOG_EXTENSION}")
    return log_file_path


# 压缩文件
def compress_file(file_path):
    compressed_file = file_path + COMPRESSED_EXTENSION
    with zipfile.ZipFile(compressed_file, 'w', zipfile.ZIP_DEFLATED) as zipf:
        zipf.write(file_path, os.path.basename(file_path))
    os.remove(file_path)
    logging.info(f"Log file {file_path} compressed to {compressed_file}")


# 监控日志轮转并压缩旧日志文件
class CompressingRotatingFileHandler(RotatingFileHandler):
    def doRollover(self):
        super().doRollover()  # 调用父类方法进行日志轮转
        # 查找上一个轮转的日志文件并压缩
        for i in range(self.backupCount, 0, -1):
            log_file = f"{self.baseFilename}.{i}"
            if os.path.exists(log_file):
                compress_file(log_file)


# 配置日志格式（使用日志轮转和压缩）
def configure_logging():
    log_file_path = get_log_file_path()
    logger = logging.getLogger()
    logger.setLevel(logging.INFO)

    # 使用自定义的 RotatingFileHandler 进行日志轮转和压缩
    handler = CompressingRotatingFileHandler(log_file_path, maxBytes=MAX_LOG_SIZE, backupCount=5)
    formatter = logging.Formatter('%(asctime)s - %(message)s', datefmt='%Y-%m-%d %H:%M:%S')
    handler.setFormatter(formatter)
    logger.addHandler(handler)

    return log_file_path


# 捕获并处理数据包，使用队列传递数据
def packet_callback(packet):
    if not stop_event.is_set():
        queue.put(packet)


# 日志处理器：处理数据包并记录日志
def process_packets():
    while not stop_event.is_set():
        try:
            packet = queue.get(timeout=1)  # 从队列中取出数据包
        except Empty:
            continue  # 队列为空则继续循环

        if IP in packet:
            timestamp = time.strftime('%Y-%m-%d %H:%M:%S', time.localtime())
            local_ip = packet[IP].src  # 本地 IP
            remote_ip = packet[IP].dst  # 目标 IP

            # 如果是 TCP 数据包
            if TCP in packet:
                local_port = packet[TCP].sport  # 本地端口
                remote_port = packet[TCP].dport  # 目标端口

                # 记录 HTTP 请求的目标 URL
                if packet[TCP].dport == 80:  # HTTP
                    if packet.haslayer('Raw'):
                        http_data = packet['Raw'].load.decode(errors='ignore')
                        if 'Host' in http_data and 'GET' in http_data:
                            lines = http_data.split('\n')
                            for line in lines:
                                if 'Host' in line:
                                    host = line.split(' ')[1].strip()
                                if 'GET' in line:
                                    request_uri = line.split(' ')[1].strip()
                            url = f"http://{host}{request_uri}"
                            logging.info(
                                f"HTTP Request to {url} | Local: {local_ip}:{local_port} -> Remote: {remote_ip}:{remote_port} at {timestamp}")
                elif packet[TCP].dport == 443:  # HTTPS
                    logging.info(
                        f"HTTPS connection | Local: {local_ip}:{local_port} -> Remote: {remote_ip}:{remote_port} at {timestamp}")
                else:
                    # 记录其他 TCP 端口连接
                    logging.info(
                        f"TCP connection | Local: {local_ip}:{local_port} -> Remote: {remote_ip}:{remote_port} at {timestamp}")

            # 如果是 UDP 数据包
            elif UDP in packet:
                local_port = packet[UDP].sport  # 本地端口
                remote_port = packet[UDP].dport  # 目标端口
                logging.info(
                    f"UDP connection | Local: {local_ip}:{local_port} -> Remote: {remote_ip}:{remote_port} at {timestamp}")

        queue.task_done()


# 捕获所有 TCP 和 UDP 数据包
def capture_all_ports():
    while not stop_event.is_set():
        sniff(filter="tcp or udp", prn=packet_callback, store=0, stop_filter=lambda x: stop_event.is_set())


# 定期上传日志文件到指定路径
def upload_log():
    log_file_path = get_log_file_path()
    folder_path, log_filename = os.path.split(log_file_path)
    destination_path = os.path.join('C:\\netlogs\\upload', folder_path)

    if not os.path.exists(destination_path):
        os.makedirs(destination_path)

    attempt = 0
    while attempt < RETRY_LIMIT:
        try:
            shutil.copy(log_file_path, destination_path)
            logging.info(f"Log file uploaded to {destination_path}")
            break  # 上传成功，退出重试循环
        except Exception as e:
            attempt += 1
            logging.error(f"Failed to upload log file (Attempt {attempt}/{RETRY_LIMIT}): {e}")
            if attempt < RETRY_LIMIT:
                time.sleep(RETRY_DELAY)


# 设置日志文件权限，非管理员不能访问
def set_log_file_permissions(file_path):
    if os.name == 'nt':
        # Windows 系统下设置只允许管理员访问
        os.chmod(file_path, stat.S_IRUSR | stat.S_IWUSR)
        logging.info(f"File permissions set for {file_path}")


# Windows 服务类
class NetworkLoggerService(win32serviceutil.ServiceFramework):
    _svc_name_ = "NetworkLoggerService"
    _svc_display_name_ = "Network Logger Service"
    _svc_description_ = "融汇Turing小组出品，客户端网络访问日志获取服务"

    def __init__(self, args):
        win32serviceutil.ServiceFramework.__init__(self, args)
        self.hWaitStop = win32event.CreateEvent(None, 0, 0, None)

    def SvcStop(self):
        self.ReportServiceStatus(win32service.SERVICE_STOP_PENDING)
        win32event.SetEvent(self.hWaitStop)
        stop_event.set()  # 触发停止事件，停止线程和任务

    def SvcDoRun(self):
        servicemanager.LogMsg(
            servicemanager.EVENTLOG_INFORMATION_TYPE,
            servicemanager.PYS_SERVICE_STARTED,
            (self._svc_name_, '')
        )
        self.main()

    def main(self):
        configure_logging()

        # 启动数据包处理线程
        packet_processor_thread = Thread(target=process_packets)
        packet_processor_thread.daemon = True
        packet_processor_thread.start()

        # 启动数据包捕获线程
        capture_thread = Thread(target=capture_all_ports)
        capture_thread.daemon = True
        capture_thread.start()

        # 调度任务
        schedule.every(1).hour.do(upload_log)  # 每小时上传日志文件

        while not stop_event.is_set():
            schedule.run_pending()
            time.sleep(1)

        # 等待线程完成
        queue.join()


if __name__ == '__main__':
    if len(sys.argv) == 1:
        try:
            evtsrc_dll = os.path.abspath(servicemanager.__file__)
            # 如果修改过名字，名字要统一
            servicemanager.PrepareToHostSingle(NetworkLoggerService)
            # 如果修改过名字，名字要统一
            servicemanager.Initialize('NetworkLoggerService', evtsrc_dll)
            servicemanager.StartServiceCtrlDispatcher()
        except win32service.error as details:
            import winerror

            if details == winerror.ERROR_FAILED_SERVICE_CONTROLLER_CONNECT:
                win32serviceutil.usage()
    else:
        win32serviceutil.HandleCommandLine(NetworkLoggerService)