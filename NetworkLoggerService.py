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
from queue import Queue, Empty, Full
from logging.handlers import RotatingFileHandler
from scapy.all import sniff, IP, TCP, UDP

# 基本配置
LOG_DIR = "C:\\netLogs\\"  # 日志存储目录
MAX_LOG_SIZE = 10 * 1024 * 1024  # 10MB
LOG_EXTENSION = ".log"
COMPRESSED_EXTENSION = ".zip"
UPLOAD_RETRY_LIMIT = 3  # 上传失败时的重试次数
UPLOAD_RETRY_DELAY = 5  # 每次重试的初始延迟时间（秒）
UPLOAD_QUEUE_MAXSIZE = 10  # 上传队列的最大长度
UPLOAD_THREAD_COUNT = 1  # 并行上传线程的数量
BATCH_SIZE = 10  # 每次批量处理的包数量

# 队列
queue = Queue(maxsize=100)  # 数据包处理队列，限制队列的大小，避免内存过载
upload_queue = Queue(maxsize=UPLOAD_QUEUE_MAXSIZE)  # 上传队列
stop_event = Event()  # 用于控制服务停止的事件


# 设置文件夹访问权限为只有管理员
def set_admin_only_permissions(folder_path):
    try:
        # 使用 icacls 命令设置权限，只允许管理员访问
        command = f'icacls "{folder_path}" /inheritance:r /grant:r Administrators:F /T /C'
        os.system(command)
        print(f"Permissions for {folder_path} set to Administrators only.")
    except Exception as e:
        print(f"Failed to set permissions for {folder_path}: {e}")


# 按天创建文件夹，按小时创建日志文件
def get_log_file_path():
    current_day = time.strftime('%Y-%m-%d')  # 生成当天日期的字符串
    current_hour = time.strftime('%H')  # 获取当前小时
    folder_path = os.path.join(LOG_DIR, current_day)

    if not os.path.exists(folder_path):
        os.makedirs(folder_path)  # 如果文件夹不存在则创建
        set_admin_only_permissions(folder_path)  # 设置目录权限为管理员可访问

    log_file_path = os.path.join(folder_path, f"logfile_{current_hour}{LOG_EXTENSION}")
    return log_file_path


# 压缩文件
def compress_file(file_path):
    compressed_file = file_path + COMPRESSED_EXTENSION
    with zipfile.ZipFile(compressed_file, 'w', zipfile.ZIP_DEFLATED) as zipf:
        zipf.write(file_path, os.path.basename(file_path))
    os.remove(file_path)
    logging.info(f"Log file {file_path} compressed to {compressed_file}")


# 自定义日志轮转处理器
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
        try:
            queue.put_nowait(packet)  # 尽量避免阻塞
        except Full:
            logging.warning("Queue is full, dropping packet.")


# 日志处理器：处理数据包并记录日志
def process_packets():
    buffer = []
    while not stop_event.is_set():
        try:
            packet = queue.get(timeout=1)  # 从队列中取出数据包
            buffer.append(packet)
            if len(buffer) >= BATCH_SIZE:
                flush_logs(buffer)  # 批量处理日志
                buffer.clear()
        except Empty:
            continue  # 队列为空则继续循环

    # 服务停止时清空缓存
    if buffer:
        flush_logs(buffer)


# 将数据包记录写入日志
def flush_logs(buffer):
    for packet in buffer:
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


# 捕获所有 TCP 和 UDP 数据包，批量捕获
def capture_all_ports():
    while not stop_event.is_set():
        sniff(filter="tcp or udp", prn=packet_callback, store=0, count=100, stop_filter=lambda x: stop_event.is_set())


# 上传日志文件，并在失败时重试
def upload_with_retry(log_file_path):
    folder_path, log_filename = os.path.split(log_file_path)
    destination_path = os.path.join('C:\\path\\to\\server\\upload', folder_path)

    if not os.path.exists(destination_path):
        os.makedirs(destination_path)

    attempt = 0
    delay = UPLOAD_RETRY_DELAY

    while attempt < UPLOAD_RETRY_LIMIT:
        try:
            shutil.copy(log_file_path, destination_path)
            logging.info(f"Log file {log_file_path} successfully uploaded to {destination_path}.")
            break  # 上传成功，退出重试循环
        except Exception as e:
            attempt += 1
            logging.error(f"Failed to upload log file {log_file_path} (Attempt {attempt}/{UPLOAD_RETRY_LIMIT}): {e}")
            if attempt < UPLOAD_RETRY_LIMIT:
                time.sleep(delay)  # 延迟上传重试
                delay *= 2  # 指数增加重试间隔时间


# 异步上传处理器，将日志文件添加到上传队列中
def async_upload_log(log_file_path):
    try:
        upload_queue.put_nowait(log_file_path)  # 将要上传的文件路径放入上传队列
        logging.info(f"Log file {log_file_path} added to upload queue.")
    except Full:
        logging.warning("Upload queue is full. Dropping log file upload request.")


# 上传日志文件的线程
def upload_worker():
    while True:
        try:
            log_file_path = upload_queue.get(timeout=1)  # 从上传队列中取出要上传的文件路径
            if log_file_path:
                upload_with_retry(log_file_path)
            upload_queue.task_done()
        except Empty:
            continue


# 启动异步上传线程池
def start_upload_threads():
    for _ in range(UPLOAD_THREAD_COUNT):
        upload_thread = Thread(target=upload_worker)
        upload_thread.daemon = True  # 设置为守护线程，在主线程退出时自动终止
        upload_thread.start()

# Windows 服务类
class NetLoggerService(win32serviceutil.ServiceFramework):
    _svc_name_ = "NetLoggerService"
    _svc_display_name_ = "NetLoggerService"
    _svc_description_ = "融汇Turing小组出品，客户端网络访问日志获取"

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

        # 启动上传线程
        start_upload_threads()

        # 启动数据包处理线程
        packet_processor_thread = Thread(target=process_packets)
        packet_processor_thread.daemon = True
        packet_processor_thread.start()

        # 启动数据包捕获线程
        capture_thread = Thread(target=capture_all_ports)
        capture_thread.daemon = True
        capture_thread.start()

        # 调度任务
        schedule.every(10).minutes.do(lambda: async_upload_log(get_log_file_path()))  # 每10分钟异步上传日志文件

        while not stop_event.is_set():
            schedule.run_pending()
            time.sleep(5)  # 延长调度轮询时间，减少CPU占用

        # 等待线程完成
        queue.join()

if __name__ == '__main__':
    if len(sys.argv) == 1:
        try:
            evtsrc_dll = os.path.abspath(servicemanager.__file__)
            # 如果修改过名字，名字要统一
            servicemanager.PrepareToHostSingle(NetLoggerService)
            # 如果修改过名字，名字要统一
            servicemanager.Initialize('NetworkLoggerService', evtsrc_dll)
            servicemanager.StartServiceCtrlDispatcher()
        except win32service.error as details:
            import winerror

            if details == winerror.ERROR_FAILED_SERVICE_CONTROLLER_CONNECT:
                win32serviceutil.usage()
    else:
        win32serviceutil.HandleCommandLine(NetLoggerService)