import sys
import win32serviceutil
import win32service
import win32event
import servicemanager
import logging
import os
import time
import shutil
import zipfile
import schedule
import socket
import ftplib  # 用于FTP上传
from threading import Thread, Event, Lock
from queue import Queue, Empty, Full
from logging.handlers import TimedRotatingFileHandler
from scapy.all import sniff, IP, TCP, UDP

# 基本配置
LOG_DIR = "C:\\netLogs\\"
LOG_EXTENSION = ".log"
COMPRESSED_EXTENSION = ".zip"
UPLOAD_RETRY_LIMIT = 3
UPLOAD_RETRY_DELAY = 5
UPLOAD_QUEUE_MAXSIZE = 20
UPLOAD_THREAD_COUNT = 4
BATCH_SIZE = 10
MAX_CONCURRENT_UPLOADS = 4
MAX_LOG_RETENTION_DAYS = 7
LOG_LOCK = Lock()

# FTP服务器配置
FTP_HOST = "192.168.110.166"
FTP_USER = "Wins"
FTP_PASS = "Ronghui123"
FTP_PORT = 21

# 队列
queue = Queue(maxsize=100)
upload_queue = Queue(maxsize=UPLOAD_QUEUE_MAXSIZE)
stop_event = Event()
current_uploads = 0


def get_terminal_name():
    return socket.gethostname()


def set_admin_only_permissions(folder_path):
    try:
        command = f'icacls "{folder_path}" /inheritance:r /grant:r Administrators:F /T /C'
        os.system(command)
        print(f"Permissions for {folder_path} set to Administrators only.")
    except Exception as e:
        print(f"Failed to set permissions for {folder_path}: {e}")


def get_log_file_path(current_day=None):
    new_day = time.strftime('%Y-%m-%d')
    if current_day is None or current_day != new_day:
        current_day = new_day
        folder_path = os.path.join(LOG_DIR, current_day)

        if not os.path.exists(folder_path):
            os.makedirs(folder_path)
            set_admin_only_permissions(folder_path)
        return folder_path, current_day

    return os.path.join(LOG_DIR, current_day), current_day


def compress_file(file_path):
    timestamp = time.strftime('%Y%m%d_%H%M%S')
    compressed_file = file_path + f"_{timestamp}" + COMPRESSED_EXTENSION
    with zipfile.ZipFile(compressed_file, 'w', zipfile.ZIP_DEFLATED) as zipf:
        zipf.write(file_path, os.path.basename(file_path))
    os.remove(file_path)
    logging.info(f"Log file {file_path} compressed to {compressed_file}")
    async_upload_log(compressed_file)


def clean_old_logs():
    current_time = time.time()
    for folder in os.listdir(LOG_DIR):
        folder_path = os.path.join(LOG_DIR, folder)
        if os.path.isdir(folder_path):
            for file in os.listdir(folder_path):
                file_path = os.path.join(folder_path, file)
                file_time = os.path.getmtime(file_path)
                if (current_time - file_time) // (24 * 3600) >= MAX_LOG_RETENTION_DAYS:
                    try:
                        os.remove(file_path)
                        logging.info(f"Deleted old log file: {file_path}")
                    except Exception as e:
                        logging.error(f"Failed to delete {file_path}: {e}")


class CompressingTimedRotatingFileHandler(TimedRotatingFileHandler):
    def doRollover(self):
        super().doRollover()
        with LOG_LOCK:
            for i in range(self.backupCount, 0, -1):
                log_file = f"{self.baseFilename}.{i}"
                if os.path.exists(log_file):
                    compress_file(log_file)


def configure_logging():
    current_day = None
    log_folder_path, current_day = get_log_file_path(current_day)
    log_file_path = os.path.join(log_folder_path, f"logfile{LOG_EXTENSION}")

    logger = logging.getLogger()
    logger.setLevel(logging.INFO)

    handler = CompressingTimedRotatingFileHandler(log_file_path, when="H", interval=1, backupCount=24)
    formatter = logging.Formatter('%(asctime)s - %(message)s', datefmt='%Y-%m-%d %H:%M:%S')
    handler.setFormatter(formatter)
    logger.addHandler(handler)

    return log_file_path, current_day


def packet_callback(packet):
    if not stop_event.is_set():
        try:
            queue.put_nowait(packet)
        except Full:
            logging.warning("Queue is full, dropping packet.")


def process_packets():
    buffer = []
    while not stop_event.is_set():
        try:
            packet = queue.get(timeout=1)
            buffer.append(packet)
            if len(buffer) >= BATCH_SIZE:
                flush_logs(buffer)
                buffer.clear()
        except Empty:
            continue

    if buffer:
        flush_logs(buffer)


def flush_logs(buffer):
    for packet in buffer:
        if IP in packet:
            timestamp = time.strftime('%Y-%m-%d %H:%M:%S', time.localtime())
            local_ip = packet[IP].src
            remote_ip = packet[IP].dst

            if TCP in packet:
                local_port = packet[TCP].sport
                remote_port = packet[TCP].dport

                if packet[TCP].dport == 80:
                    if packet.haslayer('Raw'):
                        http_data = packet['Raw'].load.decode(errors='ignore')
                        if 'Host' in http_data and 'GET' in http_data:
                            lines = http_data.split('\n')
                            host, request_uri = "", ""
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
                    logging.info(
                        f"TCP connection | Local: {local_ip}:{local_port} -> Remote: {remote_ip}:{remote_port} at {timestamp}")

            elif UDP in packet:
                local_port = packet[UDP].sport
                remote_port = packet[UDP].dport
                logging.info(
                    f"UDP connection | Local: {local_ip}:{local_port} -> Remote: {remote_ip}:{remote_port} at {timestamp}")

        queue.task_done()


# 捕获所有 TCP 和 UDP 数据包，批量捕获
def capture_all_ports():
    while not stop_event.is_set():
        sniff(filter="tcp or udp", prn=packet_callback, store=0, count=100, stop_filter=lambda x: stop_event.is_set())


# 递归创建FTP目录
def create_ftp_directory(ftp, directory):
    directories = directory.split('/')
    for dir in directories:
        if dir not in ftp.nlst():
            try:
                ftp.mkd(dir)
            except ftplib.error_perm as e:
                logging.error(f"Failed to create directory {dir} on FTP server: {e}")
                raise e
        ftp.cwd(dir)


# 上传日志文件，并在失败时重试，优化上传逻辑，避免重复连接
def upload_with_retry(log_file_path):
    global current_uploads
    folder_path, log_filename = os.path.split(log_file_path)
    terminal_name = get_terminal_name()  # 获取终端名称
    ftp_directory = f"{terminal_name}/{folder_path}"  # 目标FTP路径

    attempt = 0
    delay = UPLOAD_RETRY_DELAY

    try:
        # 连接FTP服务器
        with ftplib.FTP() as ftp:
            ftp.connect(FTP_HOST, FTP_PORT)
            ftp.login(FTP_USER, FTP_PASS)

            # 创建目录结构，如果目录不存在
            create_ftp_directory(ftp, ftp_directory)

            # 切换到目标目录
            ftp.cwd(ftp_directory)

            while attempt < UPLOAD_RETRY_LIMIT:
                try:
                    # 上传文件
                    with open(log_file_path, 'rb') as file:
                        ftp.storbinary(f'STOR {log_filename}', file)

                    logging.info(f"Compressed log file {log_file_path} successfully uploaded to FTP: {ftp_directory}.")
                    print(f"Compressed log file {log_file_path} successfully uploaded to FTP: {ftp_directory}.")

                    # 标记日志已成功上传
                    mark_as_synced(log_file_path)

                    # 上传成功后删除本地压缩文件
                    os.remove(log_file_path)
                    logging.info(f"Local compressed log file {log_file_path} deleted after successful upload.")
                    break  # 上传成功，退出重试循环

                except Exception as e:
                    attempt += 1
                    logging.error(f"Failed to upload compressed log file {log_file_path} (Attempt {attempt}/{UPLOAD_RETRY_LIMIT}): {e}")
                    if attempt < UPLOAD_RETRY_LIMIT:
                        time.sleep(delay)  # 延迟上传重试
                        delay *= 2  # 指数增加重试间隔时间
    finally:
        current_uploads -= 1  # 上传结束后，减少当前上传数

# 标记文件为已上传的函数（防止重复上传）
def mark_as_synced(file_path):
    synced_marker = file_path + ".synced"
    with open(synced_marker, "w") as f:
        f.write("synced")
    logging.info(f"Marked {file_path} as synced.")


# 检查日志是否已上传
def is_file_synced(file_path):
    return os.path.exists(file_path + ".synced")


# 异步上传处理器，将未上传的日志文件添加到上传队列中
def async_upload_log(log_file_path):
    if not is_file_synced(log_file_path):  # 检查文件是否已经上传
        try:
            upload_queue.put_nowait(log_file_path)  # 将要上传的文件路径放入上传队列
            logging.info(f"Compressed log file {log_file_path} added to upload queue.")
        except Full:
            logging.warning("Upload queue is full. Dropping log file upload request.")
    else:
        logging.info(f"Compressed log file {log_file_path} has already been uploaded. Skipping.")


# 上传日志文件的线程
def upload_worker():
    global current_uploads
    while True:
        try:
            # 从上传队列中取出要上传的文件路径
            log_file_path = upload_queue.get(timeout=1)
            if log_file_path:
                if current_uploads < MAX_CONCURRENT_UPLOADS:  # 检查当前上传数是否达到上限
                    current_uploads += 1  # 增加当前上传数
                    upload_with_retry(log_file_path)  # 上传日志文件
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
        stop_event.set()  # 触发停止事件，停止线程和任务

    def SvcDoRun(self):
        servicemanager.LogMsg(
            servicemanager.EVENTLOG_INFORMATION_TYPE,
            servicemanager.PYS_SERVICE_STARTED,
            (self._svc_name_, '')
        )
        self.main()

    def main(self):
        log_file_path, current_day = configure_logging()

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

        # 调度任务，定期清理日志和上传
        schedule.every(10).minutes.do(lambda: async_upload_log(log_file_path))  # 每10分钟异步上传日志文件
        schedule.every(24).hours.do(clean_old_logs)  # 每24小时清理一次旧日志

        while not stop_event.is_set():
            schedule.run_pending()
            log_folder_path, new_day = get_log_file_path(current_day)  # 检查是否有新的一天
            if new_day != current_day:
                log_file_path, current_day = configure_logging()  # 新的一天重新配置日志

            time.sleep(5)  # 延长调度轮询时间，减少CPU占用

        # 等待线程完成
        queue.join()


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