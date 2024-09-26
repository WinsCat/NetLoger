from scapy.all import sniff, IP, TCP, UDP
import logging
import time
import os
import shutil
import stat
import schedule

# 基本配置
LOG_DIR = "C:\\netlogs\\"  # 根目录
MAX_LOG_SIZE = 10 * 1024 * 1024  # 10MB
LOG_EXTENSION = ".log"


# 按天创建文件夹，按小时创建日志文件
def get_log_file_path():
    current_day = time.strftime('%Y-%m-%d')  # 生成当天日期的字符串
    current_hour = time.strftime('%H')  # 获取当前小时
    folder_path = os.path.join(LOG_DIR, current_day)

    if not os.path.exists(folder_path):
        os.makedirs(folder_path)  # 如果文件夹不存在则创建

    log_file_path = os.path.join(folder_path, f"logfile_{current_hour}{LOG_EXTENSION}")
    return log_file_path


# 配置日志格式
def configure_logging():
    log_file_path = get_log_file_path()
    logging.basicConfig(
        filename=log_file_path,
        level=logging.INFO,
        format='%(asctime)s - %(message)s',
        datefmt='%Y-%m-%d %H:%M:%S'
    )
    return log_file_path


# 压缩日志文件
def compress_log_file(log_file_path):
    folder_path, log_filename = os.path.split(log_file_path)
    compressed_filename = f"{log_filename}.zip"
    compressed_file_path = os.path.join(folder_path, compressed_filename)

    # 压缩日志文件
    shutil.make_archive(log_file_path, 'zip', folder_path, log_filename)
    os.remove(log_file_path)  # 删除原始日志文件

    logging.info(f"Log file compressed: {compressed_file_path}")


# 检查文件大小并压缩
def check_and_compress_log():
    log_file_path = get_log_file_path()

    if os.path.exists(log_file_path):
        log_file_size = os.path.getsize(log_file_path)
        if log_file_size >= MAX_LOG_SIZE:
            compress_log_file(log_file_path)


# 解析捕获到的数据包
def packet_callback(packet):
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

        # 检查并压缩日志文件
        check_and_compress_log()


# 捕获所有 TCP 和 UDP 数据包
def capture_all_ports():
    sniff(filter="tcp or udp", prn=packet_callback, store=0)


# 定期上传日志文件到指定路径
def upload_log():
    try:
        log_file_path = get_log_file_path()
        folder_path, log_filename = os.path.split(log_file_path)
        destination_path = os.path.join('C:\\path\\to\\server\\upload', folder_path)

        # 创建服务器上传路径文件夹
        if not os.path.exists(destination_path):
            os.makedirs(destination_path)

        shutil.copy(log_file_path, destination_path)
        logging.info(f"Log file uploaded to {destination_path}")
    except Exception as e:
        logging.error(f"Failed to upload log file: {e}")


# 设置日志文件权限，非管理员不能访问
def set_log_file_permissions(file_path):
    if os.name == 'nt':
        # Windows 系统下设置只允许管理员访问
        os.chmod(file_path, stat.S_IRUSR | stat.S_IWUSR)  # 仅限管理员有读写权限
        logging.info(f"File permissions set for {file_path}")


# 设置计划任务
def schedule_tasks():
    schedule.every(10).seconds.do(capture_all_ports)  # 每10秒抓取一次流量
    schedule.every(1).hour.do(upload_log)  # 每小时上传日志文件

    while True:
        schedule.run_pending()
        time.sleep(1)


if __name__ == '__main__':
    # 设置初始日志文件
    log_file_path = configure_logging()

    # 设置初始权限
    set_log_file_permissions(log_file_path)

    # 开始任务调度
    schedule_tasks()