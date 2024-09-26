import pyshark
import logging
import time
import os
import stat
import schedule
import socket

# 设置日志文件路径
LOG_FILE_PATH = "C:\\logs\\logfile.log"

# 配置日志格式
logging.basicConfig(
    filename=LOG_FILE_PATH,
    level=logging.INFO,
    format='%(asctime)s - %(message)s',
    datefmt='%Y-%m-%d %H:%M:%S'
)


# 自动获取网络接口
def get_default_network_interface():
    interfaces = pyshark.LiveCapture().interfaces
    # 返回第一个有效的接口，或者你可以通过指定具体接口名称
    return interfaces[0] if interfaces else None


# 获取网络连接的信息
def capture_http_https_packets(interface):
    capture = pyshark.LiveCapture(interface=interface, bpf_filter='tcp port 80 or tcp port 443')

    for packet in capture.sniff_continuously(packet_count=10):
        try:
            timestamp = time.strftime('%Y-%m-%d %H:%M:%S', time.localtime())

            # 提取本地IP和端口
            local_ip = packet.ip.src
            local_port = packet.tcp.srcport

            # 提取目标IP和端口
            remote_ip = packet.ip.dst
            remote_port = packet.tcp.dstport

            if 'HTTP' in packet:
                # 获取 HTTP 请求的信息
                url = packet.http.host + packet.http.request_uri
                method = packet.http.request_method
                logging.info(
                    f"HTTP {method} Request to {url} | Local: {local_ip}:{local_port} -> Remote: {remote_ip}:{remote_port} at {timestamp}")
            elif 'SSL' in packet or 'TLS' in packet:
                # 处理 HTTPS 请求（仅记录IP和端口，无法获取URL）
                logging.info(
                    f"HTTPS connection | Local: {local_ip}:{local_port} -> Remote: {remote_ip}:{remote_port} at {timestamp}")
        except AttributeError:
            # 跳过没有 HTTP 或 HTTPS 层的数据包
            continue


# 定期上传日志文件到指定路径
def upload_log():
    try:
        # 假设上传路径为服务器上的某个路径
        destination_path = 'C:\\path\\to\\server\\upload\\logfile.log'
        os.rename(LOG_FILE_PATH, destination_path)  # 移动日志文件
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
def schedule_tasks(interface):
    schedule.every(10).seconds.do(capture_http_https_packets, interface=interface)  # 每10秒抓取一次流量
    schedule.every(1).hour.do(upload_log)  # 每小时上传日志文件

    while True:
        schedule.run_pending()
        time.sleep(1)


if __name__ == '__main__':
    # 获取默认网络接口
    default_interface = get_default_network_interface()
    if default_interface is None:
        logging.error("No valid network interfaces found.")
        exit(1)

    # 设置初始权限
    set_log_file_permissions(LOG_FILE_PATH)

    # 开始任务调度
    schedule_tasks(default_interface)