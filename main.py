import re
import pydivert
import logging
import socket
import os
import datetime
import requests
import win32serviceutil
import win32service
import win32event
from time import sleep
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import padding
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives import hashes
import base64
import zipfile

# 配置文件路径
CONFIG = {
    "server_url": "http://your-server-url/upload",  # 替换为服务器上传地址
    "log_directory": "./logs",  # 本地日志存储位置
    "max_log_size_mb": 10,  # 每个日志文件的最大大小 (单位MB)
    "interval_seconds": 3600,  # 日志上传间隔时间，单位秒（1小时）
    "log_file": "service_log.txt",  # 服务运行时的日志文件
    "encryption_password": "your-secure-password"  # AES 加密密钥派生的密码
}

# 配置日志记录
logging.basicConfig(
    filename=CONFIG["log_file"],
    level=logging.INFO,
    format="%(asctime)s %(levelname)s %(message)s"
)


class EncryptedDomainLoggerService(win32serviceutil.ServiceFramework):
    _svc_name_ = "EncryptedDomainLoggerService"
    _svc_display_name_ = "Encrypted Domain Logger Service"
    _svc_description_ = "A service that logs HTTPS IP activity and attempts reverse DNS lookups with encrypted and compressed logs."

    def __init__(self, args):
        win32serviceutil.ServiceFramework.__init__(self, args)
        self.hWaitStop = win32event.CreateEvent(None, 0, 0, None)
        self.is_running = True
        self.current_log_index = 1  # 用于日志文件的编号

    def SvcStop(self):
        logging.info("Service is stopping...")
        self.is_running = False
        win32event.SetEvent(self.hWaitStop)

    def SvcDoRun(self):
        logging.info("Service started successfully.")
        self.main()

    def main(self):
        while self.is_running:
            try:
                # 捕获 HTTPS 流量并获取 IP 地址和时间戳
                ip_entries = capture_https_ip_with_timestamp()
                print("ip",ip_entries)
                # 通过 IP 地址反向 DNS 获取域名
                domains = resolve_domains_from_ip(ip_entries)

                # 本地存储加密并分割日志
                log_files = store_and_compress_log(domains)

                # 上传日志到服务器
                upload_logs_to_server(log_files)

            except Exception as e:
                logging.error(f"Error during service execution: {e}")

            # 每隔一段时间执行一次
            sleep(CONFIG["interval_seconds"])


# 捕获 HTTPS 请求中的 IP 地址并附加时间戳
def capture_https_ip_with_timestamp():
    ip_entries = []
    try:
        with pydivert.WinDivert("tcp.DstPort == 80 or tcp.DstPort == 443") as w:
            for packet in w:
                try:
                    if packet.is_outbound and packet.dst_addr:
                        dst_ip = packet.dst_addr
                        timestamp = datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")
                        logging.info(f"Captured IP: {dst_ip} at {timestamp}")
                        ip_entries.append(f"{timestamp} - {dst_ip}")

                    w.send(packet)  # 确保网络流量不中断
                except Exception as e:
                    logging.error(f"Error capturing IP address: {e}")
            # print(ip_entries)
            print(ip_entries)
    except Exception as e:
        logging.error(f"Error capturing HTTPS traffic: {e}")
        print(e)
    return ip_entries


# 通过 IP 地址进行反向 DNS 查询获取域名
def resolve_domains_from_ip(ip_entries):
    domains = []
    for entry in ip_entries:
        try:
            timestamp, ip = entry.split(" - ")
            domain, _, _ = socket.gethostbyaddr(ip)
            logging.info(f"Resolved domain {domain} from IP {ip} at {timestamp}")
            domains.append(f"{timestamp} - {domain}")
            print(domains)
        except socket.herror:
            logging.warning(f"Failed to resolve domain from IP {ip}")
            domains.append(entry)  # 无法解析的 IP 也记录下来
    return domains


# 生成 AES 加密密钥
def generate_key(password: str, salt: bytes) -> bytes:
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=32,
        salt=salt,
        iterations=100000,
        backend=default_backend()
    )
    return base64.urlsafe_b64encode(kdf.derive(password.encode()))


# AES 加密函数
def encrypt_data(data: str, key: bytes) -> bytes:
    padder = padding.PKCS7(128).padder()
    padded_data = padder.update(data.encode()) + padder.finalize()

    iv = os.urandom(16)  # 生成随机的 IV
    cipher = Cipher(algorithms.AES(key), modes.CFB(iv), backend=default_backend())
    encryptor = cipher.encryptor()
    encrypted_data = encryptor.update(padded_data) + encryptor.finalize()

    return iv + encrypted_data  # 返回加密数据包含 IV


# 存储加密日志到本地文件，并压缩日志，支持日志分割
def store_and_compress_log(domains):
    today = datetime.date.today()
    log_dir = os.path.join(CONFIG["log_directory"], str(today))
    os.makedirs(log_dir, exist_ok=True)

    try:
        # 生成 AES 密钥
        salt = os.urandom(16)
        encryption_key = generate_key(CONFIG["encryption_password"], salt)

        # 日志数据加密
        log_data = "\n".join(domains)
        encrypted_log_data = encrypt_data(log_data, encryption_key)

        # 检查文件大小，并分割日志文件
        log_file_base = os.path.join(log_dir, f"captured_domains_part_{self.current_log_index}.enc")
        while os.path.exists(log_file_base) and os.path.getsize(log_file_base) > CONFIG[
            "max_log_size_mb"] * 1024 * 1024:
            self.current_log_index += 1
            log_file_base = os.path.join(log_dir, f"captured_domains_part_{self.current_log_index}.enc")

        # 存储加密日志文件
        with open(log_file_base, "wb") as file:
            file.write(salt + encrypted_log_data)  # 保存 salt 和加密数据

        # 压缩日志文件
        zip_file = os.path.join(log_dir, f"captured_domains_part_{self.current_log_index}.zip")
        with zipfile.ZipFile(zip_file, 'w', zipfile.ZIP_DEFLATED) as zipf:
            zipf.write(log_file_base, arcname=os.path.basename(log_file_base))

        logging.info("Captured domains encrypted, stored, and compressed successfully.")

        # 删除原始加密文件，保留压缩文件
        os.remove(log_file_base)

        return [zip_file]
    except Exception as e:
        logging.error(f"Failed to store and compress logs locally: {e}")
        return []


# 上传日志到服务器
def upload_logs_to_server(log_files):
    if not log_files:
        logging.error("No valid log files to upload.")
        return

    for log_file in log_files:
        try:
            with open(log_file, "rb") as file:
                files = {'file': file}
                response = requests.post(CONFIG["server_url"], files=files)

            if response.status_code == 200:
                logging.info(f"{log_file} uploaded successfully.")
            else:
                logging.error(f"Failed to upload {log_file}: {response.status_code}")
        except Exception as e:
            logging.error(f"Failed to upload log file {log_file}: {e}")


if __name__ == '__main__':
    win32serviceutil.HandleCommandLine(EncryptedDomainLoggerService)