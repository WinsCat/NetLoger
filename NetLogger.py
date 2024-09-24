# Copyright (C) 2023-2024 iSeeNEw Studio, Inc. All Rights Reserved 
#
# @Time    : 15/9/24 PM9:20
# @Author  : Wins
# @Email   : cn.lazycat@gmail.com
# @File    : NetLogger.py
# @Software: PyCharm
# @Desc    : 网络访问日志服务

import os
import subprocess
import datetime
import sys
# from scapy.all import *

import requests
import re
from time import sleep
import pydivert
import win32serviceutil
import win32service
import win32event
import servicemanager
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import padding
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives import hashes
import base64
import logging

# 配置文件路径
CONFIG = {
    "password": "Ronghui123",  # 替换为你自己的安全密码
    "server_url": "http://your-server-url/upload",  # 替换为服务器上传地址
    "log_directory": "./logs",  # 本地日志存储位置
    "interval_seconds": 10,  # 日志上传间隔时间，单位秒（1小时）
    "log_file": "service_log.txt",  # 服务运行时的日志文件
}

# 配置日志记录
logging.basicConfig(
    filename=CONFIG["log_file"],
    level=logging.INFO,
    format="%(asctime)s %(levelname)s %(message)s"
)


class NetworkLoggerService(win32serviceutil.ServiceFramework):
    _svc_name_ = "NetworkLoggerService"
    _svc_display_name_ = "Network Logger Service"
    _svc_description_ = "融汇Turing小组出品，客户端网络访问日志获取服务"

    def __init__(self, args):
        win32serviceutil.ServiceFramework.__init__(self, args)
        self.hWaitStop = win32event.CreateEvent(None, 0, 0, None)
        self.is_running = True

    def SvcStop(self):
        logging.info("Service is stopping...")
        self.is_running = False
        win32event.SetEvent(self.hWaitStop)

    def SvcDoRun(self):
        logging.info("Service started successfully.")
        self.main()

    def main(self):
        salt = os.urandom(16)
        encryption_key = generate_key(CONFIG["password"], salt)

        while self.is_running:
            try:
                # 捕获网络端口信息
                port_data = capture_network_ports()
                print("捕获网络端口信息",port_data)
                # 捕获 HTTP 请求中的 URL
                url_data = capture_http_requests()
                print("捕获 HTTP 请求中的 URL", url_data)
                # 本地存储加密日志
                log_files = store_log_locally_encrypted(port_data, url_data, encryption_key)
                print("本地存储加密日志", log_files)
                # 上传日志到服务器
                # upload_logs_to_server(log_files)

            except Exception as e:
                logging.error(f"Error during service execution: {e}")

            # 每隔一段时间执行一次
            sleep(CONFIG["interval_seconds"])


# 生成密钥
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

    iv = os.urandom(16)
    cipher = Cipher(algorithms.AES(key), modes.CFB(iv), backend=default_backend())
    encryptor = cipher.encryptor()
    encrypted_data = encryptor.update(padded_data) + encryptor.finalize()

    return base64.urlsafe_b64encode(iv + encrypted_data)


# 捕获所有网络端口信息
def capture_network_ports():
    try:
        result = subprocess.run(['netstat', '-an'], stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
        if result.returncode != 0:
            raise Exception(result.stderr)
        logging.info("Successfully captured network port data.")
        # print(result.stdout)
        print("Successfully captured network port data.")
        return result.stdout
    except Exception as e:
        logging.error(f"Failed to capture network ports: {e}")
        return ""


# 捕获 HTTP 请求中的 URL
def capture_http_requests():
    urls = []
    try:
        with pydivert.WinDivert("tcp.DstPort == 80 or tcp.DstPort == 443") as w:
            print(w)
            for packet in w:
                try:
                    payload = packet.payload.decode('utf-8', errors='ignore')
                    match = re.search(r'Host: ([^\r\n]+)', payload)
                    if match:
                        host = match.group(1)
                        urls.append(f"http://{host}")
                    w.send(packet)
                    # print("payload",payload)
                    print("packet",packet.dst_addr,packet.dst_port,str(packet.payload))
                    print("urls",urls)
                except Exception as e:
                    logging.error(f"Failed to parse packet: {e}")

        logging.info("Successfully captured HTTP requests.")
        print("Successfully captured HTTP requests.")
    except Exception as e:
        logging.error(f"Failed to capture HTTP requests: {e}")
    return urls


# 存储加密日志到本地文件
def store_log_locally_encrypted(port_data, url_data, encryption_key):
    try:
        today = datetime.date.today()
        log_dir = os.path.join(CONFIG["log_directory"], str(today))
        os.makedirs(log_dir, exist_ok=True)

        # 加密端口信息
        encrypted_port_data = encrypt_data(port_data, encryption_key)
        port_log_file = os.path.join(log_dir, "port_log.txt.enc")
        with open(port_log_file, "wb") as file:
            file.write(encrypted_port_data)

        # 加密 URL 信息
        encrypted_url_data = encrypt_data("\n".join(url_data), encryption_key)
        url_log_file = os.path.join(log_dir, "url_log.txt.enc")
        with open(url_log_file, "wb") as file:
            file.write(encrypted_url_data)

        logging.info("Logs stored locally and encrypted successfully.")
        return port_log_file, url_log_file
    except Exception as e:
        logging.error(f"Failed to store logs locally: {e}")
        return None, None


# 上传日志到服务器
def upload_logs_to_server(log_files):
    if not log_files or not all(log_files):
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
        # 如果修改过名字，名字要统一
        win32serviceutil.HandleCommandLine(NetworkLoggerService)
