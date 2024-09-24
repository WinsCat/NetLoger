import subprocess
import time
import re

def get_network_connections():
    # 调用 netstat 命令
    result = subprocess.check_output(['netstat', '-an'], text=True)

    # 使用正则表达式解析 netstat 输出
    connections = []
    for line in result.splitlines():
        if re.match(r'^\s*TCP', line):
            parts = line.split()
            local_address = parts[1]
            remote_address = parts[2]
            state = parts[3]

            if state == 'ESTABLISHED':  # 获取已建立连接
                local_ip, local_port = local_address.rsplit(':', 1)
                remote_ip, remote_port = remote_address.rsplit(':', 1)
                timestamp = time.strftime("%Y-%m-%d %H:%M:%S", time.localtime())
                connections.append({
                    'timestamp': timestamp,
                    'local_ip': local_ip,
                    'local_port': local_port,
                    'remote_ip': remote_ip,
                    'remote_port': remote_port
                })
    return connections
def log_connections():
    while True:
        connections = get_network_connections()
        with open("network_log.txt", "a") as logfile:
            for conn in connections:
                log_entry = (f"Time: {conn['timestamp']}, Local IP: {conn['local_ip']}:{conn['local_port']}, "
                             f"Remote IP: {conn['remote_ip']}:{conn['remote_port']}\n")
                logfile.write(log_entry)
        time.sleep(5)  # 每隔60秒执行一次


# log_connections()
# 打印网络连接信息
connections = get_network_connections()
for conn in connections:

    print(f"Time: {conn['timestamp']}, Local IP: {conn['local_ip']}:{conn['local_port']}, "
          f"Remote IP: {conn['remote_ip']}:{conn['remote_port']}")