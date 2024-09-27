### 代码功能总结说明：

1. **日志存储与轮转**：
   - 日志存储路径为 `C:\\netLogs\\`，服务按天生成子文件夹，按小时生成日志文件。日志文件大小限制为 10MB，超过后会自动轮转。
   - 轮转后的日志文件会自动压缩成 `.zip` 文件，节省磁盘空间，并保留一定数量的旧日志文件。

2. **日志文件权限控制**：
   - 在日志目录创建时，使用 Windows 的 `icacls` 命令将权限设置为只有管理员组可以访问，保证日志文件的安全性。
   - 每次创建新的日志文件夹时，都会自动调用权限设置函数，确保日志文件无法被非管理员用户访问。

3. **数据包捕获**：
   - 使用 `scapy` 捕获所有 TCP 和 UDP 网络流量。捕获到的数据包包括源 IP、目标 IP、源端口、目标端口、时间戳等信息。
   - 日志中记录了 HTTP 和 HTTPS 请求的相关信息。对于 HTTP 请求，能够捕获并记录目标 URL。

4. **日志异步上传**：
   - 通过异步线程池和队列机制管理日志文件的上传，避免阻塞服务的主线程。
   - 上传失败时会进行多次重试，使用指数退避策略来延长重试等待时间，从而减少网络波动对上传的影响。
   - 每 10 分钟自动调度上传一次当前日志文件。

5. **Windows 服务管理**：
   - 该程序以 Windows 服务的形式运行，可以通过 `install`、`start`、`stop` 和 `remove` 命令来进行服务管理操作。
   - 该服务在后台运行时不会干扰用户操作，并且会在系统启动时自动启动。

6. **守护线程管理**：
   - 日志处理、数据包捕获以及上传日志文件都在后台守护线程中运行，确保服务的流畅性，主线程负责调度和整体控制。

### 代码执行流程：

1. **启动服务**：通过命令行启动服务，日志文件开始创建，网络流量捕获开始。
2. **日志捕获与记录**：捕获到的 TCP 和 UDP 网络流量信息被写入日志文件。每小时生成一个新的日志文件，超过 10MB 的日志文件会自动轮转并压缩。
3. **权限控制**：每次创建日志文件夹时，确保日志文件夹只有管理员组才能访问，防止未经授权的访问。
4. **日志上传**：每 10 分钟通过异步线程将日志文件上传到指定的服务器路径，确保日志被安全备份和存储。
5. **服务管理**：可以随时通过命令停止或卸载服务，服务会优雅地关闭并完成未处理的任务。

### 使用方式：

1. **安装服务**：通过 `netlogger_service.exe install` 命令安装服务。
2. **启动服务**：通过 `netlogger_service.exe start` 命令启动服务，开始捕获网络流量并记录日志。
3. **停止服务**：通过 `netlogger_service.exe stop` 命令停止服务。
4. **卸载服务**：通过 `netlogger_service.exe remove` 命令卸载服务。

### 关键功能：

- **网络流量捕获**：记录客户端的 TCP 和 UDP 网络流量。
- **日志管理**：自动轮转与压缩日志文件，节省空间。
- **权限控制**：确保日志文件安全，只有管理员组可以访问。
- **异步上传**：通过异步队列上传日志文件到服务器，并带有重试机制。
- **Windows 服务**：服务化，自动化后台运行，支持标准的服务操作。

该代码能够帮助你捕获客户端的网络访问日志并安全地存储和上传，确保日志数据的安全和完整性。
**<h3>Python 安装运行服务</h3>**

# 1.安装服务

<pre><code>python NetworkLoggerService.py install</code></pre>

# 2.让服务自动启动

<pre><code>python NetworkLoggerService.py --startup auto install</code></pre>

# 3.启动服务

<pre><code>python NetworkMonitorService.py start</code></pre>

# 4.重启服务

<pre><code>python NetworkLoggerService.py restart</code></pre>

# 5.停止服务

<pre><code>python NetworkLoggerService.py stop</code></pre>

# 6.删除/卸载服务

<pre><code>python NetworkLoggerService.py remove</code></pre>

**<h3>打包为可执行文件</h3>**

您可以使用之前提到的PyInstaller来将此脚本打包为一个Windows可执行文件：
<pre><code>pyinstaller --onefile --hidden-import=win32timezone NetworkLoggerService.py</code></pre>

**<h3>可执行文件安装和运行服务</h3>**
安装服务
<pre><code>NetworkLoggerService.exe install</code></pre>
启动服务
<pre><code>NetworkLoggerService.exe start</code></pre>