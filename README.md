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