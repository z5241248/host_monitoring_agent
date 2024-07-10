## 主机安全巡检工具

### 简介
这是一个资产巡检的客户端程序，核心是扫描和监控资产信息，包含Windows和Linux机器的```指纹数据获取```、```实时数据监控```，可用于HVV、重保等安全项目实施前的资产巡检。

### 支持的操作系统
Windows、Linux

### 功能概览
#### Windows
概况
![win_profile.png](profile_img%2Fwin_profile.png)
性能监控
![win_monitor.png](profile_img%2Fwin_monitor.png)
资产指纹
![win_finger1.png](profile_img%2Fwin_finger1.png)


#### Linux
除了windows固有的功能外，还有```安全策略核查功能```项
![linux_finger1.png](profile_img%2Flinux_finger1.png)

### 使用说明
推荐使用python3.6（为了方便使用PyInstaller打包成单独可运行文件）；

如果只是运行源码，那么python版本没有硬性要求。

### 二次开发
对于二次开发，你可以修改agent_utils下的core.py，将数据发送到你的存储地址。

本项目有2种功能，即```指纹数据获取```、```实时数据监控```，对应的ttype为：```指纹数据获取（finger_collection）```、```实时数据监控（monitor_collection）```。

当前数据来自于tasks方法，目前是读取的文件，你可以改成远程请求某个地址。

### 使用PyInstaller
在Windows或Linux运行：```pyinstaller main.spec```