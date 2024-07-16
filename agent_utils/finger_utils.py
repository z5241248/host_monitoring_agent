import datetime
import platform
import socket
import subprocess
import netifaces
import time
import psutil


# 实时磁盘IO（KB）、网络IO信息（KB）
def get_real_time_io_info():
    # 获取磁盘IO信息
    disk_io = psutil.disk_io_counters()
    old_read_bytes = disk_io.read_bytes
    old_write_bytes = disk_io.write_bytes
    # 获取网络IO信息
    net_io = psutil.net_io_counters()
    old_bytes_sent = net_io.bytes_sent
    old_bytes_recv = net_io.bytes_recv
    # 等待
    time.sleep(1)
    # 再次获取磁盘IO信息
    disk_io = psutil.disk_io_counters()
    new_read_bytes = disk_io.read_bytes
    new_write_bytes = disk_io.write_bytes
    # 再次获取网络IO信息
    net_io = psutil.net_io_counters()
    new_bytes_sent = net_io.bytes_sent
    new_bytes_recv = net_io.bytes_recv
    # 计算每秒的IO量（转换为KiB并保留2位小数）
    # 磁盘
    read_bytes_per_second = round(abs((new_read_bytes - old_read_bytes)) / 1024, 2)
    write_bytes_per_second = round(abs((new_write_bytes - old_write_bytes)) / 1024, 2)
    # 网络
    bytes_sent_per_second = round(abs(new_bytes_sent - old_bytes_sent) / 1024, 2)
    bytes_recv_per_second = round(abs(new_bytes_recv - old_bytes_recv) / 1024, 2)
    return [read_bytes_per_second, write_bytes_per_second, bytes_sent_per_second, bytes_recv_per_second]


# 性能监控
def get_system_state(system):
    # CPU使用率
    global single
    cpu_percent = psutil.cpu_percent(interval=1)
    # 获取内存信息（MB）
    memory_info = psutil.virtual_memory()
    total_memory = round(memory_info.total / (1024 ** 2), 2)
    used_memory = round(memory_info.used / (1024 ** 2), 2)
    memory_percent = round(memory_info.used / memory_info.total * 100, 2)
    # 获取磁盘信息（MB）
    total_disk = 0
    used_disk = 0
    all_disk = psutil.disk_partitions()
    for single_disk in all_disk:
        if system == 'windows':
            if single_disk.fstype:
                single = psutil.disk_usage(single_disk.device)
        else:
            single = psutil.disk_usage(single_disk.mountpoint)
        try:
            total_disk += single.total / (1024 ** 2)
            used_disk += single.used / (1024 ** 2)
        except:
            pass
    disk_use_percent = round(used_disk / total_disk, 2)
    # 调用方法获取磁盘、网络IO信息（KB）
    io_info = get_real_time_io_info()
    # 磁盘IO信息（KB）
    read_bytes = io_info[0]
    write_bytes = io_info[1]
    # 获取网络IO信息（KB）
    bytes_sent = io_info[2]
    bytes_recv = io_info[3]
    # 系统时间
    current_time = datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    return {
        'Cpu': cpu_percent,
        'Memory': memory_percent,
        'MemoryTotal': total_memory,
        'MemoryUsed': used_memory,
        'DiskTotal': round(total_disk, 2),
        'DiskUsed': round(used_disk, 2),
        'DiskUsePer': disk_use_percent,
        'DiskReadBytes': read_bytes,
        'DiskWriteBytes': write_bytes,
        'NetSentBytes': bytes_sent,
        'NetRecvBytes': bytes_recv,
        'Time': current_time,
    }


# 开放端口
def get_ports():
    process_str = ''
    type_map = {
        socket.SOCK_STREAM: 'TCP',
        socket.SOCK_DGRAM: 'UDP',
        socket.SOCK_RAW: 'RAW',
        socket.SOCK_RDM: 'RDM',
        socket.SOCK_SEQPACKET: 'SEQPACKET',
    }
    connections = psutil.net_connections()
    ports = []
    for conn in connections:
        net_id = type_map.get(conn.type, 'UNKNOWN')
        try:
            process = psutil.Process(conn.pid)
            if process is not None:
                process_str = "Pid: " + str(process.pid) + " Name: " + process.name() + " Status: " + process.status()
            port = {
                'Netid': net_id,
                'State': conn.status,
                'Local': f'{conn.laddr[0]}:{conn.laddr[1]}',
                'Process': process_str,
            }
            ports.append(port)
        except:
            continue
    return ports


# 获取所有进程
def get_running_processes():
    processes = []
    for proc in psutil.process_iter(['pid', 'name', 'username']):
        processes.append(proc.info)
    return processes

# 获取ipv4和ipv6
def get_ip_addresses():
    ip_addresses = {'IPv4': [], 'IPv6': []}
    for interface in netifaces.interfaces():
        addresses = netifaces.ifaddresses(interface)
        # 获取IPv4地址
        if netifaces.AF_INET in addresses:
            for addr in addresses[netifaces.AF_INET]:
                ip_addresses['IPv4'].append(addr['addr'])
        # 获取IPv6地址
        if netifaces.AF_INET6 in addresses:
            for addr in addresses[netifaces.AF_INET6]:
                ip_addresses['IPv6'].append(addr['addr'])
    return ip_addresses

# 主机概览数据
def get_info():
    # 主机名称
    hostname = socket.gethostname()
    ip_addresses = get_ip_addresses()
    try:
        private_ipv4 = ",".join(ip_addresses['IPv4'])
    except:
        private_ipv4 = None
    try:
        private_ipv6 = ",".join(ip_addresses['IPv6'])
    except:
        private_ipv6 = None
    # 网关IP
    gws = netifaces.gateways()
    try:
        default_gateway = gws['default'][netifaces.AF_INET][0]
        subprocess.run(["ping", "-w", "2", "www.baidu.com"], check=True)
        ping_status = True
    except:
        default_gateway = None
        ping_status = False
    # 磁盘
    space_total = 0
    space_free = 0
    partitions = psutil.disk_partitions()
    for par in partitions:
        try:
            device = psutil.disk_usage(par.device)
            space_total += device.total
            space_free += device.free
        except:
            continue
    return {
        'Hostname': hostname,
        'System': platform.system() + " " + platform.release(),
        'Version': platform.uname().version,
        'Arch': platform.machine(),
        'MemTotal': str(round(psutil.virtual_memory().total / (1024 ** 3), 2)) + 'G',
        'MemFree': str(round(psutil.virtual_memory().available / (1024 ** 3), 2)) + 'G',
        'SpaceTotal': str(round(space_total / (1024 ** 3), 2)) + 'G',
        'SpaceFree': str(round(space_free / (1024 ** 3), 2)) + 'G',
        'Cpu': platform.processor(),
        'CpuPhysical': psutil.cpu_count(logical=False),
        'CpuCore': psutil.cpu_count(logical=True),
        'Ipv4': private_ipv4,
        'Ipv6': private_ipv6,
        'Gateway': default_gateway,
        'CpuUseRatio': psutil.cpu_percent(interval=1),
        'MemUseRatio': psutil.virtual_memory().percent,
        'SystemStartupDate': time.strftime('%Y-%m-%d %H:%M:%S', time.localtime(psutil.boot_time())),
        'Ping': ping_status
    }


if __name__ == '__main__':
    print(get_info())