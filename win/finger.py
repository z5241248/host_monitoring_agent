import datetime
import winreg

import psutil
import win32com.client
import win32net
from agent_utils import finger_utils


# 获取dns信息（从注册表）
def get_dns_servers():
    interfaces_path = r'SYSTEM\CurrentControlSet\Services\Tcpip\Parameters\Interfaces'
    with winreg.OpenKey(winreg.HKEY_LOCAL_MACHINE, interfaces_path) as interfaces_key:
        dns_servers = []
        for i in range(winreg.QueryInfoKey(interfaces_key)[0]):
            interface_path = winreg.EnumKey(interfaces_key, i)
            with winreg.OpenKey(interfaces_key, interface_path) as interface_key:
                try:
                    dns_server = winreg.QueryValueEx(interface_key, 'NameServer')[0]
                    if dns_server:
                        dns_servers.append(dns_server)
                except WindowsError:
                    pass
    if dns_servers:
        # 去重后返回
        return ",".join(list(set(dns_servers[0].split(','))))
    else:
        return None


# 主机概览
def get_info():
    info = finger_utils.get_info()
    info['DNS'] = get_dns_servers()
    return info


# 获取所有用户
def get_all_users():
    users_info = win32net.NetUserEnum(None, 2)
    users = []
    for user in users_info[0]:
        last_logon_date = ''
        if user['last_logon']:
            last_logon_date = datetime.datetime.fromtimestamp(user['last_logon']).strftime("%Y-%m-%d %H:%M:%S")
        single = {
            'name': user['name'],
            'remark': user['comment'],
            'last_logon': last_logon_date
        }
        users.append(single)
    return users


# 定时任务
def get_scheduled_tasks():
    import xmltodict
    def get_all_tasks(folder, schedule_list):
        tasks = folder.GetTasks(0)
        for task in tasks:
            enabled = task.Enabled
            if enabled:
                try:
                    detail = task.Xml
                    dict_text = xmltodict.parse(detail)
                    # 获取Author
                    author = dict_text['Task']['RegistrationInfo']['Author']
                    exec_text = dict_text['Task']['Actions']['Exec']
                    # 获取Command
                    command = exec_text['Command']
                    # 获取Arguments
                    arguments = exec_text.get('Arguments', '')
                    # 获取路径
                    working_directory = exec_text['WorkingDirectory']
                    single_task = {
                        'name': author,
                        'path': working_directory,
                        'command': command + ' ' + arguments,
                        'last_run_time': task.LastRunTime.strftime("%Y-%m-%d %H:%M:%S"),
                        'next_run_time': task.NextRunTime.strftime("%Y-%m-%d %H:%M:%S"),
                    }
                    schedule_list.append(single_task)
                except:
                    pass
        for folder_name in folder.GetFolders(0):
            get_all_tasks(folder_name, schedule_list)
        return schedule_list

    # 递归调用方法
    scheduler = win32com.client.Dispatch('Schedule.Service')
    scheduler.Connect()
    root_folder = scheduler.GetFolder('\\')
    # 定时任务名单
    schedule_list = []
    task_list = get_all_tasks(root_folder, schedule_list)
    return task_list


# 已装软件
def get_installed_programs():
    installed_programs = []
    hklm = winreg.ConnectRegistry(None, winreg.HKEY_LOCAL_MACHINE)
    for key_path in [r"SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall",
                     r"SOFTWARE\Wow6432Node\Microsoft\Windows\CurrentVersion\Uninstall"]:
        with winreg.OpenKey(hklm, key_path) as key:
            for i in range(0, winreg.QueryInfoKey(key)[0]):
                skey_name = winreg.EnumKey(key, i)
                with winreg.OpenKey(key, skey_name) as skey:
                    try:
                        program = {
                            'name': winreg.QueryValueEx(skey, 'DisplayName')[0],
                            'version': winreg.QueryValueEx(skey, 'DisplayVersion')[0]
                        }
                        installed_programs.append(program)
                    except OSError as e:
                        pass
    return installed_programs


# 指纹数据
def get_finger():
    Info = get_info()
    Ports = finger_utils.get_ports()
    Processes = finger_utils.get_running_processes()
    Users = get_all_users()
    Scheduled = get_scheduled_tasks()
    Software = get_installed_programs()

    data = {
        'Info': Info,
        'Ports': Ports,
        'Processes': Processes,
        'Users': Users,
        'Scheduled': Scheduled,
        'Software': Software
    }
    return data


# 监控数据
def get_system_state():
    system_state = finger_utils.get_system_state('windows')
    return system_state


if __name__ == '__main__':
    tasks = get_scheduled_tasks()
    print()
