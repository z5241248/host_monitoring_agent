import sys
import time
import uuid
from multiprocessing import Process, freeze_support
from pathlib import Path
from threading import Thread

BASE_DIR = str(Path(__file__).resolve().parent.parent)
sys.path.append(BASE_DIR)

from agent_utils.os_utils import get_system_type
from agent_utils.core import Client

AGENT_ID = uuid.uuid4().hex

AGENT_INFO = {
    'agent_id': AGENT_ID,
    'info': get_system_type()
}

os_type = AGENT_INFO['info'].get('os_type')
if os_type == 'linux':
    from linux.task import LinuxTask as Task
elif os_type == 'win':
    from win.task import WinTask as Task
else:
    raise '不支持的操作系统'


def heartbeat(sec):
    client = Client()
    while True:
        try:
            client.post_heartbeat(data=AGENT_INFO)
        except:
            pass
        time.sleep(sec)


def do_task(task_info, client):
    task_obj = Task(AGENT_INFO, task_info)
    task_obj.do(client)


def task(sec):
    client = Client()
    while True:
        for task_info in client.tasks():
            print("-----------------Execute task-----------------")
            do_task(task_info, client)
            time.sleep(1)


def monitor(sec):
    client = Client()
    while True:
        try:
            # 获取监控数据
            if os_type == 'linux':
                from linux import finger
                state = finger.get_system_state()
            else:
                from win import finger
                state = finger.get_system_state()
            rs = {
                'AgentId': AGENT_ID,
                'DataCreateTime': time.strftime('%Y-%m-%d %H:%M:%S', time.localtime()),
                'OsType': os_type
            }
            state.update(rs)
            print("------------------Send real-time monitoring data-----------------")
            client.post_monitor_data(data=state)
        except:
            pass
        time.sleep(sec)


def main():
    freeze_support()

    # 心跳线程
    t1 = Thread(target=heartbeat, args=(5,))
    t1.start()
    time.sleep(1)  # 等agent_id心跳完成
    print('heartbeat start...')

    # 实例化进程对象，任务列表获取
    p1 = Process(target=task, args=(5,))
    p1.start()
    print('task start...')

    # 监控数据
    # 监控数据采集间隔秒数
    t2 = Thread(target=monitor, args=(30,))
    t2.start()
    print('monitor start...')

    t1.join()
    p1.join()


if __name__ == '__main__':
    main()
