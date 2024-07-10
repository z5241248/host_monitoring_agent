from agent_utils.parse_yaml import load_yaml_file

class Client(object):
    def __init__(self, host=None):
        self.host = host

    # 心跳数据
    def post_heartbeat(self, data=None):
        print('----------------模拟与服务端保持心跳----------------')
        print(data)

    # 单个任务结果数据
    def post_task_rs(self, data):
        print(data)

    # 待执行的任务清单（这里使用yaml文件模拟了两种不同的类型）
    def tasks(self, data=None):
        return load_yaml_file('tasks.yaml').get('tasks')

    # 发送监控数据
    def post_monitor_data(self, data):
        print('----------------监控数据发送到服务端存储----------------')
        print(data)
