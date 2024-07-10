from .core import Client


class Task(object):

    def __init__(self, agent_info, task_info):
        self.agent_info = agent_info
        self.agent_id = self.agent_info.get('agent_id')
        self.task_info = task_info
        self.task_id = self.task_info.get('id')

        self.ttype = self.task_info.get('ttype')  # baseline_collection
        self.result = None

    def do(self, client):
        proc_method = getattr(self, self.ttype, None)
        if proc_method and callable(proc_method):
            try:
                self.result = proc_method(client)
            except Exception as e:
                print(e)
                self.result = {}
        else:
            print('error ... {proc_method}')
            self.result = {}
        print(f'self.result....{self.result}')
        client.post_task_rs(data={'data': self.result, 'agent_id': self.agent_id, 'task_id': self.task_id})
