from agent_utils.task import Task
from win.finger import get_finger, get_system_state

class WinTask(Task):

    def finger_collection(self, client):
        return get_finger()

    def monitor_collection(self, client):
        return get_system_state()
