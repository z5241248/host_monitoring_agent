from agent_utils.task import Task
from linux.collect import collect_rules, collect
from linux.finger import get_finger, get_system_state


class LinuxTask(Task):

    def finger_collection(self, client):
        return get_finger()

    def monitor_collection(self, client):
        return get_system_state()
