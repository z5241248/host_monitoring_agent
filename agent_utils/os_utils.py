import os
import stat
import subprocess
import sys
import socket
from agent_utils.except_wrap import catch_except


def get_system_type():
    os_type = sys.platform
    platform = os_type
    if os_type.startswith('linux'):
        os_type = 'linux'
        platform = get_linux_type()
    elif os_type.startswith('win'):
        os_type = 'win'
    return {
        'os_type': os_type,
        'platform': platform,
        'hostname': get_hostname()
    }


def get_hostname():
    return socket.gethostname()


def get_linux_type():
    cmd = "uname -a"
    cmd_rs = command_check(cmd)
    if 'Ubuntu' in cmd_rs:
        return "ubuntu"
    if 'Debian' in cmd_rs:
        return "debian"
    else:
        return "centos"


@catch_except()
def read_file(fp):
    with open(fp, 'r', encoding='utf-8') as f:
        return f.read()


@catch_except()
def get_file_lines(fp):
    with open(fp, 'r') as f:
        return f.readlines()


@catch_except()
def read_file_permission(f):
    filestat = os.stat(f)
    mode = filestat.st_mode
    # return oct(stat.S_IMODE(mode))
    return mode


@catch_except()
def if_file_exist(f):
    return os.path.exists(f)


@catch_except()
def command_check(cmd):
    return subprocess.getoutput(cmd)
