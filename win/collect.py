import tempfile
import winreg

from agent_utils.os_utils import *

TEMP_DIR = tempfile.gettempdir()


def collect_rules(conf):
    check_list = conf['check_list']
    checks = [i.get('check') for i in check_list]
    rules = set()

    for check in checks:
        _rules = check.get('rules')
        for _rule in _rules:
            rule_type = _rule.get("type")

            if rule_type == 'secedit':
                coll_key = f'{rule_type}:""'
            else:
                coll_key = f'{rule_type}:{_rule.get("param")[0]}'
            rules.add(coll_key)

    return rules


def collect(coll_rules):
    coll_result = {}
    for rule in coll_rules:
        _type, f = rule.split(':')  # "type:file
        if _type == 'registry':
            _r = read_registry(f)  # 注册表
        elif _type == 'secedit':
            _r = read_secedit()  # 组策略
        else:
            print(_type)
            _r = None
        coll_result[rule] = _r
    return coll_result


def read_registry(reg_path):
    # 注册表路径
    # 检测项
    reg_str_all = reg_path.split('\\')
    hkey_str = reg_str_all[0]
    hkey = getattr(winreg, hkey_str, None)

    reg_key = reg_str_all[-1]
    reg_path = '\\'.join(reg_str_all[1:-1])

    try:
        open_key = winreg.OpenKey(hkey, reg_path)
        value = winreg.QueryValueEx(open_key, reg_key)[0]
        return value
    except:
        return None


def read_secedit():
    out_f = os.path.join(TEMP_DIR, 'gp.inf')
    print(out_f)
    a = os.popen(f"secedit /export /cfg {out_f}")
    a.close()

    with open(out_f, "r", encoding='utf-16') as f:
        data = f.read()
        print(data)
        return data


if __name__ == '__main__':
    # reg_path = 'HKEY_LOCAL_MACHINE\\SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\Winlogon\\AutoAdminLogon'
    # reg_path = 'HKEY_LOCAL_MACHINE\\SYSTEM\\CurrentControlSet\\Control\\Terminal Server\\WinStations\\RDP-Tcp\\PortNumber'
    # reg_path = 'HKEY_LOCAL_MACHINE\\SYSTEM\\ControlSet001\\services\\LanmanServer\\Parameters\\NullSessionPipes'
    # reg_path = 'HKEY_LOCAL_MACHINE\\SYSTEM\\CurrentControlSet\\Control\\Lsa\\Restrictanonymous'
    # open_key = read_registry(reg_path)
    # print(open_key)

    read_secedit()
