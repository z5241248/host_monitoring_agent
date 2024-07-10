from agent_utils.os_utils import *


def collect_rules(conf):
    check_list = conf['check_list']
    checks = [i.get('check') for i in check_list]
    rules = set()

    for check in checks:
        _rules = check.get('rules')
        for _rule in _rules:
            coll_key = f'{_rule.get("type")}:{_rule.get("param")[0]}'
            rules.add(coll_key)

    return rules


def collect(coll_rules):
    coll_result = {}
    for rule in coll_rules:
        _type, f = rule.split(':')  # "type:file
        if _type == 'file_line_check':
            _r = read_file(f)
        elif _type == 'file_permission':
            _r = read_file_permission(f)
        elif _type == 'if_file_exist':
            _r = if_file_exist(f)
        elif _type == 'command_check':
            _r = command_check(f)
        else:
            print(_type)
            _r = None
        print(f'{rule}::::{_r}')
        coll_result[rule] = _r
    return coll_result
