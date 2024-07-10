from ..agent_utils.os_utils import get_file_lines, command_check
from ..agent_utils.host_check_passwd import verify_weak

# 检测linux的弱口令工具
def proc():
    f_lines = get_file_lines("/etc/passwd")
    m = {}
    for line in f_lines:
        fields = line.split(":")
        if len(fields) == 0:
            continue
        padding = len(fields)
        for _ in range(7 - padding):
            fields.append("")

        u = {
            'Username': fields[0],
            'Password': fields[1],
            'Uid': fields[2],
            'Gid': fields[3],
            'Info': fields[4],
            'Home': fields[5],
            'Shell': fields[6],
            # 'Groupname': agent_utils.GetGroupname(fields[3])    # TODO
        }
        m[fields[0]] = u

    # f_lines = get_file("/var/log/wtmp")
    # u.LastLoginIP = net.IP(ip).String()
    # u.LastLoginTime = strconv.FormatInt(int64(l.Time.Sec), 10)

    f_lines = get_file_lines("/etc/shadow")
    for line in f_lines:
        fields = line.split(":")
        if len(fields) < 2:
            continue
        u = m.get(fields[0])
        if u:
            if '*' in fields[1] or '!' in fields[1]:
                u.WeakPassword, u.WeakPasswordContent = "false", ""
            else:
                u.WeakPassword, u.WeakPasswordContent = verify_weak(fields[1])

    for k, v in m.items():
        command = f"sudo -l -U {k}"

        output = command_check(command)
        idx = output.index("may run the following commands")
        if idx > 0:
            output = output[idx:]
            _idx = output.index(':')

            if _idx > 0 and len(output) > _idx + 1:
                output = output[idx + 1:]
                m[k]['Sudoers'] = output
    return m

if __name__ == '__main__':
    print(proc())