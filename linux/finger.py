import hashlib
import json
import os
import os.path
import pwd
import re
from collections import namedtuple
from pathlib import Path

import distro

from agent_utils import finger_utils
from agent_utils.os_utils import command_check


def get_quality():
    if os.path.exists('/etc/security/pwquality.conf'):
        _file = '/etc/security/pwquality.conf'
    else:
        _file = '/etc/pam.d/common-password'
    return {
        'PwQualityConf': command_check("""cat """ + _file + """ | grep -v "^#"|grep -v "^$" """),
        'MinLen': command_check(
            """grep '^[^#]' """ + _file + """ |grep "minlen"|awk -F= '{print $2}'"""),
        'DCredit': command_check(
            """grep '^[^#]' """ + _file + """ |grep "dcredit"|awk -F= '{print $2}'"""),
        'UCredit': command_check(
            """grep '^[^#]' """ + _file + """ |grep "ucredit"|awk -F= '{print $2}'"""),
        'LCredit': command_check(
            """grep '^[^#]' """ + _file + """ |grep "lcredit"|awk -F= '{print $2}'"""),
        'OCredit': command_check(
            """grep '^[^#]' """ + _file + """ |grep "ocredit"|awk -F= '{print $2}'"""),
        'MinClass': command_check(
            """grep '^[^#]' """ + _file + """ |grep "minclass"|awk -F= '{print $2}'"""),
        'MaxRepeat': command_check(
            """grep '^[^#]' """ + _file + """ |grep "maxrepeat"|awk -F= '{print $2}'"""),
        'MaxSequence': command_check(
            """grep '^[^#]' """ + _file + """ |grep "maxsequence"|awk -F= '{print $2}'"""),
    }


def get_users():
    # 通过 / etc / passwd    以及结合chage命令获取用户基本信息
    users = []
    for v in command_check("cat /etc/passwd").split("\n"):
        userinfo = v.split(":")
        if len(userinfo) != 7:
            continue

        login = False
        if userinfo[6] in ("/bin/bash", "/bin/zsh"):
            login = True

        shadow = command_check(f"chage -l {userinfo[0]}").replace("：", ":").split("\n")

        if len(shadow) < 7:
            continue

        passwdstatus = command_check(f"passwd -S {userinfo[0]}").split(" ")
        passwdremark = "".join(passwdstatus[7:]).replace("\n", "")
        user = {
            'name': userinfo[0],
            'passwd': passwdstatus[1],
            'remark': passwdremark,
            'uid': userinfo[2],
            'gid': userinfo[3],
            'pwd': userinfo[5],
            'bash': userinfo[6],
            'login': login,
            'lastPasswd': shadow[0].split(":")[1],
            'passwdExpired': shadow[1].split(":")[1],
            'userExpired': shadow[3].split(":")[1],
            'maxPasswd': shadow[5].split(":")[1],
        }
        users.append(user)
    return users


def get_groups():
    # 组信息
    groups = []
    for v in command_check("cat /etc/group").split("\n"):
        if len(v.split(":")) != 4:
            continue

        group = {
            'Name': v.split(":")[0],
            'Password': v.split(":")[1],
            'Gid': v.split(":")[2],
            'UserList': v.split(":")[3],
        }
        groups.append(group)
    return groups


def get_create_user():
    # 读取/etc/login.defs获取新创建用户时的信息
    return {
        'PassMaxDays': command_check(
            """cat /etc/login.defs |grep -v "^#" |grep "PASS_MAX_DAYS"|awk -F " " '{print $2}'"""),
        'PassMinDays': command_check(
            """cat /etc/login.defs |grep -v "^#" |grep "PASS_MIN_DAYS"|awk -F " " '{print $2}'"""),
        'PassWarnAge': command_check(
            """cat /etc/login.defs |grep -v "^#" |grep "PASS_WARN_AGE"|awk -F " " '{print $2}'"""),
        'UMASK': command_check("""cat /etc/login.defs |grep -v "^#" |grep "UMASK"|awk -F " " '{print $2}'"""),
        'EncryptMethod': command_check(
            """cat /etc/login.defs |grep -v "^#" |grep "ENCRYPT_METHOD"|awk -F " " '{print $2}'"""),
    }


# def get_ports():
#     通过ss -tulnp获取端口信息
#     ports = []
#     for p in command_check("""ss -tulnp|grep -v "Netid" """).split("\n"):
#         listen = re.sub("\s+", " ", p).split(" ")
#
#         if len(listen) < 7:
#             continue
#
#         port = {
#             'Netid': listen[0],
#             'State': listen[1],
#             'Local': listen[4],
#             'Process': listen[6],
#         }
#         ports.append(port)
#     return ports


def get_ssh():
    # 获取sshd_config配置
    PasswordAuthentication = True
    if 'no' in command_check(
            """cat /etc/ssh/sshd_config|grep -v "^#" |grep "PasswordAuthentication"|awk -F " " '{print $2}'"""):
        PasswordAuthentication = False

    PermitRootLogin = True
    if 'no' in command_check(
            """cat /etc/ssh/sshd_config|grep -v "^#" |grep "PermitRootLogin"|awk -F " " '{print $2}'"""):
        PermitRootLogin = False

    PermitEmptyPasswords = False
    if 'yes' in command_check(
            """cat /etc/ssh/sshd_config|grep -v "^#" |grep "PermitEmptyPasswords"|awk -F " " '{print $2}'"""):
        PermitEmptyPasswords = True

    Protocol = "SSHV2"
    _Protocol = command_check("""cat /etc/ssh/sshd_config|grep -v "^#" |grep "Protocol"|awk -F " " '{print $2}'""")
    Protocol = _Protocol if _Protocol != '' else Protocol

    MaxAuthTries = "6"
    _MaxAuthTries = command_check(
        """cat /etc/ssh/sshd_config|grep -v "^#" |grep "MaxAuthTries"|awk -F " " '{print $2}'""")
    MaxAuthTries = _MaxAuthTries if _MaxAuthTries != '' else MaxAuthTries

    PubkeyAuthentication = True
    if "no" in command_check(
            """cat /etc/ssh/sshd_config|grep -v "^#" |grep "PubkeyAuthentication"|awk -F " " '{print $2}'"""):
        PubkeyAuthentication = False

    return {
        'PasswordAuthentication': PasswordAuthentication,
        'PermitRootLogin': PermitRootLogin,
        'PermitEmptyPasswords': PermitEmptyPasswords,
        'Protocol': Protocol,
        'MaxAuthTries': MaxAuthTries,
        'PubkeyAuthentication': PubkeyAuthentication
    }


def get_file_permission():
    # 文件权限
    FilePers = []
    FileList = ["/etc/passwd", "/etc/shadow", "/etc/group", "/etc/rsyslog.conf", "/etc/sudoers", "/etc/hosts.allow",
                "/etc/hosts.deny", "/etc/ssh/sshd_config", "/etc/pam.d/sshd", "/etc/pam.d/passwd", "/var/log/messages",
                "/var/log/audit/audit.log", "/etc/security/pwquality.conf", "/usr/lib64/security/pam_pwquality.so",
                "/etc/resolv.conf", "/etc/fstab", "/etc/sysctl.conf", "/etc/selinux/config", "/etc/sysctl.conf",
                "/etc/audit/auditd.conf"]
    for name in FileList:
        Permission, Size, Uid, Gid, LastReadTime, LastWriteTime = '', '', '', '', '', ''
        if os.path.exists(name):
            Permission, Size, Uid, Gid, LastReadTime, LastWriteTime = command_check(
                f"stat -c '%a ... %s ... %U ... %G ... %x ... %y' {name} ").split(' ... ')

        FilePer = {
            'Name': name,
            'Permission': Permission,
            'Size': Size,
            'Uid': Uid,
            'Gid': Gid,
            'LastReadTime': LastReadTime.split('.')[0] if LastReadTime else LastReadTime,
            'LastWriteTime': LastWriteTime.split('.')[0] if LastWriteTime else LastWriteTime,
        }
        FilePers.append(FilePer)
    return FilePers


def get_dns_servers():
    dns_servers = []
    with open('/etc/resolv.conf', 'r') as f:
        content = f.read()
        dns_pattern = re.compile(r'nameserver\s+(\S+)')
        matches = dns_pattern.findall(content)
        for match in matches:
            dns_servers.append(match)
    return dns_servers


def get_info():
    info = finger_utils.get_info()
    # dns
    dns = get_dns_servers()
    if dns:
        info['DNS'] = ",".join(dns)
    return info


def get_pam():
    pam_system_file = '/etc/pam.d/system-auth'
    if not os.path.exists(pam_system_file):
        pam_system_file = '/etc/pam.d/common-auth'

    return {
        'PamSSH': command_check("""cat /etc/pam.d/sshd|grep -v "^#"|grep -v "^$" """),
        'PamSystem': command_check("""cat """ + pam_system_file + """ |grep -v "^#"|grep -v "^$" """),
        'PamPasswd': command_check("""cat /etc/pam.d/passwd|grep -v "^#"|grep -v "^$" """),
    }


def get_log_info():
    return {
        'Rsyslog': command_check("""cat /etc/rsyslog.conf|grep -v "^#"|grep -v "^$" """),
        'HeadLog': command_check(
            """head -n 10 /var/log/messages /var/log/secure /var/log/audit/audit.log /var/log/yum.log /var/log/cron"""),
        'TailLog': command_check(
            """tail -n 10 /var/log/messages /var/log/secure /var/log/audit/audit.log /var/log/yum.log /var/log/cron"""),
        'Logrotate': command_check(
            """awk 'FNR==1 {if(NR!=1) print "File: " FILENAME; else print "File: " FILENAME} {if ($0 !~ /^#/ && $0 !~ /^$/) print $0}' /etc/logrotate.conf /etc/logrotate.d/* """),
        # noqa
        'LastLog': command_check("lastlog | grep -v '\*\*Never logged in\*\*'"),
    }


def get_installed_programs():
    packages = []
    dist = distro.linux_distribution()[0].lower()
    if 'debian' in dist or 'ubuntu' in dist:
        cmd = "dpkg -l | tail -n +6 | awk '{print $2\", \" $3}'"
    elif 'centos' in dist or 'fedora' in dist or 'red hat' in dist:
        cmd = 'rpm -qa --queryformat \'%{NAME}, %{VERSION}\n\''
    else:
        return packages
    process = command_check(cmd)
    # output = process.stdout.decode('utf-8')
    lines = process.strip().split('\n')
    for line in lines:
        split = line.split(",")
        if len(split) >= 2:
            single_software = {
                'name': split[0].strip(),
                'version': split[1].strip()
            }
            packages.append(single_software)
    return packages


def get_scheduled_tasks():
    Crontab = namedtuple('Crontab', ['path', 'username', 'schedule', 'command', 'checksum'])
    crontabs = []
    paths = [Path('/var/spool/cron').glob('*'), Path('/etc/cron.d').glob('*')]
    for pathlist in paths:
        for path in pathlist:
            if path.is_file():
                username = pwd.getpwuid(path.stat().st_uid).pw_name if '/var/spool/cron' in str(path) else None
                try:
                    with open(path, 'r') as f:
                        content = f.read()
                except Exception as e:
                    print(f"Error reading file {path}: {e}")
                    continue

                md5 = hashlib.md5(content.encode()).hexdigest()
                lines = content.split('\n')

                for line in lines:
                    line = line.strip()
                    if line == "" or line.startswith("#"):
                        continue

                    c = Crontab(
                        path=str(path),
                        username=username if username else os.path.basename(str(path)),
                        checksum=md5,
                        schedule='',  # 设置默认值
                        command='',  # 设置默认值
                    )

                    fields = line.split()
                    if line.startswith("@"):
                        c = c._replace(schedule=fields[0], command=' '.join(fields[1:]))
                    else:
                        c = c._replace(schedule=' '.join(fields[:5]), command=' '.join(fields[5:]))
                    c = dict(c._asdict())
                    crontabs.append(c)
    return crontabs


def get_finger():
    # 读取地址限制
    HostAllow = {
        'Name': '/etc/hosts.allow',
        'Value': command_check(""" cat /etc/hosts.allow |grep -v "^#" |grep -v "^$" """)
    }
    HostDeny = {
        'Name': '/etc/hosts.Deny',
        'Value': command_check(""" cat /etc/hosts.Deny |grep -v "^#" |grep -v "^$" """),
    }
    Hosts = [HostAllow, HostDeny]

    # 防火墙 selinux状态
    FireWallds = []
    FireWallds.append({
        'Name': "firewalld",
        'Status': command_check("""systemctl status firewalld  |grep "Active"|awk -F " " '{print $2}'""")
    })
    FireWallds.append({
        'Name': "selinux",
        'Status': command_check(
            """cat /etc/selinux/config |grep -v "^#"|grep -v "^$"|awk -F 'SELINUX=' '{print $2}'"""),
    })

    return {
        'Info': get_info(),
        'Quality': get_quality(),
        'Address': command_check("ifconfig"),
        'Disk': command_check("df -h"),
        'Dns': command_check("""cat /etc/resolv.conf|grep -v "^#"|grep -v "^$" """),
        'SSHAuthorized': command_check("""cat /root/.ssh/authorized_keys"""),
        'PAM': get_pam(),
        'IptablesInfo': command_check("iptables -L"),
        'Sudoers': command_check("""cat /etc/sudoers|grep -v "^#"|grep -v "^$" """),
        'Share': command_check("""cat /etc/exports|grep -v "^#"|grep -v "^$" """),
        'Env': command_check("""cat /etc/profile |grep -v "^#" |grep -v "^$" """),
        'Docker': command_check("docker ps"),
        'ListUnit': command_check("systemctl list-unit-files|grep enabled"),
        'AuditCtl': command_check("auditctl -l"),
        'LogInfo': get_log_info(),
        'RpmInstall': command_check("rpm -qa"),
        'HomeLimits': command_check("ls -lh /home"),

        'Users': get_users(),
        'Processes': finger_utils.get_running_processes(),
        'Scheduled': get_scheduled_tasks(),
        'Groups': get_groups(),
        'CreateUser': get_create_user(),
        'Ports': finger_utils.get_ports(),
        'Software': get_installed_programs(),

        'ConfigSSH': get_ssh(),
        'Hosts': Hosts,
        'FilePers': get_file_permission(),
        'FireWallds': FireWallds,
    }


# 监控数据
def get_system_state():
    system_state = finger_utils.get_system_state('linux')
    return system_state


def test():
    d = get_finger()
    with open('finger.json', 'w') as f:
        f.write(json.dumps(d))


if __name__ == '__main__':
    test()
