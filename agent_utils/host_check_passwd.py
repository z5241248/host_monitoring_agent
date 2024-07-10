import crypt
from hmac import compare_digest as compare_hash
from os_utils import get_file_lines

passwd_txt_file = 'weak_password'   # TODO: weak_password:  datas/baseline/weak_password/weak_password


def verify(explain, passwd):
    return compare_hash(crypt.crypt(explain, passwd), passwd)


def verify_weak(passwd):
    lines = get_file_lines(passwd_txt_file)
    for explain in lines:
        if verify(explain, passwd):
            return "true", explain

    return "false", ""

# 对加密后密码进行暴力破解（仅linux）
if __name__ == '__main__':
    explain = '123456'
    passwd = 'A6aHHz1Cym.uIV/IWtEqyo2p3XgP8.ZDnekkJ.9/6GS5smPAj6KdUDSQrFti.uBsZha79nHGtcIaKfkkSIAyd/'
