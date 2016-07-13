#!/usr/bin/env python
#coding=utf-8
import _mysql
import MySQLdb
import datetime
import os,sys,subprocess
import random
from Crypto.Cipher import AES
from binascii import b2a_hex, a2b_hex
import random

def keygen(num):
    """生成随机密码"""
    seed = "1234567890abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ"
    sa = []
    for i in range(num):
        sa.append(random.choice(seed))
    salt = ''.join(sa)
    return salt
#print keygen(15)

class PyCrypt(object):
    """对称加密解密"""
    def __init__(self, key):
        self.key = key
        self.mode = AES.MODE_CBC

    def encrypt(self, text):
        cryptor = AES.new(self.key, self.mode, b'0000000000000000')
        length = 16
        count = len(text)
        if count < length:
            add = (length - count)
            text += ('\0' * add)
        elif count > length:
            add = (length - (count % length))
            text += ('\0' * add)
        ciphertext = cryptor.encrypt(text)
        return b2a_hex(ciphertext)

    def decrypt(self, text):
        cryptor = AES.new(self.key, self.mode, b'0000000000000000')
        plain_text = cryptor.decrypt(a2b_hex(text))
        return plain_text.rstrip('\0')

def use_mysql(sql_cmd):
    sql_cmd = sql_cmd
    config = {'host': 'localhost',
              'db': 'jump',
              'user': 'u',
              'passwd': 'u@zj-2015'}
    conn = MySQLdb.connect(**config)
    cursor = conn.cursor()
    #cursor.executemany(sql)
    cursor.execute(sql_cmd)
    #data = cursor.fetchone()
    data = cursor.fetchall()
    conn.commit()
    conn.close()
    return data

def useradd(username,passwd):
    username = username
    passwd = passwd
    p = subprocess.Popen('id %s' %username, shell=True,stdout=subprocess.PIPE,stderr=subprocess.PIPE)
    if not p.stderr.read():
        print 'username:%s haved.' %username
    else:
        os.system('/usr/sbin/useradd %s' %username)
        p1 = subprocess.Popen("/bin/echo '%s' | /usr/bin/passwd --stdin %s" %(passwd,username),shell=True,stdout=subprocess.PIPE,stderr=subprocess.PIPE)
        p1.wait()
        #os.system('echo "%s ALL=(root) NOPASSWD:ALL" >> /etc/sudoers' %username)
        print 'useradd %s successed.' % username
        return 'ok'

def set_bash(user,f,workdir):
    user = user
    f = f
    f1 = '/home/%s/.bash_profile' % user
    f1 = file(f1,'w')
    uid = get_uid(user)
    os.system('mkdir /home/%s/.ssh' % user)
    os.system('chmod 700 /home/%s/.ssh' % user)
    os.system('cp %s /home/%s/.ssh/' % (f,user))
    os.system('chown -R %s.%s /home/%s/.ssh/' %(uid,uid,user))
    f1.write('python %s/user_profile.py\nlogout' %workdir)
    f1.flush()
    f1.close()
    print 'set %s bash success.' %user

def get_uid(user):
    user = user
    p = subprocess.Popen('/usr/bin/id %s' %user, shell=True,stdout=subprocess.PIPE)
    a = p.stdout.read()
    a = a.replace('(','=')
    l = a.split('=')
    return l[1]

def check_user(user):
    user = user
    cmd = '/bin/grep "/%s:" /etc/passwd' %user
    p = subprocess.Popen(cmd, shell=True, stdout=subprocess.PIPE)
    o = p.stdout.read()
    return o

def userdel(user):
    user = user
    os.system('userdel -r %s' % user)
    print '%s del is ok'

if __name__=='__main__':
    key = '11aa22bb33cc44dd'
    jm = PyCrypt(key)
    #password = 'a123456!'
    #enpasswd = jm.encrypt(password)
    #print enpasswd
    #passwd = jm.decrypt('db922a38a89ef5f3986e70f5a40b2960')
    #print passwd

    workdir = os.path.split(os.path.realpath(__file__))[0]
    f = workdir + "/id_rsa"
    dt = datetime.datetime.now()
    today = dt.strftime('%Y-%m-%d')
    sql_cmd = "select username,password from jump_user where update_time > '%s';" % today
    arg = use_mysql(sql_cmd)
    if arg:
        for i in range(0,len(arg)):
            u = arg[i][0]
            passwd = arg[i][1]
            p = jm.decrypt(passwd)
            s = check_user(u)
            if not s:
                r = useradd(u,p)
                if r == 'ok':set_bash(u,f,workdir)
            else: print "user '%s' already exists" %u
    else: print "don't update"
