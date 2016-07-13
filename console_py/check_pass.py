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
    #sql_cmd = "select username,password from jump_user ;"
    arg = use_mysql(sql_cmd)
    if arg:
        for i in range(0,len(arg)):
            u = arg[i][0]
            passwd = arg[i][1]
            p = jm.decrypt(passwd)
            print u,p
    else: print "don't update"
