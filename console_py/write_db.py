#!/usr/bin/python
#coding=utf-8
import _mysql
import MySQLdb
import os,sys,subprocess
reload(sys)
sys.setdefaultencoding("utf-8")

def use_mysql(sql_cmd):
    sql_cmd = sql_cmd
    config = {'host': 'localhost',
              'db': 'jump',
              'user': 'root',
              'passwd': 'zj@2015'}
    conn = MySQLdb.connect(**config)
    cursor = conn.cursor()
    #cursor.executemany(sql)
    cursor.execute(sql_cmd)
    data = cursor.fetchone()
    #data = cursor.fetchall()
    conn.commit()
    conn.close()
    return data

if __name__=='__main__':
    ip = sys.argv[1]
    ip_list = []
    for i in range(2,6):
        ips = ip + '.' + str(i)
        ip_list.append(ips)
    for ip in ip_list:
        #sql_cmd = "insert into jump_host(hostid,idc,addr,sn,ip,port,online,use,switch,comment) values('','%s',%s,%s,%s,%s,%s,%s,%s,%s);" % ('','木樨园','','',ip,22,'','','','')
        sql_cmd = "insert into jump_host values('', %s, %s, %s, %s, %s, %s, %s, %s, %s);" % ('muxiyuan', '', '', ip, 22, '', '', '', '')
        a = use_mysql(sql_cmd)
        if not a: print 'OK'
