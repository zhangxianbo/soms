#!/usr/bin/python
#coding = utf-8
import os, sys, subprocess
import _mysql, MySQLdb
import getpass
#import pexpect

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
    res = cursor.fetchone()
    #res = cursor.fetchall()
    conn.commit()
    conn.close()
    return res

def check_user_ip(user,ip):
    user = user
    ip = ip
    #sql_cmd="select username,ip,port from jump_userhost join jump_user on username='%s' and userid=uid_id join jump_host on ip='%s' and hostid=hid_id;" %(user,ip)
    sql_cmd="select u.username,h.ip,h.port from (jump_host h inner join jump_userhost uh on uh.hid_id = h.hostid and h.ip='%s') inner join jump_user u on u.userid = uh.uid_id  where u.username = '%s';" %(ip,user)
    a = use_mysql(sql_cmd)
    if not a: return 'Err'
    else : return a
    #return a

def ssh_login(user,ip,port):
    user = user
    ip = ip
    port = port
    cmd = 'ssh -p %s %s@%s' %(port,user,ip)
    p = subprocess.Popen(cmd, shell=True)
    p.wait()

def m_pass(user):
    user = user
    p1 = getpass.getpass('Your Password:').strip()
    p2 = getpass.getpass('Your Password:').strip()
    if p1 == p2:
        #os.system('echo %s| passwd  --stdin %s' %(p1,user))
        os.system('passwd')
    else:print 'Sorry, passwords do not match'

if __name__ == '__main__':
        u = subprocess.Popen('/usr/bin/whoami',shell=True,stdout=subprocess.PIPE)
        user = u.stdout.read().strip('\n')
        i = 0
        while i<5:
            i += 1
            try:
                ip = raw_input('\033[32m%s Please enter your login ip:\033[0m ' % user).strip()
            except KeyboardInterrupt:
                print '\n'
                sys.exit()
            except EOFError:
                print '\n'
                pass
                sys.exit()
            s = check_user_ip(user,ip)
            if s == 'Err':
                print "  %s No Permission" %user
                pass
            else:
                port = str(s[2])
                ssh_login(user,ip,port)
