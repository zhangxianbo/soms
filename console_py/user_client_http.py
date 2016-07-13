#!/usr/bin/python
#coding=utf-8
import subprocess
import urllib2
import re,sys,os

def get_ip():
    ip_list = []
    p = subprocess.Popen('/sbin/ifconfig |egrep  "inet addr"|grep -v "127.0.0.1" ',shell=True,stdout=subprocess.PIPE)
    o = p.stdout.readlines()
    for i in range(0,len(o)):
        ip = o[i]
        ip = ip.replace(':',' ').strip()
        ip = ip.split(' ')
        ip = ip[2]
        ip_list.append(ip)
    return ip_list

'''*获取用户列表*'''
class get_user():
    def __init__(self,url):
        self.url = url

    def get_html(self):
        req = urllib2.Request(self.url)
        res = urllib2.urlopen(req)
        html = res.read()
        return html
    
    def find_user(self):
        html = self.get_html()
        if 'the jump server res code' in html:
            print html
        msg = re.findall(r'<td class=username>(.*)</td>',html)
        return msg
    def find_perm(self):
        html = self.get_html()
        if 'the jump server res code' in html:
            print html
        msg = re.findall(r'<td class=permcode>(.*)</td>',html)
        return msg

'''*检查-创建用户*'''
class create_user():
    def __init__(self,user,password,c_key):
        self.user = user
        self.password = password
        self.c_key = c_key

    def get_uid(self):
        p = subprocess.Popen('id %s' % self.user, shell=True,stdout=subprocess.PIPE)
        a = p.stdout.read()
        a = a.replace('(','=')
        l = a.split('=')
        return l[1]

    def check_user(self):
        user = self.user
        cmd = '/bin/grep "/%s:" /etc/passwd' %user
        p = subprocess.Popen(cmd, shell=True, stdout=subprocess.PIPE)
        o = p.stdout.read()
        return o
    
    def useradd(self):
        username = self.user
        passwd = self.password
        p = subprocess.Popen('id %s' %username, shell=True,stdout=subprocess.PIPE,stderr=subprocess.PIPE)
        if not p.stderr.read():
            print 'username:%s haved.' %username
        else:
            os.system('/usr/sbin/useradd %s' %username)
            p1 = subprocess.Popen('/bin/echo %s | /usr/bin/passwd --stdin %s' %(passwd,username),shell=True,stdout=subprocess.PIPE,stderr=subprocess.PIPE)
            p1.wait()
            p2 = subprocess.Popen('grep ^"%s " /etc/sudoers' %username ,shell=True,stdout=subprocess.PIPE)
            o = p2.stdout.read()
            if o:
                return 'ok'
            subprocess.call('echo "%s ALL=(root) NOPASSWD:ALL" >> /etc/sudoers' %username,shell=True,stdout=subprocess.PIPE,stderr=subprocess.PIPE)
            print 'useradd %s successed.' % username
            return 'ok'

    def set_bash(self):
        user = self.user
        key = self.c_key
        uid = self.get_uid()
        os.system('mkdir /home/%s/.ssh' % user)
        f1 = '/home/%s/.ssh/authorized_keys' % user
        f1 = file(f1,'w')
        f1.write(key)
        f1.flush()
        f1.close()
        os.system('chmod 700 /home/%s/.ssh' % user)
        os.system('chown -R %s.%s /home/%s/.ssh/' %(uid,uid,user))
        print 'set %s key success.' % user

    def handle(self):
        s = self.check_user()
        if not s:
            r = self.useradd()
            if r == 'ok':
                set_bash = self.set_bash()
        else:
            print "%s already exists" % self.user
###检查系统存在的用户
def existing_user():
    f=file('/etc/passwd')
    user = []
    for line in f.readlines():
        line = line.strip('\n').split(':')
        user.append(line[0])
    e_user = []
    for i in user:
        if  re.findall (r'[a-z]+\.[a-z]+',i):
            e_user.append(i)
    return e_user
###删除不存在权限的用户
def delete_user(user):
    username = user
    d1 = subprocess.Popen('/usr/sbin/userdel -rf %s'  %username ,shell=True,stdout=subprocess.PIPE)
    o = d1.stdout.read() 
    if not o:
       print '不存在权限用户 %s is deleted.' % username
    else:
       print '删除用户失败  %s' %usename

if __name__=="__main__":
    #ip = sys.argv[1]
    password = 'asjk!@#123'
    c_key = "ssh-rsa AAAAB3NzaC1yc2EAAAABIwAAAQEA25iyuo+3kPw3gRR8NWW+7REEwXPhn1cKRngVURly/npis9uyGF4M2B3tyfALtOTjFdgQyo0vPpZwBjqXdeWKwNh2qns/yd2wET66OCS0v6Uk9Noy2e9/XH0xZPjufY5k7fVxcssC8AuCkcjF/F86TdaKOsiQLooNW961nbG9BJasX7XwuhmCQEN6fRcowhRH/ckOk2oDyD2OM8SBZax1SiQyonyMbV07q34bgbicUK8PYq6zoDuHXVPVXMcklTU+mU+mQAmBC05hzuD5JiHTsMT7K/6hxLQloL6XXqfWn9Pga1cOzDx9/TPmMlR3qMiHpG9I4TPPQROIeQ9TRP6WAw== root@c.jrj.cn"
    ip_list = get_ip()
    for ip in ip_list:
	url = "http://192.168.136.128:90/client_search_perm/?ip=%s" % ip
        p = get_user(url)
        u_list = p.find_user()
        for user in u_list:
            c = create_user(user,password,c_key)
            c.handle()
        e_user = existing_user()
        for i in e_user:
            if i in u_list:
                pass
            else:
                delete_user(i)
