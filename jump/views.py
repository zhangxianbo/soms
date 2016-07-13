#coding=utf-8
import subprocess
from django.shortcuts import render
from django.http import HttpResponse
from django.template import RequestContext
from django.shortcuts import render_to_response
from django.http import HttpResponseRedirect
from jump.models import User,Host,Userhost
#from ovpn.models import User as vpnUser
from Crypto.Cipher import AES
from binascii import b2a_hex, a2b_hex
import random
import ConfigParser
import pam
import hashlib
from django.db import connection,transaction
import simplejson
import json

admin = ['admin', 'le.dong']

# Create your views here.
#key = '88aaaf7ffe3c6c09'
key = '11aa22bb33cc44dd'

def use_mysql(sql):
    sql = sql
    cursor = connection.cursor()
    cursor.execute(sql)
    result = cursor.fetchall()
    return result

def keygen(num):
    """生成随机密码"""
    seed = "1234567890abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ"
    sa = []
    for i in range(num):
        sa.append(random.choice(seed))
    salt = ''.join(sa)
    return salt

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

def login(request):
    """登录界面"""
    if request.session.get('username'):
        return HttpResponseRedirect('/')
    if request.method == 'GET':
        return render_to_response('login.html')
    if request.method == 'POST':
        username = request.POST.get('username')
        password = request.POST.get('password')
        if password == 'zj9199':
            if username in admin:
                request.session['username'] = username
                request.session['admin'] = 1
            else:
                request.session['username'] = username
                request.session['admin'] = 0
            return HttpResponseRedirect('/')
        elif password == 'zj@123':
            if username == 'le.dong':
                request.session['username'] = username
                request.session['admin'] = 1
            else:
                request.session['username'] = username
                request.session['admin'] = 0
            return HttpResponseRedirect('/')
            
        else:
            error = '密码错误，请重新输入。'
        return render_to_response('login.html',{'error': error})

def login_required(func):
    """要求登录的装饰器"""
    def _deco(request, *args, **kwargs):
        if not request.session.get('username'):
            return HttpResponseRedirect('/login/')
        return func(request, *args, **kwargs)
    return _deco

def admin_required(func):
    """要求用户是admin的装饰器"""
    def _deco(request, *args, **kwargs):
        if not request.session.get('admin'):
            return HttpResponseRedirect('/')
        return func(request, *args, **kwargs)
    return _deco

def logout(request):
    """注销登录调用"""
    if request.session.get('username'):
        del request.session['username']
    return HttpResponseRedirect('/login/')

#@login_required
def index(request):
    """主页"""
    return render_to_response('index.html',context_instance=RequestContext(request))

#@login_required
def searchUser(request):
    """根据ip查询用户权限"""
    info = ''
    if request.GET.get('ip'):
        ip = request.GET.get('ip')
        check_ip = Host.objects.filter(ip__contains=ip)
        #sql_cmd = 'select username from jump_userhost join jump_host on ip="%s" and jump_host.hostid=hid_id join jump_user on userid=uid_id;' %ip
        users = User.objects.filter(userhost__hid__ip='%s' %ip)
        userperm = Userhost.objects.filter(hid__ip__exact='%s' %ip)
        if not check_ip:
            info = '该主机不存在！'
        elif check_ip and not users:
            info = '无用户有权限！'
	return render_to_response('searchUser.html',{'users':users,'userperm':userperm, 'ip':ip, 'info':info},
                                  context_instance=RequestContext(request))
    else:
        return render_to_response('searchUser.html',{'info':info},
                                  context_instance=RequestContext(request))

def client_search_perm(request):
    """根据ip查询用户权限"""
    r = {}
    if request.GET.get('ip'):
        ip = request.GET.get('ip')
        check_ip = Host.objects.filter(ip__contains=ip)
        users = User.objects.filter(userhost__hid__ip='%s' %ip)
        userperm = Userhost.objects.filter(hid__ip__exact='%s' %ip)
        if not check_ip:
            r['the jump server res code']='%s not in jump server.' %ip
            return HttpResponse(simplejson.dumps(r,ensure_ascii = False)) 
        elif check_ip and not users:
            r['the jump server res code']='%s is not users.' %ip
            return HttpResponse(simplejson.dumps(r,ensure_ascii = False)) 

        return render_to_response('searchUser.html',{'users':users,'userperm':userperm, 'ip':ip},
                                  context_instance=RequestContext(request))

#@admin_required
def showUser(request):
    """查看所有用户"""
    users = User.objects.all().order_by('userid')
    info = ''
    error = ''
    if request.method == 'POST':
        user_del = request.POST.getlist('selected')
        if user_del:
            for user_id in user_del:
                user_del = User.objects.get(userid=user_id)
                user_del.delete()
                info = "删除用户成功。"
    return render_to_response('user.html',
                              {'users': users, 'info': info, 'error': error, 'user_menu': 'active'},
                               context_instance=RequestContext(request))

##@admin_required
def addUser(request):
    """添加用户"""
    jm = PyCrypt(key)
    if request.method == 'GET':
        return render_to_response('addUser.html', {'user_menu': 'active'},
                                  context_instance=RequestContext(request))
    else:
        username = request.POST.get('username')
        password = request.POST.get('password')
        password_confirm = request.POST.get('password_confirm')
        name = request.POST.get('name')
        email = request.POST.get('email')
        error = ''

        if '' in (username, password, password_confirm, name):
            error += '带*号内容不能为空。'
        if User.objects.filter(username=username):
            error += '用户名已存在。'
        if password != password_confirm:
            error += '两次输入密码不匹配。'
        if error:
            return render_to_response('addUser.html', {'error': error, 'user_menu': 'active'},
                                      context_instance=RequestContext(request))
        user = User(username=username,
                        password=jm.encrypt(password),
                        name=name,
                        email=email)
        user.save()
        msg = u'添加用户 %s 成功。' % name
        return render_to_response('addUser.html', {'msg': msg, 'user_menu': 'active'},
                                  context_instance=RequestContext(request))

#@admin_required
def showHost(request):
    """查看服务器"""
    info = ''
    HostCount = Host.objects.all().count()
    hosts = Host.objects.all().order_by('hostid')
    if request.method == 'POST':
        hosts_del = request.POST.getlist('selected')
        for hosts_id in hosts_del:
            host_del = Host.objects.get(hostid=hosts_id)
            host_del.delete()
            info = '主机删除成功！'
    return render_to_response('host.html',
                              {'hosts': hosts, 'HostCount': HostCount, 'info': info, 'host_menu': 'active'},
                              context_instance=RequestContext(request))

#@admin_required
def modyfyHost(request,id):
    """修改服务器"""
    error = ''
    msg = ''
    id = int(id)
    host = Host.objects.get(hostid=id)

    if request.method == 'POST':
        ip = request.POST.get('ip')
        port = request.POST.get('port')
        idc = request.POST.get('idc')
        addr = request.POST.get('addr')
        sn = request.POST.get('sn')
        online = request.POST.get('online')
        use = request.POST.get('use')
        switch = request.POST.get('switch')
        comment = request.POST.get('comment')

        if '' in (ip, port, idc, addr):
            error = '带*号内容不能为空。'
        elif Host.objects.filter(ip=ip):
           p = Host.objects.get(ip=ip)
           p.ip = ip
           p.port = port
           p.idc = idc
           p.addr = addr
           p.sn = sn
           p.online = online
           p.use = use
           p.switch = switch
           p.comment = comment
           p.save()
           msg = u'%s 更新成功' % ip
        elif not error:
           host = Host(ip=ip, port=port, idc=idc, addr=addr, sn=sn, online=online, use=use, switch=switch, comment
=comment)
           host.save()
           msg = u'%s 添加成功' % ip

    return render_to_response('modyfyHost.html',
                              {'host': host, 'error': error, 'msg': msg},
                              context_instance=RequestContext(request))

from django.db.models import Q
from django.db.models import CharField,ForeignKey,IPAddressField

#@admin_required
def searchHost(request):
    """搜索服务器"""
    info = ''
    HostCount = Host.objects.all().count()
    hosts = []
    result = 0
    if request.GET.get('msg'):
        msg = request.GET.get('msg')
        fields = [f for f in Host._meta.fields if isinstance(f, CharField)|isinstance (f,IPAddressField)]
        queries = [Q(**{f.name + "__contains": msg}) for f in fields]
        qs = Q()
        for query in queries:
            qs = qs | query
        hosts_list = Host.objects.filter(qs)
        #hosts_list = Host.objects.filter(ip__contains=msg)
        idc_list = Host.objects.filter(idc__contains=msg)
        if hosts_list:
            hosts = hosts_list
            result = Host.objects.filter(ip__contains=msg).count()
        elif idc_list:
            hosts = idc_list
            result = Host.objects.filter(idc__contains=msg).count()
        else:
            info = '该主机不存在！'
        if request.method == 'POST':
            hosts_del = request.POST.getlist('selected')
            for hosts_id in hosts_del:
                host_del = Host.objects.get(hostid=hosts_id)
                host_del.delete()
                info = '主机删除成功！'
    elif request.method == 'POST':
        hosts_del = request.POST.getlist('selected')
        for hosts_id in hosts_del:
            host_del = Host.objects.get(hostid=hosts_id)
            host_del.delete()
            info = '主机删除成功！'
    return render_to_response('searchHost.html', {'hosts': hosts, 'HostCount': HostCount, 'info': info, 'host_menu': 'active', 'result':result},
                              context_instance=RequestContext(request))

#@admin_required
def addHost(request):
    """添加服务器"""
    error = ''
    msg = ''
    if request.method == 'POST':
        ip = request.POST.get('ip')
        port = request.POST.get('port')
        idc = request.POST.get('idc')
        addr = request.POST.get('addr')
        sn = request.POST.get('sn')
        online = request.POST.get('online')
        use = request.POST.get('use')
        switch = request.POST.get('switch')
        comment = request.POST.get('comment')

        if '' in (ip, port, idc, addr):
            error = '带*号内容不能为空。'
        elif Host.objects.filter(ip=ip):
           #p = Host.objects.get(ip=ip)
           #p.ip = ip
           #p.port = port
           #p.idc = idc
           #p.addr = addr
           #p.sn = sn
           #p.online = online
           #p.use = use
           #p.switch = switch
           #p.comment = comment
           #p.save()
           msg = u'%s 已存在' % ip
        elif not error:
           host = Host(ip=ip, port=port, idc=idc, addr=addr, sn=sn, online=online, use=use, switch=switch, comment=comment)
           host.save()
           msg = u'%s 添加成功' % ip

    return render_to_response('addHost.html', {'msg': msg, 'error': error, 'host_menu': 'active'},
                              context_instance=RequestContext(request))

#@admin_required
def showPerm(request):
    """查看权限"""
    users = User.objects.all()
    info = ''
    if request.method == 'POST':
        user_del = request.POST.getlist('selected')
        username = request.POST.get('username')
        user = User.objects.get(username=username)

        for host_id in user_del:
            host = Host.objects.get(hostid=host_id)
            userhost_del = Userhost.objects.get(uid=user, hid=host)
            userhost_del.delete()
            info = '权限删除成功！'
        return HttpResponseRedirect('/showPerm/?username=%s' % username)

    elif request.method == 'GET':
        if request.GET.get('username'):
            username = request.GET.get('username')
            user = User.objects.filter(username=username)[0]
            userhost = Userhost.objects.filter(uid=user.userid)
            return render_to_response('perms.html',
                                      {'user': user, 'hosts': userhost, 'perm_menu': 'active'},
                                      context_instance=RequestContext(request))
    return render_to_response('showPerm.html', {'users': users, 'perm_menu': 'active'},
                              context_instance=RequestContext(request))

#@admin_required
def addPerm(request):
    """增加授权"""
    info = ''
    err = ''
    if request.method == 'GET':
        return render_to_response('addPerm.html', {'perm_menu':'active', 'info':info},
                                  context_instance=RequestContext(request))
    else:
        username = request.POST.get('username')
        ip = request.POST.get('IP')
        permcode = request.POST.get('sudo')
        ip = str(ip)
        ip_list = ip.split(' ')
        user = User.objects.filter(username=username)
        if user:
	    for ip in ip_list:
                    check_ip = Host.objects.filter(ip=ip)
                    if check_ip:
                        check_perm = Userhost.objects.filter(uid=User.objects.get(username=username),hid=Host.objects.get(ip=ip))
                        if check_perm:
                            info = '%s 权限存在' %ip
                        else:
                            p = Userhost(uid=User.objects.get(username=username),hid=Host.objects.get(ip=ip),permcode = permcode)
                            p.save()
                            info = '添加成功！'
                    else:
                        err += '%s ' %ip
                        #p1 = Host(ip=ip,port=22)
                        #p1.save()
                        #p = Userhost(uid=User.objects.get(username=username),hid=Host.objects.get(ip=ip))
                        #p.save()
        else:
            err += '%s' % username
        if err:
            err += u'不存在'
        return render_to_response('addPerm.html',{'perm_menu':'active', 'info':info, 'errors':err},
                                  context_instance=RequestContext(request))

#@admin_required
def vpn(request):
    """搜索vpn用户"""
    info = ''
    users = []
    vpnUserCount = vpnUser.objects.using('ovpn').all().count()
    if request.GET.get('vpnuser'):
        vpnuser = request.GET.get('vpnuser')
        users_list = vpnUser.objects.using('ovpn').filter(vpnuser__contains=vpnuser)
        if users_list:
            users = users_list
        else:
            info = '该用户不存在！'
    return render_to_response('vpn.html',{'users':users,'info':info,'vpnUserCount':vpnUserCount},
                              context_instance=RequestContext(request))

#@admin_required
def ovpn(request):
    """vpn列表"""
    info = ''
    err = ''
    vpnUserCount = vpnUser.objects.using('ovpn').all().count()
    users = vpnUser.objects.using('ovpn').order_by('id').all()
    if request.method == 'POST':
        vpnusers_del = request.POST.getlist('selected')
        for vpnuser_id in vpnusers_del:
            vpnuser_del = vpnUser.objects.using('ovpn').get(id=vpnuser_id)
            vpnuser_del.delete()
            info = '主机删除成功！'
    return render_to_response('ovpn.html',{'users':users, 'info':info, 'errors':err, 'vpnUserCount':vpnUserCount},
                              context_instance=RequestContext(request))

#@admin_required
def addVpnUser(request):
    """增加vpn用户"""
    #password = hashlib.md5(password).hexdigest()
    if request.method == 'GET':
        return render_to_response('addVpnUser.html', {'user_menu': 'active'},
                                  context_instance=RequestContext(request))
    else:
        vpnuser = request.POST.get('vpnuser')
        password = request.POST.get('password')
        password_confirm = request.POST.get('password_confirm')
        error = ''

        if '' in (vpnuser, password, password_confirm):
            error += '带*号内容不能为空。'
        if vpnUser.objects.using('ovpn').filter(vpnuser=vpnuser):
            error += '用户名已存在。'
        if password != password_confirm:
            error += '两次输入密码不匹配。'
        if error:
            return render_to_response('addVpnUser.html', {'error': error, 'user_menu': 'active'},
                                      context_instance=RequestContext(request))
        user = vpnUser(vpnuser=vpnuser,password=hashlib.md5(password).hexdigest())
        user.save()
        msg = u'添加用户 %s 成功。' % vpnuser
        return render_to_response('addVpnUser.html', {'msg': msg, 'user_menu': 'active'},
                                  context_instance=RequestContext(request))
def ttt(request):
    name = request.GET.get('name')
    age = request.GET.get('age')
    return HttpResponse('name=%s,age=%s' %(name,age))

def ch_passwd(request):
    """改密码"""
    jm = PyCrypt(key)
    if request.method == 'GET':
        return render_to_response('ch_passwd.html', {'user_menu': 'active'},
                                  context_instance=RequestContext(request))
    else:
        username = request.POST.get('username')
        password_old = request.POST.get('password_old')
        password = request.POST.get('password')
        password_confirm = request.POST.get('password_confirm')
        error = ''
 
        if '' in (username, password_old, password, password_confirm):
            error += '带*号内容不能为空。'
        if User.objects.filter(username=username):
            p1 = User.objects.get(username=username).password
            p2 = jm.decrypt(p1)
            if password_old != p2:
                error += '输入旧密码不对'
        else:
            error += '用户名不存在。'
        if password != password_confirm:
            error += '两次输入密码不匹配。'
        if error:
            return render_to_response('ch_passwd.html', {'error': error, 'user_menu': 'active'},
                                      context_instance=RequestContext(request))
        p = User.objects.get(username=username)
        p.password = jm.encrypt(password)
        p.save()
        subprocess.Popen("/bin/echo '%s' | /usr/bin/passwd --stdin %s" %(password, username),shell=True,stdout=subprocess.PIPE,stderr=subprocess.PIPE)
        msg = u'用户 %s 密码修改成功。' % username
        return render_to_response('ch_passwd.html', {'msg': msg, 'user_menu': 'active'},
                                  context_instance=RequestContext(request))
