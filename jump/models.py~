#coding=utf-8
from django.db import models
from datetime import datetime

# Create your models here.
class Host(models.Model):
    hostid = models.AutoField(primary_key=True)
    idc = models.CharField('机房',max_length=50)
    addr = models.CharField('机架等标识',max_length=50)
    sn = models.CharField('序列号',max_length=30,blank=True)
    ip = models.GenericIPAddressField('ip地址')
    port = models.IntegerField()
    online = models.CharField('在线状态',max_length=10)
    use = models.CharField('用途',max_length=50,blank=True)
    switch = models.CharField('交换机',max_length=50,blank=True)
    comment = models.CharField('备注',max_length=100, blank=True, null=True)
    def __unicode__(self):
        return u' %s' % (self.ip)

class User(models.Model):
    userid =  models.AutoField(primary_key=True)
    username = models.CharField('用户名',max_length=20)
    password = models.CharField('密码',max_length=100,blank=True)
    #ip = models.ManyToManyField(Host)
    name = models.CharField('姓名',max_length=50,blank=True)
    email = models.EmailField('邮箱',max_length=50,blank=True)
    update_time = models.DateTimeField('更新时间',default=datetime.now)

    def __unicode__(self):
        return u'%s' % (self.username)
        
    class Meta:
        ordering = ['username']

class Userhost(models.Model):
    #uid = models.OneToOneField(User)
    #hid = models.ManyToManyField(Host)
    uid = models.ForeignKey(User)
    hid = models.ForeignKey(Host)
    permcode = models.CharField('权限位',max_length=10,blank=True)
    def __unicode__(self):
        return u'%s %s %s' % (self.uid,self.hid,self.permcode)
