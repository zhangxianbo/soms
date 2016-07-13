#coding=utf-8
from django.db import models
import hashlib

# Create your models here.

class User(models.Model):
    vpnuser = models.CharField('用户名',max_length=64)
    password = models.CharField('密码',max_length=254)
    def __unicode__(self):
        return u'%s %s' % (self.vpnuser, self.password)
    def save(self,*args,**kwargs):
        self.password = hashlib.md5(self.password).hexdigest()
        super(User,self).save(*args,**kwargs)
