# -*- coding: utf-8 -*-
from __future__ import unicode_literals

from django.db import migrations, models
import datetime


class Migration(migrations.Migration):

    dependencies = [
    ]

    operations = [
        migrations.CreateModel(
            name='Host',
            fields=[
                ('hostid', models.AutoField(serialize=False, primary_key=True)),
                ('idc', models.CharField(max_length=50, verbose_name=b'\xe6\x9c\xba\xe6\x88\xbf')),
                ('addr', models.CharField(max_length=50, verbose_name=b'\xe6\x9c\xba\xe6\x9e\xb6\xe7\xad\x89\xe6\xa0\x87\xe8\xaf\x86')),
                ('sn', models.CharField(max_length=30, verbose_name=b'\xe5\xba\x8f\xe5\x88\x97\xe5\x8f\xb7', blank=True)),
                ('ip', models.IPAddressField(verbose_name=b'ip\xe5\x9c\xb0\xe5\x9d\x80')),
                ('port', models.IntegerField()),
                ('online', models.CharField(max_length=10, verbose_name=b'\xe5\x9c\xa8\xe7\xba\xbf\xe7\x8a\xb6\xe6\x80\x81')),
                ('use', models.CharField(max_length=50, verbose_name=b'\xe7\x94\xa8\xe9\x80\x94', blank=True)),
                ('switch', models.CharField(max_length=50, verbose_name=b'\xe4\xba\xa4\xe6\x8d\xa2\xe6\x9c\xba', blank=True)),
                ('comment', models.CharField(max_length=100, null=True, verbose_name=b'\xe5\xa4\x87\xe6\xb3\xa8', blank=True)),
            ],
        ),
        migrations.CreateModel(
            name='User',
            fields=[
                ('userid', models.AutoField(serialize=False, primary_key=True)),
                ('username', models.CharField(max_length=20, verbose_name=b'\xe7\x94\xa8\xe6\x88\xb7\xe5\x90\x8d')),
                ('password', models.CharField(max_length=100, verbose_name=b'\xe5\xaf\x86\xe7\xa0\x81', blank=True)),
                ('name', models.CharField(max_length=50, verbose_name=b'\xe5\xa7\x93\xe5\x90\x8d', blank=True)),
                ('email', models.EmailField(max_length=50, verbose_name=b'\xe9\x82\xae\xe7\xae\xb1', blank=True)),
                ('update_time', models.DateTimeField(default=datetime.datetime.now, verbose_name=b'\xe6\x9b\xb4\xe6\x96\xb0\xe6\x97\xb6\xe9\x97\xb4')),
            ],
            options={
                'ordering': ['username'],
            },
        ),
        migrations.CreateModel(
            name='Userhost',
            fields=[
                ('id', models.AutoField(verbose_name='ID', serialize=False, auto_created=True, primary_key=True)),
                ('hid', models.ForeignKey(to='jump.Host')),
                ('uid', models.ForeignKey(to='jump.User')),
            ],
        ),
    ]
