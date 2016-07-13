# -*- coding: utf-8 -*-
from __future__ import unicode_literals

from django.db import migrations, models


class Migration(migrations.Migration):

    dependencies = [
        ('jump', '0002_auto_20160713_0325'),
    ]

    operations = [
        migrations.AddField(
            model_name='userhost',
            name='permcode',
            field=models.CharField(max_length=3, verbose_name=b'\xe6\x9d\x83\xe9\x99\x90\xe4\xbd\x8d', blank=True),
        ),
    ]
