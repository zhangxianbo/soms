# -*- coding: utf-8 -*-
from __future__ import unicode_literals

from django.db import migrations, models


class Migration(migrations.Migration):

    dependencies = [
        ('jump', '0003_userhost_permcode'),
    ]

    operations = [
        migrations.AlterField(
            model_name='userhost',
            name='permcode',
            field=models.CharField(max_length=10, verbose_name=b'\xe6\x9d\x83\xe9\x99\x90\xe4\xbd\x8d', blank=True),
        ),
    ]
