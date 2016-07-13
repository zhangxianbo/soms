# -*- coding: utf-8 -*-
from __future__ import unicode_literals

from django.db import migrations, models


class Migration(migrations.Migration):

    dependencies = [
        ('jump', '0001_initial'),
    ]

    operations = [
        migrations.AlterField(
            model_name='host',
            name='ip',
            field=models.GenericIPAddressField(verbose_name=b'ip\xe5\x9c\xb0\xe5\x9d\x80'),
        ),
    ]
