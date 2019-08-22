# -*- coding: utf-8 -*-
from __future__ import unicode_literals

from django.db import models, migrations


class Migration(migrations.Migration):

    dependencies = [
        ('helios', '0014_voters_upload'),
    ]

    operations = [
        migrations.AddField(
            model_name='voterfile',
            name='preferred_encoding',
            field=models.CharField(default=b'utf8', max_length=255),
            preserve_default=True,
        ),
    ]
