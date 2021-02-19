# -*- coding: utf-8 -*-
from __future__ import unicode_literals

from django.db import models, migrations


class Migration(migrations.Migration):

    dependencies = [
        ('helios', '0015_voterfile_preferred_encoding'),
    ]

    operations = [
        migrations.AddField(
            model_name='poll',
            name='taxisnet_auth',
            field=models.BooleanField(default=False, verbose_name='Taxisnet login'),
            preserve_default=True,
        ),
    ]
