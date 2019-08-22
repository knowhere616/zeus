# -*- coding: utf-8 -*-
from __future__ import unicode_literals

from django.db import models, migrations


class Migration(migrations.Migration):

    dependencies = [
        ('helios', '0013_linked_polls'),
    ]

    operations = [
        migrations.AlterModelOptions(
            name='poll',
            options={'ordering': ('-linked_ref', 'pk', 'created_at')},
        ),
        migrations.AddField(
            model_name='voterfile',
            name='is_processing',
            field=models.BooleanField(default=False),
            preserve_default=True,
        ),
        migrations.AddField(
            model_name='voterfile',
            name='process_error',
            field=models.TextField(default=None, null=True),
            preserve_default=True,
        ),
        migrations.AddField(
            model_name='voterfile',
            name='process_status',
            field=models.TextField(default=None, null=True),
            preserve_default=True,
        ),
    ]
