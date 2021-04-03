# -*- coding: utf-8 -*-
from __future__ import unicode_literals

from django.db import models, migrations


class Migration(migrations.Migration):

    dependencies = [
        ('helios', '0016_poll_taxisnet_auth'),
    ]

    operations = [
        migrations.AddField(
            model_name='election',
            name='terms_consent_at',
            field=models.DateTimeField(default=None, auto_now_add=True, null=True),
            preserve_default=True,
        ),
    ]
