# -*- coding: utf-8 -*-
from __future__ import unicode_literals

from django.db import models, migrations


class Migration(migrations.Migration):

    dependencies = [
        ('helios', '0017_election_terms_consent_at'),
    ]

    operations = [
        migrations.AddField(
            model_name='election',
            name='legal_representative',
            field=models.CharField(default=None, max_length=2000, null=True, verbose_name='Legal representative', blank=True),
            preserve_default=True,
        ),
    ]
