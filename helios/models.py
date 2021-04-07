# -*- coding: utf-8 -*-
"""
Data Objects for Helios.

Ben Adida
(ben@adida.net)
"""

import traceback
import datetime
import logging
import uuid
import random
import StringIO
import copy
import base64
import zipfile
import os
from zeus.utils import defusedcsv as csv
import tempfile
import mmap
import marshal
import itertools
import urllib
import re

from functools import wraps
from datetime import timedelta
from collections import defaultdict

from django.template.loader import render_to_string
from django.db import models, transaction
from django.db.models.query import QuerySet
from django.db.models import Count, Q
from django.conf import settings
from django.core.mail import send_mail, mail_admins
from django.core.files import File
from django.utils.translation import ugettext_lazy as _
from django.core.validators import validate_email as django_validate_email
from django.forms import ValidationError
from django.core.urlresolvers import reverse
from django.core.context_processors import csrf
from django.utils import translation

from helios.crypto import electionalgs, algs, utils
from helios import utils as heliosutils
from helios import datatypes
from helios import exceptions
from helios.datatypes.djangofield import LDObjectField
from helios.byte_fields import ByteaField
from helios.utils import force_utf8


from heliosauth.models import User, AUTH_SYSTEMS, SMSBackendData
from heliosauth.jsonfield import JSONField
from helios.datatypes import LDObject

from zeus.core import (numbers_hash, gamma_encoding_max,
                       gamma_decode, to_absolute_answers, to_canonical,
                       from_canonical)
from zeus.slugify import slughifi
from zeus.election_modules import ELECTION_MODULES_CHOICES, get_poll_module, \
    get_election_module

from zeus.model_features import ElectionFeatures, PollFeatures, \
        TrusteeFeatures, VoterFeatures
from zeus.model_tasks import TaskModel, PollTasks, ElectionTasks
from zeus import help_texts as help
from zeus.log import init_election_logger, init_poll_logger
from zeus.utils import decalize, undecalize, CSVReader, safe_unlink

import stdnum.gr.vat


logger = logging.getLogger(__name__)

RESULTS_PATH = getattr(settings, 'ZEUS_RESULTS_PATH', os.path.join(settings.MEDIA_ROOT, 'results'))
ELECTION_MODEL_VERSION = 1


validate_email = lambda email,ln: django_validate_email(email)

def validate_afm(afm):
    try:
        stdnum.gr.vat.validate(afm)
    except Exception, e:
        msg = e.message
        raise Exception("Invalid AFM: %r" % msg)

class HeliosModel(TaskModel, datatypes.LDObjectContainer):

    class Meta:
        abstract = True


class PollMixQuerySet(QuerySet):

    def local(self):
        return self.filter(mix_type="local")

    def finished(self):
        return self.filter(status="finished")

    def mixing(self):
        return self.filter(status="mixing")

    def pending(self):
        return self.filter(status="pending")


class PollMixManager(models.Manager):

    def get_queryset(self):
        return PollMixQuerySet(self.model)

from django.core.files import storage
default_mixes_path = settings.MEDIA_ROOT + "/zeus_mixes/"
ZEUS_MIXES_PATH = getattr(settings, 'ZEUS_MIXES_PATH', default_mixes_path)

class CustomFileSystemStorage(storage.FileSystemStorage):
    def __init__(self, location=None):
        if not location:
            location = ZEUS_MIXES_PATH
        super(CustomFileSystemStorage, self).__init__(location)
zeus_mixes_storage = CustomFileSystemStorage()

def dummy_upload_to(x):
    return ''

class PollMix(models.Model):

    MIX_REMOTE_TYPE_CHOICES = (('helios', 'Helios'),
                                ('verificatum', 'Verificatum'),
                                ('zeus_client', 'Zeus server'))
    MIX_TYPE_CHOICES = (('local', 'Local'), ('remote', 'Remote'))
    MIX_STATUS_CHOICES = (('pending', 'Pending'), ('mixing', 'Mixing'),
                           ('validating', 'Validating'), ('error', 'Error'),
                           ('finished', 'Finished'))

    name = models.CharField(max_length=255, null=False, default='Zeus mixnet')
    mix_type = models.CharField(max_length=255, choices=MIX_TYPE_CHOICES,
                              default='local')
    poll = models.ForeignKey('Poll', related_name='mixes')
    mix_order = models.PositiveIntegerField(default=0)

    remote_ip = models.CharField(max_length=255, null=True, blank=True)
    remote_protocol = models.CharField(max_length=255,
                                     choices=MIX_REMOTE_TYPE_CHOICES,
                                     default='zeus_client')

    mixing_started_at = models.DateTimeField(null=True)
    mixing_finished_at = models.DateTimeField(null=True)

    status = models.CharField(max_length=255, choices=MIX_STATUS_CHOICES,
                            default='pending')
    mix_error = models.TextField(null=True, blank=True)
    mix_file = models.FileField(upload_to=dummy_upload_to,
                                storage=zeus_mixes_storage,
                                null=True, default=None)


    objects = PollMixManager()

    class Meta:
        ordering = ['-mix_order']
        unique_together = [('poll', 'mix_order')]


    @property
    def mix_path(self):
        fname = str(self.pk) + ".canonical"
        return os.path.join(ZEUS_MIXES_PATH, fname)

    def store_mix_in_file(self, mix):
        """
        Expects mix dict object
        """
        fname = str(self.pk) + ".canonical"
        fpath =  os.path.join(ZEUS_MIXES_PATH, fname)
        with open(fpath, "w") as f:
            to_canonical(mix, out=f)
        self.mix_file = fname
        self.save()

    def reset_mixing(self, force=True):
        if self.status == 'finished' and self.mix_file and not force:
            raise Exception("Cannot reset finished mix")
        # TODO: also reset mix with higher that current mix_order
        self.mixing_started_at = None
        self.status = 'pending'
        self.mix_error = None
        self.save()
        self.parts.all().delete()
        return True

    def zeus_mix(self):
        return from_canonical(self.mix_file.read())

    def mix_parts_iter(self, mix):
        size = len(mix)
        index = 0
        while index < size:
            yield buffer(mix, index, settings.MIX_PART_SIZE)
            index += settings.MIX_PART_SIZE

    def store_mix(self, mix):
        """
        mix is a dict object
        """
        self.parts.all().delete()
        mix = marshal.dumps(mix)

        for part in self.mix_parts_iter(mix):
            self.parts.create(data=part)

    @transaction.atomic
    def _do_mix(self):
        last_mix = self.poll.zeus.get_last_mix()
        new_mix = self.poll.zeus.mix(last_mix)

        #self.store_mix(new_mix)
        self.store_mix_in_file(new_mix)

        self.status = 'finished'
        self.save()
        return new_mix


    def mix_ciphers(self):
        if self.mix_type == "remote":
            raise Exception("Remote mixes not implemented yet.")

        self.mixing_started_at = datetime.datetime.now()
        self.status = 'mixing'
        self.save()

        try:
            self._do_mix()
        except Exception, e:
            self.status = 'error'
            self.mix_error = traceback.format_exc()
            self.parts.all().delete()
            self.save()
            raise


class MixPart(models.Model):
    mix = models.ForeignKey(PollMix, related_name="parts")
    data = ByteaField()


class ElectionManager(models.Manager):

    def get_queryset(self):
        return super(ElectionManager, self).get_queryset().filter(deleted=False)

    def administered_by(self, user):
        if user.superadmin_p:
            return super(ElectionManager, self).get_queryset().filter()

        return super(ElectionManager, self).get_queryset().filter(admins__in=[user])


def _default_voting_starts_at(*args):
    return datetime.datetime.now()

def _default_voting_ends_at(*args):
    return datetime.datetime.now() + timedelta(hours=12)


class Election(ElectionTasks, HeliosModel, ElectionFeatures):

    OFFICIAL_CHOICES = (
        (None, _('Unresolved')),
        (0, _('Unofficial')),
        (1, _('Official')),
    )

    election_module = models.CharField(_("Election type"), max_length=250,
                                         null=False,
                                         choices=ELECTION_MODULES_CHOICES,
                                         default='simple',
                                         help_text=help.election_module)
    version = models.CharField(max_length=255, default=ELECTION_MODEL_VERSION)
    uuid = models.CharField(max_length=50, null=False)
    name = models.CharField(_("Election name"), max_length=255,
                            help_text=help.election_name)
    short_name = models.CharField(max_length=255)
    communication_language = models.CharField("", max_length=5, null=True)
    help_email = models.CharField(_("Support email"),
                                  max_length=254, null=True, blank=True,
                                  help_text=help.help_email)
    help_phone = models.CharField(_("Support phone"),
                                  max_length=254, null=True, blank=True,
                                  help_text=help.help_phone)

    description = models.TextField(_("Election description"),
                                   help_text=help.election_description)
    trial = models.BooleanField(_("Trial election"), default=False,
                                help_text=help.trial)

    public_key = LDObjectField(type_hint = 'legacy/EGPublicKey', null=True)
    private_key = LDObjectField(type_hint = 'legacy/EGSecretKey', null=True)

    admins = models.ManyToManyField(User, related_name="elections")
    institution = models.ForeignKey('zeus.Institution', null=True)

    departments = models.TextField(_("Departments"), null=True,
                                   help_text=_("University Schools. e.g."
                                   "<br/><br/> School of Engineering <br />"
                                   "School of Medicine<br />School of"
                                   "Informatics<br />"))

    mix_key = models.CharField(max_length=50, default=None, null=True)
    remote_mixing_finished_at = models.DateTimeField(default=None, null=True)

    created_at = models.DateTimeField(auto_now_add=True)
    terms_consent_at = models.DateTimeField(auto_now_add=True, null=True, default=None)
    modified_at = models.DateTimeField(auto_now=True)
    canceled_at = models.DateTimeField(default=None, null=True)
    cancelation_reason = models.TextField(default="")
    completed_at = models.DateTimeField(default=None, null=True)

    deleted = models.BooleanField(default=False)

    frozen_at = models.DateTimeField(default=None, null=True)
    voting_starts_at = models.DateTimeField(_("Voting starts at"),
                                            auto_now_add=False,
                                            default=_default_voting_starts_at,
                                            null=True,
                                            help_text=help.voting_starts_at)
    voting_ends_at = models.DateTimeField(_("Voting ends at"),
                                          auto_now_add=False,
                                          default=_default_voting_ends_at,
                                          null=True,
                                          help_text=help.voting_ends_at)
    voting_extended_until = models.DateTimeField(_("Voting extended until"),
                                                 auto_now_add=False,
                                                 default=None, blank=True,
                                                 null=True,
                                                 help_text=help.voting_extended_until)
    voting_ended_at = models.DateTimeField(auto_now_add=False, default=None,
                                           null=True)
    archived_at = models.DateTimeField(auto_now_add=False, default=None,
                                        null=True)
    official = models.IntegerField(null=True, default=None,
                                    choices=OFFICIAL_CHOICES)
    objects = ElectionManager()

    sms_data = models.ForeignKey(SMSBackendData, default=None, null=True)
    sms_api_enabled = models.BooleanField(default=False)

    cast_notify_once = models.BooleanField(default=True)

    cast_consent_text = models.TextField(_("Cast consent test"),
                                         default=None, null=True, blank=True,
                                         help_text=help.cast_consent_text)

    class Meta:
        ordering = ('-created_at', )

    def __init__(self, *args, **kwargs):
        self._logger = None
        super(Election, self).__init__(*args, **kwargs)


    @property
    def voter_code_login_url(self):
        default = settings.SECURE_URL_HOST + reverse('voter_quick_login', args=(self.communication_language,))
        return self._owner_override('VOTERS_LOGIN_URL', default)

    def _owner_override(self, setting, default):
        return getattr(settings, setting, {}).get(self.created_by.user_id, default)

    @property
    def created_by(self):
        return self.admins.filter()[0]

    @property
    def voter_password_len(self):
        default = getattr(settings, 'DEFAULT_VOTER_PASSWORD_SIZE', 12)
        return self._owner_override('VOTER_PASSWORD_SIZE', default)

    @property
    def sms_credentials(self):
        try:
            data = self.sms_data.credentials
            if not data:
                return None
            return data.strip().split(":")
        except:
            return None

    @property
    def sms_enabled(self):
        return self.sms_api_enabled and self.sms_data

    @property
    def polls_by_link(self):
        linked = self.polls.exclude(linked_ref=None).distinct("linked_ref")
        uuids = linked.values_list('linked_ref', flat=True)
        linked = map(lambda l: l.linked_to_poll, linked)
        unlinked = self.polls.filter(linked_ref=None).exclude(uuid__in=uuids)
        return itertools.chain(linked, unlinked)

    @property
    def voting_end_date(self):
        return self.voting_extended_until or self.voting_ends_at

    @property
    def zeus_stage(self):
        if not self.pk or not self.frozen_at:
            return 'CREATING'

        if not self.voting_ended_at:
            return 'VOTING'

        if not self.tallying_finished_at:
            return 'MIXING'

        if self.mix_key and not self.remote_mixing_finished_at:
            return 'MIXING'

        if not self.mix_finished_at:
            return 'DECRYPTING'

        return 'FINISHED'

    def reset_logger(self):
        self._logger = None

    @property
    def logger(self):
        if not self._logger:
            self._logger = init_election_logger(self)
        return self._logger

    @property
    def zeus(self):
        from zeus import election
        obj = election.ZeusDjangoElection.from_election(self)
        obj.do_set_stage(self.zeus_stage)
        return obj

    @property
    def polls_issues_before_freeze(self):
        issues = {}
        for poll in self.polls.all():
            poll_issues = poll.issues_before_freeze
            if len(poll_issues) > 0:
                issues[poll] = poll_issues
        return issues

    @property
    def election_issues_before_freeze(self):
        issues = []
        trustees = Trustee.objects.filter(election=self)
        if len(trustees) == 0:
            issues.append({
                'type': 'trustees',
                'action': _("Add at least one trustee")
            })

        for t in trustees:
            if t.public_key == None:
                issues.append({
                    'type': 'trustee-keypairs',
                    'action': _('Have trustee %s generate a keypair') % t.name
                })

            if t.public_key and t.last_verified_key_at == None:
                issues.append({
                    'type': 'trustee-verification',
                    'action': _('Have trustee %s verify his key') % t.name
                })
        return issues

    def status_display_cls(self):
        if self.feature_canceled:
            return 'error alert'
        return ''

    def status_display(self):

      if self.feature_canceled:
          return _('Canceled')

      if self.feature_completed:
          return _('Completed')

      if self.feature_voting:
          return _('Voting')

      if self.polls_feature_compute_results_finished:
          return _('Results computed')

      if self.any_poll_feature_compute_results_running:
          return _('Computing results')

      if self.polls_feature_decrypt_finished:
          return _('Decryption finished')

      if self.any_poll_feature_decrypt_running:
          return _('Decrypting')

      if self.polls_feature_partial_decrypt_finished:
          return _('Partial decryptions finished')

      if self.any_poll_feature_can_partial_decrypt and \
          self.polls_feature_validate_mixing_finished:
          return _('Pending completion of partial decryptions')

      if self.any_poll_feature_validate_mixing_running or \
          self.any_poll_feature_validate_mixing_finished:
          return _('Validating mixing')

      if self.polls_feature_mixing_finished:
          return _('Mixing finished')

      if self.feature_can_close_remote_mixing:
          return _('Waiting for remote mixes')

      if self.any_poll_feature_mix_running or self.any_poll_feature_mix_finished:
          return _('Mixing')

      if self.any_poll_feature_validate_voting_running or \
          self.any_poll_feature_validate_voting_finished:
          return _('Validating voting')

      if self.feature_closed:
          return _('Election closed')

      if self.feature_frozen and not self.feature_voting_started:
          return _('Waiting for voting to start.')

      if self.feature_frozen and not self.feature_within_voting_date:
          return _('Voting stopped. Pending close.')

      if self.any_poll_feature_validate_create_running:
          return _('Freezing')

      if self.feature_frozen:
          return _('Frozen')

      return _('Election pending to freeze')

    @property
    def remote_mix_url(self):
        return "%s%s" % (settings.SECURE_URL_HOST,
                         reverse('election_remote_mix', args=(self.uuid,
                            self.mix_key)))

    def check_mix_key(self, key):
        return key == self.mix_key

    def close_voting(self):
        self.voting_ended_at = datetime.datetime.now()
        self.save()
        self.logger.info("Voting closed")
        subject = "Election closed"
        msg = "Election closed"
        self.notify_admins(msg=msg, subject=subject)

    def freeze(self):
        for poll in self.polls.all():
            poll.freeze()

    def get_absolute_url(self):
        return "%s%s" % (settings.SECURE_URL_HOST,
                         reverse('election_index', args=(self.uuid,)))

    @property
    def cast_votes(self):
        return CastVote.objects.filter(poll__election=self)

    @property
    def voters(self):
        return Voter.objects.filter(poll__election=self)

    @property
    def voter_weights_enabled(self):
        return self.voters.filter(voter_weight__gt=1).count()

    @property
    def vote_weights_count(self):
        if self.voter_weights_enabled:
            weights = self.voters.not_excluded().values_list('voter_weight', flat=True)
            return reduce(lambda s, v: s + v, weights, 0)
        return self.voters.count()

    @property
    def audits(self):
        return AuditedBallot.objects.filter(poll__election=self)

    @property
    def casts(self):
        return CastVote.objects.filter(poll__election=self)

    def questions_count(self):
        count = 0
        for poll in self.polls.filter().only('questions_data'):
            count += len(poll.questions_data or [])
        return count

    def generate_mix_key(self):
        if self.mix_key:
            return self.mix_key
        else:
            self.mix_key = heliosutils.random_string(20)
        return self.mix_key

    def generate_trustee(self):
        """
        Generate the Zeus trustee.
        """

        if self.get_zeus_trustee():
            return self.get_zeus_trustee()

        self.zeus.create_zeus_key()
        return self.get_zeus_trustee()

    def get_zeus_trustee(self):
        trustees_with_sk = self.trustees.filter().zeus()
        if len(trustees_with_sk) > 0:
            return trustees_with_sk[0]
        else:
            return None

    def has_helios_trustee(self):
        return self.get_zeus_trustee() != None

    @transaction.atomic
    def update_trustees(self, trustees, notify=True):
        for name, email in trustees:
            trustee, created = self.trustees.get_or_create(email=email)
            if created:
                self.logger.info("Trustee %r created", trustee.email)
            # LOG TRUSTEE CREATED
            trustee.name = name
            trustee.save()

        if self.trustees.filter().no_secret().count() != len(trustees):
            emails = map(lambda t:t[1], trustees)
            for trustee in self.trustees.filter().no_secret():
                if not trustee.email in emails:
                    self.zeus.invalidate_election_public()
                    trustee.delete()
                    self.logger.info("Trustee %r deleted", trustee.email)
                    self.zeus.compute_election_public()
                    self.logger.info("Public key updated")
        if notify:
            self.auto_notify_trustees()

    def auto_notify_trustees(self, force=False):
        for trustee in self.trustees.exclude(secret_key__isnull=False):
            if not trustee.last_notified_at or force:
                trustee.send_url_via_mail()

    _zeus = None

    @property
    def zeus_stage(self):
        if not self.pk or not self.feature_frozen:
            return 'CREATING'

        if not self.voting_ended_at:
            return 'VOTING'

        if not self.any_poll_feature_mix_finished:
            return 'MIXING'

        if self.mix_key and not self.remote_mixing_finished_at:
            return 'MIXING'

        if not self.feature_polls_results_computed:
            return 'DECRYPTING'

        return 'FINISHED'

    def reprove_trustee(self, trustee):
        # public_key = trustee.public_key
        # pok = trustee.pok
        # self.zeus.reprove_trustee(public_key.y, [pok.commitment,
        #                                                  pok.challenge,
        #                                                  pok.response])
        self.logger.info("Trustee %r PK reproved", trustee.email)

        trustee.last_verified_key_at = datetime.datetime.now()
        trustee.save()

    def add_trustee_pk(self, trustee, public_key, pok):
        trustee.public_key = public_key
        trustee.pok = pok
        trustee.public_key_hash = utils.hash_b64(
            utils.to_json(
                trustee.public_key.toJSONDict()))
        trustee.last_verified_key_at = None
        trustee.save()
        # verify the pok
        trustee.send_url_via_mail()
        self.zeus.add_trustee(trustee.public_key.y, [pok.commitment,
                                                         pok.challenge,
                                                         pok.response])
        self.logger.info("Trustee %r PK updated", trustee.email)

    def notify_admins(self, msg='', subject='', send_anyway=False):
        """
        Notify admins with email
        """
        if send_anyway or (not self.trial):
            election_type = self.get_module().module_id
            trustees = self.trustees.all()
            admins = self.admins.all()
            context = {
                'election': self,
                'msg': msg,
                'election_type': election_type,
                'trustees': trustees,
                'admins': admins,
                'subject': subject,
            }

            body = render_to_string("email/admin_mail.txt", context)
            subject = render_to_string("email/admin_mail_subject.txt", context)
            mail_admins(subject.replace("\n", ""), body)

    def save(self, *args, **kwargs):
        if not self.uuid:
            self.uuid = unicode(uuid.uuid4())
        if not self.short_name:
            self.short_name = slughifi(self.name)[:100]
            es = Election.objects.filter()
            count = 1
            while es.filter(short_name=self.short_name).count() > 0:
                self.short_name = slughifi(self.name)[:100] + '-%d' % count
                count += 1

        super(Election, self).save(*args, **kwargs)

    def get_module(self):
        return get_election_module(self)
    
    def delete_trustees(self, dry=True):
        for trustee in self.trustees.filter():
            if not dry:
                self.logger.info("Delete trustee %s", trustee.email)
                trustee.delete()
            else:
                print "Delete %r" % trustee

    def delete_polls(self, dry=True):
        for poll in self.polls.filter():
            poll.delete_mixes(dry)
            poll.delete_proofs(dry)
            poll.delete_results(dry)
            if not dry:
                self.logger.info("Delete poll %s", poll.uuid)
                poll.delete()
            else:
                print "Delete poll %r" % poll.uuid

    def delete(self, dry=True):
        assert self.pk
        self.logger.info("Removing election data.")
        with transaction.atomic():
            self.delete_trustees(dry)
            self.delete_polls(dry)
            if not dry:
                self.logger.info("Election deleted.")
                super(Election, self).delete()
            else:
                print "Delete election %r" % self.uuid
        try:
            return self.logger.logger.handlers[0].stream.name
        except:
            return None



class PollQuerySet(QuerySet):
    pass


class PollManager(models.Manager):

    def forum_open(self, date=None):
        date = date or datetime.datetime.now()
        q = Q(forum_ends_at__gt=date,
              forum_extended_until__isnull=True) | \
            Q(forum_extended_until__gt=date,
              forum_extended_until__isnull=False)

        return self.filter(forum_enabled=True) \
                   .filter(election__voting_ended_at__isnull=True) \
                   .filter(q)
    def get_queryset(self):
        return PollQuerySet(self.model).defer('encrypted_tally')



class Poll(PollTasks, HeliosModel, PollFeatures):
  linked_ref = models.CharField(_('Poll reference id'), max_length=255,
                                null=True, default=None)
  name = models.CharField(_('Poll name'), max_length=255)
  short_name = models.CharField(max_length=255)

  election = models.ForeignKey('Election', related_name="polls")

  uuid = models.CharField(max_length=50, null=False, unique=True, db_index=True)
  zeus_fingerprint = models.TextField(null=True, default=None)

  # dates at which this was touched
  frozen_at = models.DateTimeField(default=None, null=True)
  created_at = models.DateTimeField(auto_now_add=True)
  modified_at = models.DateTimeField(auto_now_add=True)

  questions = LDObjectField(type_hint = 'legacy/Questions',
                            null=True)
  questions_data = JSONField(null=True)

  # used only for homomorphic tallies
  encrypted_tally = LDObjectField(type_hint='phoebus/Tally',
                                  null=True)

  # results of the election
  result = LDObjectField(type_hint = 'phoebus/Result',
                         null=True)
  stv_results = JSONField(null=True)
  stv_droop = models.BooleanField(default=True)

  eligibles_count = models.PositiveIntegerField(default=5)
  has_department_limit = models.BooleanField(default=0)
  department_limit = models.PositiveIntegerField(default=0)

  voters_last_notified_at = models.DateTimeField(null=True, default=None)
  index = models.PositiveIntegerField(default=1)
  
  taxisnet_auth = models.BooleanField(default=False, verbose_name=_("Taxisnet login"))

  # voters oauth2 authentication
  oauth2_thirdparty = models.BooleanField(default=False, verbose_name=_("Oauth2 login"))

  oauth2_type = models.CharField(max_length=25,
                                 null=True, blank=True)
  oauth2_client_type = models.CharField(max_length=25,
                                        null=True, blank=True)
  oauth2_client_id = models.CharField(max_length=255,
                                      null=True, blank=True)
  oauth2_client_secret = models.CharField(max_length=255,
                                          null=True, blank=True)
  oauth2_code_url = models.CharField(max_length=255,
                                null=True, blank=True)
  oauth2_exchange_url = models.CharField(max_length=255,
                                null=True, blank=True)
  oauth2_confirmation_url = models.CharField(max_length=255,
                                null=True, blank=True)
  oauth2_extra = models.CharField(max_length=255,
                                  null=True, blank=True)
  # jwt authentication
  jwt_auth = models.BooleanField(default=False, verbose_name=_("JWT login"))
  jwt_public_key = models.TextField(null=True, default=None)
  jwt_issuer = models.CharField(max_length=255,
                                null=True, blank=True)

  # shibboleth authentication
  shibboleth_auth = models.BooleanField(default=False, verbose_name=_("Shibboleth login"))
  shibboleth_constraints = JSONField(default=None, null=True, blank=True)

  forum_enabled = models.BooleanField(_('Election forum enabled'), default=False)
  forum_description = models.TextField(_('Forum description'), blank=True, null=True)
  forum_starts_at = models.DateTimeField(_("Forum access starts at"),
                                            auto_now_add=False,
                                            null=True,
                                            blank=True,
                                            default=None,
                                            help_text=help.forum_starts_at)
  forum_ends_at = models.DateTimeField(_("Forum access ends at"),
                                            auto_now_add=False,
                                            null=True,
                                            blank=True,
                                            default=None,
                                            help_text=help.forum_ends_at)
  forum_extended_until = models.DateTimeField(_("Forum extension date"),
                                            auto_now_add=False,
                                            null=True,
                                            blank=True,
                                            default=None,
                                            help_text=help.forum_ends_at)
  forum_last_periodic_notification_at = models.DateTimeField(null=True,
                                                          default=None)


  objects = PollManager()

  class Meta:
      ordering = ('-linked_ref', 'pk', 'created_at', )
      unique_together = (('name', 'election'),)

  def __init__(self, *args, **kwargs):
      self._logger = None
      super(Poll, self).__init__(*args, **kwargs)

  @property
  def remote_mix_url(self):
        return "%s%s" % (settings.SECURE_URL_HOST,
                         reverse('election_poll_remote_mix', args=(
                            self.election.uuid, self.uuid,
                            self.election.mix_key)))

  @property
  def sms_enabled(self):
    return self.election.sms_enabled

  @property
  def forum_posts(self):
      return self.post_set.filter(is_replaced=False)

  @property
  def forum_voters_count(self):
      return self.post_set.filter().distinct('voter').count()

  def get_shibboleth_constraints(self):
    defaults = {
        'assert_idp_key': 'REMOTE_USER',
        'assert_voter_key': 'id',
        'required_fields': ['REMOTE_USER', 'EPPN'],
        'endpoint': 'default/login'
    }
    profiles = getattr(settings, 'ZEUS_SHIBBOLETH_PROFILES', {})
    default_constraints = getattr(settings, 'SHIBBOLETH_DEFAULT_CONSTRAINTS',
                                  defaults)
    constraints = {}
    constraints.update(default_constraints)

    data = self.shibboleth_constraints or {}
    profile = data.get('profile', None)
    if data and profile and profile in profiles:
        data = profiles.get(profile)['data']
    constraints.update(data or {})
    return constraints

  @property
  def remote_login(self):
      return self.oauth2_thirdparty or self.jwt_auth or self.shibboleth_auth or self.taxisnet_auth

  @property
  def shibboleth_profile(self):
      profiles = getattr(settings, 'ZEUS_SHIBBOLETH_PROFILES', {})
      data = self.shibboleth_constraints

      if data and 'profile' in data:
          profile = profiles.get(data.get('profile'), None)
          return profile
      return None

  @property
  def remote_login_display(self):
      if self.jwt_auth:
          return _("JSON Web Token Login")
      if self.oauth2_thirdparty:
          return _("Oauth2 Login %s") % self.oauth2_client_id
      if self.shibboleth_profile:
          return _(self.shibboleth_profile.get('label', "Shibboleth authentication"))
      if self.shibboleth_auth:
          return _("Shibboleth authentication")
      if self.taxisnet_auth:
          return _("Taxisnet authentication")
      return None

  def reset_logger(self):
      self._logger = None

  @property
  def is_linked_root(self):
      return self.uuid and not self.linked_ref and self.linked_polls.count() > 1

  @property
  def is_linked_leaf(self):
      return self.is_linked and not self.is_linked_root

  @property
  def has_linked_polls(self):
    if not self.pk:
        return bool(self.linked_ref)
    return self.linked_ref or self.linked_polls.count() > 1

  @property
  def linked_to_poll(self):
      if self.is_linked_root:
          return self
      if not self.linked_ref:
          return None
      return self.election.polls.get(uuid=self.linked_ref)

  @property
  def linked_polls(self):
    polls = None
    qroot = Q(uuid=self.uuid)
    qother = Q(linked_ref=self.uuid)
    if self.linked_ref:
        qroot = Q(uuid=self.linked_ref)
        qother = Q(linked_ref=self.linked_ref)
    return self.election.polls.filter(qroot | qother).order_by('linked_ref', 'pk')

  @property
  def other_linked_polls(self):
    return self.linked_polls.exclude(pk=self.pk)

  @property
  def is_linked(self):
      return self.linked_ref or self.has_linked_polls

  def get_linked_ref(self):
      if self.is_linked_root:
          return self.uuid
      else:
          return self.linked_ref

  def next_linked_poll(self, voter_id=None, exclude_cast_done=True, cyclic=False):
      polls = self.other_linked_polls
      is_last = polls.filter(pk__gt=self.pk).count() == 0
      if is_last:
          if not cyclic:
              return None
      else:
          polls = polls.filter(pk__gt=self.pk)

      if voter_id and exclude_cast_done:
          polls = polls.filter(voters__voter_login_id=voter_id,
                               voters__cast_at__isnull=True)

      if polls.count():
          return polls[0]
      return None

  def sync_voter(self, root, voter):
    voter.voter_name = root.voter_name
    voter.voter_email = root.voter_email
    voter.voter_login_id = root.voter_login_id
    voter.voter_surname = root.voter_surname
    voter.voter_fathername = root.voter_fathername
    voter.voter_mobile = root.voter_mobile
    voter.voter_weight = root.voter_weight
    voter.excluded_at = root.excluded_at
    voter.exclude_reason = root.exclude_reason
    voter.last_sms_send_at = root.last_sms_send_at
    voter.last_sms_code = root.last_sms_code
    voter.last_email_send_at = root.last_email_send_at
    return voter

  def sync_linked_voters(self, force=False):
      assert not self.linked_ref
      if not self.feature_can_sync_voters and not force:
          self.logger.error("Skipping voter sync. Election is frozen")
          return

      self.logger.info("Sync voters for link %s", self.uuid)
      root_voter_ids = set(self.voters.filter().values_list('voter_login_id', flat=True))
      for poll in self.other_linked_polls:
          poll_voter_ids = set(poll.voters.filter().values_list('voter_login_id', flat=True))
          existing = root_voter_ids.intersection(poll_voter_ids)
          missing = root_voter_ids.difference(poll_voter_ids)
          stray = poll_voter_ids.difference(root_voter_ids)
          self.logger.info("Sync: Update %d existing voters", len(existing))
          self.logger.info("Sync: Create %d missing voters", len(missing))
          self.logger.error("Sync: Remove %d stray voters", len(stray))

          for root in self.voters.filter(voter_login_id__in=missing):
                voter_uuid = str(uuid.uuid4())
                voter = Voter(uuid=voter_uuid, poll=poll)
                voter.generate_password()
                voter.init_audit_passwords()
                self.sync_voter(root, voter)
                voter.save()

          for root in self.voters.filter(voter_login_id__in=existing):
              voter = poll.voters.get(voter_login_id=root.voter_login_id)
              self.sync_voter(root, voter)
              voter.save()

          for voter in poll.voters.filter(voter_login_id__in=stray):
              assert not voter.vote
              voter.delete()

  @property
  def logger(self):
      if not self._logger:
          self._logger = init_poll_logger(self)
      return self._logger

  @property
  def issues_before_freeze(self):
    issues = []
    if not self.questions:
        issues.append({
            "type": "questions",
            "action": _("Prepare poll questions")
        })
    if self.voters.count() == 0:
      issues.append({
          "type" : "voters",
          "action" : _('Import voters list')
          })

    return issues

  @property
  def zeus_stage(self):
    if not self.pk or not self.frozen_at:
        return 'CREATING'

    if not self.election.voting_ended_at:
        return 'VOTING'

    if not self.feature_mix_finished:
        return 'MIXING'

    if self.election.mix_key and not self.election.remote_mixing_finished_at:
        return 'MIXING'

    if not self.result:
        return 'DECRYPTING'

    return 'FINISHED'

  _zeus = None

  @property
  def zeus(self):
      """
      Retrieve zeus core django
      """
      from zeus import election
      obj = election.ZeusDjangoElection.from_poll(self)
      obj.do_set_stage(self.zeus_stage)
      return obj

  @property
  def get_oauth2_module(self):
    from zeus import oauth2
    return oauth2.get_oauth2_module(self)

  def get_booth_url(self, request, preview=False):
    url_params = {
        'token': unicode(csrf(request)['csrf_token']),
        'poll_url': "%s%s" % (settings.SECURE_URL_HOST,
                                self.get_absolute_url()),
        'poll_json_url': "%s%s" % (settings.SECURE_URL_HOST,
                                    self.get_json_url()),
        'messages_url': "%s%s" % (settings.SECURE_URL_HOST,
                                    self.get_js_messages_url()),
        'language': "%s" % (request.LANGUAGE_CODE)
    }
    if preview is True:
        url_params['preview'] = 1
    vote_url = "%s/%s/booth/vote.html?%s" % (
            settings.SECURE_URL_HOST,
            settings.SERVER_PREFIX,
            urllib.urlencode(url_params))
    return vote_url

  def get_absolute_url(self):
      return reverse('election_poll_index', args=[self.election.uuid,
                                                  self.uuid])

  def get_js_messages_url(self):
      return reverse('js_messages')

  def get_json_url(self):
      return reverse('election_poll_json', args=[self.election.uuid,
                                                  self.uuid])

  def get_module(self):
    return get_poll_module(self)

  def status_display(self):

      if self.election.feature_canceled:
          return _('Canceled')

      if self.election.feature_completed:
          return _('Completed')

      if self.feature_compute_results_finished:
          return _('Results computed')

      if self.feature_compute_results_running:
          return _('Computing results')

      if self.feature_decrypt_finished:
          return _('Decryption finished')

      if self.feature_decrypt_running:
          return _('Decrypting')

      if self.feature_partial_decrypt_running:
          return _('Waiting for all partial decryptions to finish')

      if self.feature_partial_decrypt_finished:
          return _('Partial decryptions finished')

      if self.election.feature_closed:
          return _('Voting closed')

      if self.election.feature_voting:
          return _('Voting')

      if self.election.feature_frozen:
          if self.election.feature_voting_date_passed:
              return _('Pending election close')

          return _('Frozen')

      if not self.questions_data:
          return _('No questions set')

      if not self.feature_voters_set:
          return _('No voters set')

      if not self.election.feature_frozen:
          return _('Ready to freeze')

  def name_display(self):
      return "%s, %s" % (self.election.name, self.name)

  def shortname_display(self):
      return "%s-%s" % (self.election.short_name, self.short_name)

  def get_last_mix(self):
    return self.mixnets.filter(status="finished").defer("data").order_by("-mix_order")[0]

  def get_booth_dict(self):
      cast_url = reverse('election_poll_cast',
                         args=[self.election.uuid, self.uuid])
      module = self.get_module()
      election = self.election

      public_key = {
        'g': str(election.public_key.g),
        'p': str(election.public_key.p),
        'q': str(election.public_key.q),
        'y': str(election.public_key.y),
      }

      data = {
          'cast_url': cast_url,
          'description': election.description,
          'frozen_at': self.frozen_at,
          'help_email': election.help_email,
          'help_phone': election.help_phone,
          'name': self.name,
          'election_name': election.name,
          'public_key': public_key,
          'questions': self.questions,
          'cast_consent_text': election.cast_consent_text or None,
          'questions_data': self.questions_data,
          'election_module': getattr(module, 'booth_module_id', module.module_id),
          'module_params': module.params,
          'uuid': self.uuid,
          'election_uuid': election.uuid,
          'voting_ends_at': election.voting_ends_at,
          'voting_starts_at': election.voting_starts_at,
          'voting_extended_until': election.voting_extended_until,
      }
      return data

  @property
  def cast_votes_count(self):
    return self.voters.exclude(vote=None).count()

  @property
  def audit_votes_cast_count(self):
    return self.audited_ballots.filter(is_request=False).count()

  @property
  def questions_count(self):
    if not self.questions_data:
      return 0
    else:
      return len(self.questions_data)

  @property
  def voters_count(self):
    return self.voters.count()

  @property
  def voter_weights_enabled(self):
    return self.voters.filter(voter_weight__gt=1).count()

  @property
  def vote_weights_count(self):
    if self.voter_weights_enabled:
        weights = self.voters.filter().not_excluded().values_list('voter_weight', flat=True)
        return reduce(lambda s, v: s + v, weights, 0)
    return self.voters.count()

  @property
  def last_alias_num(self):
    """
    FIXME: we should be tracking alias number, not the V* alias which then
    makes things a lot harder
    """

    # FIXME: https://docs.djangoproject.com/en/dev/topics/db/multi-db/#database-routers
    # use database routes api to find proper database for the Voter model.
    # This will still work if someone deploys helios using only the default
    # database.
    SUBSTR_FUNCNAME = "substring"
    if 'sqlite' in settings.DATABASES['default']['ENGINE']:
        SUBSTR_FUNCNAME = "substr"

    sql = "select max(cast(%s(alias, 2) as integer)) from %s where " \
          "poll_id = %s"
    sql = sql % (SUBSTR_FUNCNAME, Voter._meta.db_table, self.id or 0)
    return heliosutils.one_val_raw_sql(sql) or 0

  @property
  def trustees_string(self):
    helios_trustee = self.get_zeus_trustee()
    trustees = [(t.name, t.email) for t in self.trustee_set.all() if \
                t != helios_trustee]
    return "\n".join(["%s,%s" % (t[0], t[1]) for t in trustees])

  def _init_questions(self, answers_count):
    if not self.questions:
        question = {}
        question['answer_urls'] = [None for x in range(answers_count)]
        question['choice_type'] = 'stv'
        question['question'] = 'Questions choices'
        question['answers'] = []
        question['result_type'] = 'absolute'
        question['tally_type'] = 'stv'
        self.questions = [question]

  def update_answers(self):
      module = self.get_module()
      module.update_answers()

  @property
  def tallied(self):
    return self.mixing_finished

  def add_voters_file(self, uploaded_file, encoding):
    """
    expects a django uploaded_file data structure, which has filename, content,
    size...
    """
    new_voter_file = VoterFile(poll=self,
                               preferred_encoding=encoding,
                               voter_file_content=\
                               base64.encodestring(uploaded_file.read()))
    new_voter_file.save()
    return new_voter_file

  def election_progress(self):
    PROGRESS_MESSAGES = {
      'created': _('Election initialized.'),
      'candidates_added': _('Election candidates added.'),
      'votres_added': _('Election voters added.'),
      'keys_generated': _('Trustees keys generated.'),
      'opened': _('Election opened.'),
      'voters_notified': _('Election voters notified'),
      'voters_not_voted_notified': _('Election voters which not voted notified'),
      'extended': _('Election extension needed.'),
      'closed': _('Election closed.'),
      'tallied': _('Election tallied.'),
      'combined_decryptions': _('Trustees should decrypt results.'),
      'results_decrypted': _('Election results where decrypted.'),
    }

    OPTIONAL_STEPS = ['voters_not_voted_notified', 'extended']


  def voters_to_csv(self, q_param=None, to=None, include_vote_field=True, include_dates=False, include_poll_name=False):
    if not to:
      to = StringIO.StringIO()

    writer = csv.writer(to)

    voters = self.voters.all()
    if q_param:
        voters = self.get_module().filter_voters(voters, q_param)

    for voter in voters:
      vote_field = unicode(_("YES")) if voter.cast_votes.count() else \
                       unicode(_("NO"))
      if voter.excluded_at:
        vote_field += unicode(_("(EXCLUDED)"))

      fields = [voter.voter_login_id,
                                       voter.voter_email,
                                       voter.voter_name or '',
                                       voter.voter_surname or '',
                                       voter.voter_fathername or '',
                                       voter.voter_mobile or '',
                                       str(voter.voter_weight)
                                       ]
      if include_vote_field:
          fields.append(vote_field)
      if include_dates:
          fields.append(voter.last_visit)
      if include_poll_name:
          fields = [self.name] + fields
      writer.writerow(map(force_utf8, fields))
    return to

  def last_voter_visit(self):
      try:
          return self.voters.filter(last_visit__isnull=False).order_by(
              '-last_visit')[0].last_visit
      except IndexError:
          return None

  def last_cast_date(self):
      try:
          last_cast = self.cast_votes.filter(
                    voter__excluded_at__isnull=True).order_by('-cast_at')[0]
      except IndexError:
          return ""

      return last_cast.cast_at

  def voters_visited_count(self):
      return self.voters.filter(last_visit__isnull=False).count()

  def voters_cast_count(self):
    return self.cast_votes.filter(
        voter__excluded_at__isnull=True).distinct('voter').count()

  def total_cast_count(self):
    return self.cast_votes.filter(
        voter__excluded_at__isnull=True).count()

  def mix_failed(self):
    try:
      return self.mixes.get(status="error")
    except PollMix.DoesNotExist:
      return None

  def mixes_count(self):
      return self.mixes.count()

  @property
  def finished_mixes(self):
      return self.mixes.filter(status='finished').defer('data')

  def mixing_errors(self):
      errors = []
      for e in self.mixnets.filter(mix_error__isnull=False,
                                   status='error').defer('data'):
          errors.append(e.mix_error)
      return errors

  def add_remote_mix(self, remote_mix, mix_name="Remote mix"):
    error = ''
    status = 'finished'
    mix_order = int(self.mixes_count())

    try:
        self.zeus.add_mix(remote_mix)
    except Exception, e:
        logging.exception("Remote mix failed")
        status = 'error'
        error = traceback.format_exc()

    try:
        with transaction.atomic():
            mix = self.mixes.create(name=mix_name,
                                    mix_order=mix_order,
                                    mix_type='remote',
                                    mixing_started_at=datetime.datetime.now(),
                                    mixing_finished_at=datetime.datetime.now(),
                                    status=status,
                                    mix_error=error if error else None)
            #mix.store_mix(remote_mix)
            mix.store_mix_in_file(remote_mix)
    except Exception, e:
        logging.exception("Remote mix creation failed.")
        return e

    with transaction.atomic():
        if not Poll.objects.get(pk=self.pk).election.remote_mixing_finished_at:
            mix.save()
        else:
            return "Mixing finished"

    return error

  @property
  def remote_mixes(self):
      return self.mixes.filter(mix_type='remote',
                               status='finished').defer("data")

  def _get_zeus_vote(self, enc_vote, voter=None, audit_password=None):
    answer = enc_vote.encrypted_answers[0]
    cipher = answer.choices[0]
    alpha, beta = cipher.alpha, cipher.beta
    modulus, generator, order = self.zeus.do_get_cryptosystem()
    commitment, challenge, response = enc_vote.encrypted_answers[0].encryption_proof
    fingerprint = numbers_hash((modulus, generator, alpha, beta,
                                commitment, challenge, response))

    zeus_vote = {
      'fingerprint': fingerprint,
      'encrypted_ballot': {
          'beta': beta,
          'alpha': alpha,
          'commitment': commitment,
          'challenge': challenge,
          'response': response,
          'modulus': modulus,
          'generator': generator,
          'order': order,
          'public': self.election.public_key.y
      }
    }

    if hasattr(answer, 'answer') and answer.answer:
      zeus_vote['audit_code'] = audit_password
      zeus_vote['voter_secret'] = answer.randomness[0]

    if audit_password:
      zeus_vote['audit_code'] = audit_password

    if voter:
      zeus_vote['voter'] = voter.uuid

    return zeus_vote

  def cast_vote(self, voter, enc_vote, audit_password=None):
    zeus_vote = self._get_zeus_vote(enc_vote, voter, audit_password)
    return self.zeus.cast_vote(zeus_vote)

  def zeus_proofs_path(self):
    return os.path.join(settings.ZEUS_PROOFS_PATH, '%s-%s.zip' %
                        (self.election.uuid, self.uuid))

  def store_zeus_proofs(self):
    if not self.result:
      return None

    zip_path = self.zeus_proofs_path()
    if os.path.exists(zip_path):
      os.unlink(zip_path)

    export_data = self.zeus.export()
    self.zeus_fingerprint = export_data[0]['election_fingerprint']
    self.save()

    zf = zipfile.ZipFile(zip_path, mode='w')
    data_info = zipfile.ZipInfo('%s_proofs.txt' % self.short_name)
    data_info.compress_type = zipfile.ZIP_DEFLATED
    data_info.comment = "Election %s (%s-%s) zeus proofs" % (self.zeus_fingerprint,
                                                          self.election.uuid, self.uuid)
    data_info.date_time = datetime.datetime.now().timetuple()
    data_info.external_attr = 0777 << 16L

    tmpf = tempfile.TemporaryFile(mode="w", suffix='.zeus',
                                  prefix='tmp', dir='/tmp')
    to_canonical(export_data[0], out=tmpf)
    tmpf.flush()
    size = tmpf.tell()
    zeus_data = mmap.mmap(tmpf.fileno(), 0, mmap.MAP_SHARED, mmap.PROT_READ)
    zf.writestr(data_info, zeus_data)
    zf.close()
    tmpf.close()

  def save(self, *args, **kwargs):
    if not self.uuid:
      self.uuid = str(uuid.uuid4())
    if not self.short_name:
      self.short_name = slughifi(self.name)[:100]
      es = self.election.polls.filter()
      count = 1
      while es.filter(short_name=self.short_name).count() > 0:
        self.short_name = slughifi(self.name)[:100] + '-%d' % count
        count += 1
    if not self.linked_ref:
        self.linked_ref = None
    super(Poll, self).save(*args, **kwargs)

  @property
  def forum_end_date(self):
    return self.forum_extended_until or self.forum_ends_at

  def delete_mixes(self, dry=True):
    for mix in self.mixes.filter():
      if not dry:
        self.logger.info("Removing mix file %s", self.zeus_proofs_path())
        safe_unlink(mix.mix_path)
        mix.delete()
      else:
        print "Delete file %s" % mix.mix_path

  def delete_proofs(self, dry=True):
    if not dry:  
      self.logger.info("Removing proofs file %s", self.zeus_proofs_path())
      safe_unlink(self.zeus_proofs_path())
    else:
      print "Delete file %s" % self.zeus_proofs_path()
  
  def delete_results(self, dry=True):
      mod = self.election.get_module()
      p = mod.get_election_result_file_path('*', '*')
      p = p[:-2] + '*'
      import glob
      results = glob.glob(p)
      for r in results:
          assert self.election.short_name in r
      for r in results:
          if not dry:
              self.logger.info("Removing result file %s", r)
              safe_unlink(r)
          else:
              print "Delete result file %s" % r

  def voter_file_processing(self):
    uploads = VoterFile.objects.filter(poll=self)
    if uploads.count():
        upload = uploads[0]
        if upload.processing_started_at and not upload.processing_finished_at:
            return upload
    return None

  @property
  def mixed_ballots_json_dict(self):
      ciphers = self.zeus.get_mixed_ballots()
      return {
          'num_tallied': len(ciphers),
          'tally': [[{'alpha':str(c[0]), 'beta':str(c[1])} for c in ciphers]]
      }

  @property
  def mixed_ballots(self):
      ciphers = self.zeus.get_mixed_ballots()
      return {
          'num_tallied': len(ciphers),
          'tally': [[{'alpha':c[0], 'beta':c[1]} for c in ciphers]]
      }


class ElectionLog(models.Model):
  """
  a log of events for an election
  """

  FROZEN = "frozen"
  VOTER_FILE_ADDED = "voter file added"
  DECRYPTIONS_COMBINED = "decryptions combined"

  election = models.ForeignKey(Election)
  log = models.CharField(max_length=500)
  at = models.DateTimeField(auto_now_add=True)


def get_voter_reader(voter_data, preferred_encoding=None):
    reader = CSVReader(voter_data, min_fields=2, max_fields=7,
                       preferred_encoding=preferred_encoding)
    return reader

def iter_voter_data(voter_data, email_validator=validate_email,
                    voter_id_validator=None, preferred_encoding=None):
    reader = get_voter_reader(voter_data, preferred_encoding)

    line = 0
    for voter_fields in reader:
        line += 1
        # bad line
        if len(voter_fields) < 1:
            continue

        return_dict = {}

        # strip leading/trailing whitespace from all fields
        for i, f in enumerate(voter_fields):
            voter_fields[i] = f.strip()

        if len(voter_fields) < 2:
            m = _("There must be at least two fields, Registration ID and Email")
            raise ValidationError(m)

        voter_id = voter_fields[0]
        if voter_id_validator:
            try:
                voter_id_validator(voter_id)
            except Exception, e:
                m = _(e.message)
                err = ValidationError(m)
                setattr(err, 'line', line)
                raise err
        return_dict['voter_id'] = voter_id

        email = voter_fields[1].strip()
        if len(email) > 0:
            email_validator(email, line)
        else:
            email = None
        return_dict['email'] = email
        if len(voter_fields) == 2:
            yield return_dict
            continue

        name = voter_fields[2]
        return_dict['name'] = name
        if len(voter_fields) == 3:
            yield return_dict
            continue

        surname = voter_fields[3]
        return_dict['surname'] = surname
        if len(voter_fields) == 4:
            yield return_dict
            continue

        fathername = voter_fields[4]
        return_dict['fathername'] = fathername
        if len(voter_fields) == 5:
            yield return_dict
            continue

        mobile = voter_fields[5]
        if mobile:
            mobile = mobile.replace(' ', '')
            mobile = mobile.replace('-', '')
            if len(mobile) < 4 or not mobile[1:].isdigit or \
                (mobile[0] != '+' and not mobile[0].isdigit()):
                    m = _("Malformed mobile phone number: %s") % mobile
                    raise ValidationError(m)
        else:
            mobile = None
        return_dict['mobile'] = mobile

        weight = voter_fields[6]
        if weight:
            try:
                weight = int(weight)
                if weight <= 0:
                    raise ValueError()
            except ValueError:
                m = _("Voter weight must be a positive integer, not %s")
                m = m % weight
                raise ValidationError(m)
            return_dict['weight'] = weight

        yield return_dict

        if len(voter_fields) > 7:
            m = _("Invalid voter data at line %s") %line
            raise ValidationError(m)

class VoterFile(models.Model):
  """
  A model to store files that are lists of voters to be processed.
  Format:
     registration_id, email, name, surname, extra_name, mobile_number.
  Note:
     - All fields are strings, stripped from leading/trailing whitespace.
     - There will be one vote per registration_id
     - Multiple registration_ids can have the same email
       (more than one votes per person)
     - Multiple emails per registration_id will update this voters email.

  """
  # path where we store voter upload
  PATH = settings.VOTER_UPLOAD_REL_PATH

  poll = models.ForeignKey(Poll)

  voter_file_content = models.TextField(null=True)

  uploaded_at = models.DateTimeField(auto_now_add=True)
  processing_started_at = models.DateTimeField(auto_now_add=False, null=True)
  is_processing = models.BooleanField(default=False)
  processing_finished_at = models.DateTimeField(auto_now_add=False, null=True)
  num_voters = models.IntegerField(null=True)
  process_error = models.TextField(null=True, default=None)
  process_status = models.TextField(null=True, default=None)
  preferred_encoding = models.CharField(max_length=255, default='utf8')


  @property
  def status(self):
      status = _("Pending")
      if self.processing_started_at:
          if self.num_voters:
              status = _("Processing (%d processed)...") % self.num_voters
          else:
              status = _("Processing...")
      if self.processing_finished_at:
          status = _("Completed (%d voters processed).") % self.num_voters
      if self.process_error:
          status = _("Something went wrong")
      return status



  @classmethod
  def upload_is_processing(cls, poll):
      return cls.objects.filter(poll=poll, is_processing=True).order_by('-pk')

  @classmethod
  def last_error_message(cls, poll):
      last = cls.objects.filter(poll=poll, is_processing=False).order_by('-pk')
      if last.count() and last[0].process_error:
          return last[0].process_error

  def itervoters(self, email_validator=validate_email, preferred_encoding=None):
    voter_data = base64.decodestring(self.voter_file_content)

    preferred_encoding = preferred_encoding or self.preferred_encoding
    return iter_voter_data(voter_data, email_validator=email_validator,
                           preferred_encoding=preferred_encoding)

  def validate_voter_entry(self, voter, line=None):
      if not any([voter['email'], voter['mobile']]):
          msg = _("Voter [%s]: Provide at least one of the email and mobile fields." \
                  % voter['voter_id'])
          err = ValidationError(msg)
          setattr(err, 'line', line)
          raise err

      if voter['mobile'] and not self.poll.sms_enabled:
          msg = _("Mobile backend is not set for this election")
          err = ValidationError(msg)
          setattr(err, 'line', line)
          raise err

      try:
          django_validate_email(voter['email'])
      except ValidationError, e:
          err = ValidationError(msg)
          err.message(_("Invalid email address", voter['email']))
          setattr(err, 'line', line)
          raise err


  def validate_process(self):
      demo_voters = 0
      poll = self.poll
      demo_user = False
      for user in poll.election.admins.all():
          if user.user_id.startswith('demo_'):
              demo_user = True

      nr = sum(e.voters.count() for e in user.elections.all())
      demo_voters += nr
      if demo_voters >= settings.DEMO_MAX_VOTERS and demo_user:
          raise exceptions.VoterLimitReached("No more voters for demo account")


  def end_process(self, error=None):
      self.process_error = error
      self.is_processing = False
      self.processing_finished_at = datetime.datetime.utcnow()
      self.save()

  def do_process(self, *args, **kwargs):
      self.processing_started_at = datetime.datetime.utcnow()
      self.is_processing = True
      self.save()
      error = None
      num_voters = 0
      try:
          num_voters = self.process(*args, **kwargs)
      except (exceptions.VoterLimitReached, \
        exceptions.DuplicateVoterID, ValidationError, ValueError, Exception) as e:
            line = None
            if e and hasattr(e, 'line'):
                line = e.line
            error = e and e.message
            if not error and hasattr(e, 'm'):
                error = e.m
            error = error or "Something went wrong"
            if line:
                error = u"%d: %s" % (line, unicode(error))
      self.num_voters = 0 if error else num_voters
      if error:
          logged_error = error
          try:
            logged_error = unicode(error)
          except:
             pass
          self.poll.logger.error("Failed to process voter file: %r. Error was: %s", self.pk, logged_error)
      self.end_process(error)

  @transaction.atomic
  def process(self, linked=True, check_dupes=True, preferred_encoding=None, report=None):
    preferred_encoding = preferred_encoding or self.preferred_encoding
    demo_voters = 0
    poll = Poll.objects.get(pk=self.poll.pk)
    demo_user = False
    for user in poll.election.admins.all():
        if user.user_id.startswith('demo_'):
            demo_user = True

    nr = sum(e.voters.count() for e in user.elections.all())
    demo_voters += nr

    # now we're looking straight at the content
    voter_data = base64.decodestring(self.voter_file_content)

    def email_validator(email, ln):
        try:
            django_validate_email(email)
        except ValidationError, e:
            err = ValidationError(e.message)
            setattr(err, 'line', ln)
            raise err
    voter_id_validator = None
    if poll.taxisnet_auth:
        voter_id_validator = validate_afm
    reader = iter_voter_data(voter_data, email_validator=email_validator,
        voter_id_validator=voter_id_validator,
        preferred_encoding=preferred_encoding)

    last_alias_num = poll.last_alias_num

    num_voters = 0
    new_voters = []
    for voter in reader:
      num_voters += 1
      voter_id = voter['voter_id']
      email = voter['email']
      name = voter.get('name', '')
      surname = voter.get('surname', '')
      fathername = voter.get('fathername', '')
      mobile = voter.get('mobile', '')
      weight = voter.get('weight', 1)

      interval = getattr(settings, 'VOTER_FILE_REPORT_COUNT', 30)
      if (num_voters % interval) == 0:
          if report:
              report(self.pk, num_voters)

      self.validate_voter_entry(voter, num_voters)

      voter = None
      try:
          voter = Voter.objects.get(poll=poll, voter_login_id=voter_id)
          if check_dupes:
            m = _("Duplicate voter id"
                    " : %s" % voter_id)
            raise exceptions.DuplicateVoterID(m)
          else:
            if not voter.can_update:
                raise ValidationError(_("Permission denied to update entry: %s") % voter_id)
      except Voter.DoesNotExist:
          pass
      # create the voter
      if not voter:
        demo_voters += 1
        if demo_voters > settings.DEMO_MAX_VOTERS and demo_user:
          raise exceptions.VoterLimitReached("No more voters for demo account")

      linked_polls = poll.linked_polls
      for _poll in linked_polls:
        new_voters = []
        voter = None
        try:
            voter = Voter.objects.get(poll=_poll, voter_login_id=voter_id)
        except Voter.DoesNotExist:
            pass
        if not voter:
            voter_uuid = str(uuid.uuid4())
            voter = Voter(uuid=voter_uuid, voter_login_id=voter_id,
                        voter_name=name, voter_email=email, poll=_poll,
                        voter_surname=surname, voter_fathername=fathername,
                        voter_mobile=mobile, voter_weight=weight)
            voter.init_audit_passwords()
            voter.generate_password()
            new_voters.append(voter)
            voter.save()
        else:
            voter.voter_name = name
            voter.voter_surname = surname
            voter.voter_fathername = fathername
            voter.voter_email = email
            voter.voter_mobile = mobile
            voter.voter_weight = weight
            voter.save()

        voter_alias_integers = range(last_alias_num+1, last_alias_num+1+num_voters)
        random.shuffle(voter_alias_integers)
        for i, voter in enumerate(new_voters):
            voter.alias = 'V%s' % voter_alias_integers[i]
            voter.save()

    return num_voters


class VoterQuerySet(QuerySet):

    def not_excluded(self):
        return self.filter(excluded_at__isnull=True)

    def excluded(self):
        return self.filter(excluded_at__isnull=False)

    def cast(self):
        return self.filter().not_excluded().annotate(
            num_cast=Count('cast_votes')).filter(num_cast__gte=1)

    def nocast(self):
        return self.filter().not_excluded().annotate(
            num_cast=Count('cast_votes')).filter(num_cast=0)

    def invited(self):
        return self.filter(last_booth_invitation_send_at__isnull=False)

    def visited(self):
        return self.filter(last_visit__isnull=False)

    def email_set(self):
        return self.filter(voter_email__isnull=False).exclude(voter_email="")

    def mobile_set(self):
        return self.filter(voter_mobile__isnull=False).exclude(voter_mobile="")

class VoterManager(models.Manager):

    def get_queryset(self):
        return VoterQuerySet(self.model)


class Voter(HeliosModel, VoterFeatures):
  poll = models.ForeignKey(Poll, related_name="voters")
  uuid = models.CharField(max_length = 50)


  # if user is null, then you need a voter login ID and password
  voter_login_id = models.CharField(max_length = 100, null=True)
  voter_password = models.CharField(max_length = 100, null=True)
  voter_name = models.CharField(max_length = 200, null=True)
  voter_surname = models.CharField(max_length = 200, null=True)
  voter_email = models.CharField(max_length = 250, null=True)
  voter_fathername = models.CharField(max_length = 250, null=True)
  voter_mobile = models.CharField(max_length = 48, null=True)
  voter_weight = models.PositiveIntegerField(default=1)

  # if election uses aliases
  alias = models.CharField(max_length = 100, null=True)

  # we keep a copy here for easy tallying
  vote = LDObjectField(type_hint = 'phoebus/EncryptedVote',
                       null=True)
  vote_hash = models.CharField(max_length = 100, null=True)
  vote_fingerprint = models.CharField(max_length=255)
  vote_signature = models.TextField()
  vote_index = models.PositiveIntegerField(null=True)

  cast_at = models.DateTimeField(auto_now_add=False, null=True)
  audit_passwords = models.CharField(max_length=200, null=True)

  last_sms_send_at = models.DateTimeField(null=True)
  last_sms_code = models.CharField(max_length=100, blank=True, null=True)
  last_sms_status = models.CharField(max_length=255, blank=True, null=True)

  last_email_send_at = models.DateTimeField(null=True)
  last_booth_invitation_send_at = models.DateTimeField(null=True)
  last_visit = models.DateTimeField(null=True)

  excluded_at = models.DateTimeField(null=True, default=None)
  exclude_reason = models.TextField(default='')

  objects = VoterManager()

  class Meta:
    unique_together = (('poll', 'voter_login_id'), ('poll', 'voter_password'))

  user = None

  def update_last_visit(self, date):
      self.last_visit = date
      for voter in self.linked_voters:
          voter.last_visit = date
          voter.save()
      self.save()

  def notify(self, method, subject, body, vars):
      backend = self.get

  @property
  def contact_methods(self):
      methods_attr_map = (
          ('voter_email', 'email'),
          ('voter_mobile', 'sms')
      )
      method_enabled = lambda x: x[1] if getattr(self, x[0], None) else None
      return filter(bool, map(method_enabled, methods_attr_map))

  def voter_email_display(self):
      return self.voter_email or _("No email set")

  def voter_contact_field_display(self):
      return self.voter_email or self.voter_mobile

  @property
  def linked_voters(self):
      return Voter.objects.filter(poll__in=self.poll.linked_polls,
                                  voter_login_id=self.voter_login_id)

  def get_cast_votes(self):
      return self.cast_votes.filter()

  def __init__(self, *args, **kwargs):
    super(Voter, self).__init__(*args, **kwargs)

    # stub the user so code is not full of IF statements
    if not self.user:
      self.user = User(user_type='password', user_id=self.voter_email,
                       name=u"%s %s" % (self.voter_name, self.voter_surname))

  @staticmethod
  def extract_login_code(code):
      code = re.sub("\s|-", "", code)
      poll_pos = (len(code) % 4) or 4
      poll = code[:poll_pos].strip()
      code = code[poll_pos:].strip()
      if not all([poll, code]):
           raise ValueError("Invalid code")
      return poll, undecalize(code)

  @property
  def login_code(self):
      return "%d-%s" % (self.poll.pk, decalize(str(self.voter_password)))

  @property
  def voted_nodb(self):
      return bool(self.vote_hash)

  @property
  def voted(self):
      return self.cast_votes.count() > 0

  @property
  def voted_linked(self):
      return any([v.voted for v in self.linked_voters])

  @property
  def participated_in_forum(self):
      return self.post_set.count() > 0

  @property
  def participated_in_forum_linked(self):
      return any([v.participated_in_forum for v in self.linked_voters])

  @property
  def forum_posts_count(self):
      return self.post_set.count()

  @property
  def zeus_string(self):
    return u"%s %s %s %s <%s>" % (self.voter_name, self.voter_surname,
                                  self.voter_fathername or '',
                                  self.voter_mobile or '', self.voter_login_id)
  @property
  def full_name(self):
    return u"%s %s %s (%s)" % (self.voter_name, self.voter_surname,
                               self.voter_fathername or '', self.voter_email)

  @property
  def forum_name(self):
    if self.voter_fathername:
        return u"%s %s, %s" % (self.voter_name, self.voter_surname,
                               self.voter_fathername)
    return u"%s %s" % (self.voter_name, self.voter_surname)

  def init_audit_passwords(self):
    if not self.audit_passwords:
      passwords = ""
      for i in range(4):
        passwords += heliosutils.random_string(5) + "|"

      self.audit_passwords = passwords

  def get_audit_passwords(self):
    if not self.audit_passwords or not self.audit_passwords.strip():
      return []

    return filter(bool, self.audit_passwords.split("|"))

  def get_quick_login_url(self):
      url = reverse('election_poll_voter_booth_login', kwargs={
          'election_uuid': self.poll.election.uuid,
          'poll_uuid': self.poll.uuid,
          'voter_uuid': self.uuid,
          'voter_secret': self.voter_password
      });
      return settings.URL_HOST + url

  def check_audit_password(self, password):
    if password != "" and password not in self.get_audit_passwords():
      return True

    return False

  @classmethod
  @transaction.atomic
  def register_user_in_election(cls, user, election):
    voter_uuid = str(uuid.uuid4())
    voter = Voter(uuid= voter_uuid, user = user, election = election)

    # do we need to generate an alias?
    heliosutils.lock_row(Election, election.id)
    alias_num = election.last_alias_num + 1
    voter.alias = "V%s" % alias_num

    voter.save()
    return voter

  @classmethod
  def get_by_election(cls, election, cast=None, order_by='voter_login_id', after=None, limit=None):
    """
    FIXME: review this for non-GAE?
    """
    query = cls.objects.filter(election = election)

    # the boolean check is not stupid, this is ternary logic
    # none means don't care if it's cast or not
    if cast == True:
      query = query.exclude(cast_at = None)
    elif cast == False:
      query = query.filter(cast_at = None)

    # little trick to get around GAE limitation
    # order by uuid only when no inequality has been added
    if cast == None or order_by == 'cast_at' or order_by =='-cast_at':
      query = query.order_by(order_by)

      # if we want the list after a certain UUID, add the inequality here
      if after:
        if order_by[0] == '-':
          field_name = "%s__gt" % order_by[1:]
        else:
          field_name = "%s__gt" % order_by
        conditions = {field_name : after}
        query = query.filter (**conditions)

    if limit:
      query = query[:limit]

    return query

  @classmethod
  def get_all_by_election_in_chunks(cls, election, cast=None, chunk=100):
    return cls.get_by_election(election)

  @classmethod
  def get_by_election_and_voter_id(cls, election, voter_id):
    try:
      return cls.objects.get(poll= election, voter_email = voter_id)
    except cls.DoesNotExist:
      return None

  @classmethod
  def get_by_election_and_user(cls, election, user):
    try:
      return cls.objects.get(election = election, user = user)
    except cls.DoesNotExist:
      return None

  @classmethod
  def get_by_election_and_uuid(cls, election, uuid):
    query = cls.objects.filter(election = election, uuid = uuid)

    try:
      return query[0]
    except:
      return None

  @classmethod
  def get_by_user(cls, user):
    return cls.objects.select_related().filter(user = user).order_by('-cast_at')

  @property
  def datatype(self):
    return self.election.datatype.replace('Election', 'Voter')

  @property
  def vote_tinyhash(self):
    """
    get the tinyhash of the latest castvote
    """
    if not self.vote_hash:
      return None

    return CastVote.objects.get(vote_hash = self.vote_hash).vote_tinyhash

  @property
  def election_uuid(self):
    return self.election.uuid

  @property
  def name(self):
    return self.voter_name

  @property
  def voter_id(self):
    return self.user.user_id

  @property
  def voter_id_hash(self):
    if self.voter_login_id:
      # for backwards compatibility with v3.0, and since it doesn't matter
      # too much if we hash the email or the unique login ID here.
      value_to_hash = self.voter_login_id
    else:
      value_to_hash = self.voter_id

    try:
      return utils.hash_b64(value_to_hash)
    except:
      try:
        return utils.hash_b64(value_to_hash.encode('latin-1'))
      except:
        return utils.hash_b64(value_to_hash.encode('utf-8'))

  @property
  def voter_type(self):
    return self.user.user_type

  @property
  def display_html_big(self):
    return self.user.display_html_big

  def send_message(self, subject, body):
    self.user.send_message(subject, body)

  def generate_password(self, force=False, size=None):
    size = size or self.poll.election.voter_password_len
    if not self.voter_password or force:
      self.voter_password = heliosutils.random_string(size)
      existing = Voter.objects.filter(
          poll=self.poll).exclude(pk=self.pk)
      while existing.filter(voter_password=self.voter_password).count() > 1:
        self.voter_password = heliosutils.random_string(size)

  def store_vote(self, cast_vote):
    # only store the vote if it's cast later than the current one
    if self.cast_at and cast_vote.cast_at < self.cast_at:
      return

    self.vote = cast_vote.vote
    self.vote_hash = cast_vote.vote_hash
    self.cast_at = cast_vote.cast_at
    self.save()

  def last_cast_vote(self):
    return CastVote(vote = self.vote, vote_hash = self.vote_hash, cast_at = self.cast_at, voter=self)

  @property
  def forum_display(self):
      return self.forum_name

  @property
  def has_active_forum_updates_registration(self):
      return self.forumupdatesregistration_set.filter(active=True).count() > 0

  @property
  def can_delete(self):
      if self.vote_hash:
          return False
      return not self.voted_linked and not self.participated_in_forum_linked

  @property
  def can_update(self):
      return self.can_delete

class CastVoteQuerySet(QuerySet):

    def distinct_voter(self):
        return self.distinct('voter')

    def countable(self):
        return self.filter(voter__excluded_at__isnull=True)

    def excluded(self):
        return self.filter(voter__excluded_at__isnull=False)

    def not_excluded(self):
        return self.filter(voter__excluded_at__isnull=True)


class CastVoteManager(models.Manager):

    def get_queryset(self):
        return CastVoteQuerySet(self.model)


class CastVote(HeliosModel):
  # the reference to the voter provides the voter_uuid
  voter = models.ForeignKey(Voter, related_name="cast_votes")
  poll = models.ForeignKey(Poll, related_name="cast_votes")

  previous = models.CharField(max_length=255, default="")

  # the actual encrypted vote
  vote = LDObjectField(type_hint='phoebus/EncryptedVote')

  # cache the hash of the vote
  vote_hash = models.CharField(max_length=100)

  # a tiny version of the hash to enable short URLs
  vote_tinyhash = models.CharField(max_length=50, null=True, unique=True)

  cast_at = models.DateTimeField(auto_now_add=True)
  audit_code = models.CharField(max_length=100, null=True)

  # some ballots can be quarantined (this is not the same thing as provisional)
  quarantined_p = models.BooleanField(default=False, null=False)
  released_from_quarantine_at = models.DateTimeField(auto_now_add=False,
                                                     null=True)

  # when is the vote verified?
  verified_at = models.DateTimeField(null=True)
  invalidated_at = models.DateTimeField(null=True)
  fingerprint = models.CharField(max_length=255)
  signature = JSONField(null=True)
  index = models.PositiveIntegerField(null=True)

  objects = CastVoteManager()

  class Meta:
    unique_together = (('poll', 'index'),)
    ordering = ('-cast_at',)

  @property
  def datatype(self):
    return self.voter.datatype.replace('Voter', 'CastVote')

  @property
  def voter_uuid(self):
    return self.voter.uuid

  @property
  def voter_hash(self):
    return self.voter.hash

  @property
  def is_quarantined(self):
    return self.quarantined_p and not self.released_from_quarantine_at

  def set_tinyhash(self):
    """
    find a tiny version of the hash for a URL slug.
    """
    safe_hash = self.vote_hash
    for c in ['/', '+']:
      safe_hash = safe_hash.replace(c,'')

    length = 8
    while True:
      vote_tinyhash = safe_hash[:length]
      if CastVote.objects.filter(vote_tinyhash = vote_tinyhash).count() == 0:
        break
      length += 1

    self.vote_tinyhash = vote_tinyhash

  def save(self, *args, **kwargs):
    """
    override this just to get a hook
    """
    # not saved yet? then we generate a tiny hash
    if not self.vote_tinyhash:
      self.set_tinyhash()

    super(CastVote, self).save(*args, **kwargs)


class AuditedBallotQuerySet(QuerySet):

    def confirmed(self):
        return self.filter(is_request=False)

    def requests(self):
        return self.filter(is_request=True)


class AuditedBallotManager(models.Manager):

    def get_queryset(self):
        return AuditedBallotQuerySet(self.model)


class AuditedBallot(models.Model):
  """
  ballots for auditing
  """
  poll = models.ForeignKey(Poll, related_name="audited_ballots")
  voter = models.ForeignKey(Voter, null=True)
  raw_vote = models.TextField()
  vote_hash = models.CharField(max_length=100)
  added_at = models.DateTimeField(auto_now_add=True)
  fingerprint = models.CharField(max_length=255)
  audit_code = models.CharField(max_length=100)
  is_request = models.BooleanField(default=True)
  signature = JSONField(null=True)

  objects = AuditedBallotManager()

  @property
  def choices(self):
    module = self.poll.get_module()
    answers = self.poll.questions[0]['answers']
    encoded = self.vote.encrypted_answers[0].answer
    return module.get_choices_pretty(encoded, answers)

  @classmethod
  def get(cls, election, vote_hash):
    return cls.objects.get(election = election, vote_hash = vote_hash,
                           is_request=False)

  @classmethod
  def get_by_election(cls, election, after=None, limit=None, extra={}):
    query = cls.objects.filter(election =
                               election).order_by('-pk').filter(**extra)

    # if we want the list after a certain UUID, add the inequality here
    if after:
      query = query.filter(vote_hash__gt = after)

    query = query.filter(is_request=False)
    if limit:
      query = query[:limit]

    return query

  @property
  def vote(self):
    return electionalgs.EncryptedVote.fromJSONDict(
                utils.from_json(self.raw_vote))
  class Meta:
    unique_together = (('poll', 'is_request', 'fingerprint'))


class TrusteeDecryptionFactorsQuerySet(QuerySet):

    def no_secret(self):
        return self.filter(trustee__secret_key__isnull=True)

    def completed(self):
        return self.filter(decryption_factors__isnull=False).filter(
            decryption_proofs__isnull=False)


class TrusteeDecryptionFactorsManager(models.Manager):

    def get_queryset(self):
        return TrusteeDecryptionFactorsQuerySet(self.model)


class TrusteeDecryptionFactors(models.Model):

  trustee = models.ForeignKey('Trustee', related_name='partial_decryptions')
  poll = models.ForeignKey('Poll', related_name='partial_decryptions')
  decryption_factors = LDObjectField(
      type_hint=datatypes.arrayOf(datatypes.arrayOf('core/BigInteger')),
      null=True)
  decryption_proofs = LDObjectField(
      type_hint=datatypes.arrayOf(datatypes.arrayOf('legacy/EGZKProof')),
      null=True)

  objects = TrusteeDecryptionFactorsManager()

  class Meta:
      unique_together = (('trustee', 'poll'),)


class TrusteeQuerySet(QuerySet):

    def no_secret(self):
        return self.filter(secret_key__isnull=True)

    def zeus(self):
        return self.filter(secret_key__isnull=False)


class TrusteeManager(models.Manager):

    def get_queryset(self):
        return TrusteeQuerySet(self.model)


class Trustee(HeliosModel, TrusteeFeatures):
    election = models.ForeignKey(Election, related_name="trustees")
    uuid = models.CharField(max_length=50)
    name = models.CharField(max_length=200)
    email = models.EmailField()
    secret = models.CharField(max_length=100)
    public_key = LDObjectField(type_hint = 'legacy/EGPublicKey', null=True)
    public_key_hash = models.CharField(max_length=100)
    secret_key = LDObjectField(type_hint = 'legacy/EGSecretKey', null=True)
    pok = LDObjectField(type_hint = 'legacy/DLogProof', null=True)
    last_verified_key_at = models.DateTimeField(null=True)
    last_notified_at = models.DateTimeField(null=True, default=None)

    objects = TrusteeManager()

    @property
    def pending_partial_decryptions_len(self):
        return len(self.pending_partial_decryptions())

    @property
    def get_partial_decryptions(self):
        for poll in self.election.polls.all():
            try:
                pd = poll.partial_decryptions.filter().only(
                    'poll').get(trustee=self)
                yield (poll, pd.decryption_factors)
            except TrusteeDecryptionFactors.DoesNotExist:
                yield (poll, None)

    def generate_password(self, force=False, size=12):
        if not self.secret or force:
            self.secret = heliosutils.random_string(size)
            existing = Trustee.objects.filter(
                election=self.election).exclude(pk=self.pk)
            while existing.filter(secret=self.secret).count() > 1:
                self.secret = heliosutils.random_string(size)

    def save(self, *args, **kwargs):
        if not self.uuid:
            self.uuid = str(uuid.uuid4())
        # set secret password
        self.generate_password()
        super(Trustee, self).save(*args, **kwargs)

    def get_login_url(self):
        url = settings.SECURE_URL_HOST + reverse('election_trustee_login',
                                                 args=[self.election.uuid,
                                                 self.email, self.secret])
        return url

    def pending_partial_decryptions(self):
        return filter(lambda p: p[1] is None, self.get_partial_decryptions)

    def get_step(self):
        """
        Step based on trustee/election state
        """
        if not self.public_key:
            return 1
        if not self.last_verified_key_at:
            return 2
        if self.pending_partial_decryptions:
            return 3
        return 1

    STEP_TEXTS = [_(u'Create trustee key'),
                  _(u'Verify trustee key'),
                  _(u'Partially decrypt votes')]

    def send_url_via_mail(self, msg='', override_email=None):
        """
        Notify trustee
        """
        lang = self.election.communication_language
        with translation.override(lang):
            url = self.get_login_url()
            context = {
                'election_name': self.election.name,
                'election': self.election,
                'url': url,
                'msg': msg,
                'SECURE_URL_HOST': settings.SECURE_URL_HOST,
                'step': self.get_step(),
                'step_text': self.STEP_TEXTS[self.get_step()-1]
            }

            body = render_to_string("trustee_email.txt", context)
            subject = render_to_string("trustee_email_subject.txt", context)

            send_to = override_email or self.email
            send_mail(subject.replace("\n", ""),
                      body,
                      settings.SERVER_EMAIL,
                      ["%s <%s>" % (self.name, send_to)],
                      fail_silently=False)
            self.election.logger.info("Trustee %r login url send via %r", self.email, send_to)
            self.last_notified_at = datetime.datetime.now()
            self.save()

    @property
    def datatype(self):
        return self.election.datatype.replace('Election', 'Trustee')

def notify_account_request(fields):
    """
    Notify admins with email
    """
    body = render_to_string("email/account_request.txt", fields)
    subject = render_to_string("email/account_request_subject.txt", fields)
    to = [settings.HELPDESK_EMAIL]
    send_mail(subject.replace(u"\n", u""), body, settings.SERVER_EMAIL, to)