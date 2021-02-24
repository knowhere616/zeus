import json
import urllib, urllib2

from django.conf import settings
from django.core.urlresolvers import reverse
from django.utils.translation import ugettext_lazy as _
import xml.etree.ElementTree as ET

from helios.models import Poll

OAUTH2_REGISTRY = {}

def oauth2_module(cls):
    OAUTH2_REGISTRY[cls.type_id] = cls
    return cls

def get_oauth2_module(poll):
    if poll.taxisnet_auth:
        return OAUTH2_REGISTRY['taxisnet'](poll)
    return OAUTH2_REGISTRY.get(poll.oauth2_type)(poll)


def oauth2_callback_url():
    base = settings.SECURE_URL_HOST
    path = reverse('oauth2_login')
    if path.startswith("/"):
        path = path[1:]
    if base.endswith("/"):
        base = base[:-1]
    return "/".join([base, path])


class Oauth2Base(object):

    def __init__(self, poll):
        self.poll = poll
        self.exchange_url = poll.oauth2_exchange_url
        self.confirmation_url = self.poll.oauth2_confirmation_url
        self.callback_url = oauth2_callback_url()
        self.client_id = self.poll.oauth2_client_id
        self.client_secret = self.poll.oauth2_client_secret
        self.state = self.poll.uuid
        self.code_url = self.poll.oauth2_code_url
        self._update_request_data()
    
    def _update_request_data(self):
        self.code_post_data = {
            'response_type': 'code',
            'client_id': self.client_id,
            'redirect_uri': self.callback_url,
            'state': self.state
            }

        self.exchange_data = {
            'client_id': self.client_id,
            'client_secret': self.client_secret,
            'redirect_uri': self.callback_url,
            'grant_type': 'authorization_code'
            }

    def get_code_url(self):
        code_data = self.code_post_data
        encoded_data = urllib.urlencode(code_data)
        url = "{}?{}".format(self.code_url, encoded_data)
        return url

    def can_exchange(self, request):
        if (request.GET.get('code') and request.GET.get('state') and
                request.session.get('oauth2_voter_uuid') and 
                request.session.get('oauth2_voter_email')):
            self.code = request.GET.get('code')
            self.session_email = request.session['oauth2_voter_email']
            self.voter_uuid = request.session.get('oauth2_voter_uuid')
            return True

    def get_exchange_url(self):
        self.exchange_data['code'] = self.code
        encoded_data = urllib.urlencode(self.exchange_data)
        return (self.exchange_url, encoded_data)

    def exchange(self, url):
        raise NotImplemented


@oauth2_module
class Oauth2Google(Oauth2Base):

    type_id = 'google'

    def __init__(self, poll):
        super(Oauth2Google, self).__init__(poll)
        self.code_post_data['scope'] = 'openid email'
        self.code_post_data['approval_prompt'] = 'auto'

    def set_login_hint(self, email):
        self.code_post_data['login_hint'] = email

    def exchange(self, url):
        self.poll.logger.info("[thirdparty] Exchange url %s", url)
        response = urllib2.urlopen(url[0], url[1])
        data = json.loads(response.read())
        self.access_token = data['access_token']
        self.id_token = data['id_token']
        self.token_type = data['token_type']
        self.expires_in = data['expires_in']

    def confirm(self):
        self.poll.logger.info("[thirdparty-google] Confirm email at %s", self.confirmation_url)
        get_params = 'access_token={}'.format(self.access_token)
        get_url = '{}?{}'.format(self.confirmation_url, get_params)
        response = urllib2.urlopen(get_url)
        resp = response.read()
        data = json.loads(resp)
        self.poll.logger.info("[thirdparty-google] resolved user data %r", data)
        response_email = data

        if 'email' in data:
            response_email = data['email']
        if 'emails' in data:
            response_email = data['emails'][0]['value']
        if response_email == self.session_email:
            return True, data, None
        return False, data, None


@oauth2_module
class Oauth2FB(Oauth2Base):

    type_id = 'facebook'
    
    def __init__(self, poll):
        super(Oauth2FB, self).__init__(poll)
        self.code_post_data['scope'] = 'email'

    def exchange(self, url):
        response = urllib2.urlopen(url[0], url[1])
        data = response.read()
        split_data = data.split('&')
        for item in split_data:
            if 'access_token' in item:
                self.access_token = item.split('=')[1]
            if 'expires' in item:
                self.expires = item.split('=')[1]

    def confirm(self):
        get_params = 'fields=email&access_token={}'.format(self.access_token)
        get_url = '{}?{}'.format(self.confirmation_url, get_params)
        response = urllib2.urlopen(get_url)
        data = json.loads(response.read())
        response_email = data['email']
        if response_email == self.session_email:
            return True, data, None
        return False, data, None


@oauth2_module
class Oauth2Other(Oauth2Base):

    type_id = 'other'

    def __init__(self, poll):
        super(Oauth2Other, self).__init__(poll)
        self.code_post_data['scope'] = 'email'

    def exchange(self, url):
        response = urllib2.urlopen(url[0], url[1])
        data = json.loads(response.read())
        self.access_token = data['access_token']
        self.id_token = data['id_token']
        self.token_type = data['token_type']
        self.expires_in = data['expires_in']
        self.poll.logger.info("[thirdparty-other] exchanged oauth2 data %r", data)

    def confirm(self):
        self.poll.logger.info("[thirdparty-other] Confirm email at %r", self.confirmation_url)
        data = urllib.urlencode({'access_token': self.access_token})
        self.poll.logger.info("[thirdparty-other] Confirm data %r", data)
        response = urllib2.urlopen(self.confirmation_url, data)
        self.poll.logger.info("[thirdparty-other] resolved user data %r", response)
        resp = response.read()
        data = json.loads(resp)
        response_email = data

        if 'email' in data:
            response_email = data['email']
        if 'emails' in data:
            response_email = data['emails'][0]['value']
        if response_email == self.session_email:
            return True, data, None
        return False, data, None

@oauth2_module
class Oauth2Taxisnet(Oauth2Base):

    type_id = 'taxisnet'

    def __init__(self, poll):
        super(Oauth2Taxisnet, self).__init__(poll)
        data = getattr(settings, 'TAXISNET_INSTITUTIONS', {})
        inst_key = poll.election.institution.name
        config = data.get(inst_key, {})
        if config.get('test', True):
            self.exchange_url = 'https://test.gsis.gr/oauth2server/oauth/token'
            self.code_url = 'https://test.gsis.gr/oauth2server/oauth/authorize'
            self.confirmation_url = 'https://test.gsis.gr/oauth2server/userinfo?format=xml'
        else:
            self.exchange_url = 'https://www1.gsis.gr/oauth2server/oauth/token'
            self.code_url = 'https://www1.gsis.gr/oauth2server/oauth/authorize'
            self.confirmation_url = 'https://www1.gsis.gr/oauth2server/userinfo?format=xml'
        self.client_id = config.get('client_id')
        self.client_secret = config.get('secret')
        self.callback_url = 'https://zeus.grnet.gr/zeus/auth/auth/oauth2'
        self._update_request_data()

    def set_login_hint(self, email):
        self.code_post_data['login_hint'] = email

    def exchange(self, url):
        self.poll.logger.info("[taxisnet] Exchange url %s", url)
        response = urllib2.urlopen(url[0], url[1])
        data = json.loads(response.read())
        self.access_token = data['access_token']

    def confirm(self):
        self.poll.logger.info("[taxisnet] Confirm taxid via %s", self.confirmation_url)
        get_params = 'access_token={}'.format(self.access_token)
        if '?' in self.confirmation_url:
            get_url = '{}&{}'.format(self.confirmation_url, get_params)
        else:
            get_url = '{}?{}'.format(self.confirmation_url, get_params)
        response = urllib2.urlopen(get_url)
        try:
            resp = response.read()
        except Exception as e:
            self.poll.logger.error("[taxisnet] failed to read user profile")
            self.poll.logger.exception(e)

        self.poll.logger.info("[taxisnet] resolved user profile (raw) %r", resp)
        profile = ET.fromstring(resp)[0].attrib
        self.poll.logger.info("[taxisnet] resolved user profile (json) %r", profile)
        taxid = profile.get('taxid', '').strip()

        confirmed = False
        err = None
        if not taxid or len(taxid) == 0:
            self.poll.logger.error('[taxisnet] cannot resolve taxid %r' % profile)
            confirmed = False
        else:
            from helios.models import Voter
            voter = Voter.objects.get(uuid=self.voter_uuid)
            confirmed = voter.voter_login_id == taxid
            if not confirmed:
                self.poll.logger.error('[taxisnet] failed to match zeus id (%r) to taxisnet id (%r)' % (voter.voter_login_id, taxid))
                err = _("Tax registration number returned by authentication provider does not match logged-in voter. Please contact election administrator.")
        return confirmed, profile, err