from django.contrib.auth.hashers import make_password
from django.test import TestCase
from django.test.client import Client

from zeus.models.zeus_models import Institution
from heliosauth.models import User, UserGroup
from helios.models import *

from utils import SetUpAdminAndClientMixin

# subclass order is significant
class TestUsersWithClient(SetUpAdminAndClientMixin, TestCase):

    def setUp(self):
        super(TestUsersWithClient, self).setUp()

    def test_user_on_login_page(self):
        r = self.c.get('/', follow=True)
        self.assertEqual(r.status_code, 200)

    def test_admin_login_with_creds(self):
        r = self.c.post(self.locations['login'], self.login_data, follow=True)
        self.assertEqual(r.status_code, 200)
        # user has no election so it redirects from /admin to /elections/new
        self.assertRedirects(r, self.locations['create'])

    def test_forbid_logged_admin_to_login(self):
        self.c.post(self.locations['login'], self.login_data)
        r = self.c.post(self.locations['login'], self.login_data)
        self.assertEqual(r.status_code, 403)

    def test_admin_login_wrong_creds(self):
        wrong_creds = {'username': 'wrong_admin', 'password': 'wrong_password'}
        r = self.c.post(self.locations['login'], wrong_creds)
        # if code is 200 user failed to login and wasn't redirected
        self.assertEqual(r.status_code, 200)

    def test_logged_admin_can_logout(self):
        self.c.post(self.locations['login'], self.login_data)
        r = self.c.get(self.locations['logout'], follow=True)
        self.assertRedirects(r, self.locations['home'])

    def test_set_language(self):
        resp = self.c.post('/i18n/setlang/', {'language': '\x00', 'next': '/'})
        self.assertEqual(resp.status_code, 302)
        resp = self.c.post('/i18n/setlang/', {'language': 'el', 'next': '/'}, follow=True)
        self.assertEqual(resp.status_code, 200)
        self.assertEqual(resp.context['LANGUAGE_CODE'], 'el')
        resp = self.c.post('/i18n/setlang/', {'language': 'en', 'next': '/'}, follow=True)
        self.assertEqual(resp.context['LANGUAGE_CODE'], 'en')


class TestAdminsPermissions(SetUpAdminAndClientMixin, TestCase):

    def setUp(self):
        super(TestAdminsPermissions, self).setUp()
        #one admin exists, we need another one
        group = UserGroup.objects.get(name="default")
        self.admin2 = User.objects.create(user_type="password",
                                         user_id="test_admin2",
                                         info={"password": make_password("test_admin2")},
                                         admin_p=True,
                                         institution=self.institution)
        self.admin2.user_groups.add(group)
        self.login_data2 = {'username': 'test_admin2', 'password': 'test_admin2'}
        trustees_num = 2
        trustees = "\n".join(",".join(['testName%x testSurname%x' %(x,x),
                                       'test%x@mail.com' %x]) for x in range(0,trustees_num))
        date1 = datetime.datetime.now() + timedelta(hours=48)
        date2 = datetime.datetime.now() + timedelta(hours=56)
        self.election_form = {
                              'trial': True,
                              'election_module': 'simple',
                              'name': 'test_election',
                              'description': 'testing_election',
                              'trustees': trustees,
                              'voting_starts_at_0': date1.strftime('%Y-%m-%d'),
                              'voting_starts_at_1': date1.strftime('%H:%M'),
                              'voting_ends_at_0': date2.strftime('%Y-%m-%d'),
                              'voting_ends_at_1': date2.strftime('%H:%M'),
                              'help_email': 'test@test.com',
                              'help_phone': 6988888888,
                              'communication_language': 'el',
                              'terms_consent': 'true',

                            }

    def login_and_create_election(self, login_data):
        self.c.post(self.locations['login'], login_data)
        r = self.c.post(self.locations['create'], self.election_form, follow=True)
        self.assertEqual(r.status_code, 200)
        self.c.get(self.locations['logout'])

    def create_elections_with_different_admins(self):
        self.login_and_create_election(self.login_data)
        self.login_and_create_election(self.login_data2)
        e = Election.objects.all()
        self.assertEqual(len(e), 2)
        #make dict with admin and his election(uuid)
        self.pairs = {}
        for election in e:
            self.pairs[election.admins.all()[0].user_id] = election.uuid

    def test_admins_cannot_access_other_elections(self):
        #login with admin2 and try to access election 1
        self.create_elections_with_different_admins()
        self.c.post(self.locations['login'], self.login_data2)
        r = self.c.get('/elections/%s/edit'% self.pairs['test_admin'])
        self.assertEqual(r.status_code, 403)


class TestSecurity(SetUpAdminAndClientMixin, TestCase):

    def make_election(self, election_kwargs=None, polls_kwargs=None):
        default_election_kwargs = {
            'institution': Institution(name="INST"),
            'election_module': 'simple'
        }
        default_poll_kwargs = {
            'questions_data': [
                {
                    'question': 'question a',
                    'max_answers': 1,
                    'min_answers': 1,
                    'answers': ['a', 'b'],
                    'answer_0': 'a',
                    'answer_1': 'b'
                }
            ],
            'result': [[1,1,1]]
        }

        election_kwargs = election_kwargs or {}
        polls_kwargs = polls_kwargs or [{}]

        kwargs = {}
        kwargs.update(default_election_kwargs)
        kwargs.update(election_kwargs)

        polls = []
        e = Election(**kwargs)
        for poll_kwargs in polls_kwargs:
            kwargs = {}
            kwargs.update(default_poll_kwargs)
            kwargs.update(poll_kwargs)
            kwargs['election'] = e
            poll = Poll(**kwargs)
            poll.get_module().update_answers()
            polls.append(poll)

        return e, polls

    def test_csv_writer(self):
        from zeus.reports import csv_from_polls
        from StringIO import StringIO
        buffer = StringIO()

        for char in ["=", "+", "-", "@"]:
            election, polls = self.make_election({
                'name': '%sINJECTION()' % char
            })

            csv_from_polls(election, polls, "el", buffer)
            # injection escaped with '
            self.assertTrue(",'%sINJECTION" % char in buffer.getvalue())


    def test_redirect(self):
        from zeus.utils import sanitize_redirect, SuspiciousOperation
        url = "https://adversary.com"
        with self.assertRaises(SuspiciousOperation):
            sanitize_redirect(url)

        url = "/404"
        assert sanitize_redirect(url) == url

        url = "https://127.0.0.1:8000/zeus"
        assert sanitize_redirect(url) == url

        url = "ftp://127.0.0.1:8000/zeus"
        with self.assertRaises(SuspiciousOperation):
            sanitize_redirect(url)

        url = "////adversary.com"
        assert sanitize_redirect(url) == "/adversary.com" # thus 404

        url = "http%3A%2F%2Fadversary.com"
        with self.assertRaises(SuspiciousOperation):
            sanitize_redirect(url)

        url = "%68%74%74%70%25%33%41%25%32%" + \
              "46%25%32%46%61%64%76%65%72%73" + \
              "%61%72%79%2e%63%6f%6d"
        with self.assertRaises(SuspiciousOperation):
            sanitize_redirect(url)
