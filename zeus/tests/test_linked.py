# -*- coding: utf-8 -*-
from zeus.tests.test_functional import TestElectionBase, Election, randint, \
    Poll, sample

class TestLinkedPollsElection(TestElectionBase):

    def setUp(self):
        super(TestLinkedPollsElection, self).setUp()
        self.election_type = 'parties'
        self.doc_exts = {
            'poll': ['pdf', 'csv', 'json'],
            'el': ['pdf', 'csv', 'zip']
            }
        if self.local_verbose:
            print '* Starting linked-polls party election *'

    def create_questions(self):
        nr_questions = self.party_election_max_questions_number
        max_nr_answers = self.party_election_max_answers_number

        post_data = {'form-TOTAL_FORMS': nr_questions,
                     'form-INITIAL_FORMS': 1,
                     'form-MAX_NUM_FORMS': ""
                     }
        post_data_with_duplicate_answers = post_data.copy()

        for num in range(0, nr_questions):
            nr_answers = randint(1, max_nr_answers)
            min_choices = randint(1, nr_answers)
            max_choices = randint(min_choices, nr_answers)
            extra_data = {}
            extra_data = {
                'form-%s-ORDER' % num: num,
                'form-%s-choice_type' % num: 'choice',
                'form-%s-question' % num: 'test question %s' % num,
                'form-%s-min_answers' % num: min_choices,
                'form-%s-max_answers' % num: max_choices,
                }
            duplicate_extra_data = extra_data.copy()
            for ans_num in range(0, nr_answers):
                extra_data['form-%s-answer_%s' % (num, ans_num)] = \
                    'testanswer %s-%s' % (num, ans_num)
                duplicate_extra_data['form-%s-answer_%s' % (num, ans_num)] = \
                    'testanswer 0-0'
                ans_num += 1
                duplicate_extra_data['form-%s-answer_%s' % (num, ans_num)] = \
                    'testanswer 0-0'
            post_data_with_duplicate_answers.update(duplicate_extra_data)
            post_data.update(extra_data)
        return post_data, nr_questions, post_data_with_duplicate_answers

    def make_ballot(self, p_uuid):
        poll = Poll.objects.get(uuid=p_uuid)
        q_d = poll.questions_data
        max_choices = len(poll.questions[0]['answers'])
        choices = []
        header_index = 0
        index = 1
        # if vote_blank is 0, the selection will be empty
        vote_blank = randint(0, 4)
        for qindex, data in enumerate(q_d):
            if vote_blank == 0:
                break
            qchoice = []
            # if vote party only is 0, vote only party without candidates
            vote_party_only = randint(0, 4)
            if vote_party_only == 0:
                qchoice.append(header_index)
            else:
                # valid answer indexes
                valid_indexes = range(index, index + (len(data['answers'])))
                min, max = int(data['min_answers']), int(data['max_answers'])
                nr_choices = randint(min, max)
                qchoice = sample(valid_indexes, nr_choices)
                '''
                while len(qchoice) < random.randint(min, max):
                    answer = random.choice(valid_indexes)
                    valid_indexes.remove(answer)
                    qchoice.append(answer)
                '''
            qchoice = sorted(qchoice)
            choices += qchoice
            # inc index to the next question
            index += len(data['answers']) + 1
            header_index += len(data['answers']) + 1
        return choices, max_choices

    def test_election_process(self):
        self.election_process()

    def create_polls(self):
        self.c.get(self.locations['logout'])
        self.c.post(self.locations['login'], self.login_data)
        e = Election.objects.all()[0]
        # there shouldn't be any polls before we create them
        self.assertEqual(e.polls.all().count(), 0)
        location = '/elections/%s/polls/add' % self.e_uuid
        linked_ref = None
        for i in range(0, self.polls_number):
            post_data = {
                'name': 'test_poll-{}'.format(i),
                'linked_ref': linked_ref or ''
            }
            post_data.update(self._get_poll_params(i, None))
            r = self.c.post(location, post_data)
            self.assertEqual(r.status_code, 302)
            if i == 0:
                linked_ref = e.polls.filter()[0].uuid

        self.linked_ref = linked_ref
        e = Election.objects.all()[0]
        self.assertEqual(e.polls.all().count(), self.polls_number)
        self.verbose('+ Polls were created')
        self.p_uuids = []
        for poll in e.polls.all():
            self.p_uuids.append(poll.uuid)

    def submit_voters_file(self):
        voter_files = self.get_voters_file()
        for p_uuid in self.p_uuids:
            poll = Election.objects.get().polls.get(uuid=p_uuid)
            upload_voters_location = '/elections/%s/polls/%s/voters/upload' \
                % (self.e_uuid, p_uuid)
            r = self.c.post(
                upload_voters_location,
                {'voters_file': file(voter_files[p_uuid]),
                 'encoding': 'iso-8859-7',
                 'voters_upload_terms': 'yes'}
                )
            if poll.linked_ref:
                self.assertEqual(r.status_code, 403)
            else:
                r = self.c.post(upload_voters_location, {'confirm_p': 1, 'encoding': 'iso-8859-7', 'voters_upload_terms': 'yes'}, follow=True)
                self.assertEqual(r.status_code, 200)

        e = Election.objects.get(uuid=self.e_uuid)
        voters = e.voters.count()
        poll = e.polls.get(uuid = self.linked_ref)

        voters_csv = '/elections/%s/polls/%s/voters/csv/%s.csv' \
                % (self.e_uuid, poll.uuid, poll.short_name)
        r = self.c.get(voters_csv)
        self.assertEqual(r.status_code, 200)
        entries = filter(bool, r.content.split("\r\n"))
        voter = poll.voters.get(voter_login_id="1")
        delete_voter_url = '/elections/%s/polls/%s/voters/%s/delete' \
                % (self.e_uuid, poll.uuid, voter.uuid )
        voters_count = poll.voters.count()
        r = self.c.post(delete_voter_url)
        self.assertEqual(r.status_code, 302)
        self.assertEqual(voters_count - 1, poll.voters.count())

        f = self.get_voters_file(1)
        upload_voters_location = '/elections/%s/polls/%s/voters/upload' \
                % (self.e_uuid, poll.uuid)
        r = self.c.post(
            upload_voters_location,
            {'voters_file': file(voter_files[poll.uuid]),
                'encoding': 'iso-8859-7',
                'voters_upload_terms': 'yes'}
            )
        r = self.c.post(upload_voters_location, {'confirm_p': 1, 'encoding': 'iso-8859-7', 'voters_upload_terms': 'yes'}, follow=True)
        self.assertEqual(r.status_code, 200)
        self.assertEqual(voters_count, poll.voters.count())

        for p_uuid in self.p_uuids:
            if p_uuid == self.linked_ref:
                continue
            p = e.polls.get(uuid=p_uuid)
            self.assertEqual(poll.voters.count(), p.voters.count())
            for voter in poll.voters.filter():
                linked = p.voters.get(voter_login_id=voter.voter_login_id)
                assert linked.voter_name == voter.voter_name
                assert linked.voter_email == voter.voter_email
                assert linked.audit_passwords != voter.audit_passwords
        self.assertEqual(voters, self.voters_num*self.polls_number)
        self.verbose('+ Voters file submitted')

    def submit_wrong_field_number_voters_file(self):
        uuids = self.p_uuids
        self.p_uuids = [self.linked_ref]
        super(TestLinkedPollsElection, self).submit_wrong_field_number_voters_file()
        self.p_uuids = uuids

    def submit_duplicate_id_voters_file(self):
        uuids = self.p_uuids
        self.p_uuids = [self.linked_ref]
        super(TestLinkedPollsElection, self).submit_duplicate_id_voters_file()
        self.p_uuids = uuids

    def submit_wrong_field_number_voters_file(self):
        uuids = self.p_uuids
        self.p_uuids = [self.linked_ref]
        super(TestLinkedPollsElection, self).submit_wrong_field_number_voters_file()
        self.p_uuids = uuids
