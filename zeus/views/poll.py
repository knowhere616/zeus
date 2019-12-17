import yaml
import copy
import os
import csv
import json
import urllib
import base64

from collections import OrderedDict

from django.core.urlresolvers import reverse
from django.forms import ValidationError
from django.utils.translation import ugettext_lazy as _
from django.db import connection
from django.db.models.query import QuerySet
from django.db.models import Q, Max
from django.core.context_processors import csrf
from django.views.decorators.csrf import csrf_exempt
from django.utils.html import mark_safe, escape
from django.shortcuts import redirect
from django import forms
from django.template.loader import Template, Context

from zeus.forms import ElectionForm
from zeus import auth
from zeus.forms import PollForm, PollFormSet, EmailVotersForm
from zeus.utils import *
from zeus.views.utils import *
from zeus import tasks

from django.utils.encoding import smart_unicode
from django.db import transaction
from django.shortcuts import get_object_or_404
from django.http import Http404, HttpResponseRedirect, HttpResponse, \
    HttpResponseBadRequest
from django.core.exceptions import PermissionDenied
from django.forms.models import modelformset_factory
from django.template.loader import render_to_string
from django.contrib import messages
from django.views.decorators.http import require_http_methods

from helios.view_utils import render_template
from helios.models import Election, Poll, Voter, VoterFile, CastVote, \
    AuditedBallot
from helios import datatypes
from helios import exceptions
from helios.crypto import utils as crypto_utils
from helios.crypto import electionalgs
from helios.utils import force_utf8

from zeus.core import to_canonical, from_canonical


@auth.election_admin_required
def list(request, election):
    polls = election.polls.filter()
    context = {'polls': polls, 'election': election}
    set_menu('polls', context)
    return render_template(request, "election_polls_list", context)

@auth.election_admin_required
@transaction.atomic
@require_http_methods(["POST"])
def rename(request, election, poll):
    newname = request.POST.get('name', '').strip()
    if newname:
        oldname = poll.name
        poll.name = newname
        poll.save()
        poll.logger.info("Renamed from %s to %s", oldname, newname)
    url = election_reverse(election, 'polls_list')
    return HttpResponseRedirect(url)


@auth.election_admin_required
@require_http_methods(["POST", "GET"])
@transaction.atomic
def add_edit(request, election, poll=None):
    admin = request.admin
    if not poll and not election.feature_can_add_poll:
        raise PermissionDenied
    if poll and not poll.feature_can_edit:
        raise PermissionDenied
    if poll:
        oldname = poll.name
    if request.method == "POST":
        form = PollForm(request.POST, instance=poll, election=election,
                        admin=admin)
        if form.is_valid():
            new_poll = form.save()
            if form.has_changed():
                new_poll.logger.info("Poll updated %r" % form.changed_data)
            message = _("Poll updated successfully")
            messages.success(request, message)
            newname = new_poll.name
            # log poll edit/creation
            if poll:
                if oldname != newname:
                    poll.logger.info("Renamed from %s to %s", oldname, newname)
            else:
                new_poll.logger.info("Poll created")
            url = election_reverse(election, 'polls_list')
            return redirect(url)
    else:
        form = PollForm(instance=poll, election=election, admin=admin)
    context = {'election': election, 'poll': poll,  'form': form}
    set_menu('polls', context)
    if poll:
        set_menu('edit_poll', context)
    tpl = "election_poll_add_or_edit"
    return render_template(request, tpl, context)

@auth.election_admin_required
@require_http_methods(["POST"])
def remove(request, election, poll):
    if poll.is_linked_root:
        messages.error(request, _("Unlink linked polls in order to be able to delete the poll."))
        return HttpResponseRedirect(election_reverse(election, 'polls_list'))
    poll.delete()
    poll.logger.info("Poll deleted")
    return HttpResponseRedirect(election_reverse(election, 'polls_list'))


@auth.election_admin_required
@auth.requires_poll_features('can_manage_questions')
@require_http_methods(["POST", "GET"])
def questions_manage(request, election, poll):
    module = poll.get_module()
    return module.questions_update_view(request, election, poll)


@auth.election_view()
@require_http_methods(["GET"])
def questions(request, election, poll):
    module = poll.get_module()
    if request.zeususer.is_admin:
        if not module.questions_set() and poll.feature_can_manage_questions:
            url = poll_reverse(poll, 'questions_manage')
            return HttpResponseRedirect(url)

    preview_booth_url = poll.get_booth_url(request, preview=True)
    linked_polls = None
    if request.zeususer.is_voter and poll.is_linked_root:
        linked_polls = poll.other_linked_polls

    questions_tpl = \
        getattr(module, 'questions_list_template', 'election_poll_questions') + ".html"
    context = {
        'election': election,
        'poll': poll,
        'questions': questions,
        'module': poll.get_module(),
        'preview_booth_url': preview_booth_url,
        'questions_tpl': questions_tpl,
        'linked_polls': linked_polls
    }
    set_menu('questions', context)
    tpl = 'election_poll_questions_wrapper'
    return render_template(request, tpl, context)


voter_search_fields = ['name', 'surname', 'email']
voter_extra_headers = ['excluded_at']
voter_bool_keys_map = {
        'voted': ('cast_votes__id', 'nullcheck'),
        'invited': ('last_booth_invitation_send_at', 'nullcheck'),
        'excluded': ('excluded_at', 'nullcheck'),
     }

@auth.election_admin_required
@require_http_methods(["GET"])
def voters_list(request, election, poll):
    # for django pagination support
    page = int(request.GET.get('page', 1))
    limit = int(request.GET.get('limit', 10))
    q_param = request.GET.get('q','')

    default_voters_per_page = getattr(settings, 'ELECTION_VOTERS_PER_PAGE', 100)
    voters_per_page = request.GET.get('limit', default_voters_per_page)
    try:
        voters_per_page = int(voters_per_page)
    except:
        voters_per_page = default_voters_per_page
    order_by = request.GET.get('order', 'voter_login_id')
    order_type = request.GET.get('order_type', 'desc')

    module = election.get_module()
    table_headers = copy.copy(module.get_voters_list_headers(request))
    if not order_by in table_headers:
        order_by = 'voter_login_id'

    if not poll.voters.filter(voter_weight__gt=1).count():
        table_headers.pop('voter_weight')
    display_weight_col = 'voter_weight' in table_headers

    if not poll.forum_enabled:
        table_headers.pop('forum')

    validate_hash = request.GET.get('vote_hash', "").strip()
    hash_invalid = None
    hash_valid = None

    if (order_type == 'asc') or (order_type == None) :
        voters = Voter.objects.filter(poll=poll).annotate(cast_votes__id=Max('cast_votes__id')).order_by(order_by)
    else:
        order_by = '-%s' % order_by
        voters = Voter.objects.filter(poll=poll).annotate(cast_votes__id=Max('cast_votes__id')).order_by(order_by)

    voters = module.filter_voters(voters, q_param, request)
    voters_count = Voter.objects.filter(poll=poll).count()
    voted_count = poll.voters_cast_count()
    nr_voters_excluded = voters.excluded().count()
    context = {
        'election': election,
        'poll': poll,
        'page': page,
        'voters': voters,
        'voters_count': voters_count,
        'voted_count': voted_count,
        'q': q_param,
        'voters_list_count': voters.count(),
        'voters_per_page': voters_per_page,
        'display_weight_col': display_weight_col,
        'voter_table_headers': table_headers,
        'voter_table_headers_iter': table_headers.iteritems(),
        'nr_voters_excluded': nr_voters_excluded,
    }
    set_menu('voters', context)
    return render_template(request, 'election_poll_voters_list', context)

@auth.election_admin_required
@auth.requires_poll_features('can_clear_voters')
@transaction.atomic
@require_http_methods(["POST"])
def voters_clear(request, election, poll):
    polls = poll.linked_polls
    q_param = request.POST.get('q_param', None)

    for p in polls:
        voters = p.voters.all()
        if q_param:
            voters = election.get_module().filter_voters(voters, q_param, request)

        for voter in voters:
            if not voter.can_delete:
                raise PermissionDenied('36')
            if not voter.cast_votes.count():
                voter.delete()
        p.logger.info("Poll voters cleared")

    url = poll_reverse(poll, 'voters')
    return HttpResponseRedirect(url)


ENCODINGS = [('utf-8', _('Unicode')),
             ('iso-8859-7', _('Greek (iso-8859-7)')),
             ('iso-8859-1', _('Latin (iso-8859-1)'))]

@auth.election_admin_required
@auth.requires_poll_features('can_add_voter')
@require_http_methods(["POST", "GET"])
def voters_upload(request, election, poll):
    upload = poll.voter_file_processing()
    common_context = {
        'election': election,
        'poll': poll,
        'encodings': ENCODINGS,
        'running_file': upload
    }

    if upload:
        messages.warning(request, _("A voters import is already in progress."))
    set_menu('voters', common_context)
    if request.method == "POST":
        preferred_encoding = request.POST.get('encoding', None)
        if preferred_encoding not in dict(ENCODINGS):
            messages.error(request, _("Invalid encoding"))
            url = poll_reverse(poll, 'voters_upload')
            return HttpResponseRedirect(url)
        else:
            common_context['preferred_encoding'] = preferred_encoding

        if request.FILES.has_key('voters_file'):
            voters_file = request.FILES['voters_file']
            voter_file_obj = poll.add_voters_file(voters_file, encoding=preferred_encoding)
        else:
            error = _("No file uploaded")
            messages.error(request, error)
            url = poll_reverse(poll, 'voters_upload')
            return HttpResponseRedirect(url)
        
        
        try:
            voter_file_obj.validate_process()
        except (exceptions.VoterLimitReached, \
            exceptions.DuplicateVoterID, ValidationError) as e:
            messages.error(request, e.message)
            voter_file_obj.delete()
            url = poll_reverse(poll, 'voters_upload')
            return HttpResponseRedirect(url)

        poll.logger.info("Submitting voter file: %r", voter_file_obj.pk)
        tasks.process_voter_file.delay(voter_file_obj.pk)
        url = poll_reverse(poll, 'voters_upload_status', pk=voter_file_obj.pk)
        return HttpResponseRedirect(url)
    else:
        if 'voter_file_id' in request.session:
            del request.session['voter_file_id']
        no_link = request.GET.get("no-link", False) != False
        request.session['no_link'] = no_link
        return render_template(request,
                               'election_poll_voters_upload',
                               common_context)


@auth.election_admin_required
def voters_upload_status(request, election, poll, pk):
    if pk == 'last':
        try:
            upload = VoterFile.objects.filter(poll=poll).order_by('-pk')[0]
            pk = upload.pk
        except IndexError:
            raise PermissionDenied('No voter file exists.')
    else:
        upload = get_object_or_404(VoterFile, poll=poll, pk=pk)
    ids = VoterFile.objects.filter(poll=poll).order_by('pk').values_list('id', flat=True)
    context = {
        'upload_id': type([])(ids).index(int(upload.pk)) + 1,
        'upload': upload,
        'election': election,
        'poll': poll
    }
    set_menu('voters', context)
    if upload.processing_finished_at and not upload.process_error:
        url = poll_reverse(poll, 'voters')
        return HttpResponseRedirect(url)
    return render_template(request,
                           'election_poll_voters_upload_status',
                           context)


@auth.election_admin_required
@require_http_methods(["POST"])
def voters_upload_cancel(request, election, poll):
    voter_file_id = request.session.get('voter_file_id', None)
    if voter_file_id:
        vf = VoterFile.objects.get(id = voter_file_id)
        vf.delete()
    if 'voter_file_id' in request.session:
        del request.session['voter_file_id']

    url = poll_reverse(poll, 'voters_upload')
    return HttpResponseRedirect(url)


@auth.election_admin_required
@require_http_methods(["POST", "GET"])
def voters_email(request, election, poll=None, voter_uuid=None):
    user = request.admin

    TEMPLATES = [
        ('vote', _('Time to Vote')),
        ('info', _('Additional Info')),
    ]


    default_template = 'vote'

    if not election.any_poll_feature_can_send_voter_mail:
        raise PermissionDenied('34')

    if not election.any_poll_feature_can_send_voter_booth_invitation:
        TEMPLATES.pop(0)
        default_template = 'info'

    polls = [poll]
    if not poll:
        polls = election.polls_by_link

    voter = None
    if voter_uuid:
        try:
            if poll:
                voter = get_object_or_404(Voter, uuid=voter_uuid, poll=poll)
            else:
                voter = get_object_or_404(Voter, uuid=voter_uuid,
                                          election=election)
        except Voter.DoesNotExist:
            raise PermissionDenied('35')
        if not voter:
            url = election_reverse(election, 'index')
            return HttpResponseRedirect(url)

        if voter.excluded_at:
            TEMPLATES.pop(0)
            default_template = 'info'

    if election.voting_extended_until and not election.voting_ended_at:
        if not voter or (voter and not voter.excluded_at):
            TEMPLATES.append(('extension', _('Voting end date extended')))

    template = request.REQUEST.get('template', default_template)

    if not template in [t[0] for t in TEMPLATES]:
        raise Exception("bad template")

    election_url = election.get_absolute_url()

    forum_enabled = False
    if (poll and poll.forum_enabled) or \
            (election.polls.filter(forum_enabled=True).count()):
        forum_enabled = True

    default_subject = render_to_string(
        'email/%s_subject.txt' % template, {
            'custom_subject': "&lt;SUBJECT&gt;"
        })

    poll_data = poll or {
        'forum_starts_at': '<FORUM_STARTS_AT>',
        'forum_ends_at': '<FORUM_ENDS_AT>',
        'poll_name': '<POLL_NAME>',
        'forum_enabled': forum_enabled
    }
    tpl_context =  {
            'election' : election,
            'election_url' : election_url,
            'custom_subject' : default_subject,
            'custom_message': '&lt;BODY&gt;',
            'custom_message_sms': '&lt;SMS_BODY&gt;',
            'SECURE_URL_HOST': settings.SECURE_URL_HOST,
            'poll': poll_data,
            'voter_url': election.voter_code_login_url,
            'voter': {
                'vote_hash' : '<SMART_TRACKER>',
                'name': '<VOTER_NAME>',
                'voter_name': '<VOTER_NAME>',
                'voter_surname': '<VOTER_SURNAME>',
                'voter_login_id': '<VOTER_LOGIN_ID>',
                'voter_password': '<VOTER_PASSWORD>',
                'login_code': '<VOTER_LOGIN_CODE>',
                'audit_passwords': '1',
                'get_audit_passwords': ['pass1', 'pass2', '...'],
                'get_quick_login_url': '<VOTER_LOGIN_URL>',
                'poll': poll_data,
                'election' : election}
            }

    default_body = render_to_string(
        'email/%s_body.txt' % template, tpl_context)

    default_sms_body = render_to_string(
        'sms/%s_body.txt' % template, tpl_context)

    q_param = request.GET.get('q', None)

    filtered_voters = election.voters.filter()
    if poll:
        filtered_voters = poll.voters.filter()

    if not q_param:
        filtered_voters = filtered_voters.none()
    else:
        election.logger.info("Filter recipient voters based on params: %r", q_param)
        filtered_voters = election.get_module().filter_voters(filtered_voters, q_param, request)

        if not filtered_voters.count():
            message = _("No voters were found.")
            messages.error(request, message)
            url = election_reverse(election, 'polls_list')
            return HttpResponseRedirect(url)

    if request.method == "GET":
        email_form = EmailVotersForm(election, template)
        email_form.fields['email_subject'].initial = dict(TEMPLATES)[template]
        if voter:
            email_form.fields['send_to'].widget = \
                email_form.fields['send_to'].hidden_widget()
    else:
        email_form = EmailVotersForm(election, template, request.POST)
        if email_form.is_valid():
            # the client knows to submit only once with a specific voter_id
            voter_constraints_include = None
            voter_constraints_exclude = None
            update_booth_invitation_date = False
            if template == 'vote':
                update_booth_invitation_date = True

            if voter:
                voter_constraints_include = {'uuid': voter.uuid}

            # exclude those who have not voted
            if email_form.cleaned_data['send_to'] == 'voted':
                voter_constraints_exclude = {'vote_hash' : None}

            # include only those who have not voted
            if email_form.cleaned_data['send_to'] == 'not-voted':
                voter_constraints_include = {'vote_hash': None}

            for _poll in polls:
                if _poll is None:
                    continue
                if not _poll.feature_can_send_voter_mail:
                    continue

                if template == 'vote' and not \
                        _poll.feature_can_send_voter_booth_invitation:
                    continue

                subject_template = 'email/%s_subject.txt' % template
                body_template = 'email/%s_body.txt' % template
                body_template_sms = 'sms/%s_body.txt' % template
                contact_method = email_form.cleaned_data['contact_method']

                extra_vars = {
                    'SECURE_URL_HOST': settings.SECURE_URL_HOST,
                    'custom_subject' : email_form.cleaned_data['email_subject'],
                    'custom_message' : email_form.cleaned_data['email_body'],
                    'custom_message_sms' : email_form.cleaned_data['sms_body'],
                    'election_url' : election_url,
                    'voter_url': election.voter_code_login_url
                }
                task_kwargs = {
                    'contact_id': template,
                    'notify_once': email_form.cleaned_data.get('notify_once'),
                    'subject_template_email': subject_template,
                    'body_template_email': body_template,
                    'body_template_sms': body_template_sms,
                    'contact_methods': contact_method.split(":"),
                    'template_vars': extra_vars,
                    'voter_constraints_include': voter_constraints_include,
                    'voter_constraints_exclude': voter_constraints_exclude,
                    'update_date': True,
                    'update_booth_invitation_date': update_booth_invitation_date,
                    'q_param': q_param,
                }
                log_obj = election
                if poll:
                    log_obj = poll
                if voter:
                    log_obj.logger.info("Notifying single voter %s, [template: %s, filter: %s]",
                                     voter.voter_login_id, template, q_param)
                else:
                    log_obj.logger.info("Notifying voters, [template: %s, filter: %r]", template, q_param)
                tasks.voters_email.delay(_poll.pk, **task_kwargs)


            filters = get_voters_filters_with_constraints(q_param,
                        voter_constraints_include, voter_constraints_exclude)
            send_to = filtered_voters.filter(filters)
            if q_param and not send_to.filter(filters).count():
                msg = "No voters matched your filters. No emails were sent."
                messages.error(request, _(msg))
            else:
                messages.info(request, _("Email sending started"))

            url = election_reverse(election, 'polls_list')
            if poll:
                url = poll_reverse(poll, 'voters')
            if q_param:
                url += '?q=%s' % urllib.quote_plus(q_param)
            return HttpResponseRedirect(url)
        else:
            message = _("Something went wrong")
            messages.error(request, message)

    if election.sms_enabled and election.sms_data.left <= 0:
        messages.warning(request, _("No SMS deliveries left."))

    context = {
        'email_form': email_form,
        'election': election,
        'poll': poll,
        'voter_o': voter,
        'default_subject': default_subject,
        'default_body': default_body,
        'default_sms_body': default_sms_body,
        'sms_enabled': election.sms_enabled,
        'template': template,
        'filtered_voters': filtered_voters,
        'templates': TEMPLATES,
        'q': q_param
    }
    set_menu('voters', context)
    if not poll:
        set_menu('polls', context)
    return render_template(request, "voters_email", context)


@auth.election_admin_required
@auth.requires_poll_features('can_delete_voter')
@require_http_methods(["POST"])
@transaction.atomic
def voter_delete(request, election, poll, voter_uuid):
    voter = get_object_or_404(Voter, uuid=voter_uuid, poll__in=poll.linked_polls)
    voter_id = voter.voter_login_id

    linked_polls = poll.linked_polls
    is_linked = poll.is_linked

    if voter.voted_linked or voter.participated_in_forum_linked:
        raise PermissionDenied('36')

    deleted = False
    for _poll in linked_polls:
        voter = None
        try:
            voter = Voter.objects.get(poll=_poll, voter_login_id=voter_id)
        except Voter.DoesNotExist:
            _poll.logger.error("Cannot remove voter '%s'. Does not exist.",
                             voter_uuid)
        if voter and (voter.voted or voter.participated_in_forum):
            raise PermissionDenied('36')
        elif voter:
            voter.delete()
            _poll.logger.info("Poll voter '%s' removed", voter.voter_login_id)
            deleted = True

    if deleted:
        message = _("Voter removed successfully")
        messages.success(request, message)

    url = poll_reverse(poll, 'voters')
    return HttpResponseRedirect(url)


@auth.election_admin_required
@auth.requires_poll_features('can_exclude_voter')
@require_http_methods(["POST"])
def voter_exclude(request, election, poll, voter_uuid):
    polls = poll.linked_polls
    voter = get_object_or_404(Voter, uuid=voter_uuid, poll__in=polls)
    for p in polls:
        linked_voter = voter.linked_voters.get(poll=p)
        if not linked_voter.excluded_at:
            reason = request.POST.get('reason', '')
            try:
                p.zeus.exclude_voter(linked_voter.uuid, reason)
                p.logger.info("Poll voter '%s' excluded", linked_voter.voter_login_id)
            except Exception, e:
                pass
    return HttpResponseRedirect(poll_reverse(poll, 'voters'))


@auth.election_admin_required
@require_http_methods(["GET"])
def voters_csv(request, election, poll, fname):
    q_param = request.GET.get('q', None)
    response = HttpResponse(content_type='text/csv')
    filename = smart_unicode("voters-%s.csv" % election.short_name)
    if fname:
        filename = fname
    response['Content-Dispotition'] = \
           'attachment; filename="%s.csv"' % filename

    headers = poll.get_module().get_voters_list_headers(request)
    include_vote_field = poll.feature_mixing_finished or request.zeususer.is_manager or 'cast_votes__id' in headers
    poll.voters_to_csv(q_param, response, include_vote_field)
    return response


@auth.poll_voter_required
@auth.requires_poll_features('can_cast_vote')
@require_http_methods(["GET"])
def voter_booth_linked_login(request, election, poll, voter_uuid):
    voter = request.zeususer._user
    linked_poll = request.GET.get('link-to', None)

    follow = bool(request.GET.get('follow', False))
    request.session['follow_linked'] = follow

    if not poll.has_linked_polls:
        raise PermissionDenied()
    if not linked_poll or linked_poll not in \
            poll.linked_polls.values_list('uuid', flat=True):
        raise PermissionDenied()

    linked_poll = election.polls.get(uuid=linked_poll)
    linked_voter = linked_poll.voters.get(voter_login_id=voter.voter_login_id)
    user = auth.ZeusUser(linked_voter)
    user.authenticate(request)
    poll.logger.info("Poll voter '%s' logged in in linked poll '%s'",
                     voter.voter_login_id, poll.uuid)
    url = linked_poll.get_booth_url(request)
    return HttpResponseRedirect(url)


@auth.election_view(check_access=False)
@require_http_methods(["GET"])
def voter_booth_login(request, election, poll, voter_uuid, voter_secret):
    voter = None

    if poll.jwt_auth:
        messages.error(request,
                        _("Poll does not support voter url login."))
        return HttpResponseRedirect(reverse('error', kwargs={'code': 403}))

    try:
        voter = Voter.objects.get(poll=poll, uuid=voter_uuid)
        if voter.excluded_at:
            raise PermissionDenied('37')
    except Voter.DoesNotExist:
        raise PermissionDenied("Invalid election")

    if request.zeususer.is_authenticated() and request.zeususer.is_voter:
        url = reverse('election_poll_index', kwargs={
            'election_uuid': request.zeususer._user.poll.election.uuid,
            'poll_uuid': request.zeususer._user.poll.uuid
        })
        return handle_voter_login_redirect(request, voter, url)

    if request.zeususer.is_authenticated() and (
            not request.zeususer.is_voter or \
                request.zeususer._user.pk != voter.pk):
        messages.error(request,
                        _("You need to logout from your current account "
                            "to access this view."))
        return HttpResponseRedirect(reverse('error', kwargs={'code': 403}))

    if voter.voter_password != unicode(voter_secret):
        raise PermissionDenied("Invalid secret")

    if poll.oauth2_thirdparty:
        oauth2 = poll.get_oauth2_module
        if oauth2.type_id == 'google':
            oauth2.set_login_hint(voter.voter_email)
        poll.logger.info("[thirdparty] setting thirdparty voter " + \
                         "session data (%s, %s)",
                         voter.voter_email, voter.uuid)
        request.session['oauth2_voter_email'] = voter.voter_email
        request.session['oauth2_voter_uuid'] = voter.uuid
        url = oauth2.get_code_url()
        poll.logger.info("[thirdparty] code handshake from %s", url)
        context = {'url': url}
        tpl = 'voter_redirect'
        return render_template(request, tpl, context)
    elif poll.shibboleth_auth:
        poll.logger.info("[thirdparty] shibboleth redirect for voter (%s, %s)",
                         voter.voter_email, voter.uuid)
        constraints = poll.get_shibboleth_constraints()
        endpoint = constraints.get('endpoint')
        request.session['shibboleth_voter_email'] = voter.voter_email
        request.session['shibboleth_voter_uuid'] = voter.uuid
        url = auth.make_shibboleth_login_url(endpoint)
        context = {'url': url}
        tpl = 'voter_redirect'
        return render_template(request, tpl, context)
    else:
        user = auth.ZeusUser(voter)
        user.authenticate(request)
        poll.logger.info("Poll voter '%s' logged in", voter.voter_login_id)
        return handle_voter_login_redirect(request, voter,
                                           poll_reverse(poll, 'index'))


@auth.election_view(check_access=False)
@require_http_methods(["GET"])
def to_json(request, election, poll):
    data = poll.get_booth_dict()
    data['token'] = unicode(csrf(request)['csrf_token'])
    return HttpResponse(json.dumps(data, default=common_json_handler),
                        content_type="application/json")


@auth.poll_voter_required
@auth.requires_poll_features('can_cast_vote')
@require_http_methods(["POST"])
def post_audited_ballot(request, election, poll):
    voter = request.voter
    raw_vote = request.POST['audited_ballot']
    encrypted_vote = crypto_utils.from_json(raw_vote)
    audit_request = crypto_utils.from_json(request.session['audit_request'])
    audit_password = request.session.get('audit_password', None)

    if audit_password:
        audit_password = audit_password.decode('utf8')
        if len(audit_password) > 100:
            return HttpResponseBadRequest(400)


    if not audit_password:
        raise Exception("Auditing with no password")

    # fill in the answers and randomness
    audit_request['answers'][0]['randomness'] = \
            encrypted_vote['answers'][0]['randomness']
    audit_request['answers'][0]['answer'] = \
            [encrypted_vote['answers'][0]['answer'][0]]
    encrypted_vote = electionalgs.EncryptedVote.fromJSONDict(audit_request)

    del request.session['audit_request']
    del request.session['audit_password']

    poll.cast_vote(voter, encrypted_vote, audit_password)
    poll.logger.info("Poll audit ballot cast")
    vote_pk = AuditedBallot.objects.filter(voter=voter).order_by('-pk')[0].pk

    return HttpResponse(json.dumps({'audit_id': vote_pk }),
                        content_type="application/json")


@auth.poll_voter_required
@auth.requires_poll_features('can_cast_vote')
@require_http_methods(["POST"])
def cast(request, election, poll):
    voter = request.voter
    encrypted_vote = request.POST['encrypted_vote']
    vote = datatypes.LDObject.fromDict(crypto_utils.from_json(encrypted_vote),
        type_hint='phoebus/EncryptedVote').wrapped_obj
    audit_password = request.POST.get('audit_password', None)

    cursor = connection.cursor()
    try:
        cursor.execute("SELECT pg_advisory_lock(1)")
        with transaction.atomic():
            cast_result = poll.cast_vote(voter, vote, audit_password)
            poll.logger.info("Poll cast")
    finally:
        cursor.execute("SELECT pg_advisory_unlock(1)")

    signature = {'signature': cast_result}

    if 'audit_request' in request.session:
        poll.logger.info("Poll cast audit request")
        del request.session['audit_request']
    else:
        poll.logger.info("Poll cast")

    if signature['signature'].startswith("AUDIT REQUEST"):
        request.session['audit_request'] = encrypted_vote
        request.session['audit_password'] = audit_password
        token = request.session.get('csrf_token')
        return HttpResponse('{"audit": 1, "token":"%s"}' % token,
                            content_type="application/json")
    else:
        # notify user
        fingerprint = voter.cast_votes.filter()[0].fingerprint
        tasks.send_cast_vote_email.delay(poll.pk, voter.pk, signature, fingerprint)
        url = "%s%s?f=%s" % (settings.SECURE_URL_HOST, poll_reverse(poll,
                                                               'cast_done'),
                             fingerprint)

        return HttpResponse('{"cast_url": "%s"}' % url,
                            content_type="application/json")


@auth.election_view(check_access=False)
@require_http_methods(["GET"])
def cast_done(request, election, poll):
    if request.zeususer.is_authenticated() and request.zeususer.is_voter:
        if poll.has_linked_polls:
            voter = request.zeususer._user

            follow = request.session.get('follow_linked', False)
            exclude_cast_done = not follow
            cyclic = not follow

            next_poll = poll.next_linked_poll(
                            voter_id=voter.voter_login_id,
                            exclude_cast_done=exclude_cast_done,
                            cyclic=cyclic)
            if next_poll:
                try:
                    voter = next_poll.voters.get(
                        voter_login_id=request.zeususer._user.voter_login_id)
                    user = auth.ZeusUser(voter)
                    user.authenticate(request)
                    url = next_poll.get_booth_url(request)
                    return HttpResponseRedirect(url)
                except Voter.DoesNotExist:
                    pass
            else:
                del request.session['follow_linked']
        request.zeususer.logout(request)

    fingerprint = request.GET.get('f')
    if not request.GET.get('f', None):
        raise PermissionDenied('39')

    vote = get_object_or_404(CastVote, fingerprint=fingerprint)

    return render_template(request, 'election_poll_cast_done', {
                               'cast_vote': vote,
                                'hide_login_link': True,
                               'election_uuid': election.uuid,
                               'poll_uuid': poll.uuid
    })


@require_http_methods(["GET"])
def download_signature_short(request, fingerprint):
    vote = CastVote.objects.get(fingerprint=fingerprint)
    return download_signature(request, vote.voter.poll.election, vote.voter.poll, fingerprint)


@auth.election_view(check_access=False)
@require_http_methods(["GET"])
def download_signature(request, election, poll, fingerprint):
    vote = get_object_or_404(CastVote, voter__poll=poll, fingerprint=fingerprint)
    response = HttpResponse(content_type='application/binary')
    response['Content-Dispotition'] = 'attachment; filename=signature.txt'
    response.write(vote.signature['signature'])
    return response


@auth.election_view()
@require_http_methods(["GET"])
def audited_ballots(request, election, poll):
    vote_hash = request.GET.get('vote_hash', None)
    if vote_hash:
        b = get_object_or_404(AuditedBallot, poll=poll, vote_hash=vote_hash)
        b = AuditedBallot.objects.get(poll=poll,
                                      vote_hash=request.GET['vote_hash'])
        return HttpResponse(b.raw_vote, content_type="text/plain")

    audited_ballots = AuditedBallot.objects.filter(is_request=False,
                                                   poll=poll)

    voter = None
    if request.zeususer.is_voter:
        voter = request.voter

    voter_audited_ballots = []
    if voter:
        voter_audited_ballots = AuditedBallot.objects.filter(poll=poll,
                                                             is_request=False,
                                                             voter=voter)
    context = {
        'election': election,
        'audited_ballots': audited_ballots,
        'voter_audited_ballots': voter_audited_ballots,
        'poll': poll,
        'per_page': 50
    }
    set_menu('audited_ballots', context)
    return render_template(request, 'election_poll_audited_ballots', context)


@auth.trustee_view
@auth.requires_poll_features('can_do_partial_decrypt')
@require_http_methods(["POST"])
def upload_decryption(request, election, poll, trustee):
    factors_and_proofs = crypto_utils.from_json(
        request.POST.get('factors_and_proofs', "{}"))

    # verify the decryption factors
    try:
        LD = datatypes.LDObject
        factors_data = factors_and_proofs['decryption_factors']
        factor = lambda fd: LD.fromDict(fd, type_hint='core/BigInteger').wrapped_obj
        factors = [[factor(f) for f in factors_data[0]]]

        proofs_data = factors_and_proofs['decryption_proofs']
        proof = lambda pd: LD.fromDict(pd, type_hint='legacy/EGZKProof').wrapped_obj
        proofs = [[proof(p) for p in proofs_data[0]]]
        poll.logger.info("Poll decryption uploaded")
    except KeyError:
        data_sample = str(request.POST.items())[:50]
        poll.logger.error("upload decryption failed (POST DATA: %s)" % data_sample)
        return HttpResponseBadRequest(400)
    tasks.poll_add_trustee_factors.delay(poll.pk, trustee.pk, factors, proofs)

    return HttpResponse("SUCCESS")


@auth.election_view()
@auth.requires_poll_features('can_do_partial_decrypt')
@require_http_methods(["GET"])
def get_tally(request, election, poll):
    if not request.zeususer.is_trustee:
        raise PermissionDenied('40')

    params = poll.get_booth_dict()
    tally = poll.mixed_ballots_json_dict

    return HttpResponse(json.dumps({
        'poll': params,
        'tally': tally}, default=common_json_handler),
        content_type="application/json")


@auth.election_view()
@auth.requires_poll_features('compute_results_finished')
@require_http_methods(["GET"])
def results(request, election, poll):
    if not request.zeususer.is_admin and not poll.feature_public_results:
        raise PermissionDenied('41')

    if not poll.get_module().display_poll_results:
        url = election_reverse(election, 'index')
        return HttpResponseRedirect(url)

    context = {
        'poll': poll,
        'election': election
    }
    set_menu('results', context)
    return render_template(request, 'election_poll_results', context)


@auth.election_admin_required
@auth.requires_poll_features('compute_results_finished')
@require_http_methods(["GET"])
def results_file(request, election, poll, language, ext):
    lang = language
    name = ext
    el_module = poll.get_module()

    if not os.path.exists(el_module.get_poll_result_file_path('pdf', 'pdf',\
        lang)):
        if el_module.pdf_result:
            el_module.generate_result_docs((lang,lang))

    if not os.path.exists(el_module.get_poll_result_file_path('csv', 'csv',\
        lang)):
        if el_module.csv_result:
            el_module.generate_csv_file((lang, lang))

    if request.GET.get('gen', None):
        el_module.compute_results()

    fname = el_module.get_poll_result_file_path(name, ext, lang=lang)

    if not os.path.exists(fname):
        raise Http404

    if settings.USE_X_SENDFILE:
        response = HttpResponse()
        response['Content-Type'] = ''
        response['X-Sendfile'] = fname
        return response
    else:
        zip_data = file(fname, 'r')
        response = HttpResponse(zip_data.read(), content_type='application/%s' % ext)
        zip_data.close()
        basename = os.path.basename(fname)
        response['Content-Dispotition'] = 'attachment; filename=%s' % basename
        return response


@auth.election_admin_required
@auth.requires_poll_features('compute_results_finished')
@require_http_methods(["GET"])
def zeus_proofs(request, election, poll):

    if not os.path.exists(poll.zeus_proofs_path()):
        poll.store_zeus_proofs()

    if settings.USE_X_SENDFILE:
        response = HttpResponse()
        response['Content-Type'] = ''
        response['X-Sendfile'] = poll.zeus_proofs_path()
        return response
    else:
        zip_data = file(poll.zeus_proofs_path())
        response = HttpResponse(zip_data.read(), content_type='application/zip')
        zip_data.close()
        response['Content-Dispotition'] = 'attachment; filename=%s_proofs.zip' % election.uuid
        return response


@auth.election_admin_required
@auth.requires_poll_features('compute_results_finished')
@require_http_methods(["GET"])
def results_json(request, election, poll):
    data = poll.zeus.get_results()
    return HttpResponse(json.dumps(data, default=common_json_handler),
                        content_type="application/json")


@csrf_exempt
@auth.election_view(check_access=False)
@require_http_methods(["POST"])
def sms_delivery(request, election, poll):
    try:
        resp = json.loads(request.body)
    except ValueError:
        raise PermissionDenied

    ip_addr = resolve_ip(request)
    error = resp.get('error', None) or None
    if error == '0':
        error = None
    code = "mybsms:" + resp['id']
    poll.logger.info(
        "Mobile delivery status received from '%r': %r" % (ip_addr, resp))
    try:
        voter = poll.voters.get(last_sms_code=code)
        status = resp.get('status', 'unknown')
        if error:
            status = "%s:%r:%r" % ("ERROR", status, resp)
        voter.last_sms_status = status
        voter.save()
    except Voter.DoesNotExist:
        poll.logger.error("Cannot resolve voter for sms delivery code: %r", code)
        pass
    return HttpResponse("OK")


@auth.election_view(check_access=False)
@auth.requires_election_features('can_upload_remote_mix')
@require_http_methods(["POST", "GET"])
@csrf_exempt
def remote_mix(request, election, poll, mix_key):
    method = request.method
    if not election.check_mix_key(mix_key):
        raise PermissionDenied
    if method == 'GET':
        resp = poll.zeus.get_last_mix()
        # Use X_SEND_FILE
        return HttpResponse(to_canonical(resp),
                        content_type="application/octet-stream")
    if method == 'POST':
        data = from_canonical(request.body or '')
        result = poll.add_remote_mix(data)
        return HttpResponse(result, content_type="plain/text")

    raise PermissionDenied
