import uuid
import threading
import re

from base64 import b64decode

from functools import wraps

from django.core.exceptions import PermissionDenied, ValidationError
from django.core.urlresolvers import reverse
from django.shortcuts import get_object_or_404
from django.http import HttpResponseRedirect
from django.conf import settings
from django.shortcuts import redirect

from helios.models import Election, Poll, Trustee, Voter
from heliosauth.models import User

from zeus.log import init_election_logger, init_poll_logger, _locals

import logging

logger = logging.getLogger(__name__)


def get_client_ip(request):
    ip = request.META.get('HTTP_X_FORWARDED_FOR', None)

    if not ip:
        ip = request.META.get('HTTP_CLIENT_IP', None)
    if not ip:
        ip = request.META.get('REMOTE_ADDR', None)

# If the IP is a comma-separated list, get the first IP from the list
    if ip:
        ip = ip.split(',')[0].strip()

    # Ensure the IP is valid
    if not ip or ip == 'unknown':

        ip = None

    return ip


def class_method(func):
    def wrapper(self, request, *args, **kwargs):
        print("Executing class method:", func.__name__)
        return func(request, *args, **kwargs)

    return wrapper


def trustee_view(func):
    @wraps(func)
    @election_view()
    def wrapper(request, election, *args, **kwargs):
        if not request.zeususer.is_trustee:
            raise PermissionDenied("Only election trustees can access this view")
        
        kwargs['trustee'] = request.trustee
        kwargs['election'] = election
        return func(request, *args, **kwargs)
    
    return wrapper

def election_view(check_access=True):
    def wrapper(func):
        @wraps(func)
        def inner(request, *args, **kwargs):
            user = request.zeususer
            if user.is_authenticated():
                _locals.user_id = user.user_id
            try:
                _locals.ip = get_ip(request)
            except KeyError:
                # Handle KeyError if 'HTTP_X_FORWARDED_FOR' or 'REMOTE_ADDR' is missing
                raise PermissionDenied("Failed to retrieve IP")
            except Exception as e:
                # Catch other specific exceptions if necessary
                raise PermissionDenied(f"failed to retrive IP: {str(e)}")
            
            allow_manager = getattr(func, '_allow_manager', False)
            if allow_manager and user.is_manager:
                check_access = False

            if 'election_uuid' in kwargs:
                uuid = kwargs.pop('election_uuid')
                election = get_object_or_404(Election, uuid = uuid)
                if not user.can_access_election(election) and check_access:
                    raise PermissionDenied("You do not have access to this election")
                kwargs['election'] = election

            if 'poll_uuid' in kwargs:
                uuid = kwargs.pop('poll_uuid')
                poll = get_object_or_404(Poll, uuid = uuid)
                if not user.can_access_poll(poll) and check_access:
                    raise PermissionDenied("You do not have access to this poll")
                    kwargs['poll'] = poll

                return func(request, *args, **kwargs)
            return inner
        return wrapper
    

def poll_voter_required(func):
    @election_view()
    @wraps(func)
    def wrapper(request, *args, **kwargs):
        user = request.zeususer
        if not user.is_authenticated:
            raise PermissionDenied("You must be authenitcated to access this view")
        if not user.is_voter:
            raise PermissionDenied("Only voters are allowed to acces this view")
        return func(request, *args, **kwargs)
    
    return wrapper


def superadmin_required(func):
    @user_required
    @wraps(func)
    def wrapper(request, *args, **kwargs):
        user = request.zeususer
        if not user.is_authenticated:
            raise PermissionDenied("You must be authenitcated to access this view")
        if not user.is_superadmin:
            raise PermissionDenied("Only superadmin users are allowed to acces this view")
        return func(request, *args, **kwargs)
    
    return wrapper

def manager_or_superadmin_required(func):
    @user_required
    @wraps(func)
    def wrapper(request, *args, **kwargs):

        user = request.zeususer
        if not (user.is_superadmin or user.is_manager):
            raise PermissionDenied("Access denied: Superadmin or manager required")
        
        return func(request, *args, **kwargs)
    
    return wrapper

logger = logging.getLogger(__name__)

def election_poll_required(func):
    @wraps(func)
    @election_view(check_access=True)
    def wrapper(request, *args, **kwargs):
        user = getattr(request, 'zeususer', None)

        if not user:
            logger.warning("Access denied: No user information in request.")
            raise PermissionDenied("Access denied: No user information")
        
        if not user.is_voter:
            logger.warning(f"Access denied: USer {user.id} is not a voter.")
            raise PermissionDenied("Access denied: Voter authentication required.")
        
        logger.info(f"User {user.id} granted access to {func.__name__}")

        return func(request, *args, **kwargs)
    
    return wrapper

def election_user_required(func):
    @ wraps(func)
    @election_view()
    @user_required
    def wrapper(request, *args, **kwargs):
        user = getattr(request, 'zeususer', None)

        if not user:
            logger.warning("Access denied: No user information in request.")
            raise PermissionDenied("Access denied: No user information")
        
        if not user.is_voter:
            logger.warning(f"Access denied: User {user.id} is not a voter.")
            raise PermissionDenied("Access denied: Voter authentication required.")
        
        logger.info(f"User {user.id} granted acces to {func.__name__}.")

        return func(request, *args, **kwargs)
   
    return wrapper
    

def election_admin_required(func):
    
    def wrapper(request, *args, **kwargs):
        user = getattr(request, 'zeususer', None)

        if not user:
            logger.warning("Access denied: No user information in request.")
            raise PermissionDenied("Access denied: No user information")
        
        if not user.is_admin:
            logger.warning(f"Access denied: User {user.id} is not an election administrator.")
            raise PermissionDenied("Access denied: Election administrator required.")
        
        logger.info(f"User {user.id} granted acces to {func.__name__}.")

        return func(request, *args, **kwargs)
    
    return wrapper


def unauthenticated_user_required(func):
    @wraps(func)
    def wrapper(request, *args, **kwargs):
        user = getattr(request, 'zeususer', None)

        if user and user.is_authenticated():
            logger.warning(f"Access denied: Authenticated user {user.id} attempted to acces {func.__name__}.")
            return redirect('some_logout_url')
        
        logger.info(f"Unauthenticated user granted access to {func.__name}.")
        return func(request, *args, **kwargs)
    
    return wrapper

def requires_election_features(*features):
    def decorator(func):
        @wraps(func)
        def inner(request, *args, **kwargs):
            election = kwargs.get('election')

            if not election:
                msg = "No election object found in arguments"
                logger.error(msg)
                raise PermissionDenied(msg)
            
            if not election.check.features(*features):
                status = election.check_features_verbose(*features)
                msg = f"Unmet election {election.uuid} required features {status}"
                logger.error(msg)

                return redirect('some_fallback_url')
            
            logger.info(f"Election {election.uuid} has required features {features}.")
            return func(request, *args, **kwargs)
        
        return inner
    
    return decorator

def requires_poll_features(*features):
    def decorator(func):
        @wraps(func)
        def inner(request, *args, **kwargs):
            poll = kwargs.get('poll')

            if not poll:
                msg = "No poll object found in arguments"
                logger.error(msg)
                raise PermissionDenied(msg)
            
            if not poll.check.features(*features):
                status = poll.check_features_verbose(*features)
                msg = f"Unmet poll {poll.uuid} required features {status}"
                logger.error(msg)

            
            logger.info(f"Election {poll.uuid} has required features {features}.")
            return func(request, *args, **kwargs)
        
        return inner
    
    return decorator

TRUSTEE_SESSION_KEY = 'zeus_trustee_uuid'
USER_SESSION_KEY = 'user'
VOTER_SESSION_KEY = 'CURRENT_VOTER'


class ZeusUser(object):

    is_user = False
    is_trustee = False
    is_voter = False
    is_admin = False
    is_manager = False
    is_superadmin = False

@classmethod
def from_requests(cls, request):
    try:
        users = get_users_from_request(request)
        valid_users = [user for user in users if user]

        if not valid_users:
            logger.warning("No valid users found in the request.")
            raise ValueError("No valid users found.")
        
        user = valid_users[0]
        logger.info(f"USer {user.id} obtained from request.")
        return cls(user)
    
    except (IndexError, ValueError) as e:
        logger.error(f"Error obtaining user from request: {str(e)}")
        return cls(None)
    
def __init__(self, user_obj):
    self._user = user_obj
    self.is_user = False
    self.is_superadmin = False
    self.is_manager = False
    self.is_admin = False
    self.institurion = None
    self.is_trustee = False
    self.is_voter = False

    if isinstance(self._user, User):
        self.is_user = True
        self.is_superadmin = getattr(self._user, 'superadmin_p', False)
        self.is_manager = getattr(self._user, 'managment_p', False) or self.is_superadmin
        self.is_admin = getattr(self._user, 'admin_p', False) or self.is_superadmin
        self.institution = getattr(self._user, 'institution', None) if self.is_admin else None

        logger.info(f"User initialized: superadming = {self.is_superadmin}, manager = {self.is_manager}, admin = {self.is_admin}")

    elif isinstance(self._user, Trustee):
        self.is_trustee = True
        logger.info("Trustee initialized")

    elif isinstance(self._user, Voter):
        if not getattr(self._user, 'excluded_at', None):
            self.is_voter = True
        logger.info(f"Voter initialized: voter = {self.is_voter}")

    else: 
        logger.warning("Invalid user object type")


@property
def user_id(self):
    if self.is_admin:
        user_id = f"ADMIN:{self._user.user_id}"
        logger.info(f"Admin user ID generated: {user_id}")
        return user_id
    
    if self.is_trustee:
        user_id = f"TRUSTEE:{self._user.user.email}"
        logger.info(f"Trustee user ID generated: {user_id}")
        return user_id
    
    if self.is_voter:
        prefix = "EXLUDED_VOTER" if slef._user.excluded_at else "VOTER"
        user_id = f"{prefix}:{self._user.voter_login_id}"
        logger.info(f"Voter user ID generated: {user_id}")
        return user_id
    
    error_msg = "Unknown user type for user_id property"
    logger.error(error_msg)
    raise Exception(error_msg)

def is_authenticated(self):
    return bool(self._user)

def is_anonymous(self):
    return not bool(self._user)

def authenticate(self, request):
    session = request.session
    key = None

    if self.is_trustee:
        key = TRUSTEE_SESSION_KEY

    elif self.is_admin:
        key = USER_SESSION_KEY

    elif self.is_voter:
        key = VOTER_SESSION_KEY

    if key is None:
        error_msg = "Authentication failed: unknown user type"
        logger.error(error_msg)
        raise Exception(error_msg)
    
    self._clear_session(request)
    session[key] = self._user.pk
    logger.info(f"User authenticated and session key {key} set for user ID {self._user.pk}")

def _clear_session(self, request):

    pass

def logout(self, request):
        self._clear_session(request)
        self._user = None
        self.is_voter = False
        self.is_admin = False
        self.is_trustee = False
        self.is_manager = False
        self.is_superadmin = False

def _clear_session(self, request):

    session_keys = [
        self.TRUSTEE_SESSION_KEY, 
        self.USER_SESSION_KEY, 
        self.VOTER_SESSION_KEY
    ]

    for sess_key in session_keys:
        request.session.pop(sess_key, None)

def can_access_poll(self, poll):
    ##Improvements: 
        ##1. simplify condition checks
        ##2. Use more descriptive variable names
        ##3. Add docstring to explain what the method does

    if self.is_voter:
        return self._user.poll.uuid == poll.uuid
    
    if self.is_admin:
        if self._user.superadming_p:
            return True
        return self._user.elections.filter(polls__in=[poll]).exists()
    
    if self.is_trustee:
        return self._user.election.polls.filter(pk=poll.pk).exists()
    
    return False

def can_access_election(self, election):
    ##Find out if a user can access a given election

    if self.is_trustee:
        return self._user.election == election

    if self.is_voter:
        return self._user.poll.election.uuid == election.uuid
    
    if self.is_admin:
        if self._user.superadmin_p:
            return True
        return self._user.elections.filter(pk=election.pk).exists()
    
    return False

def can_access_active_election(self, election):

    ##can access a given election and determine if it is active

    if election.is_active:
        return self.can_access_election(election)
    return False

def get_users_from_request(request):

    session = getattr(request, 'session', {})

    user = None
    admin = None
    trustee = None
    voter = None

    def identify_user_and_admin():
        user_id = session.get(USER_SESSION_KEY)
        if user_id:
            try:
                user = User.objects.get(pj=user_id)
                if user.admin_p or user.superadmin_p:
                    admin = user
            except User.DoesNotExist:
                user = None

    def identufy_voter():
        voter_id = session.get(VOTER_SESSION_KEY)
        if voter_id:
            try:
                voter = Voter.objects.get(pk=voter_id)
                if voter.excluded_at:
                    raise Voter.DoesNotExist
            except Voter.DoesNotExist:
                voter = None
                session.pop(VOTER_SESSION_KEY, None)

    def identify_trustee():
        trustee_id = session.get(TRUSTEE_SESSION_KEY)
        if trustee_id:
            try:
                trustee = Trustee.objects.get(pk=int(trustee_id))
                trustee = None
            except Trustee.DoesNotExist:
                trustee = None

    def identify_trustee_hhtp_basic_auth():
         api_auth_header = request.META.get('HTTP_AUTHORIZATION')
         if api_auth_header:
             try:
                  auth = AUTH_RE.findall(api_auth_header)
                  election, username, password = b64decode(auth[0]).split(":")
                  auth_trustee = Trustee.objects.get(email=username, election__uuid=election)
                  if auth_trustee.secret == password:
                      trustee = auth_trustee
                      setattr(request, '_dont_enforce_csrf_checks', True)
                  else:
                      raise PermissionDenied
             except (ValueError, Trustee.DoesNotExist):
                 raise PermissionDenied

    def cleanup_duplicate_logins():
        activate_roles = [role for role in [voter, trustee, admin] if role]
        if len(active_roles) > 1:
            if voter:
                if trustee:
                    session.pop(TRUSTEE_SESSION_KEY, None)
                if admin:
                    session.pop(USER_SESSION_KEY, None)
                elif trustee:
                    if admin: 
                        session.pop(USER_SESSION_KEY, None)

    identify_user_and_admin()
    identify_trustee()
    identify_trustee_hhtp_basic_auth()
    identufy_voter()

    if user and not admin:
        session.pop(USER_SESSION_KEY, None)
        user, admin = None, None

    cleanup_duplicate_logins()

    return {'user': user, 'admin': admin, 'trustee': trustee, 'voter': voter}

def allow_manager_access(func):

    ##allow manager access to a function

    setattr(func, '_allow_manager', True)

    logger.info(f"Manager access allowed for function: {func.__name__}")
    return func

def make_shibboleth_login_url(endpoint):

    ##Create a Shibboleth login URL 

    if not isinstance(endpoint, str) or not endpoint:
        raise ValueError("Endpoint must be a non-empty string.")

    shibboleth_login = reverse('shibboleth_login', kwargs={'endpoint': endpoint})
    url = '/'.join(shibboleth_login.strip('/'))

    logger.info(f"Created Shibboleth login URL: {url}")                            
                        













        



