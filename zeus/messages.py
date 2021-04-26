from django.utils.translation import ugettext_lazy as _


VOTER_REMOVE_CONFIRM = _("Confirm voter removal: {{ voter.voter_name}} "
                         "{{ voter.voter_surname }} "
                         "{{ voter.voter_fathername }} "
                         "({{ voter.voter_contact_field_display }})")


TRUSTEE_REMOVE_CONFIRM = _("Are you sure you want to delete the selected"
                           " trustee ?")

ELECTION_FREEZE_CONFIRM = _("Are you sure you want to freeze the election ?")
POLL_DELETE_CONFIRM = _("Are you sure you want to delete the selected poll ?")

ADMIN_GUIDE = _('Admin guide for')
VOTER_GUIDE = _('Voter guide for')
VOTER_QUICK_GUIDE = _('Voter quick guide for')

LANG_EL = _('Greek')
LANG_EN = _('English')
LANG_RO = _('Romanian')

TERMS_CUSTOM_CONSENT_TEXT1 = _('terms custom consent text1')