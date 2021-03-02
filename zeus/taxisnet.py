from django.conf import settings

TAXISNET_INSTITUTIONS = getattr(settings, 'TAXISNET_INSTITUTIONS', {})
TAXISNET_GROUPS = getattr(settings, 'TAXISNET_GROUPS', {})

def is_enabled(admin):
  admin_enabled = admin.user_groups.filter(name="taxisnet").exists()
  inst_enabled = admin.institution.name in TAXISNET_INSTITUTIONS
  group_enabled = False
  for group in admin.user_groups.filter().values_list('name', flat=True):
    if group in TAXISNET_GROUPS:
      group_enabled = True
  return admin_enabled and (inst_enabled or group_enabled)

def resolve_config(poll):
  admin = poll.election.admins.filter()[0]
  if not is_enabled(admin):
    return False
  
  inst = poll.election.institution.name
  groups = admin.user_groups.filter().values_list('name', flat=True)
  if inst in TAXISNET_INSTITUTIONS:
    return TAXISNET_INSTITUTIONS.get(inst)
  
  conf = None
  for group in groups:
    if group in TAXISNET_GROUPS:
      conf = TAXISNET_GROUPS[group]
      break
  return conf