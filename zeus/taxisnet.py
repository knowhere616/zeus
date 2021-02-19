from django.conf import settings

TAXISNET_INSTITUTIONS = getattr(settings, 'TAXISNET_INSTITUTIONS', {}).keys()

def is_enabled(admin):
  admin_enabled = admin.user_groups.filter(name="taxisnet").exists()
  inst_enabled = admin.institution.name in TAXISNET_INSTITUTIONS
  return admin_enabled and inst_enabled