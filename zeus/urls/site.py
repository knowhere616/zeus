from django.conf.urls import include, patterns, url

urlpatterns = patterns('zeus.views.site',
    url(r'^$', 'home', name='home'),
    url(r'^landing/$', 'landing', name='landing'),
    url(r'^stvcount/$', 'stv_count', name='stv_count'),
    url(r'^terms/$', 'terms', name='terms'),
    url(r'^faqs/$', 'faqs_voter', name='faqs'),
    url(r'^faqs/voter/$', 'faqs_voter', name='faqs_voter'),
    url(r'^faqs/trustee/$', 'faqs_trustee', name='faqs_trustee'),
    url(r'^resources/$', 'resources', name='site_resources'),
    url(r'^contact/$', 'contact', name='site_contact'),
    url(r'^stats/$', 'stats', name='site_stats'),
    url(r'^usage/$', 'csv_report', name='site_csv_report'),
    url(r'^elections-held/$', 'csv_report_redirect', name='site_csv_report_redirect'),
    url(r'^demo$', 'demo', name='site_demo'),
    url(r'^account-request$', 'account_request', name='site_demo_request'),
    url(r'^error/(?P<code>[0-9]+)$', 'error', name='error')
)

