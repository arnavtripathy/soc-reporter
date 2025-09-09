# soc_dashboard/urls.py
from django.urls import path
from . import views

urlpatterns = [
    path("check_abuseipdb_ip/", views.check_abuseipdb_ip, name="check_abuseipdb_ip"),
    path("vt_domain/", views.vt_domain_lookup, name="vt_domain_lookup"), 
    path("vt_url/", views.vt_url_lookup, name="vt_url_lookup"),
    path("dynamic-form/", views.dynamic_scan_form, name="dynamic_scan_form"),
    path("dynamic-submit/", views.submit_dynamic_scan, name="submit_dynamic_scan"),
]