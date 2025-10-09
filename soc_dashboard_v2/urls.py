from django.urls import path
from . import views

urlpatterns = [
    path("vt_hash_lookup", views.vt_hash_lookup_view, name="vt_hash_lookup_view"),
]