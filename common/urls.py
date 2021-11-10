from django.urls import path

from .views import *

urlpatterns = [
    path('login', login, name='login'),
    path('logout', log_out, name='logout'),
]