from django.urls import path
from client.views import *
urlpatterns = [
    path('', result,name='home'),
    path('api/<path:id>/', api,name='home'),

]