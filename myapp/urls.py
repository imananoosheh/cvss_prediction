from django.urls import path
from myapp import views

app_name = 'myapp'

urlpatterns = [
    # path(r'', views.index, name='index'),
    path(r'', views.single_decs_query, name='single_decs_query'),
]
