from django.urls import path
from . import views

urlpatterns = [
  path('',views.index,name="index"),
  path('phishing/submitted',views.subm,name="sub")
]
