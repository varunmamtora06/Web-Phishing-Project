# i have created this file

from django.http import HttpResponse
from django.template import Context, loader
from django.shortcuts import render

def index(request):
    template = loader.get_template("Webpage.html")
    return HttpResponse(template.render())
