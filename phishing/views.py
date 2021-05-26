from django.shortcuts import render
from phishing.phishing_project import *
from django.views.decorators.csrf import ensure_csrf_cookie

@ensure_csrf_cookie
def index(request):
    return render(request,'Webpage.html')

def subm(request):
    submitbutton = request.POST.get("URL")
    print(submitbutton)
    num = TakeInput(submitbutton)
    if num==100:
        return render(request,'Invalid.html')
    elif num==1:
        return render(request,'illegi.html')
    elif num==0:
        return render(request,'suspicious.html')
    elif num==-1:
        return render(request,'valid.html')
