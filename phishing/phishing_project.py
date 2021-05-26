# -*- coding: utf-8 -*-
"""
Created on Wed Mar 31 13:04:31 2021

@author: Khan Affan
"""

import pandas as pd
import numpy as np
import matplotlib.pyplot as plt
from sklearn.tree import DecisionTreeClassifier
from sklearn.ensemble import RandomForestClassifier
from sklearn.model_selection import train_test_split
from sklearn.preprocessing import StandardScaler
from sklearn.metrics import confusion_matrix, accuracy_score, classification_report
from sklearn.impute import SimpleImputer
import requests
import lxml,re
from bs4 import BeautifulSoup
import bs4
import json
import sys,urllib
import socket
from urllib.parse import urlparse
import subprocess
import datetime, time
import dateutil.parser as p

def RunAlgo(arr):
    ##################################################################################
    ################## Data Preprocessing ###########################################

    dataset = pd.read_csv('.\\phishing\\phishing.csv',encoding='utf-8')
    #x = dataset.iloc[:,[1,4,5,6,7,8,9,11,12,13,15,16,24]].values
    x = dataset.iloc[:,[1,2,3,4,5,6,7,8,15,24,23,14,17]].values
    y = dataset.iloc[:, -1].values

    imputer = SimpleImputer(missing_values=np.nan, strategy='mean')
    imputer.fit(x)
    x = imputer.transform(x)
    x_train, x_test, y_train, y_test = train_test_split(x,y,test_size = 0.1,random_state = 0)

    ################################################################################
    ###################### Algorithmic Implementation #############################

    reg = DecisionTreeClassifier(criterion='entropy', random_state = 0)
    reg.fit(x_train,y_train)
    y_pred = reg.predict(x_test)
    #print(np.concatenate((y_pred.reshape(len(y_pred),1),y_test.reshape(len(y_test),1)),1))
    print("---------------Decision Tree---------------------\n\n")
    print(np.concatenate((y_pred.reshape(len(y_pred),1),y_test.reshape(len(y_test),1)),1))

    print(classification_report(y_pred,y_test))

    mat = confusion_matrix(y_pred, y_test)
    print(mat)
    print(accuracy_score(y_test, y_pred))

    #print(x_test)

    print("\n\n---------------Random Forest---------------------\n\n")

    rfc=RandomForestClassifier()
    model_4=rfc.fit(x_train,y_train)

    rfc_predict=model_4.predict(x_test)
    print(classification_report(rfc_predict,y_test))
    print(confusion_matrix(rfc_predict, y_test))
    print(accuracy_score(rfc_predict,y_test))

    return model_4.predict(arr)
    #print(x_test)

##############################################################
###############  features extraction ########################
# lyst = []
# with open('\..\JSON_Dataset.json','r') as jd:
#    y = json.loads(jd.read())

arr = []
# for i in range(100):
def TakeInput(url):
    headers = {
      'User-Agent': 'Mozilla/5.0 (Windows NT 6.1; WOW64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/63.0.3239.132 Safari/537.36 QIHU 360SE'
    }
    domain = urlparse(url).netloc
    #print(domain)
    atrr = []
    try:
        f = requests.get(url, headers = headers)
    except:
        return 100
    soup = BeautifulSoup(f.content,'lxml')

    #Finding Using IP attribute
    ip = socket.gethostbyname(domain)
    x = re.search('.'+ip+'.',url)
    if x==None:
        atrr.append(-1)
    else:
        atrr.append(1)

    #using at@ symbol

    x = re.search('.@.',url)
    if x==None:
        atrr.append(-1)
    else:
        atrr.append(1)

    #redirecting //
    x = url.find("//")
    if x>=7:
        atrr.append(1)
    else:
        atrr.append(-1)

    #preffix-suffix
    x = re.search('.-.',domain)
    if x==None:
        atrr.append(-1)
    else:
        atrr.append(1)

    #HTTPS
    x = re.search('https:.',url)
    if x==None:
        atrr.append(1)
    else:
        atrr.append(-1)

    #longUrl
    if len(url) > 25:
        atrr.append(1)
    elif 15<len(url)<=25:
        atrr.append(0)
    else:
        atrr.append(-1)

    #subdomains
    if domain.count('.') > 3:
        atrr.append(1)
    elif 1<=domain.count('.') <=3:
        atrr.append(0)
    else:
        atrr.append(-1)

    #ShortUrl
    resp = requests.get(url, headers = headers)
    if url==resp:
        atrr.append(-1)
    else:
        atrr.append(1)

    #AnchorURL
    flag = 0
    anchor = soup.find_all('a')
    for stri in anchor:
        try:
            do = urlparse(stri['href']).netloc
            if do != domain:
                if do.index("#")==-1:
                    atrr.append(0)
                elif do!=domain:
                    atrr.append(1)
                    flag = 1
                    break
        except:
            flag=0
    if flag==0:
        atrr.append(-1)

    #LinksInScriptTags
    flag = 0
    scripts = soup.find_all('script')
    for stri in scripts:
        try:
            do = urlparse(stri['src']).netloc
            if do != domain:
                if do.index(" ")==-1:
                    atrr.append(0)
                elif do!=domain:
                    atrr.append(1)
                    flag = 1
                    break
        except:
            flag=0
    if flag==0:
        atrr.append(-1)

    #infoMail
    mailtos = soup.select('a[href^=mailto]')
    if mailtos==None:
        atrr.append(-1)
    else:
        atrr.append(1)


    #iframeRedirection

    ifr = soup.find_all('iframe')
    flag = 0
    for stri in ifr:
        do = urlparse(stri['src']).netloc
        if do != domain:
            atrr.append(1)
            flag = 1
            break
    if flag==0:
        atrr.append(-1)

    #DomainAge
    show = "https://input.payapi.io/v1/api/fraud/domain/age/" + domain
    r = requests.get(show)

    data = r.text
    jsonToPython = json.loads(data)
    try:
        stri = jsonToPython['message']
        list = stri.split()
        ind = list.index("days")
        num = int(list[ind-1])

        if num<182:
            atrr.append(1)
        else:
            atrr.append(-1)
    except:
        atrr.append(1)

    #print(atrr)
    atrr = np.array(atrr)
    atrr = atrr.reshape(1,-1)
    list = RunAlgo(atrr)
    return list[0]

# print(accuracy_score(lyst,arr))
