from django.shortcuts import render
import re, whois, favicon, time, requests, json, sys, xmltodict
from bs4 import BeautifulSoup
from datetime import  datetime
from urllib.parse import urlencode,urlparse
from urllib.error import HTTPError
import urllib.request
from xml.etree.ElementTree import fromstring
from sklearn.ensemble import RandomForestClassifier
import pandas as pd
# Create your views here.

class pred:
    def __init__(self):
        print('Loading Dataset...')
        df = pd.read_csv('ml/dataset.csv')
        features = ['having_IP_Address','URL_Length','Shortining_Service','having_At_Symbol','double_slash_redirecting','Prefix_Suffix',
            'having_Sub_Domain','SSLfinal_State','Domain_registeration_length','Favicon','port','HTTPS_token','Request_URL','URL_of_Anchor',
            'SFH','Submitting_to_email','Redirect','RightClick','Iframe','age_of_domain','web_traffic','Page_Rank','Google_Index','Statistical_report']
        print("Creating Random Forest Classifier instance...")
        self.clf = RandomForestClassifier()
        print("Instance created")
        X = df[features]
        y = df['Result']
        print("Training the Classifier...")
        self.clf.fit(X,y)
    def prediction(self,X):
        result = self.clf.predict(X)
        print("Predicted value is "+str(result))
        return result


def extract(url):
    print("Feature extracting")
    url1=url
    soup = BeautifulSoup(urllib.request.urlopen(url))
    labels=[0]*30

    url_tokens = '/'.join(url.split('//')).split('/')
    print(url_tokens)

    #1.Searching IP address IPv4, IPv6
    match = re.search('(([01]?\\d\\d?|2[0-4]\\d|25[0-5])\\.([01]?\\d\\d?|2[0-4]\\d|25[0-5])\\.([01]?\\d\\d?|2[0-4]\\d|25[0-5])\\.([01]?\\d\\d?|2[0-4]\\d|25[0-5])\\/)|'  #IPv4
                        '((0x[0-9a-fA-F]{1,2})\\.(0x[0-9a-fA-F]{1,2})\\.(0x[0-9a-fA-F]{1,2})\\.(0x[0-9a-fA-F]{1,2})\\/)'  #IPv4 in hexadecimal
                        '(?:[a-fA-F0-9]{1,4}:){7}[a-fA-F0-9]{1,4}',url)  #IPv6
    if match:
        having_IP = 1
    else:
        having_IP = -1
    print("IP Complete")

    #2.Length
    length = len(url)
    if(length < 54):
        url_len = -1
    elif ( length >=54 and length <75):
        url_len = 0
    else:
        url_len = 1
    print("Length Complete")

    #3.Shortened URL
    match=re.search('bit\.ly|goo\.gl|shorte\.st|go2l\.ink|x\.co|ow\.ly|t\.co|tinyurl|tr\.im|is\.gd|cli\.gs|' 
                        'yfrog\.com|migre\.me|ff\.im|tiny\.cc|url4\.eu|twit\.ac|su\.pr|twurl\.nl|snipurl\.com|' 
                        'short\.to|BudURL\.com|ping\.fm|post\.ly|Just\.as|bkite\.com|snipr\.com|fic\.kr|loopt\.us|'
                        'doiop\.com|short\.ie|kl\.am|wp\.me|rubyurl\.com|om\.ly|to\.ly|bit\.do|t\.co|lnkd\.in|'
                        'db\.tt|qr\.ae|adf\.ly|goo\.gl|bitly\.com|cur\.lv|tinyurl\.com|ow\.ly|bit\.ly|ity\.im|'
                        'q\.gs|is\.gd|po\.st|bc\.vc|twitthis\.com|u\.to|j\.mp|buzurl\.com|cutt\.us|u\.bb|yourls\.org|'
                        'x\.co|prettylinkpro\.com|scrnch\.me|filoops\.info|vzturl\.com|qr\.net|1url\.com|tweez\.me|v\.gd|tr\.im|link\.zip\.net',url)
    if match:
        shortining = 1
    else:
        shortining = -1
    print("shortining Complete")

    #4.having @
    if '@' in url:
        having_at = 1
    else:
        having_at = -1
    print("@ Complete")

    #5.redirecting using //
    try:
        position= url.rfind("//")
        if(position<7):
            doubleSlash_redirecting = -1
        else:
            doubleSlash_redirecting = 1
    except:
        doubleSlash_redirecting = 0
    print("doubleSlash_redirecting Complete")

    #6.Adding Prefix or Suffix Separated by (-) to the Domain
    if '-' in url_tokens[1]:
        prefix_suffix=1
    else:
        prefix_suffix=-1
    print("prefix_suffix Complete")

    #7.Sub Domain and Multi Sub Domains
    if url.count(".") < 3:
        having_Sub_Domain= -1   # legitimate
    elif url.count(".") == 3:
        having_Sub_Domain=0     # suspicious
    else:
        having_Sub_Domain=1     # phishing

    #8.HTTPS (Hyper Text Transfer Protocol with Secure Sockets Layer)
    if(url_tokens[0]=='https:'):
        sSLfinal_State=-1
    else:
        sSLfinal_State=1 

    #9.Domain Registration Length
    dns = 0
    try:
        domain_name = whois.whois(urlparse(url).netloc)
    except:
        dns = 1
            
    if dns == 1:
        Domain_registeration_length=1   #phishing
    else:
        expiration_date = domain_name.expiration_date
        today = time.strftime('%Y-%m-%d')
        today = datetime.strptime(today, '%Y-%m-%d')
        if expiration_date is None:
            Domain_registeration_length=1 #it is phishing
            
        elif type(expiration_date) is list or type(today) is list :
            Domain_registeration_length=0   #If it is a type of list then we can't select a single value from list. So,it is regarded as suspected website  
        else:
            creation_date = domain_name.creation_date
            expiration_date = domain_name.expiration_date
            if (isinstance(creation_date,str) or isinstance(expiration_date,str)):
                try:
                    creation_date = datetime.strptime(creation_date,'%Y-%m-%d')
                    expiration_date = datetime.strptime(expiration_date,"%Y-%m-%d")
                except:
                    Domain_registeration_length=0                
            registration_length = abs((expiration_date - today).days)
            if registration_length / 365 <= 1:
                Domain_registeration_length=1             #phishing
            else:
                Domain_registeration_length=-1             # legitimate

    #10.Favicon
    Favicon = -1
    furl=url_tokens[0]+'//'+url_tokens[1]
    try:
        print('try')
        icons=favicon.get(furl)
        for i in icons:
            if furl not in i.url:
                Favicon = 1

                break
    except:
        print ("Caught")
        Favicon = 0
    print(Favicon)

    #11.Using Non-Standard Port
    port = -1
    P=':[0-9]{1,4}|[1-5][0-9]{4}|6[0-4][0-9]{3}|65[0-4][0-9]{2}|655[0-2][0-9]|6553[0-5]'
    PORT =re.findall(P,url)
    predefined=['21',   #FTP
                '22',   #SSH
                '23',	#Telnet
                '443',	#HTTPS
                '445',	#SMB
                '1433',	#MSSQL
                '1521', #ORACLE
                '3306', #MySQL
                '3389'] #Remote Desktop
    PORT = set(PORT).intersection(predefined) 
    if(len(PORT) != 0):
        port = 1
    print('favicon')

    #12.The Existence of HTTPs Token in the Domain Part of the URL
    mat=re.search('https://|http://',url)
    try:
        if mat.start(0)==0 and mat.start(0) is not None:
            url=url[mat.end(0):]
            mat=re.search('http|https',url)
            if mat:
                HTTPS_token=1      #phishing      
            else:
                HTTPS_token=-1  #legit
    except:
        HTTPS_token=1      #phishing 
    print("HTTPS_token")

    #13.Request URL
    c = 0
    ar = soup.findAll('img')  #For Images
    n = len(ar)
    for line in ar:
        href=line.get('src')
        if re.search(url1,href):
            c+=1


    ar = soup.findAll('video')  #For Videos
    n += len(ar)
    for line in ar:
        href=line.get('href')
        if re.search(url1,href):
            c+=1


    ar = soup.findAll('<audio')  #For Audios
    n += len(ar)
    for line in ar:
        href=line.get('href')
        if re.search(url1,href):
            c+=1

    try:
        p = (n-c)/n * 100
    except:
        p = 22
    if p < 22:
        Request_URL = -1
    elif p>=22 and p<=61:
        Request_URL = 0
    else:
        Request_URL = 1
    print("Request_URL")

    #14.URL of Anchor
    ar=soup.findAll('a')

    c=0
    try:
        for line in ar:
            href=line.get('href')
            if re.search(url,href):
                c+=1
        if re.search('^#$',url):
            c+=1
        if re.search('^#content$',url):
            c+=1
        if re.search('^#skip$',url):
            c+=1
        if re.search('JavaScript ::void(0)',url):
            c+=1
        n = len(ar)
        try:
            p = (n-c)/n * 100
        except:
            p = 31
        if p < 31:
            URL_of_Anchor = -1
        elif p>=31 and p<=67:
            URL_of_Anchor = 0
        else:
            URL_of_Anchor = 1
    except:
        URL_of_Anchor = 0
    print("URL_of_Anchor")

    #15.Server Form Handler (SFH)
    form = soup.findAll('form')
    SFH =0
    try:
        for i in form:
            if re.search(i.get('action'),url_tokens[0]+'//'+url_tokens[1]+'/')  or re.search("/",i.get('action')):
                SFH = -1
            elif re.search(i.get('action'),url_tokens[0]):
                SFH = 0
            else:
                SFH = 1
    except:
        SFH =0
    print("SFH Complete")

    #16.Submitting Information to Email
    Submitting_to_email = -1
    for i in form:
        if re.search(i.get("action"),"mailto"):
            Submitting_to_email = 1

    #17.Website Forwarding
    Redirect=0
    r = requests.get(url1)
    red = len(r.history)
    if red>=4:
        Redirect = 1
    elif red <=1:
        Redirect = -1

    #18.Disabling Right Click
    RightClick = -1
    scripts = soup.findAll('script')
    for i in scripts:
        texts = i.get_text()
        if texts.find("event.preventDefault()"):
            RightClick = 1
            break


    #19.IFrame Redirection
    try:
        if len(soup.findAll('iframe')):
            Iframe = 1
        else:
            Iframe = -1
    except:
        Iframe=0

    #20.Age of Domain
    dns = 0
    try:
        domain_name = whois.whois(urlparse(url).netloc)
    except:
        dns = 1
    if dns == 1:
        age_of_domain=1 #phishing
    else:
        creation_date = domain_name.creation_date
        expiration_date = domain_name.expiration_date
        if (isinstance(creation_date,str) or isinstance(expiration_date,str)):
            try:
                creation_date = datetime.strptime(creation_date,'%Y-%m-%d')
                expiration_date = datetime.strptime(expiration_date,"%Y-%m-%d")
            except:
                age_of_domain=0      #sus
        if ((expiration_date is None) or (creation_date is None)):
            age_of_domain=1        #phishing
        elif ((type(expiration_date) is list) or (type(creation_date) is list)):
            age_of_domain=0     #sus
        else:
            ageofdomain = abs((expiration_date - creation_date).days)
            if ((ageofdomain/30) < 6):
                age_of_domain=1            #phishing
            else:
                age_of_domain=-1            #legit

    #21.Website Traffic
    try:
        x = bs4.BeautifulSoup(urllib.request.urlopen("http://data.alexa.com/data?cli=10&dat=s&url="+url_tokens[1]).read(), "xml").find("REACH")['RANK']
        web_traffic=0
    except:
        web_traffic = 1

    #22.PageRank
    Page_Rank=0
    try:
        if type(domain_name[domain_name])==list:
            link = domain_name[domain_name][0]
        else:
            link = domain_name[domain_name]
        print("Domain"+link)
        pgurl = 'https://openpagerank.com/api/v1.0/getPageRank?domains%5B0%5D='+link
        headers = {'API-OPR':'w44g4gs0c40sgcg84okcow00kscss4cgg400s48s'}
        x = requests.get(pgurl , headers = headers)
        json_string = x.text
        obj = json.loads(json_string)
        rank = obj['response'][0]['page_rank_decimal']
        if type(rank)==int:
            if rank<3:
                Page_Rank = 1
            else:
                Page_Rank = -1
    except:
        Page_Rank=0

    #23.Google Index
    google_index=0
    line=url
    user_agent = 'Mozilla/5.0 (Windows NT 6.1; WOW64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/48.0.2564.116 Safari/537.36'
    headers = { 'User-Agent' : user_agent}
    query={'q':'info:'+line}
    google = "https://www.google.com/search?"+urlencode(query)
    data = requests.get(google,headers=headers)
    data.encoding = 'ISO-8859-1'
    soup = BeautifulSoup(str(data.content), "html.parser")
    try:
        soup.find(id="rso").find("div").find("div").find("h3").find("a")
        google_index=-1
    except AttributeError:
        google_index=1



    #24.Statistical-Reports Based Feature
    user_agent = 'phishtank/arunsura'
    HEADERS = { 'User-Agent' : user_agent}
    PARAMS = {'format':'json','url': url1, 'app_key':'64a9b1e127ea901f37e4af6ec90a178e3c11af86946ad2b48077462da20296a5'}

    try:
        r = requests.request('POST','http://checkurl.phishtank.com/checkurl/index.php', headers=HEADERS, params=PARAMS)
        json_data = json.dumps(xmltodict.parse(r.text))
        res = json.loads(json_data)
        res = res['response']['results']['url0']['valid']
        if res == 'true':
            Statistical_report = 1
        else:
            Statistical_report = -1
    except:
        Statistical_report=0

    print("All labels are set")
    
    # Actual Labels 
    labels=[having_IP,url_len,shortining,having_at,doubleSlash_redirecting,prefix_suffix,having_Sub_Domain,sSLfinal_State,Domain_registeration_length,Favicon,port,HTTPS_token,Request_URL,URL_of_Anchor,SFH,Submitting_to_email,Redirect,RightClick,Iframe,age_of_domain,web_traffic,Page_Rank,google_index,Statistical_report]
    print (labels)
    return labels