
import pandas as pd
from urllib.parse import urlparse
from tld import get_tld
import re
from sklearn.tree import DecisionTreeClassifier
from sklearn.model_selection import train_test_split
from sklearn.metrics import accuracy_score

url_list=pd.read_csv('malicious_phish.csv')


url_list.loc[651191,'url']='http://verzeomarch64.eu5.org/fb/facebook.html'
url_list.loc[651191,'type']='benign'
print(url_list.head())
print(url_list.tail())

def first_d(urlpath):
    try:
        return len(urlpath.split('/')[1])
    except:
        return 0
def tld_length(tld):
    try:
        return len(tld)
    except:
        return -1
def digit_count(url):
    digits = 0
    for i in url:
        if i.isnumeric():
            digits = digits + 1
    return digits
def letter_count(url):
    letters = 0
    for i in url:
        if i.isalpha():
            letters = letters + 1
    return letters
def having_ip_address(url):
    match = re.search(
        '(([01]?\\d\\d?|2[0-4]\\d|25[0-5])\\.([01]?\\d\\d?|2[0-4]\\d|25[0-5])\\.([01]?\\d\\d?|2[0-4]\\d|25[0-5])\\.'
        '([01]?\\d\\d?|2[0-4]\\d|25[0-5])\\/)|'  # IPv4
        '((0x[0-9a-fA-F]{1,2})\\.(0x[0-9a-fA-F]{1,2})\\.(0x[0-9a-fA-F]{1,2})\\.(0x[0-9a-fA-F]{1,2})\\/)' # IPv4 in hexadecimal
        '(?:[a-fA-F0-9]{1,4}:){7}[a-fA-F0-9]{1,4}', url)  # Ipv6
    if match:   
        return -1
    else:
        return 1
def shortening_service(url):
    match = re.search('bit\.ly|goo\.gl|shorte\.st|go2l\.ink|x\.co|ow\.ly|t\.co|tinyurl|tr\.im|is\.gd|cli\.gs|'
                      'yfrog\.com|migre\.me|ff\.im|tiny\.cc|url4\.eu|twit\.ac|su\.pr|twurl\.nl|snipurl\.com|'
                      'short\.to|BudURL\.com|ping\.fm|post\.ly|Just\.as|bkite\.com|snipr\.com|fic\.kr|loopt\.us|'
                      'doiop\.com|short\.ie|kl\.am|wp\.me|rubyurl\.com|om\.ly|to\.ly|bit\.do|t\.co|lnkd\.in|'
                      'db\.tt|qr\.ae|adf\.ly|goo\.gl|bitly\.com|cur\.lv|tinyurl\.com|ow\.ly|bit\.ly|ity\.im|'
                      'q\.gs|is\.gd|po\.st|bc\.vc|twitthis\.com|u\.to|j\.mp|buzurl\.com|cutt\.us|u\.bb|yourls\.org|'
                      'x\.co|prettylinkpro\.com|scrnch\.me|filoops\.info|vzturl\.com|qr\.net|1url\.com|tweez\.me|v\.gd|'
                      'tr\.im|link\.zip\.net',
                      url)
    if match:
        return -1
    else:
        return 1
def copied_html(url):
    if("Facebook.html" in url):
        return 1
    elif("Instagram.html" in url):
        return 1
    elif("Twitter.html" in url):
        return 1
    elif("Skype.html" in url):
        return 1
    else:
        return 0

url_list['length']=url_list['url'].apply(lambda i: len(str(i)))
url_list['path_length'] = url_list['url'].apply(lambda i: len(urlparse(i).path))
url_list['firstd_length'] = url_list['url'].apply(lambda i: first_d(urlparse(i).path))
url_list['.ext_length'] = url_list['url'].apply(lambda i: tld_length(get_tld(i,fail_silently=True)))
url_list['count-'] = url_list['url'].apply(lambda i: i.count('-'))
url_list['count@'] = url_list['url'].apply(lambda i: i.count('@'))
url_list['count?'] = url_list['url'].apply(lambda i: i.count('?'))
url_list['count%'] = url_list['url'].apply(lambda i: i.count('%'))
url_list['count.'] = url_list['url'].apply(lambda i: i.count('.'))
url_list['count='] = url_list['url'].apply(lambda i: i.count('='))
url_list['count/'] = url_list['url'].apply(lambda i: (urlparse(i).path).count('/'))
url_list['count-http'] = url_list['url'].apply(lambda i : i.count('http'))
url_list['count-https'] = url_list['url'].apply(lambda i : i.count('https'))
url_list['count-www'] = url_list['url'].apply(lambda i: i.count('www'))
url_list['count-digits']= url_list['url'].apply(lambda i: digit_count(i))
url_list['count-letters']= url_list['url'].apply(lambda i: letter_count(i))
url_list['use_of_ip'] = url_list['url'].apply(lambda i: having_ip_address(i))
url_list['short_url'] = url_list['url'].apply(lambda i: shortening_service(i))
url_list['fake_html'] = url_list['url'].apply(lambda i: copied_html(i))

x = url_list[['length','path_length', 'firstd_length', '.ext_length', 'count-', 'count@', 'count?','count%', 'count.', 'count=', 'count/','count-http','count-https', 'count-www', 'count-digits','count-letters', 'use_of_ip','short_url','fake_html']]

y = url_list['type']

x_train, x_test, y_train, y_test = train_test_split(x, y, train_size=0.8, random_state=41)


dt_model = DecisionTreeClassifier()
dt_model.fit(x_train,y_train)
p=dt_model.predict([x_test.iloc[-1]])

dt_predictions = dt_model.predict(x_test)
print(accuracy_score(y_test,dt_predictions))
print(p)




