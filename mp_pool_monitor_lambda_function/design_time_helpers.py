import sys
import requests
from requests.auth import HTTPBasicAuth
import json
from time import time
import urllib3
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)


def get_oauth_token(oath_endpoint,username,password):
    r = requests.get(oath_endpoint,auth=(username,password),verify=False)
    if r.status_code == 200:
        data = json.loads(r.text)
        return data['access_token']

def get_mp_XProperty(endpoint,access_token):
    headers = {
        'Accept':'application/json',
        'Content-Type': 'application/json',
        'Authorization': 'Bearer {}'.format(access_token)
        }
    r = requests.get(endpoint,verify=False,headers=headers)
    if r.status_code == 200:
        data = json.loads(r.text)
        for each_property in data['d']['results']:
            if each_property['name'] == 'apiportal.onboarding.apiruntime_prod.mps':
                print('Existing MP UUID List ====> {}'.format(each_property['value']))
                return True
        return False
    else:
        return False

def post_mp_XProperty(endpoint,access_token,data):
    headers = {
        'Accept':'application/json',
        'Content-Type': 'application/json',
        'Authorization': 'Bearer {}'.format(access_token)
        }
    r = requests.post(endpoint,verify=False,headers=headers,json=data)
    if r.status_code == 201:
        data = json.loads(r.text)
        print(data['d']['__metadata'])
        return True
    return False

def put_mp_XProperty(endpoint,access_token,data):
    headers = {
        'Accept':'application/json',
        'Content-Type': 'application/json',
        'Authorization': 'Bearer {}'.format(access_token)
        }
    r = requests.put(endpoint,verify=False,headers=headers,json=data)
    print(r.text)
    if r.status_code == 204:
        return True
    else:
        return False

def update_DT_mp_uuid(uuid_list,oauth_host,dt_host,username,password):
    oath_endpoint = 'https://{}/oauth/token?grant_type=client_credentials'.format(oauth_host)
    dt_endpoint = 'https://{}/apiportal/operations/1.0/Configuration.svc/XPropertys'.format(dt_host)
    XProperty = '(\'apiportal.onboarding.apiruntime_prod.mps\')'
    access_token = get_oauth_token(oath_endpoint,username,password)
    data = {
        'name': 'apiportal.onboarding.apiruntime_prod.mps',
        'value': ",".join(uuid_list)
        }
    if get_mp_XProperty(dt_endpoint,access_token):
        if put_mp_XProperty(dt_endpoint+XProperty,access_token,data):
            print('Design Time Update of Xproperty Suucess')
            return True
        else:
            print('Design Time Update of Xproperty Failure')
            return False
    else:
        if post_mp_XProperty(dt_endpoint,access_token,data):
            print('Design Time Creation of Xproperty Suucess')
            return True
        else:
            print('Design Time Creation of Xproperty Failure')
            return False