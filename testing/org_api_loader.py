from time import time,sleep
import requests
import json
import urllib3
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)


def create_api(api_url,org,username,password,api_name):
    endpoint = '{}/v1/organizations/{}/apis'.format(api_url,org)
    
    data = {
    'name': api_name
    }
    headers = {
        'Accept':'application/json',
        'Content-Type': 'application/json'
        }
    r = requests.post(endpoint,auth=(username,password),verify=False,headers=headers,json=data)
    if r.status_code == 201:
        return True
    return False

def create_api_revison(api_url,org,username,password,api_name):
    endpoint = '{}/v1/organizations/{}/apis/revisions/{}'.format(api_url,org,1)
    files = [
    ('file', open('C:\\Users\\I501950\\Downloads\\api1_rev1_2020_06_23.zip','rb'))
    ]
    headers = {
        'Accept':'application/json',
        'Content-Type': 'multipart/form-data'
        }
    r = requests.post(endpoint,auth=(username,password),verify=False,headers=headers,json={},files=files)
    print(r.status_code)
    print(r.text)
    if r.status_code == 201:
        return True
    return False

def import_api(api_url,org,username,password,api_name):
    endpoint = '{}/v1/organizations/{}/apis?action=import&name={}'.format(api_url,org,api_name)
    files = [
    ('file', open('C:\\Users\\I501950\\Downloads\\api1_rev1_2020_06_23.zip','rb'))
    ]
    headers = {
        'Accept':'application/json',
        'Content-Type': 'multipart/form-data'
        }
    r = requests.post(endpoint,auth=(username,password),verify=False,headers=headers,json={},files=files)
    if r.status_code == 201:
        return True
    return False


def e2e_proxy():
    api_url = 'https://aws-mp-pool-001-msui-nlb-442439183.us-east-1.elb.amazonaws.com'
    org = 'validate'
    username = 'admin@sap.com'
    password = 'Manager123'
    api_name = '{}-{}'.format(org,time())
    if import_api(api_url,org,username,password,api_name):
        print('created proxy --> {}'.format(api_name))

def main():
    for i in range(100):
        e2e_proxy()

if __name__ == "__main__":
    main()