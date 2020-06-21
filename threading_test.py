import logging
import threading
from time import time,sleep
import concurrent.futures
import requests
import json
import urllib3
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

def get_mp_org_bindings(baseUrl,username,password,uuid):
    result = requests.get(baseUrl+"/v1/servers/" + uuid + "/bindings" , auth=(username,password),verify=False)
    response = json.loads(result.text)
    return response

def get_org_env_proxy_count(baseUrl,username,password,org):
    result = requests.get(baseUrl+"/v1/o/"+org+"/apis",auth=(username,password),verify=False)
    response = json.loads(result.text)
    return len(response)

def get_mp_proxy_countv1(baseUrl,username,password,uuid):
    mp_org_bindings = get_mp_org_bindings(baseUrl,username,password,uuid)
    proxy_count = 0
    thread_list = []
    with concurrent.futures.ThreadPoolExecutor() as executor:
        futures = [executor.submit(get_org_env_proxy_count, baseUrl,username,password,org_env['organization']) for org_env in mp_org_bindings]
    for f in futures:
        proxy_count += f.result()
    org_count = len(mp_org_bindings)
    print('Processed Number of Orgs ==> {}'.format(org_count))
    print('{} proxies found in {} orgs'.format(proxy_count,org_count))
    return proxy_count


if __name__ == "__main__":
    format = "%(asctime)s: %(message)s"
    
    logging.basicConfig(format=format, level=logging.INFO,datefmt="%H:%M:%S")

    logging.info("Main    : before creating thread")
    #orgs = list(range(1,1000))
    """
    logging.info("Main    : Parallel Threads Started")
    t1 = int(str(time()).split('.')[0])
    run_parallel_multi_thread(orgs)
    t2 = int(str(time()).split('.')[0])
    print('\nTime Taken : {}\n'.format(t2-t1))

    logging.info("Main    : Parallel Threads Ended")
    """
    logging.info("Main    : Serial Threads Started")
    t1 = int(str(time()).split('.')[0])
    baseUrl='https://cluster3eude1devmanagementserver.apim.hana.ondemand.com'
    username='admin@sap.com'
    password='Manager123'
    uuid='e8b276d3-7af2-4b93-b349-d82eab63a039'
    get_mp_proxy_countv1(baseUrl,username,password,uuid)
    #run_serial_multi_thread(orgs)
    t2 = int(str(time()).split('.')[0])
    print('\nTime Taken : {}\n'.format(t2-t1))
    logging.info("Main    : Serial Threads Ended")