import json
import requests
import logging

logger = logging.getLogger()
logger.setLevel(logging.INFO)

def dynatrace_alert(url, message, hostname, api_token, dynatrace_host):
  print ("dynatrace_alert_method")
  try:
    payload = json.dumps({
    "eventType": "AVAILABILITY_EVENT",
    "attachRules": {
      "entityIds": [dynatrace_host],
      "tagRule": [{"meTypes": ["HOST"], "tags": [{"context": "CONTEXTLESS","key": "azure_vmss"}]}]
     },
    "source": hostname,\
    "description": message,
    "title": hostname
    })
    headers = {
     'Accept': 'application/json',
     'Authorization': 'Api-Token '+str(api_token),
     'Cache-Control': 'no-cache',
     'Connection': 'keep-alive',
     'Content-Type': 'application/json',
     'Postman-Token': '4987b471-2041-466f-9202-5e36f41532a1,708db755-d13f-40e4-9a1d-4012bde718c1',
     'User-Agent': 'PostmanRuntime/7.15.0',
     'accept-encoding': 'accept-encoding',
     'cache-control': 'no-cache',
     'content-length': '485',
     'cookie': 'apmroute=4e6d803274f85d95bbe23f2e363013b8',
     }
    response = requests.post(url, verify=False, headers=headers, data=payload)
    print("Dynatrace event post response {}".format(response.text))
    logger.info ("Dynatrace event  post call response: {} ".format(response.text))
  except Exception as err:
    logger.error (err)
    logger.error("Error while posting to dynatrace")

def get_host_id(host_id_file):
  print ("get_host_id")
  with open(host_id_file) as fl:
    idlist = fl.readlines()
  host_id = 'HOST-' + idlist[0].replace('\n','')
  logger.info("dynatrace host id {}".format(host_id))
  return host_id