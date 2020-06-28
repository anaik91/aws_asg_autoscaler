import json,sys,os
import boto3
from botocore.exceptions import ClientError
import logging
from  time import time
from asg_helpers import *
from asg import create_e2e_asg
import manage_component
import urllib3
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

logger = logging.getLogger()
logger.setLevel(logging.INFO)

def check_asg(asg_uuid_map,ProxyCountThreshold):
    createAsgFlag = True
    AsgProxyCount = None
    for each_asg in asg_uuid_map:
        if asg_uuid_map[each_asg]['proxy_count'] >= ProxyCountThreshold:
            createAsgFlag = createAsgFlag and True
            if AsgProxyCount is not None:
                if AsgProxyCount < asg_uuid_map[each_asg]['proxy_count']:
                    pass
                else:
                    activeAsg = each_asg
                    AsgProxyCount = asg_uuid_map[each_asg]['proxy_count']
            else:
                AsgProxyCount = asg_uuid_map[each_asg]['proxy_count']
                activeAsg = each_asg
        else:
            createAsgFlag = createAsgFlag and False
            if AsgProxyCount is not None:
                if AsgProxyCount < asg_uuid_map[each_asg]['proxy_count']:
                    pass
                else:
                    activeAsg = each_asg
                    AsgProxyCount = asg_uuid_map[each_asg]['proxy_count']
            else:
                AsgProxyCount = asg_uuid_map[each_asg]['proxy_count']
                activeAsg = each_asg
        print(AsgProxyCount)
        print(activeAsg)
    return createAsgFlag,activeAsg

def lambda_handler(event, context):
    Project = os.getenv("Project")
    SubType = os.getenv("SubType")
    ProxyCountThreshold = os.getenv("ProxyCountThreshold")
    query = {'Project':Project,'SubType':SubType}
    asg_status = get_asgs_by_tag(query)
    asg_uuid_map = {}
    if asg_status['Status']:
        asg_list = asg_status['asg_list']
        for each_asg in asg_list:
            ip_list = []
            instanceList = get_asg_instance_list(each_asg)
            if instanceList['Status']:
                instance_list = instanceList['instance_list']
                uuid_list = []
                for each_instance in instance_list:
                    ip_status = get_instance_ip(each_instance)
                    if ip_status['Status']:
                        if ip_status['ip_address'] is not None:
                            ip_address = ip_status['ip_address']
                            ip_list.append(ip_address)
                            uuid = manage_component.get_uuid('message-processor','mp',ip_address)
                            if uuid is not None:
                                uuid_list.append(uuid)
                    else:
                        return {
                        'statusCode': 500,
                        'body': 'Unable to Fetch IP of {}'.format(each_instance)
                    }
                asg_uuid_map[each_asg] = {'instance_list':instance_list,'ip_list':ip_list,'uuid_list':uuid_list}
            else:
                print('Unable to get Instance list for AGS - {}'.format(each_asg))
        
        for each_asg_info in asg_uuid_map:
            if len(asg_uuid_map[each_asg_info]['uuid_list']) > 0:
                proxy_count = manage_component.proxy_count_from_mp_uuid(asg_uuid_map[each_asg_info]['uuid_list'][0])
                asg_uuid_map[each_asg_info]['proxy_count'] = proxy_count
            else:
                asg_uuid_map[each_asg_info]['proxy_count'] = 0
        if ProxyCountThreshold is None:
            ProxyCountThreshold = 2000
        createAsgFlag,activeAsg = check_asg(asg_uuid_map,int(ProxyCountThreshold))
        print('createAsgFlag ==> {}'.format(createAsgFlag))
        print('Active UUIDs ==> {}'.format(asg_uuid_map[activeAsg]['uuid_list']))
        if createAsgFlag:
            new_asg_name = create_e2e_asg(asg_uuid_map,Project)
            return {
                'statusCode': 201,
                'body': 'New Autoscaling Group Created {}'.format(new_asg_name)
            }
        else:
            if manage_component.update_dt(asg_uuid_map[activeAsg]['uuid_list']):
                print('Updated Design Time')
                return {
                    'statusCode': 200,
                    'body': 'No Change to the MP Pools',
                    'asg_list' :asg_uuid_map
                }
            else:
                print('Failure in Updating Design Time')
                return {
                        'statusCode': 500,
                        'body': 'Issue Updating DT',
                        'asg_list' :asg_uuid_map
                    }
    else:
        return {
                'statusCode': 404,
                'body': 'No ASGS matching tags : {}'.format(query)
            }