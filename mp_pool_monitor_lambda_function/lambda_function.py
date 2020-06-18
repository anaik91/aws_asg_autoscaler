import json,sys,os
import boto3
from botocore.exceptions import ClientError
import logging
from  time import time
from asg_helpers import *
import manage_component 

logger = logging.getLogger()
logger.setLevel(logging.INFO)


def lambda_handler(event, context):
    Project = os.getenv("Project")
    SubType = os.getenv("SubType")
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
        return {
                'statusCode': 200,
                'body': asg_uuid_map
            }
        
    else:
        return {
                'statusCode': 404,
                'body': 'No ASGS matching tags : {}'.format(query)
            }