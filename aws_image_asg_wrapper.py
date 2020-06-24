import boto3
from botocore.exceptions import ClientError
import os,shutil
from os.path import basename
import requests
import apigee_util_methods
import json

def get_self_instanceID():
    r = requests.get('http://169.254.169.254/latest/meta-data/instance-id')
    return r.text

def get_self_instanceIP():
    r = requests.get('http://169.254.169.254/latest/meta-data/local-ipv4')
    return r.text

def get_self_instanceRegion():
    r = requests.get('http://169.254.169.254/latest/dynamic/instance-identity/document')
    return json.loads(r.text)['region']

def get_instance_tag(EC2InstanceId,key,region):
    ec2 = boto3.resource('ec2',region_name=region)
    ec2instance = ec2.Instance(EC2InstanceId)
    value = None
    for tags in ec2instance.tags:
        if tags["Key"] == key:
            value = tags["Value"]
    return value

def get_instance_ip(EC2InstanceId,region):
    try:
        client = boto3.client('ec2',region_name=region)
        response = client.describe_instances(InstanceIds=[EC2InstanceId])
    except ClientError as e:
        print("Unexpected error: {}".format(e))
        return {'Status' : False }
    if response['ResponseMetadata']['HTTPStatusCode'] == 200:
        return {'Status' : True, 'ip_address': response['Reservations'][0]['Instances'][0]['PrivateIpAddress']}
    else:
        return {'Status' : False }


def get_asg_instance_list(asg,region):
    #taglist = [{'Name':'sample'}]
    instance_list = []
    try:
        client = boto3.client('autoscaling',region_name=region)
        response = client.describe_auto_scaling_groups(AutoScalingGroupNames=[asg])            
    except ClientError as e:
        print("Unexpected error: {}".format(e))
        return {'Status': False}
    if response['ResponseMetadata']['HTTPStatusCode'] == 200:
        for i in response['AutoScalingGroups']:
            for j in i['Instances']:
                instance_list.append(j['InstanceId'])
        return {'Status': True,'instance_list':instance_list}
    else:
        return {'Status': False}

def get_mp_org_list(baseUrl,username,password,pod,compType,region):
    instanceID = get_self_instanceID()
    instanceIP = get_self_instanceIP()
    region = get_self_instanceRegion()
    instanceASG = get_instance_tag(instanceID,'aws:autoscaling:groupName',region)
    asgInstances = get_asg_instance_list(instanceASG,region)
    instance_list = asgInstances['instance_list']
    ip_list = []
    for each_instance in instance_list:
        ip_status = get_instance_ip(each_instance,region)
        if ip_status['Status']:
            ip_address = ip_status['ip_address']
            ip_list.append(ip_address)
    ip_list.remove(instanceIP)
    uuid = apigee_util_methods.get_uuid_from_ip(baseUrl,username,password,pod,compType,region,ip_list[0])
    mp_org_bindings = apigee_util_methods.get_mp_org_bindings(baseUrl,username,password,uuid)
    org_list = [org_env['organization'] for org_env in mp_org_bindings ]
    return org_list