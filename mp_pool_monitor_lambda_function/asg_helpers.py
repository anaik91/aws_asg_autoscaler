import json,sys
import boto3
from botocore.exceptions import ClientError

def get_asg_lifecycle_hook(AutoScalingGroupName):
    #subnetList = ','.join(subnetList)
    try:
        client = boto3.client('autoscaling')
        response = client.describe_lifecycle_hooks(
            AutoScalingGroupName=AutoScalingGroupName
        )          
    except ClientError as e:
        print("Unexpected error: {}".format(e))
        return {'Status': False}
    if response['ResponseMetadata']['HTTPStatusCode'] == 200:
        return {'Status': True,'LifecycleHooks':response['LifecycleHooks']}
    else:
        return {'Status': False}


def get_asgs_by_tag(tags):
    #taglist = [{'Name':'sample'}]
    asg_list = []
    try:
        client = boto3.client('autoscaling')
        paginator = client.get_paginator('describe_auto_scaling_groups')
        page_iterator = paginator.paginate(
            PaginationConfig={'PageSize': 100}
        )
        filter = 'AutoScalingGroups[]'
        for tag in tags:
            filter = ('{} | [?contains(Tags[?Key==`{}`].Value, `{}`)]'.format(filter, tag, tags[tag]))
        filtered_asgs = page_iterator.search(filter)
        for asg in filtered_asgs:
            asg_list.append(asg['AutoScalingGroupName'])
        return {'Status': True,'asg_list':asg_list}
    except ClientError as e:
        print("Unexpected error: {}".format(e))
        return {'Status': False}
    else:
        return {'Status': False}

def get_asg_instance_list(asg):
    #taglist = [{'Name':'sample'}]
    instance_list = []
    try:
        client = boto3.client('autoscaling')
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

def get_asg_info(asg):
    #taglist = [{'Name':'sample'}]
    instance_list = []
    try:
        client = boto3.client('autoscaling')
        response = client.describe_auto_scaling_groups(AutoScalingGroupNames=[asg])            
    except ClientError as e:
        print("Unexpected error: {}".format(e))
        return {'Status': False}
    if response['ResponseMetadata']['HTTPStatusCode'] == 200:
        return {'Status': True,'AutoScalingGroups':response['AutoScalingGroups'][0]}
    else:
        return {'Status': False}

def get_asg_tag(AutoScalingGroupName,Key):
    try:
        client = boto3.client('autoscaling')
        response = client.describe_tags(Filters=[{'Name': 'auto-scaling-group','Values': [AutoScalingGroupName]}])
    except ClientError as e:
        print("Unexpected error: {}".format(e))
        return {'Status': False}
    if response['ResponseMetadata']['HTTPStatusCode'] == 200:
        for i in response['Tags']:
            if i['Key'] == Key:
                return {'Status': True,'value': i['Value']} 
        return {'Status': False}
    else:
        return {'Status': False}


def get_instance_tag(EC2InstanceId,key):
    ec2 = boto3.resource('ec2')
    ec2instance = ec2.Instance(EC2InstanceId)
    value = None
    for tags in ec2instance.tags:
        if tags["Key"] == key:
            value = tags["Value"]
    return value

def get_instance_ip(EC2InstanceId):
    try:
        client = boto3.client('ec2')
        response = client.describe_instances(InstanceIds=[EC2InstanceId])
    except ClientError as e:
        print("Unexpected error: {}".format(e))
        return {'Status' : False }
    if response['ResponseMetadata']['HTTPStatusCode'] == 200:
        return {'Status' : True, 'ip_address': response['Reservations'][0]['Instances'][0]['PrivateIpAddress']}
    else:
        return {'Status' : False }

def tag_instance(EC2InstanceId,TagKey,TagValue):
    try:
        client = boto3.client('ec2')
        response = client.create_tags(Resources=[EC2InstanceId], Tags=[{'Key':TagKey, 'Value':TagValue}])
    except ClientError as e:
        print("Unexpected error: {}".format(e))
        return {'Status' : False }
    if response['ResponseMetadata']['HTTPStatusCode'] == 200:
        return True
    else:
        return False