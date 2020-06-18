import json,sys
import boto3
from botocore.exceptions import ClientError
#import remove_component
import logging
from  time import time

logger = logging.getLogger()
logger.setLevel(logging.INFO)


def toggle_asg_lifecycle(LifecycleHookName,AutoScalingGroupName,EC2InstanceId,LifecycleActionToken):
    try:
        client = boto3.client('autoscaling')
        response = client.complete_lifecycle_action(
            LifecycleHookName=LifecycleHookName,
            AutoScalingGroupName=AutoScalingGroupName,
            LifecycleActionToken=LifecycleActionToken,
            LifecycleActionResult='CONTINUE',
            InstanceId=EC2InstanceId
        )
    except ClientError as e:
        print("Unexpected error: {}".format(e))
        return False
    if response['ResponseMetadata']['HTTPStatusCode'] == 200:
        return True
    else:
        return False

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

def create_asg_tag(AutoScalingGroupName,Key,value,PropagateAtLaunch):
    try:
        client = boto3.client('autoscaling')
        response = client.create_or_update_tags(Tags=[{
            'ResourceId': AutoScalingGroupName,
            'ResourceType': 'auto-scaling-group',
            'Key': Key,
            'Value': value,
            'PropagateAtLaunch': PropagateAtLaunch}])
    except ClientError as e:
        print("Unexpected error: {}".format(e))
        return False
    if response['ResponseMetadata']['HTTPStatusCode'] == 200:
        return True
    else:
        return False


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


def parse_sns_message(message):
    try:
        sns_message = message['Records'][0]['Sns']['Message']
        sns_message = json.loads(sns_message)
        event_type = sns_message['LifecycleTransition']
    except KeyError:
        data = {
            'Status': False
        }
        return data
    if event_type == 'autoscaling:EC2_INSTANCE_TERMINATING':
        print('Scaled In')
        data = {
            'Status': 'EC2_INSTANCE_TERMINATING',
            'LifecycleHookName': sns_message['LifecycleHookName'],
            'AutoScalingGroupName':sns_message['AutoScalingGroupName'],
            'EC2InstanceId':sns_message['EC2InstanceId'],
            'LifecycleActionToken':sns_message['LifecycleActionToken'],
            'ComponentData' : json.loads(sns_message['NotificationMetadata'])
        }
        return data
    elif event_type == 'autoscaling:EC2_INSTANCE_LAUNCHING':
        print('Scaled Out')
        data = {
            'Status': 'EC2_INSTANCE_LAUNCHING',
            'LifecycleHookName': sns_message['LifecycleHookName'],
            'AutoScalingGroupName':sns_message['AutoScalingGroupName'],
            'EC2InstanceId':sns_message['EC2InstanceId'],
            'LifecycleActionToken':sns_message['LifecycleActionToken']
            #'ComponentData' : json.loads(sns_message['NotificationMetadata']
            
        }
        return data
    else:
        print('Unknown Event')
        data = {
            'Status': 'Unknown'
        }
        return data

def update_dead_mp_list(table,pool,dead_mp,op):
    response = table.get_item(Key={'mp_pool': pool})
    dead_mp_list = response['Item']['dead_mp_list']
    if op == 'append':
        dead_mp_list.append(dead_mp)
    elif op == 'remove':
        dead_mp_list.remove(dead_mp)
    response = table.update_item(
        Key={
            'mp_pool': pool
        },
        UpdateExpression="set dead_mp_list=:d",
        ExpressionAttributeValues={
            ':d': dead_mp_list
        },
        ReturnValues="UPDATED_NEW"
    )
    return {
            'statusCode': 200,
            'body': 'Done'
            }

def get_dead_mp(table,pool):
    response = table.get_item(Key={'mp_pool': pool})
    try:
        dead_mp = response['Item']['dead_mp_list'][0]
        update_dead_mp_list(table,pool,dead_mp,'remove')
        return dead_mp
    except KeyError:
        return {
            'statusCode': 404,
            'body': json.dumps({'message': 'Invalid Pool - {}'.format(pool)})
        }
    except IndexError:
        return None

def lambda_handler(event, context):
    print(event)
    asg_data = parse_sns_message(event)
    if asg_data['Status'] == 'EC2_INSTANCE_TERMINATING':
        print('Trying to Fetch UUID and Update the DB')
        compType = asg_data['ComponentData']['compType']
        component_name = asg_data['ComponentData']['component_name']
        instance_data = get_instance_ip(asg_data['EC2InstanceId'])
        if instance_data['Status']:
            ip_address = instance_data['ip_address']
        else:
            return {
                'statusCode': 500,
                'body': 'Unable to Fetch IP of {}'.format(asg_data['EC2InstanceId'])
            }
        print('Removing {} in Progress ...'.format(compType))
        #remove_status = remove_component.execute(compType,component_name,ip_address)
        #uuid = remove_component.get_uuid(compType,component_name,ip_address)
        #print('Removing {} Finished'.format(compType))
        uuid = 'uuid_' + str(time()).split('.')[0]
        print('uuid ==========> {}'.format(uuid))
        pool_status = get_asg_tag(asg_data['AutoScalingGroupName'],'pool')
        if pool_status['Status']:
            pool = pool_status['value']
        else:
            print('Unable to get a tag pool in ASG - {}'.format(asg_data['AutoScalingGroupName']))
            if toggle_asg_lifecycle(asg_data['LifecycleHookName'],asg_data['AutoScalingGroupName'],asg_data['EC2InstanceId'],asg_data['LifecycleActionToken']):
                return {
                    'statusCode': 200,
                    'body': 'Removed Router/MP'
                }
        ############# Dynamo DB Update #############
        #dynamodb = boto3.resource('dynamodb')
        #table = dynamodb.Table('mp_pool_inventory')
        #update_dead_mp_list(table,pool,uuid,'append')
        ############# Dynamo DB Update #############

        ############# ASG Tag Update #############
        dead_mp_list = get_asg_tag(asg_data['AutoScalingGroupName'],'dead_mp_list')
        print('dead_mp_list ======> {}'.format(dead_mp_list))
        if dead_mp_list['Status']:
            if len(dead_mp_list['value']) > 0:
                dead_mp_list = dead_mp_list['value'].split(',')
                dead_mp_list.append(uuid)
                dead_mp_list = ','.join(dead_mp_list)
                create_asg_tag(asg_data['AutoScalingGroupName'],'dead_mp_list',dead_mp_list,False)
            else:
                create_asg_tag(asg_data['AutoScalingGroupName'],'dead_mp_list',uuid,False)
        else:
            return {
                'statusCode': 500
            }
        ############# ASG Tag Update #############
        print('Proceeding with Instance - {} Termination'.format(asg_data['EC2InstanceId']))
        if toggle_asg_lifecycle(asg_data['LifecycleHookName'],asg_data['AutoScalingGroupName'],asg_data['EC2InstanceId'],asg_data['LifecycleActionToken']):
            return {
                'statusCode': 200,
                'body': 'Removed Router/MP'
            }
    elif asg_data['Status'] == 'EC2_INSTANCE_LAUNCHING':
        print('Trying to Fetch Dead MP UUID from DB')
        
        pool_status = get_asg_tag(asg_data['AutoScalingGroupName'],'pool')
        if pool_status['Status']:
            pool = pool_status['value']
        else:
            return {
                'statusCode': 500,
                'body': 'Unable to Fetch IP of {}'.format(asg_data['EC2InstanceId'])
            }
        ############# Dynamo DB Fetch #############
        #dynamodb = boto3.resource('dynamodb')
        #table = dynamodb.Table('mp_pool_inventory')
        #uuid = get_dead_mp(table,pool)
        ############# Dynamo DB Fetch #############

        print('Checking if uuid tag already exists on Instance {}'.format(asg_data['EC2InstanceId']))
        if get_instance_tag(asg_data['EC2InstanceId'],'uuid') is not None:
            print('Tag uuid already exists on Instance {}'.format(asg_data['EC2InstanceId']))
            return {
                'statusCode': 200,
                'body': 'Tagged Instance'
            }
        print('Tag uuid Doesnt exists on Instance {}'.format(asg_data['EC2InstanceId']))
        ############# ASG Tag Fetch #############
        dead_mp_list = get_asg_tag(asg_data['AutoScalingGroupName'],'dead_mp_list')
        print('dead_mp_list ======> {}'.format(dead_mp_list))
        if dead_mp_list['Status']:
            if len(dead_mp_list['value']) > 0:
                dead_mp_list = dead_mp_list['value'].split(',')
                uuid = dead_mp_list[0]
                dead_mp_list.remove(uuid)
                dead_mp_list = ','.join(dead_mp_list)
                create_asg_tag(asg_data['AutoScalingGroupName'],'dead_mp_list',dead_mp_list,False)
            else:
                uuid = None
        else:
            return {
                'statusCode': 500
            }
        ############# ASG Tag Fetch #############

        if uuid is not None:
            print('Proceeding with tagging on Instance - {}'.format(asg_data['EC2InstanceId']))
            tag_instance(asg_data['EC2InstanceId'],'uuid',uuid)
        else:
            print('Proceeding with Default tagging on Instance - {}'.format(asg_data['EC2InstanceId']))
            tag_instance(asg_data['EC2InstanceId'],'uuid','Default')
        if toggle_asg_lifecycle(asg_data['LifecycleHookName'],asg_data['AutoScalingGroupName'],asg_data['EC2InstanceId'],asg_data['LifecycleActionToken']):
            return {
                'statusCode': 200,
                'body': 'Tagged Instance'
            }

    else:
        return {
                'statusCode': 200,
                'body': 'No Action'
            }