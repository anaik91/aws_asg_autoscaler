import json,sys
import boto3
from botocore.exceptions import ClientError
import yaml
import base64
import zipfile
import os
from os.path import basename
import subprocess

def filter_tags(tags,Key):
    for tag in tags:
        if tag['Key'] == Key:
            return tag['Value']
    return None

def create_policy_version(PolicyArn,PolicyDocument):
    try:
        client = boto3.client('iam')
        response = client.create_policy_version(
            PolicyArn=PolicyArn,
            PolicyDocument=PolicyDocument,
            SetAsDefault=True
        )
        print(response)          
    except ClientError as e:
        print("Unexpected error: {}".format(e))
        return False
    if response['ResponseMetadata']['HTTPStatusCode'] == 200:
        return True
    else:
        return False

def get_policy_document(PolicyArn,VersionId):
    try:
        client = boto3.client('iam')
        response = client.get_policy_version(
            PolicyArn=PolicyArn,
            VersionId=VersionId
        )          
    except ClientError as e:
        print("Unexpected error: {}".format(e))
        return {'Status': False}
    if response['ResponseMetadata']['HTTPStatusCode'] == 200:
        return {'Status': True ,'Document': response['PolicyVersion']['Document']}
    else:
        return {'Status': False}

def get_policy(PolicyArn):
    try:
        client = boto3.client('iam')
        response = client.get_policy(
            PolicyArn=PolicyArn
        )          
    except ClientError as e:
        print("Unexpected error: {}".format(e))
        return {'Status': False}
    if response['ResponseMetadata']['HTTPStatusCode'] == 200:
        return {'Status': True ,'Policy': response['Policy']}
    else:
        return {'Status': False}


def list_attached_role_policies(RoleName):
    try:
        client = boto3.client('iam')
        response = client.list_attached_role_policies(
            RoleName=RoleName
        )          
    except ClientError as e:
        print("Unexpected error: {}".format(e))
        return {'Status': False}
    if response['ResponseMetadata']['HTTPStatusCode'] == 200:
        return {'Status': True ,'AttachedPolicies': response['AttachedPolicies']}
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

def pip_dependecies(python_bin,target,requirements):
    print('\nResolving Lambda Dependencies..')
    try:
        subprocess.check_output([python_bin,'-m','pip','install','--target',target,'-r', requirements ])
    except FileNotFoundError:
        print('{} not found . Try using python3 or python3.<version>'.format(python_bin))
        sys.exit(1)
    print('Resolved Lambda Dependencies...\n')
    
def read_file_b64(filename):
    with open(filename, "rb") as f:
        encodedZip = base64.b64encode(f.read())
    return encodedZip.decode('utf-8')

def build_zip(filename, target_dir): 
    print('Zipping Contents of folder ==>{}'.format(target_dir))           
    zipobj = zipfile.ZipFile(filename, 'w', zipfile.ZIP_DEFLATED)
    rootlen = len(target_dir) + 1
    for base, dirs, files in os.walk(target_dir):
        for file in files:
            fn = os.path.join(base, file)
            zipobj.write(fn, fn[rootlen:])
    print('Finished Zipping Contents of folder ==>{}'.format(target_dir)) 

def create_cloudwatch_event_rule(EventName,ScheduleExpression):
    try:
        client = boto3.client('events')
        response = client.put_rule(
            Name=EventName,
            ScheduleExpression=ScheduleExpression,
            State='ENABLED',
            Description=EventName,
            #RoleArn=RoleArn
            )           
    except ClientError as e:
        print("Unexpected error: {}".format(e))
        return {'Status': False}
    if response['ResponseMetadata']['HTTPStatusCode'] == 200:
        return {'Status': True,'RuleArn':response['RuleArn']}
    else:
        return {'Status': False}

def create_cloudwatch_event_target(RuleName,Id,Arn):
    try:
        client = boto3.client('events')
        response = client.put_targets(
            Rule=RuleName,
            Targets=[{
                    'Id': Id,
                    'Arn': Arn}])  
    except ClientError as e:
        print("Unexpected error: {}".format(e))
        return False
    if response['ResponseMetadata']['HTTPStatusCode'] == 200:
        return True
    else:
        return False

def add_lambda_invoke_permission(FunctionName,SourceArn):
    try:
        client = boto3.client('lambda')
        response = client.add_permission(
            FunctionName=FunctionName,
            StatementId='AllowExecutionFromCloudWatch',
            Action='lambda:InvokeFunction',
            Principal='events.amazonaws.com',
            SourceArn=SourceArn
            )            
    except ClientError as e:
        if e.response['ResponseMetadata']['HTTPStatusCode'] == 409:
            print('Lmabda Invoke Permission Already Exists..')
            return True
        else:
            print("Unexpected error: {}".format(e))
            return False
    if response['ResponseMetadata']['HTTPStatusCode'] == 200:
        return True
    else:
        return False

def update_lambda_function(FunctionName,ZipFile):
    try:
        client = boto3.client('lambda')
        response = client.update_function_code(
            FunctionName=FunctionName,
            ZipFile=open(ZipFile,'rb').read()
            )            
    except ClientError as e:
        print("Unexpected error: {}".format(e))
        return False
    if response['ResponseMetadata']['HTTPStatusCode'] == 200:
        return True
    else:
        return False

def create_lambda_function(FunctionName,Role,Handler,ZipFile,Timeout,Environment):
    try:
        client = boto3.client('lambda')
        response = client.create_function(
            FunctionName=FunctionName,
            Runtime='python3.6',
            Role=Role,
            Handler=Handler,
            Code={
                'ZipFile': open(ZipFile,'rb').read()
            },
            Timeout=Timeout,
            Environment={
                'Variables': Environment
            })      
    except ClientError as e:
        print("Unexpected error: {}".format(e))
        return {'Status': False}
    if response['ResponseMetadata']['HTTPStatusCode'] == 201:
        return {'Status': True,'FunctionArn':response['FunctionArn']}
    else:
        return {'Status': False}

def get_lambda_function(FunctionName):
    try:
        client = boto3.client('lambda')
        response = client.get_function(
            FunctionName=FunctionName
            )         
    except ClientError as e:
        #print("Unexpected error: {}".format(e))
        return {'Status': False}
    if response['ResponseMetadata']['HTTPStatusCode'] == 200:
        return {'Status': True,'Configuration':response['Configuration']}
    else:
        return {'Status': False}

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

def update_asg_lifecycle_hook(LifecycleHookName,AutoScalingGroupName,LifecycleTransition,RoleARN,NotificationTargetARN,NotificationMetadata):
    #subnetList = ','.join(subnetList)
    try:
        client = boto3.client('autoscaling')
        response = client.put_lifecycle_hook(
            LifecycleHookName=LifecycleHookName,
            AutoScalingGroupName=AutoScalingGroupName,
            LifecycleTransition=LifecycleTransition,
            RoleARN=RoleARN,
            NotificationTargetARN=NotificationTargetARN,
            NotificationMetadata=NotificationMetadata,
            HeartbeatTimeout=2000,
            DefaultResult='CONTINUE'
        )          
    except ClientError as e:
        print("Unexpected error: {}".format(e))
        return False
    if response['ResponseMetadata']['HTTPStatusCode'] == 200:
        return True
    else:
        return False


def get_asg_details(AutoScalingGroupName):
    instance_list = []
    try:
        client = boto3.client('autoscaling')
        response = client.describe_auto_scaling_groups(AutoScalingGroupNames=[AutoScalingGroupName])            
    except ClientError as e:
        print("Unexpected error: {}".format(e))
        return {'Status': False}
    if response['ResponseMetadata']['HTTPStatusCode'] == 200:
        parsed = {
        'LaunchConfigurationName' : response['AutoScalingGroups'][0]['LaunchConfigurationName'],
        'Tags' : response['AutoScalingGroups'][0]['Tags']
        }
        return {'Status': True,'AutoScalingGroups':parsed}
    else:
        return {'Status': False}

def update_asg_launch_config(AutoScalingGroupName,LaunchConfigurationName):
    instance_list = []
    try:
        client = boto3.client('autoscaling')
        response = client.update_auto_scaling_group(AutoScalingGroupName=AutoScalingGroupName,
        LaunchConfigurationName=LaunchConfigurationName)            
    except ClientError as e:
        print("Unexpected error: {}".format(e))
        return False
    if response['ResponseMetadata']['HTTPStatusCode'] == 200:
        return True
    else:
        return False

def get_launch_config(LaunchConfigurationNames):
    try:
        client = boto3.client('autoscaling')
        response = client.describe_launch_configurations(
            LaunchConfigurationNames=[LaunchConfigurationNames]
        )          
    except ClientError as e:
        print("Unexpected error: {}".format(e))
        return {'Status': False}
    if response['ResponseMetadata']['HTTPStatusCode'] == 200:
        parsed_response = {
            'ImageId' : response['LaunchConfigurations'][0]['ImageId'],
            'SecurityGroups' : response['LaunchConfigurations'][0]['SecurityGroups'],
            'UserData' : response['LaunchConfigurations'][0]['UserData'],
            'InstanceType' : response['LaunchConfigurations'][0]['InstanceType'],
            'IamInstanceProfile' : response['LaunchConfigurations'][0]['IamInstanceProfile']
        }
        return {'Status': True,'LaunchConfig':parsed_response}
    else:
        return {'Status': False}

def modify_user_data(UserDatab64):
    data = {'content': '#!/bin/bash\nKEY=uuid\nINSTANCE_ID=$(curl -s http://169.254.169.254/latest/meta-data/instance-id)\nREGION=$(curl -s http://169.254.169.254/latest/dynamic/instance-identity/document | grep region | awk -F\\" \'{print $4}\')\nTAG_VALUE=$(aws ec2 describe-tags --filters "Name=resource-id,Values=$INSTANCE_ID" "Name=key,Values=$KEY" --region=$REGION --output=text | cut -f5)\nif [ "${TAG_VALUE}" != "Default"  ] || [ "${TAG_VALUE}" != "" ] ; then\n  mkdir -p /opt/apigee/data/edge-message-processor/${TAG_VALUE}\n  chown apigee:apigee -R /opt/apigee/data\nfi\n', 'path': '/opt/AutoScaling/uuid_configure.sh', 'permissions': '0755'}
    UserData = base64.b64decode(UserDatab64).decode('utf-8')
    UserDataJSON = yaml.safe_load(UserData)
    for cmds in UserDataJSON['runcmd']:
        if 'sudo /opt/AutoScaling/uuid_configure.sh' in cmds:
            print('No need to update UserData .')
            return {'Status': False ,'UserData': '#cloud-config\n{}'.format(yaml.dump(UserDataJSON)) }
    UserDataJSON['write_files'].append(data)
    UserDataJSON['runcmd'].insert(2,'sudo /opt/AutoScaling/uuid_configure.sh')
    print('Finished Modifying User-Data')
    return {'Status': True ,'UserData': '#cloud-config\n{}'.format(yaml.dump(UserDataJSON)) }


def create_launch_config(LaunchConfigurationName,ImageId,SecurityGroups,UserData,InstanceType,IamInstanceProfile):
    try:
        client = boto3.client('autoscaling')
        response = client.create_launch_configuration(
            LaunchConfigurationName=LaunchConfigurationName,
            ImageId=ImageId,
            SecurityGroups=SecurityGroups,
            UserData=UserData,
            InstanceType=InstanceType,
            BlockDeviceMappings= [{
                    'DeviceName': '/dev/sdf',
                    'Ebs': {
                        'VolumeSize': 100,
                        'VolumeType': 'io1',
                        'DeleteOnTermination': False,
                        'Iops': 2000,
                        'Encrypted': True
                    }
                }, {
                    'DeviceName': '/dev/xvda',
                    'Ebs': {
                        'DeleteOnTermination': True,
                        'Encrypted': True
                    }
                }
            ],
            InstanceMonitoring={
                'Enabled': True
            },
            IamInstanceProfile = IamInstanceProfile,
            EbsOptimized = False
        )          
    except ClientError as e:
        print("Unexpected error: {}".format(e))
        return False
    if response['ResponseMetadata']['HTTPStatusCode'] == 200:
        return True
    else:
        return False

def banner(msg):
    print('\n############## {} ##############\n'.format(msg))