import json,sys
import boto3
from botocore.exceptions import ClientError
from asg_helpers import *

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


def create_cloudwatch_metric_alarm(AlarmName,MetricName,Namespace,Threshold,ComparisonOperator,AlarmActions):
    try:
        client = boto3.client('cloudwatch')
        response = client.put_metric_alarm(
            AlarmName=AlarmName,
            AlarmDescription=AlarmName,
            MetricName=MetricName,
            Namespace=Namespace,
            Statistic='Average',
            Period=120,
            EvaluationPeriods=2,
            Threshold=Threshold,
            ComparisonOperator=ComparisonOperator,
            AlarmActions=[AlarmActions]
        )          
    except ClientError as e:
        print("Unexpected error: {}".format(e))
        return {'Status': False}
    if response['ResponseMetadata']['HTTPStatusCode'] == 200:
        return {'Status': True}
    else:
        return {'Status': False}

def create_asg_scaling_policy(AutoScalingGroupName,PolicyName,ThresholdType):
    if ThresholdType == 'high':
        StepAdjustments = {
                        'MetricIntervalLowerBound': 0.0,
                        'ScalingAdjustment': 1
        }   
    elif ThresholdType == 'low':
        StepAdjustments = {
                        'MetricIntervalUpperBound': 0.0,
                        'ScalingAdjustment': 1
        } 
    else:
        print('ERROR : Set ThresholdType to high/low')
        sys.exit(1)
    try:
        client = boto3.client('autoscaling')
        response = client.put_scaling_policy(
                AutoScalingGroupName=AutoScalingGroupName,
                PolicyName=PolicyName,
                PolicyType='StepScaling',
                AdjustmentType='ChangeInCapacity',
                MetricAggregationType='Average',
                StepAdjustments=[StepAdjustments]
        )          
    except ClientError as e:
        print("Unexpected error: {}".format(e))
        return {'Status': False}
    if response['ResponseMetadata']['HTTPStatusCode'] == 200:
        return {'Status': True,'PolicyARN':response['PolicyARN']}
    else:
        return {'Status': False}

def create_asg_lifecycle_hook(LifecycleHookName,AutoScalingGroupName,LifecycleTransition,RoleARN,NotificationTargetARN,NotificationMetadata):
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


def create_asg(AutoScalingGroupName,LaunchConfigurationName,subnetList):
    #subnetList = ','.join(subnetList)
    try:
        client = boto3.client('autoscaling')
        response = client.create_auto_scaling_group(
            AutoScalingGroupName=AutoScalingGroupName,
            LaunchConfigurationName=LaunchConfigurationName,
            MaxSize=0,
            MinSize=0,
            DesiredCapacity=0,
            VPCZoneIdentifier=subnetList
        )          
    except ClientError as e:
        print("Unexpected error: {}".format(e))
        return {'Status': False}
    if response['ResponseMetadata']['HTTPStatusCode'] == 200:
        return {'Status': True}
    else:
        return {'Status': False}


def create_e2e_asg(asg_uuid_map,Project):
    current_asg_count = len(asg_uuid_map.keys())
    asg_name_prefix = '{}-mp-asg-{}'.format(Project,current_asg_count+1)
    print('Current ASG Count - {}'.format(current_asg_count))
    reference_asg = list(asg_uuid_map.keys())[0]
    existing_asg_details = get_asg_info(reference_asg)
    existing_asg_lc_hook_details = get_asg_lifecycle_hook(reference_asg)
    print('Creating Autoscaling Group ==> {}'.format(asg_name_prefix))
    create_asg(asg_name_prefix,existing_asg_details['AutoScalingGroups']['LaunchConfigurationName'],existing_asg_details['AutoScalingGroups']['VPCZoneIdentifier'])
    print('Creating Autoscaling Group Scaling Policies .. ')
    mp_high_cpu_policy = create_asg_scaling_policy(asg_name_prefix,asg_name_prefix+'cpu-high-mp','high')
    mp_high_mem_policy = create_asg_scaling_policy(asg_name_prefix,asg_name_prefix+'memory-high-mp','high')
    mp_low_cpu_policy = create_asg_scaling_policy(asg_name_prefix,asg_name_prefix+'cpu-low-mp','low')
    mp_low_mem_policy = create_asg_scaling_policy(asg_name_prefix,asg_name_prefix+'memory-low-mp','low')
    print('Creating Cloud Watch Metrics for Autoscaling Group... ')
    create_cloudwatch_metric_alarm(asg_name_prefix+'-cpu-high','CPUUtilization','AWS/EC2',80,'GreaterThanOrEqualToThreshold',mp_high_cpu_policy['PolicyARN'])
    create_cloudwatch_metric_alarm(asg_name_prefix+'-memory-high','mem_used_percent','CWAgent',80,'GreaterThanOrEqualToThreshold',mp_high_mem_policy['PolicyARN'])
    create_cloudwatch_metric_alarm(asg_name_prefix+'-cpu-low','CPUUtilization','AWS/EC2',10,'GreaterThanOrEqualToThreshold',mp_low_cpu_policy['PolicyARN'])
    create_cloudwatch_metric_alarm(asg_name_prefix+'-memory-low','mem_used_percent','CWAgent',10,'GreaterThanOrEqualToThreshold',mp_low_mem_policy['PolicyARN'])
    print('Creating Lifecycle hook for Autoscaling Group... ')
    create_asg_lifecycle_hook(asg_name_prefix+'mp-launch-hook',asg_name_prefix,'autoscaling:EC2_INSTANCE_LAUNCHING',existing_asg_lc_hook_details['LifecycleHooks'][0]['RoleARN'],existing_asg_lc_hook_details['LifecycleHooks'][0]['NotificationTargetARN'],existing_asg_lc_hook_details['LifecycleHooks'][0]['NotificationMetadata'])
    create_asg_lifecycle_hook(asg_name_prefix+'mp-terminate-hook',asg_name_prefix,'autoscaling:EC2_INSTANCE_TERMINATING',existing_asg_lc_hook_details['LifecycleHooks'][0]['RoleARN'],existing_asg_lc_hook_details['LifecycleHooks'][0]['NotificationTargetARN'],existing_asg_lc_hook_details['LifecycleHooks'][0]['NotificationMetadata'])
    print('Creating Tags on Autoscaling Group... ')
    create_asg_tag(asg_name_prefix,'Project',Project,True)
    create_asg_tag(asg_name_prefix,'Name',asg_name_prefix,True)
    create_asg_tag(asg_name_prefix,'Type','runtime',True)
    create_asg_tag(asg_name_prefix,'SubType','messageprocessor',True)
    print('Finished Creating Autoscaling Group ==> {}'.format(asg_name_prefix))