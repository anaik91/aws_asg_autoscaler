from mp_pool_helpers import *
from time import time
import os
import sys
import json

def update_existing_iam_policy(AutoScalingGroupName,RoleName):
    asg_lifecycle_hook_list = get_asg_lifecycle_hook(AutoScalingGroupName)
    asg_role_arn = asg_lifecycle_hook_list['LifecycleHooks'][0]['RoleARN']
    policy_list = list_attached_role_policies(RoleName)
    if len(policy_list) > 0:
        policyArn = policy_list['AttachedPolicies'][0]['PolicyArn']
        policy_details = get_policy(policyArn)
        policy_document = get_policy_document(policyArn,policy_details['Policy']['DefaultVersionId'])
        permission = {
            'Action': 'iam:PassRole',
            'Resource': [asg_role_arn],
            'Effect': 'Allow'
        }
        policy_document = policy_document['Document']
        for statement in policy_document['Statement']:
            if statement['Action'] == 'iam:PassRole':
                print('IAM Role Policy already Up To Date.')
                return True
        updated_policy_document = policy_document
        updated_policy_document['Statement'].append(permission)
        
        if create_policy_version(policyArn,json.dumps(updated_policy_document)):
            print('Updated IAM Policy ==> {}'.format(policyArn))
            return True
        else:
            print('Failure Updating IAM Policy ==> {}'.format(policyArn))
            return False


def update_existing_lambda(python_bin,functionName,functionDir):
    functionZip = 'asgfunction.zip'
    pip_dependecies(python_bin,functionDir,'{}/requirements.txt'.format(functionDir))
    build_zip(functionZip,functionDir)
    #build_zip_b64 = read_file_b64(functionZip)
    lambdaDetails = get_lambda_function(functionName)
    if lambdaDetails['Status']:
        print('Updating LambdaFuntion ==> {}'.format(functionName))
        lambda_status = update_lambda_function(functionName,functionZip)
        if update_lambda_function(functionName,functionZip):
            print('Finished Updating LambdaFuntion ==> {}'.format(functionName))


def create_mp_pool_monitor_lambda(python_bin,referenceFunction,functionName,functionDir,Project,ProxyCountThreshold):
    functionZip = 'poolmonitorfunction.zip'
    pip_dependecies(python_bin,functionDir,'{}/requirements.txt'.format(functionDir))
    build_zip(functionZip,functionDir)
    #build_zip_b64 = read_file_b64(functionZip)
    lambdaDetails = get_lambda_function(referenceFunction)
    if lambdaDetails['Status']:
        print('Creating LambdaFuntion ==> {}'.format(functionName))
        env_variables = lambdaDetails['Configuration']['Environment']['Variables']
        env_variables['Project'] = Project
        env_variables['SubType'] = 'messageprocessor'
        env_variables['ProxyCountThreshold'] = ProxyCountThreshold
        if create_lambda_function(functionName,lambdaDetails['Configuration']['Role'],lambdaDetails['Configuration']['Handler'],functionZip,900,env_variables):
            print('Successfully Finished Creating LambdaFuntion ==> {}'.format(functionName))


def update_existing_asg(AutoScalingGroupName):
    print('Getting Details of ASG ==> {}'.format(AutoScalingGroupName))
    asg = get_asg_details(AutoScalingGroupName)
    if asg['Status']:
        asg_tags = asg['AutoScalingGroups']['Tags']
        Project = filter_tags(asg_tags,'Project')
        print('Succesfully gathered Details of ASG ==> {}'.format(AutoScalingGroupName))
        existingLC = asg['AutoScalingGroups']['LaunchConfigurationName']
        print('Getting Details of Launch Config ==> {}'.format(existingLC))
        launchConfig = get_launch_config(existingLC)
        if launchConfig['Status']:
            print('Succesfully gathered Details of Launch Config ==> {}'.format(existingLC))
            print('Checking if User-Data has to be modified')
            userdata = modify_user_data(launchConfig['LaunchConfig']['UserData'])
            if userdata['Status']:
                newLC = existingLC[:30] + str(time()).split('.')[0]
                print('Creating new Launch Config ==> {}'.format(newLC))
                if create_launch_config(newLC,launchConfig['LaunchConfig']['ImageId'],launchConfig['LaunchConfig']['SecurityGroups'],userdata['UserData'],launchConfig['LaunchConfig']['InstanceType'],launchConfig['LaunchConfig']['IamInstanceProfile']):
                    print('Successfully Created LaunchConfig ==> {}'.format(newLC))
                    print('Updating of ASG ==> {} with Launch Config ==> {}'.format(AutoScalingGroupName,newLC))
                    if update_asg_launch_config(AutoScalingGroupName,newLC):
                        print('Successfully Changed Launch Config of  ASG ==> {}'.format(AutoScalingGroupName))
            else:
                pass
            LifecycleHooks = get_asg_lifecycle_hook(AutoScalingGroupName)
            lch = LifecycleHooks['LifecycleHooks'][0]
            print('Updating of ASG ==> {} with lifecycle_hook '.format(AutoScalingGroupName))
            if update_asg_lifecycle_hook(Project+'-mp-launch-hook',lch['AutoScalingGroupName'],'autoscaling:EC2_INSTANCE_LAUNCHING',lch['RoleARN'],lch['NotificationTargetARN'],lch['NotificationMetadata']):
                print('Successfully Updated the ASG ==> {} with lifecycle_hook'.format(AutoScalingGroupName))


def main():
    autoscaling_lambda_dir = 'mp-pool-clip-asg-tagging'
    mp_pool_monitor_lambda_dir = 'mp_pool_monitor_lambda_function'
    banner('START of MESSAGE PROCESSOR POOL SCALING')
    Project = os.getenv('Project')
    ProxyCountThreshold = '2000'
    if Project is not None:
        print('"Project" Env Variable Found!')
        print('Scanning for Resoureces in AWS related to the Project ==> {}\n'.format(Project))
        query = {'Project':Project,'SubType':'messageprocessor'}
        asg_status = get_asgs_by_tag(query)

        if asg_status['Status']:
            if len(asg_status['asg_list']) > 0:
                asg = asg_status['asg_list'][0]
                print('Message Processor ASG Found ==> {}'.format(asg))
            else:
                print('Unable to find ASGs in Project ==> {}'.format(Project))
                banner('END of MESSAGE PROCESSOR POOL SCALING')
                sys.exit(1)
        else:
            print('ERROR: Unable to Query ASGs based on Project ==> {}'.format(Project))
            banner('END of MESSAGE PROCESSOR POOL SCALING')
            sys.exit(1)
        
        ############### Handle Autoscaling Lambda ###############
        existingLambdaName = '{}-lambda-auto-scaling'.format(Project)
        lambdaDetails = get_lambda_function(existingLambdaName)
        if lambdaDetails['Status']:
            print('Lambda Function Found       ==> {}'.format(existingLambdaName))
        else:
            print('\nERROR: Unable to find Lambda Function in Project ==> {}'.format(Project))
            banner('END of MESSAGE PROCESSOR POOL SCALING')
            sys.exit(1)
        print('\nProceeding with Upgrading Lambda Function ==> {}'.format(existingLambdaName))
        update_existing_lambda(sys.executable,existingLambdaName,autoscaling_lambda_dir)
        
        ############### Handle Autoscaling Lambda ###############

        ############### Handle MP Pool Monitor Lambda ###############
        print('\nChecking if  Monitoring MP Pool Already Exists...')
        poolLambdaName = '{}-mp-pool-monitor'.format(Project)
        poolLambdaDetails = get_lambda_function(poolLambdaName)
        if poolLambdaDetails['Status']:
            print('\nLambda Function for Monitoring MP Pool Already Exists. Hence Updating...')
            poolLambdaInfo = update_existing_lambda(sys.executable,poolLambdaName,mp_pool_monitor_lambda_dir)
            print(poolLambdaInfo)
            poolLambdaARN = poolLambdaDetails['Configuration']['FunctionArn']
        else:
            print('\nLambda Function for Monitoring MP Pool doesnt exists...')
            print('\nNow Creating a new  Lambda Function for Monitoring MP Pool')
            create_mp_pool_monitor_lambda(sys.executable,existingLambdaName,poolLambdaName,mp_pool_monitor_lambda_dir,Project,ProxyCountThreshold)
            poolLambdaDetails = get_lambda_function(poolLambdaName)
            poolLambdaARN = poolLambdaDetails['Configuration']['FunctionArn']
        ############### Handle MP Pool Monitor Lambda ###############

        ############### Handle IAM Policy ###############
        lambda_role_name = '{}-lambda-role'.format(Project)
        print('\nValidating IAM Policy of role ==> {} has relevant access to Create Autoscaling Group'.format(lambda_role_name))
        update_existing_iam_policy(asg,lambda_role_name)
        ############### Handle IAM Policy ###############
        
        ############### Handle CloudWatch CRON ###############
        print('\nCreating/Updating Cloudwatch Event Rule to enable MP Pool Monitoring...\n')
        cloudwatch_event_rule_name = '{}-mp-pool-monitor'.format(Project)
        print('Creating a Cloud Watch Rule ==> {}'.format(cloudwatch_event_rule_name))
        event_rule_status = create_cloudwatch_event_rule(cloudwatch_event_rule_name,'rate(2 hours)')
        print('Successfully Created a Cloud Watch Rule ==> {}'.format(cloudwatch_event_rule_name))
        print('Updating a Cloud Watch Rule ==> {} to set Target Lambda Function==> {}'.format(cloudwatch_event_rule_name,poolLambdaName))
        create_cloudwatch_event_target(cloudwatch_event_rule_name,'ID12345678',poolLambdaARN)
        print('Successfully Updated a Cloud Watch Rule ==> {} to set Target Lambda Function==> {}'.format(cloudwatch_event_rule_name,poolLambdaName))
        print('Adding Invoke Function by Event ==> {} Permission to Target Lambda Function==> {}'.format(cloudwatch_event_rule_name,poolLambdaName))
        add_lambda_invoke_permission(poolLambdaName,event_rule_status['RuleArn'])
        ############### Handle CloudWatch CRON ###############
        """
        ############### Handle Autoscaling ###############
        print('\nUpgrading Message Processor ASG ...\n')
        update_existing_asg(asg)
        ############### Handle Autoscaling ###############
        """
        banner('END of MESSAGE PROCESSOR POOL SCALING')
    else:
        print('\nERROR: Environment Variable "Project" is not Set\nSet it to coninue...')
        banner('END of MESSAGE PROCESSOR POOL SCALING')
        sys.exit(1)


if __name__ == "__main__":
    main()