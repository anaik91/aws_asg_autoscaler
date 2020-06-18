from mp_pool_helpers import *
from time import time
import os
import sys

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



def create_mp_pool_monitor_lambda(python_bin,referenceFunction,functionName,functionDir,Project):
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
        if create_lambda_function(functionName,lambdaDetails['Configuration']['Role'],lambdaDetails['Configuration']['Handler'],functionZip,900,env_variables):
            print('Successfully Finished Creating LambdaFuntion ==> {}'.format(functionName))


def update_existing_asg(AutoScalingGroupName):
    #banner('START')
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
            print('Modifying User-Data')
            userdata = modify_user_data(launchConfig['LaunchConfig']['UserData'])
            print('Finished Modifying User-Data')
            newLC = existingLC[:30] + str(time()).split('.')[0]
            print('Creating new Launch Config ==> {}'.format(newLC))
            if create_launch_config(newLC,launchConfig['LaunchConfig']['ImageId'],launchConfig['LaunchConfig']['SecurityGroups'],userdata,launchConfig['LaunchConfig']['InstanceType'],launchConfig['LaunchConfig']['IamInstanceProfile']):
                print('Successfully Created LaunchConfig ==> {}'.format(newLC))
                print('Updating of ASG ==> {} with Launch Config ==> {}'.format(AutoScalingGroupName,newLC))
                if update_asg_launch_config(AutoScalingGroupName,newLC):
                    print('Successfully Changed Launch Config of  ASG ==> {}'.format(AutoScalingGroupName))
                    LifecycleHooks = get_asg_lifecycle_hook(AutoScalingGroupName)
                    lch = LifecycleHooks['LifecycleHooks'][0]
                    print('Updating of ASG ==> {} with lifecycle_hook '.format(AutoScalingGroupName))
                    if update_asg_lifecycle_hook(Project+'-mp-launch-hook',lch['AutoScalingGroupName'],'autoscaling:EC2_INSTANCE_LAUNCHING',lch['RoleARN'],lch['NotificationTargetARN'],lch['NotificationMetadata']):
                        print('Successfully Updated the ASG ==> {} with lifecycle_hook'.format(AutoScalingGroupName))
    #banner('END')

def main():
    autoscaling_lambda_dir = 'mp-pool-clip-asg-tagging'
    mp_pool_monitor_lambda_dir = 'mp_pool_monitor_lambda_function'
    banner('START of MESSAGE PROCESSOR POOL SCALING')
    Project = os.getenv('Project')
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
        ############### Handle Lambda ###############
        """
        existingLambdaName = '{}-lambda-auto-scaling'.format(Project)
        lambdaDetails = get_lambda_function(existingLambdaName)
        if lambdaDetails['Status']:
            print('Lambda Function Found       ==> {}'.format(existingLambdaName))
        else:
            print('\nERROR: Unable to find Lambda Function in Project ==> {}'.format(Project))
            banner('END of MESSAGE PROCESSOR POOL SCALING')
            sys.exit(1)
        print('\nProceeding with Updgragrading Lambda Function ==> {}'.format(existingLambdaName))
        update_existing_lambda(sys.executable,existingLambdaName,autoscaling_lambda_dir)
        """
        poolLambdaName = '{}-mp-pool-monitor'.format(Project)
        poolLambdaDetails = get_lambda_function(poolLambdaName)
        print('\nChecking if  Monitoring MP Pool Already Exists...')
        if poolLambdaDetails['Status']:
            print('\nLambda Function for Monitoring MP Pool Already Exists. Hence Updating...')
            poolLambdaInfo = update_existing_lambda(sys.executable,poolLambdaName,mp_pool_monitor_lambda_dir)
            print(poolLambdaInfo)
            poolLambdaARN = poolLambdaDetails['Configuration']['FunctionArn']
        else:
            print('\nLambda Function for Monitoring MP Pool doesnt exists...')
            print('\nNow Creating a new  Lambda Function for Monitoring MP Pool')
            create_mp_pool_monitor_lambda(sys.executable,existingLambdaName,poolLambdaName,mp_pool_monitor_lambda_dir,Project)
            poolLambdaDetails = get_lambda_function(poolLambdaName)
            poolLambdaARN = poolLambdaDetails['Configuration']['FunctionArn']
        #do
        ############### Handle Lambda ###############

        ############### Handle CloudWatch CRON ###############
        print('\nCreating/Updating Cloudwatch Event Rule to enable MP Pool Monitoring...\n')
        cloudwatch_event_rule_name = '{}-mp-pool-monitor'.format(Project)
        create_cloudwatch_event_rule(cloudwatch_event_rule_name,'rate(2 hours)')
        print('Created a Cloud Watch Rule ==> {}'.format(cloudwatch_event_rule_name))
        create_cloudwatch_event_target(cloudwatch_event_rule_name,'ID12345678',poolLambdaARN)
        print('Updated a Cloud Watch Rule ==> {} to set Target Lambda Function==> {}'.format(cloudwatch_event_rule_name,poolLambdaName))
        ############### Handle CloudWatch CRON ###############

        ############### Handle Autoscaling ###############
        print('\nUpgrading Message Processor ASG ...')
        update_existing_asg(asg)
        ############### Handle Autoscaling ###############
        banner('END of MESSAGE PROCESSOR POOL SCALING')
    else:
        print('\nERROR: Environment Variable "Project" is not Set\nSet it to coninue...')
        sys.exit(1)


if __name__ == "__main__":
    main()