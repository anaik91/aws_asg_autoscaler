from mp_pool_helpers import *
from time import time

def update_existing_lambda(python_bin,functionName,functionDir):
    functionZip = 'function.zip'
    pip_dependecies(python_bin,functionDir,'{}/requirements.txt'.format(functionDir))
    build_zip(functionZip,functionDir)
    #build_zip_b64 = read_file_b64(functionZip)
    lambdaDetails = get_lambda_function(functionName)
    if lambdaDetails['Status']:
        print('Updating LambdaFuntion ==> {}'.format(functionName))
        if update_lambda_function(functionName,functionZip):
            print('Finished Updating LambdaFuntion ==> {}'.format(functionName))


def create_mp_pool_monitor_lambda(python_bin,referenceFunction,functionName,functionDir):
    functionZip = 'function.zip'
    pip_dependecies(python_bin,functionDir,'{}/requirements.txt'.format(functionDir))
    build_zip(functionZip,functionDir)
    #build_zip_b64 = read_file_b64(functionZip)
    lambdaDetails = get_lambda_function(referenceFunction)
    if lambdaDetails['Status']:
        print('Creating LambdaFuntion ==> {}'.format(functionName))
        if create_lambda_function(functionName,functionZip):
            print('Finished Creating LambdaFuntion ==> {}'.format(functionName))


def update_existing_asg(AutoScalingGroupName):
    banner('START')
    print('Getting Details of ASG ==> {}'.format(AutoScalingGroupName))
    asg = get_asg_details(AutoScalingGroupName)
    if asg['Status']:
        asg_tags = asg['AutoScalingGroups']['Tags']
        Project = filter(asg_tags,'Project')
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
                    if update_asg_lifecycle_hook(Project+'mp-launch-hook',lch['AutoScalingGroupName'],'autoscaling:EC2_INSTANCE_LAUNCHING',lch['RoleARN'],lch['NotificationTargetARN'],lch['NotificationMetadata']):
                        print('Updated the ASG ==> {} with lifecycle_hook'.format(AutoScalingGroupName))
    banner('END')