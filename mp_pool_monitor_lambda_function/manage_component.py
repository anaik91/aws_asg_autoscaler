import logging
import apigee_util_methods as apigee_utils
import os
import time
import boto3
import base64
import json
from botocore.exceptions import ClientError

#import azure.functions as func
logger = logging.getLogger()
logger.setLevel(logging.INFO)

def get_secret(secret_key):
    print ("get_secret_method")
    secret_name = os.environ['apim_secret_manager']
    print ("print secret manager name {}".format(secret_name))
    client = boto3.client('secretsmanager')
    try:
        get_secret_value_response = client.get_secret_value(SecretId=secret_name)
        creds = get_secret_value_response['SecretString']
        apim_secrets = json.loads(creds)
        print("secret key you're looking for {}".format(secret_key))
        return apim_secrets[secret_key]
    except ClientError as e:
        if e.response['Error']['Code'] == 'DecryptionFailureException':
            # Secrets Manager can't decrypt the protected secret text using the provided KMS key.
            # Deal with the exception here, and/or rethrow at your discretion.
            raise e
        elif e.response['Error']['Code'] == 'InternalServiceErrorException':
            # An error occurred on the server side.
            # Deal with the exception here, and/or rethrow at your discretion.
            raise e
        elif e.response['Error']['Code'] == 'InvalidParameterException':
            # You provided an invalid value for a parameter.
            # Deal with the exception here, and/or rethrow at your discretion.
            raise e
        elif e.response['Error']['Code'] == 'InvalidRequestException':
            # You provided a parameter value that is not valid for the current state of the resource.
            # Deal with the exception here, and/or rethrow at your discretion.
            raise e
        elif e.response['Error']['Code'] == 'ResourceNotFoundException':
            # We can't find the resource that you asked for.
            # Deal with the exception here, and/or rethrow at your discretion.
            raise e
        else:
        # Decrypts secret using the associated KMS CMK.
        # Depending on whether the secret is a string or binary, one of these fields will be populated.
            if 'SecretString' in get_secret_value_response:
                secret = get_secret_value_response['SecretString']
            else:
                decoded_binary_secret = base64.b64decode(get_secret_value_response['SecretBinary'])


def get_uuid(compType,component_name,ip_address):
    logger.info('Component Removal Request Received')
    username = get_secret("msusername")
    password = get_secret("mspassword")
    protocol = os.getenv("protocol")
    port = os.getenv("port")
    ms_ip = os.getenv("ms_ip")
    region = os.getenv("region")
    baseUrl = protocol+ '://' + ms_ip + ':' + port
    pod = os.getenv("pod")
    stale_retry = int(os.getenv("stale_retry"))
    logger.info("Component Name {}" .format(compType))
    uuid = apigee_utils.get_uuid_from_ip(baseUrl,username,password,pod,compType,region,ip_address)
    return uuid

def proxy_count_from_mp_uuid(uuid):
    username = get_secret("msusername")
    password = get_secret("mspassword")
    protocol = os.getenv("protocol")
    port = os.getenv("port")
    ms_ip = os.getenv("ms_ip")
    baseUrl = protocol+ '://' + ms_ip + ':' + port
    proxy_count = apigee_utils.get_mp_proxy_count(baseUrl,username,password,uuid)
    return proxy_count