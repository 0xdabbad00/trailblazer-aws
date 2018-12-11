from inspect import getmembers, isfunction, ismethod
import json
import os
import re
import time

import boto3
import botocore
from botocore.exceptions import ClientError

from trailblazer import log
from trailblazer.boto.util import botocore_config

def get_service_json_files(config):
    service_file = {}

    root_dir = config['botocore_document_json_path']

    for service_dir in os.listdir(root_dir):
        if os.path.isdir(os.path.join(root_dir,service_dir)):
            date_dirs = os.listdir(os.path.join(root_dir,service_dir))
            date_dir = None
            if len(date_dirs) > 1:
                date_dir = date_dirs[-1]
            else:
                date_dir = date_dirs[0]
            if os.path.exists(os.path.join(root_dir, service_dir, date_dir, 'service-2.json')):
                service_file[service_dir] = os.path.join(root_dir, service_dir, date_dir, 'service-2.json')
            else:
                service_file[service_dir] = None

    return service_file

def get_service_call_params(service_json_file):

    services = {}

    json_data = json.load(open(service_json_file))

    for key, value in json_data.get('operations', {}).items():
        services[key.lower()] = value.get('http', {}).get('requestUri', '/')

    return services


def get_service_call_mutation(service_json_file):

    services = {}

    json_data = json.load(open(service_json_file))

    for key, value in json_data.get('operations', {}).items():

        method = value.get('http', {}).get('method', 'UNKOWN')

        if method == 'GET':
            services[key.lower()] = 'nonmutating'
        else:
            services[key.lower()] = 'mutating'

    return services


def get_boto_functions(client):
    """Loop through the client member functions and pull out what we can actually call"""
    functions_list = [o for o in getmembers(client) if ( ( isfunction(o[1]) or ismethod(o[1]) )
            and not o[0].startswith('_') and not o[0] == 'can_paginate' and not o[0] == 'get_paginator'
            and not o[0] == 'get_waiter' and 'presigned' not in o[0])]

    return functions_list


def make_api_call(service, function, region, func_params):
    arn = 'arn:aws:iam::123456789012:user/test'
    filepath = os.path.abspath(os.__file__)

    if function[0] == 'generate_presigned_url':
        func_params['ClientMethod'] = 'get_object'

    if service == 's3':
        if function[0] == 'copy':
            copy_source = {
                'Bucket': 'mybucket',
                'Key': 'mykey'
            }
            function[1](copy_source, 'testbucket', 'testkey')
            time.sleep(.1)
            return
        elif function[0] == 'download_file':
            function[1]('testbucket', 'testkey', 'test')
            time.sleep(.1)
            return
        elif function[0] == 'download_fileobj':
            with open('testfile', 'wb') as data:
                function[1]('testbucket', 'testkey', data)
                time.sleep(.1)
                return
        elif function[0] == 'upload_file':
            function[1](filepath, 'testbucket', 'testkey')
            time.sleep(.1)
            return
        elif function[0] == 'upload_fileobj':
            with open(filepath, 'rb') as data:
                function[1](data, 'testbucket', 'testkey')
                time.sleep(.1)
                return
    elif service == 'ec2':
        if function[0] == 'copy_snapshot':
            function[1](SourceRegion=region, **func_params)
            time.sleep(.1)
    elif service == 'iam':
        if function[0] == 'add_client_id_to_open_id_connect_provider':
            function[1](OpenIDConnectProviderArn='arn:aws:iam::123456789012:user/test', ClientID='1', **func_params)
            time.sleep(.1)
            return
        elif function[0] == 'add_role_to_instance_profile':
            function[1](RoleName='test', InstanceProfileName='test', **func_params)
            time.sleep(.1)
            return
        elif function[0] == 'add_user_to_group':
            function[1](UserName='test', GroupName='test', **func_params)
            time.sleep(.1)
            return
        elif function[0] == 'attach_group_policy':
            function[1](PolicyArn=arn, GroupName='test', **func_params)
            time.sleep(.1)
            return
        elif function[0] == 'attach_role_policy':
            function[1](PolicyArn=arn, RoleName='test', **func_params)
            time.sleep(.1)
            return
        elif function[0] == 'attach_user_policy':
            function[1](PolicyArn=arn, UserName='test', **func_params)
            time.sleep(.1)
            return
        elif function[0] == 'change_password':
            function[1](NewPassword='test', OldPassword='test', **func_params)
            time.sleep(.1)
            return
        elif function[0] == 'create_account_alias':
            function[1](AccountAlias='test', **func_params)
            time.sleep(.1)
            return
        elif function[0] == 'create_group':
            function[1](GroupName='test', **func_params)
            time.sleep(.1)
            return
        elif function[0] == 'create_instance_profile':
            function[1](InstanceProfileName='test', **func_params)
            time.sleep(.1)
            return
        elif function[0] == 'create_login_profile':
            function[1](Password='test', UserName='test', **func_params)
            time.sleep(.1)
            return
        elif function[0] == 'create_open_id_connect_provider':
            function[1](ThumbprintList=['c3768084dfb3d2b68b7897bf5f565da8eEXAMPLE'], Url='https://server.example.com', **func_params)
            time.sleep(.1)
            return
        elif function[0] == 'create_policy':
            function[1](PolicyDocument='test', PolicyName='test', **func_params)
            time.sleep(.1)
            return
        elif function[0] == 'create_policy_version':
            function[1](PolicyArn=arn, PolicyDocument='test', **func_params)
            time.sleep(.1)
            return
        elif function[0] == 'create_role':
            function[1](AssumeRolePolicyDocument='test', RoleName='test', **func_params)
            time.sleep(.1)
            return
        elif function[0] == 'create_saml_provider':
            function[1](SAMLMetadataDocument='A'*1024, Name='test', **func_params)
            time.sleep(.1)
            return
        elif function[0] == 'create_service_linked_role':
            function[1](AWSServiceName='test', **func_params)
            time.sleep(.1)
            return
        elif function[0] == 'create_service_specific_credential':
            function[1](ServiceName='test', **func_params)
            time.sleep(.1)
            return
        elif function[0] == 'create_user':
            function[1](UserName='test', **func_params)
            time.sleep(.1)
            return
        elif function[0] == 'create_virtual_mfa_device':
            function[1](VirtualMFADeviceName='test', **func_params)
            time.sleep(.1)
            return
        elif function[0] == 'deactivate_mfa_device':
            function[1](UserName='test', SerialNumber='testtesttest', **func_params)
            time.sleep(.1)
            return
        elif function[0] == 'delete_access_key':
            function[1](AccessKeyId='testtesttesttest', **func_params)
            time.sleep(.1)
            return
        elif function[0] == 'delete_account_alias':
            function[1](AccountAlias='test', **func_params)
            time.sleep(.1)
            return
        elif function[0] == 'delete_group':
            function[1](GroupName='test', **func_params)
            time.sleep(.1)
            return
        elif function[0] == 'delete_group_policy':
            function[1](PolicyName='test', GroupName='test', **func_params)
            time.sleep(.1)
            return
        elif function[0] == 'delete_instance_profile':
            function[1](InstanceProfileName='test', **func_params)
            time.sleep(.1)
            return
        elif function[0] == 'delete_login_profile':
            function[1](UserName='test', **func_params)
            time.sleep(.1)
            return
        elif function[0] == 'delete_open_id_connect_provider':
            function[1](OpenIDConnectProviderArn=arn, **func_params)
            time.sleep(.1)
            return
        elif function[0] == 'delete_policy':
            function[1](PolicyArn=arn, **func_params)
            time.sleep(.1)
            return
        elif function[0] == 'delete_policy_version':
            function[1](PolicyArn=arn, VersionId='v1', **func_params)
            time.sleep(.1)
            return
        elif function[0] == 'delete_role':
            function[1](RoleName='test', **func_params)
            time.sleep(.1)
            return
        elif function[0] == 'delete_role_permissions_boundary':
            function[1](RoleName='test', **func_params)
            time.sleep(.1)
            return
        elif function[0] == 'delete_role_policy':
            function[1](RoleName='test', PolicyName='test', **func_params)
            time.sleep(.1)
            return
        elif function[0] == 'delete_saml_provider':
            function[1](SAMLProviderArn=arn, **func_params)
            time.sleep(.1)
            return
        elif function[0] == 'delete_server_certificate':
            function[1](ServerCertificateName='test', **func_params)
            time.sleep(.1)
            return
        elif function[0] == 'delete_service_linked_role':
            function[1](RoleName='test', **func_params)
            time.sleep(.1)
            return
        elif function[0] == 'delete_service_specific_credential':
            function[1](ServiceSpecificCredentialId='a'*20, **func_params)
            time.sleep(.1)
            return
        elif function[0] == 'delete_signing_certificate':
            function[1](CertificateId='a'*24, **func_params)
            time.sleep(.1)
            return
        elif function[0] == 'delete_ssh_public_key':
            function[1](UserName='test', SSHPublicKeyId='a'*20, **func_params)
            time.sleep(.1)
            return
        elif function[0] == 'delete_user':
            function[1](UserName='test', **func_params)
            time.sleep(.1)
            return
        elif function[0] == 'delete_user_permissions_boundary':
            function[1](UserName='test', **func_params)
            time.sleep(.1)
            return
        elif function[0] == 'delete_user_policy':
            function[1](UserName='test', PolicyName='test', **func_params)
            time.sleep(.1)
            return
        elif function[0] == 'delete_virtual_mfa_device':
            function[1](SerialNumber='a'*9, **func_params)
            time.sleep(.1)
            return
        elif function[0] == 'detach_group_policy':
            function[1](PolicyArn=arn, GroupName='test', **func_params)
            time.sleep(.1)
            return
        elif function[0] == 'detach_role_policy':
            function[1](PolicyArn=arn, RoleName='test', **func_params)
            time.sleep(.1)
            return
        elif function[0] == 'detach_user_policy':
            function[1](PolicyArn=arn, UserName='test', **func_params)
            time.sleep(.1)
            return
        elif function[0] == 'enable_mfa_device':
            function[1](AuthenticationCode2='0'*6, SerialNumber='0'*20, AuthenticationCode1='0'*6,UserName='test', **func_params)
            time.sleep(.1)
            return
        elif function[0] == 'generate_service_last_accessed_details':
            function[1](Arn=arn, **func_params)
            time.sleep(.1)
            return
        elif function[0] == 'get_access_key_last_used':
            function[1](AccessKeyId='a'*16, **func_params)
            time.sleep(.1)
            return
        elif function[0] == 'get_context_keys_for_custom_policy':
            function[1](PolicyInputList='test', **func_params)
            time.sleep(.1)
            return
        elif function[0] == 'get_context_keys_for_principal_policy':
            function[1](PolicySourceArn=arn, **func_params)
            time.sleep(.1)
            return
        elif function[0] == 'get_group':
            function[1](GroupName='test', **func_params)
            time.sleep(.1)
            return
        elif function[0] == 'get_group_policy':
            function[1](PolicyName='test', GroupName='test', **func_params)
            time.sleep(.1)
            return
        elif function[0] == 'get_instance_profile':
            function[1](InstanceProfileName='test', **func_params)
            time.sleep(.1)
            return
        elif function[0] == 'get_login_profile':
            function[1](UserName='test', **func_params)
            time.sleep(.1)
            return
        elif function[0] == 'get_open_id_connect_provider':
            function[1](OpenIDConnectProviderArn=arn, **func_params)
            time.sleep(.1)
            return
        elif function[0] == 'get_policy':
            function[1](PolicyArn=arn, **func_params)
            time.sleep(.1)
            return
        elif function[0] == 'get_policy_version':
            function[1](PolicyArn=arn, VersionId='v1', **func_params)
            time.sleep(.1)
            return
        elif function[0] == 'get_role':
            function[1](RoleName='test', **func_params)
            time.sleep(.1)
            return
        elif function[0] == 'get_role_policy':
            function[1](RoleName='test', PolicyName='test', **func_params)
            time.sleep(.1)
            return
        elif function[0] == 'get_saml_provider':
            function[1](SAMLProviderArn=arn, **func_params)
            time.sleep(.1)
            return
        elif function[0] == 'get_server_certificate':
            function[1](ServerCertificateName='test', **func_params)
            time.sleep(.1)
            return
        elif function[0] == 'get_service_last_accessed_details':
            function[1](JobId='a'*36, **func_params)
            time.sleep(.1)
            return
        elif function[0] == 'get_service_last_accessed_details_with_entities':
            function[1](JobId='a'*36, ServiceNamespace='test', **func_params)
            time.sleep(.1)
            return
        elif function[0] == 'get_service_linked_role_deletion_status':
            function[1](DeletionTaskId='test', **func_params)
            time.sleep(.1)
            return
        elif function[0] == 'get_ssh_public_key':
            function[1](SSHPublicKeyId='a'*20, UserName='test', Encoding='SSH', **func_params)
            time.sleep(.1)
            return
        elif function[0] == 'get_user_policy':
            function[1](UserName='test', PolicyName='test', **func_params)
            time.sleep(.1)
            return
        elif function[0] == 'list_attached_group_policies':
            function[1](GroupName='test', **func_params)
            time.sleep(.1)
            return
        elif function[0] == 'list_attached_role_policies':
            function[1](RoleName='test', **func_params)
            time.sleep(.1)
            return
        elif function[0] == 'list_attached_user_policies':
            function[1](UserName='test', **func_params)
            time.sleep(.1)
            return
        elif function[0] == 'list_entities_for_policy':
            function[1](PolicyArn=arn, **func_params)
            time.sleep(.1)
            return
        elif function[0] == 'list_group_policies':
            function[1](GroupName='test', **func_params)
            time.sleep(.1)
            return
        elif function[0] == 'list_groups_for_user':
            function[1](UserName='test', **func_params)
            time.sleep(.1)
            return
        elif function[0] == 'list_instance_profiles_for_role':
            function[1](RoleName='test', **func_params)
            time.sleep(.1)
            return
        elif function[0] == 'list_policies_granting_service_access':
            function[1](ServiceNamespaces='test', Arn=arn, **func_params)
            time.sleep(.1)
            return
        elif function[0] == 'list_policy_versions':
            function[1](PolicyArn=arn, **func_params)
            time.sleep(.1)
            return
        elif function[0] == 'list_role_policies':
            function[1](RoleName='test', **func_params)
            time.sleep(.1)
            return
        elif function[0] == 'list_role_tags':
            function[1](RoleName='test', **func_params)
            time.sleep(.1)
            return
        elif function[0] == 'list_user_policies':
            function[1](UserName='test', **func_params)
            time.sleep(.1)
            return
        elif function[0] == 'list_user_tags':
            function[1](UserName='test', **func_params)
            time.sleep(.1)
            return
        elif function[0] == 'put_group_policy':
            function[1](PolicyDocument='test', GroupName='test', PolicyName='test', **func_params)
            time.sleep(.1)
            return
        elif function[0] == 'put_role_permissions_boundary':
            function[1](RoleName='test', PermissionsBoundary='a'*20, **func_params)
            time.sleep(.1)
            return
        elif function[0] == 'put_role_policy':
            function[1](PolicyDocument='test', RoleName='test', PolicyName='test', **func_params)
            time.sleep(.1)
            return
        elif function[0] == 'put_user_permissions_boundary':
            function[1](UserName='test', PermissionsBoundary='a'*20, **func_params)
            time.sleep(.1)
            return
        elif function[0] == 'put_user_policy':
            function[1](PolicyDocument='test', UserName='test', PolicyName='test', **func_params)
            time.sleep(.1)
            return
        elif function[0] == 'remove_client_id_from_open_id_connect_provider':
            function[1](OpenIDConnectProviderArn=arn, ClientID='test', **func_params)
            time.sleep(.1)
            return
        elif function[0] == 'remove_role_from_instance_profile':
            function[1](RoleName='test', InstanceProfileName='test', **func_params)
            time.sleep(.1)
            return
        elif function[0] == 'remove_user_from_group':
            function[1](UserName='test', GroupName='test', **func_params)
            time.sleep(.1)
            return
        elif function[0] == 'reset_service_specific_credential':
            function[1](ServiceSpecificCredentialId='a'*20, **func_params)
            time.sleep(.1)
            return
        elif function[0] == 'resync_mfa_device':
            function[1](AuthenticationCode2='0'*6, SerialNumber='0'*20, AuthenticationCode1='0'*6, UserName='test', **func_params)
            time.sleep(.1)
            return
        elif function[0] == 'set_default_policy_version':
            function[1](PolicyArn=arn, VersionId='v1', **func_params)
            time.sleep(.1)
            return
        elif function[0] == 'simulate_custom_policy':
            function[1](PolicyInputList='test', ActionNames=['test'], **func_params)
            time.sleep(.1)
            return
        elif function[0] == 'simulate_principal_policy':
            function[1](PolicySourceArn=arn, ActionNames=['test'], **func_params)
            time.sleep(.1)
            return
        elif function[0] == 'tag_role':
            function[1](RoleName='testrolename', Tags=[{'testtagkey':'testtagvalue'}], **func_params)
            time.sleep(.1)
            return
        elif function[0] == 'tag_user':
            function[1](UserName='test', Tags=[{'testtagkey':'testtagvalue'}], **func_params)
            time.sleep(.1)
            return
        elif function[0] == 'untag_role':
            function[1](RoleName='test', TagKeys='test', **func_params)
            time.sleep(.1)
            return
        elif function[0] == 'untag_user':
            function[1](UserName='test', TagKeys='test', **func_params)
            time.sleep(.1)
            return
        elif function[0] == 'update_access_key':
            function[1](AccessKeyId='test', Status='test', **func_params)
            time.sleep(.1)
            return
        elif function[0] == 'update_assume_role_policy':
            function[1](PolicyDocument='test', RoleName='test', **func_params)
            time.sleep(.1)
            return
        elif function[0] == 'update_group':
            function[1](GroupName='test', **func_params)
            time.sleep(.1)
            return
        elif function[0] == 'update_login_profile':
            function[1](UserName='test', **func_params)
            time.sleep(.1)
            return
        elif function[0] == 'update_open_id_connect_provider_thumbprint':
            function[1](OpenIDConnectProviderArn=arn, ThumbprintList='test', **func_params)
            time.sleep(.1)
            return
        elif function[0] == 'update_role':
            function[1](RoleName='test', **func_params)
            time.sleep(.1)
            return
        elif function[0] == 'update_role_description':
            function[1](RoleName='test', Description='test', **func_params)
            time.sleep(.1)
            return
        elif function[0] == 'update_saml_provider':
            function[1](SAMLMetadataDocument='test', SAMLProviderArn=arn, **func_params)
            time.sleep(.1)
            return
        elif function[0] == 'update_server_certificate':
            function[1](ServerCertificateName='test', **func_params)
            time.sleep(.1)
            return
        elif function[0] == 'update_service_specific_credential':
            function[1](ServiceSpecificCredentialId='test', Status='test', **func_params)
            time.sleep(.1)
            return
        elif function[0] == 'update_signing_certificate':
            function[1](CertificateId='test', Status='test', **func_params)
            time.sleep(.1)
            return
        elif function[0] == 'update_ssh_public_key':
            function[1](SSHPublicKeyId='test', UserName='test', Status='test', **func_params)
            time.sleep(.1)
            return
        elif function[0] == 'update_user':
            function[1](UserName='test', **func_params)
            time.sleep(.1)
            return
        elif function[0] == 'upload_server_certificate':
            function[1](PrivateKey='test', ServerCertificateName='test', CertificateBody='test', **func_params)
            time.sleep(.1)
            return
        elif function[0] == 'upload_signing_certificate':
            function[1](CertificateBody='test', **func_params)
            time.sleep(.1)
            return
        elif function[0] == 'upload_ssh_public_key':
            function[1](UserName='test', SSHPublicKeyBody='test', **func_params)
            time.sleep(.1)
            return

    function[1](**func_params)
    time.sleep(.1)
    return
