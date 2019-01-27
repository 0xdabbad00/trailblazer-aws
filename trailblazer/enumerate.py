import re
import json
import string

import boto3
from botocore.exceptions import ClientError

from xeger import Xeger

from trailblazer import log
from trailblazer.boto.util import botocore_config
from trailblazer.boto.service import get_boto_functions, get_service_call_params, \
									get_service_json_files, make_api_call
from trailblazer.boto.sts import get_assume_role_session


def snake_case_to_CamelCase(snake_str):
    components = snake_str.split('_')
    CamelCase = ''.join(x.title() for x in components)

    # Fix special cases
    CamelCase = CamelCase.replace('Id', 'ID')
    CamelCase = CamelCase.replace('IDentity', 'Identity')
    CamelCase = CamelCase.replace('IDentities', 'Identities')
    CamelCase = CamelCase.replace('GetID', 'GetId')
    CamelCase = CamelCase.replace('GetOpenIDToken', 'GetOpenIdToken')
    CamelCase = CamelCase.replace('GetOpenIDTokenForDeveloperIdentity', 'GetOpenIdTokenForDeveloperIdentity')
    
    
    CamelCase = CamelCase.replace('Csv', 'CSV')
    CamelCase = CamelCase.replace('Ssh', 'SSH')
    CamelCase = CamelCase.replace('Saml', 'SAML')
    CamelCase = CamelCase.replace('Mfa', 'MFA')
    # Fix the function that doen't follow this rule
    CamelCase = CamelCase.replace('SetUserPoolMFAConfig', 'SetUserPoolMfaConfig')
    CamelCase = CamelCase.replace('GetUserPoolMFAConfig', 'GetUserPoolMfaConfig')
    
    CamelCase = CamelCase.replace('Ml', 'ML')
    CamelCase = CamelCase.replace('Ui', 'UI')
    CamelCase = CamelCase.replace('Avs', 'AVS')
    CamelCase = CamelCase.replace('Url', 'URL')
    CamelCase = CamelCase.replace('CreateEnvironmentEc2', 'CreateEnvironmentEC2')
    CamelCase = CamelCase.replace('ResetPersonalPin', 'ResetPersonalPIN')
    
    

    return CamelCase


def get_value_for_shape(shape, shape_name, param_name, service_json):
    if shape['type'] == 'list':
        member_shape_name = shape['member']['shape']
        member_shape = service_json['shapes'][member_shape_name]
        return [get_value_for_shape(member_shape, member_shape_name, shape_name, service_json)]
    elif shape['type'] == 'boolean':
        return True
    elif shape['type'] == 'double':
        return 0.1
    elif shape['type'] == 'float':
        return 0.1
    elif shape['type'] == 'integer':
        return 1
    elif shape['type'] == 'long':
        return 1
    elif shape['type'] == 'blob':
        return 'blob'
    elif shape['type'] == 'timestamp':
        return '2019-01-19T18:39:31+00:00'
    elif shape['type'] == 'structure':
        response = {}
        for member in shape.get('required', []):
            member_shape_name = shape['members'][member]['shape']
            member_shape = service_json['shapes'][member_shape_name]
            response[member] = get_value_for_shape(member_shape, member_shape_name, shape_name, service_json)
        return response
    elif shape['type'] == 'map':
        response = {}

        member_shape_name = shape['key']['shape']
        member_shape = service_json['shapes'][member_shape_name]
        key_name = get_value_for_shape(member_shape, member_shape_name, shape_name, service_json)

        member_shape_name = shape['value']['shape']
        member_shape = service_json['shapes'][member_shape_name]
        value_name = get_value_for_shape(member_shape, member_shape_name, shape_name, service_json)

        return {key_name: value_name}

    elif shape['type'] != 'string':
        # TODO Should throw an error
        log.error('Unexpected shape type \"{}\" for {}'.format(shape['type'], param_name))

    if 'enum' in shape:
        return shape['enum'][0]

    if param_name == 'PolicyArn':
        return 'arn:aws:iam::aws:policy/SecurityAudit'
    elif param_name == 'CertificateArn':
        return 'arn:aws:acm:us-east-1:123456789012:certificate/12345678-1234-1234-1234-123456789012'
    elif shape_name == 'DomainNameString':
        return 'example.com'
    elif param_name == 'CertificateAuthorityArn':
        return 'arn:aws:acm-pca:us-east-1:123456789012:certificate-authority/12345678-1234-1234-1234-123456789012'
    elif shape_name == 'InstanceType':
        return 't2.micro'
    elif shape_name == 'EnvironmentName':
        return 'test'
    elif shape_name == 'UserArn':
        return 'arn:aws:iam::123456789012:user/David'
    elif shape_name == 'EnvironmentId':
        return 'testtest'
    elif param_name == 'DirectoryArn':
        return 'arn:aws:clouddirectory:us-east-1:123456789012:directory/ARIqk1HD-UjdtmcIrJHEvPI'
    elif param_name == 'SchemaArn' or param_name == 'DevelopmentSchemaArn' or param_name == 'PublishedSchemaArn':
        return 'arn:aws:clouddirectory:us-east-1:12345678910:schema/development/cognito'
    elif shape_name == 'EnvironmentId':
        return 'arn:aws:cloudhsm:eu-central-1:315160724404:hapg-8e3be050'
    elif shape_name == 'NonEmptyString':
        return 'test'
    elif param_name == 'ProjectName':
        return 'test'
    elif shape_name == 'CommentId':
        return 'ff30b348EXAMPLEb9aa670f'
    elif shape_name == 'PullRequestId':
        return '8'
    elif shape_name == 'RetentionPeriodInDays':
        return '30'
    elif shape_name == 'DocumentClassifierArn':
        return 'arn:aws:comprehend:us-east-1:123456789012:document-classifier/test'
    elif param_name == 'ResourceArn':
        return 'arn:aws:iam::123456789012:user/David'


    
    elif param_name == 'PredictEndpoint':
        return 'https://realtime.machinelearning.us-east-1.amazonaws.com' 
    elif shape_name == 'arnType':
        return 'arn:aws:iam::123456789012:user/David'
    elif shape_name == 'accountAliasType':
        return 'abc'
    elif shape_name == 'OpenIDConnectProviderUrlType':
        return 'http://www.example.com'
    elif shape_name == 'DeletionTaskIdType':
        return 'task/aws-service-role/lex.amazonaws.com/AWSServiceRoleForLexBots/ec720f7a-c0ba-4838-be33-f72e1873dd52'

    # The shape must be a string and doesn't match a special case, so generate a string from the
    # given regex pattern

    pattern = '[a-z]+'
    if 'pattern' in shape:
        pattern = shape['pattern']

    # Sometimes xeger crashes for the regex's, so we hard-code some values
    if (pattern == "[\\p{L}\\p{Z}\\p{N}_.:/=+\\-@]+" or
        pattern == "[\\p{L}\\p{Z}\\p{N}_.:\\/=+\\-@]*" or
        pattern == "[\\p{L}\\p{Z}\\p{N}_.:/=+\\-@]*" or
        pattern == "[\\p{L}\\p{Z}\\p{N}_.:\\/=+\\-@]*"):
        return 'LZN'
    if pattern == "^[\\w-.+]+@[\\w-.+]+$":
        return "abc@example.com"
    if pattern == "arn:aws.*:kinesis:.*:\\d{12}:stream/.*":
        return "arn:aws:kinesis:us-east-1:123456789012:stream/example-stream-name"
    if pattern == '[\\u0020-\\uD7FF\\uE000-\\uFFFD\\uD800\\uDC00-\\uDBFF\\uDFFF\\r\\n\\t]*':
        return 'df-00627471SOVYZEXAMPLE'
    if pattern == 'arn:aws(-iso)?:cloudhsm:[a-zA-Z0-9\\-]*:[0-9]{12}:hsm-[0-9a-f]{8}':
        return 'arn:aws:cloudhsm:us-east-1:123456789012:hsm-00000000'
    if pattern == 'arn:aws(-iso)?:cloudhsm:[a-zA-Z0-9\\-]*:[0-9]{12}:hapg-[0-9a-f]{8}':
        return 'arn:aws:cloudhsm:us-east-1:123456789012:hapg-00000000'
    if pattern == '^[a-zA-Z0-9]{1,50}$':
        return 'test'
    if pattern == '^\\S+{1,256}$':
        return 'test'

    max_length = shape.get('max', 100)
    min_length = shape.get('min', 10) + 1
    # In the case of TaskInput in sagemaker.render_ui_template the max length is 128,000 bytes, so we just keep it at 1024 so it's not too crazy.
    if max_length > 1024 and 1024 > min_length:
        max_length = 1024
    x = Xeger(limit=max_length)
    pattern = pattern.replace('.*', '[a-z]*')
    
    try:
        value = x.xeger(pattern)
    except Exception as e:
        log.error('xeger crashed using pattern: \"{}\" for {}'.format(pattern, shape_name))
        raise e

    if value == '':
        value = 'a'

    # The reverse regex libraries don't seem to understand forward look-ahead tricks, so
    # to get this to correct size, we'll grow it by concatenating it, then truncate it.
    if len(value) < min_length:
        value = value * min_length
    if len(value) > max_length:
        value = value[:max_length]

    return value

def enumerate_services(config, services, dry_run=False):

    # Create a boto3 session to use for enumeration
    session = boto3.Session()

    authorized_calls = []

    for service in services:

        if service == 's3control':
            log.info('Skipping {} - End-points do not seem to be working'.format(service))
            continue

        if len(session.get_available_regions(service)) == 0:
            if service in ['budgets', 'ce', 'chime', 'cloudfront', 'iam', 'importexport', 'organizations', 'route53', 'sts', 'waf']:
                region = 'us-east-1'
            else:
                log.info('Skipping {} - No regions exist for this service'.format(service))
                continue
        else:
            if 'us-east-1' in session.get_available_regions(service):
                region = 'us-east-1'
            else:
                log.info('Skipping {} - Only available in {}'.format(service, session.get_available_regions(service)))
                continue

        # Create a service client
        log.info('Creating {} client...'.format(service))

        # Set the user-agent if specified in the config
        if config.get('user_agent', None):
            botocore_config.user_agent = config['user_agent']

        # Create a client with parameter validation off
        client = session.client(service, region_name=region, config=botocore_config)

        # Get the functions that you can call
        functions_list = get_boto_functions(client)

        # Get the service file
        service_file_json = get_service_json_files(config)

        # Get a list of params needed to make the serialization pass in botocore
        service_call_params = get_service_call_params(service_file_json[service])

        service_json = json.load(open(service_file_json[service]))

        # Loop through all the functions and call them
        for function in functions_list:
            # if not function[0].startswith('create_policy'):
            #     continue

            # The service_file_json doesn't have underscores in names so let's remove them
            function_key = function[0].replace('_','')

            # Session Name Can only be 64 characters long
            if len(function_key) > 64:
                session_name = function_key[:63]
                log.info('Session Name {} is for {}'.format(session_name, function_key))
            else:
                session_name = function_key

            # Set the session to the name of the API call we are making
            session = get_assume_role_session(
                account_number=config['account_number'],
                role=config['account_role'],
                session_id=session_name
            )

            new_client = session.client(service, region_name=region, config=botocore_config)
            new_functions_list = get_boto_functions(new_client)

            for new_func in new_functions_list:
                if new_func[0] == function[0]:

                    # We need to pull out the parameters needed in the requestUri, ex. /{Bucket}/{Key+} -> ['Bucket', 'Key']
                    params = re.findall('\{(.*?)\}', service_call_params.get(function_key, '/'))
                    params = [p.strip('+') for p in params]

                    try:
                        func_params = {}

                        # Automate parameter generation
                        function_name_CamelCase = snake_case_to_CamelCase(function[0])
                        function_json = service_json['operations'].get(function_name_CamelCase, {})
                        if function_json == {}:
                            log.error('Could not find {} in service json {}'.format(function_name_CamelCase, service_file_json[service]))
                            # TODO Raise this as an error
                        elif 'input' in function_json:
                            func_shape_name = function_json['input']['shape']
                            func_shape = service_json['shapes'][func_shape_name]

                            for required_param in func_shape.get('required', []):
                                param_shape_name = func_shape['members'][required_param]['shape']

                                param_shape = service_json['shapes'][param_shape_name]
                                param_value = get_value_for_shape(param_shape, param_shape_name, required_param, service_json)

                                func_params[required_param] = param_value

                        # Fix one-off functions
                        if function_name_CamelCase in ['ListServiceSpecificCredentials', 'ResetServiceSpecificCredential', 'ListServiceSpecificCredentials', 'DeleteServiceSpecificCredential', 'UpdateServiceSpecificCredential']:
                            func_params['UserName'] = 'abc'

                        log.info('Calling {}.{} with params {} in {}'.format(service, new_func[0], func_params, region))

                        if not dry_run:
                        	make_api_call(service, new_func, region, func_params)

                    except ClientError as e:
                        if ('AccessDenied' in str(e) or 
                            'UnauthorizedOperation' in str(e) or 
                            'ForbiddenException' in str(e) or
                            'NotAuthorizedException' in str(e)):
                            # TODO I need to check if these really all are the same as AccessDenied
                            log.debug(e)
                        else:
                            log.error(e)
                    except boto3.exceptions.S3UploadFailedError as e:
                        log.debug(e)
                    except TypeError as e:
                        log.debug(e)
                    except KeyError as e:
                        log.error('KeyError Exception: {}.{} - {}'.format(service, new_func[0], e))
                        #traceback.print_exc()
