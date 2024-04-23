from doctest import FAIL_FAST
import string
import random
from datetime import date, datetime
from multiprocessing import set_forkserver_preload
from os import link
from re import T
from unicodedata import name
from venv import create
from aws_cdk import (
    Duration,
    Stack,
    aws_s3 as s3,
    aws_cognito as cognito,
    aws_iam as iam,
    aws_dynamodb as dynamodb,
    aws_apigateway as apigateway,
    aws_logs as logs,
    aws_iot as iot,
    aws_iotevents as iotEvents,
    RemovalPolicy as removePolicy,
    aws_ec2 as ec2,
)

# todo: remove unused import
from constructs import Construct
from .customize_layer.customize_layer_micro_services import CustomizeLayerMicroservices
from .customize_layer.customize_layer_api_stack import CustomizeLayerApiStack
from .customize_layer.customize_layer_manage_stack import CustomizeLayerManageStack


class KasoIotFitOneCdkv2Stack(Stack):
    _remove_policy = removePolicy.DESTROY

    # cdk config
    application_name = ""
    environment = ""
    resource_name = ""
    region = ""
    account = ""
    secret_key = ""
    line_message_id = ""
    line_message_secret = ""
    line_message_token = ""
    firebase_messaging_key = ""
    canvas_nodejs_layer_path = ""
    alarm_topic_arn = ""
    aws_profile_name = ""

    # AWS resource
    iot_endpoint = ""
    user_pool = None
    app_client = None
    apigateway_manager = None
    gateway_policy = None
    gateway_policy_list = {}
    greengrass_policy = None
    iot_full_access_role = None
    bucket = None
    vpc = None
    vpc_endpoint = None
    greengrass_token_exchange_role = None

    # Tables
    sensor_data_table = None
    iot_core_access_key_table = None
    log_table = None
    log_table_category_index_name = None
    log_table_current_status_index_name = None
    log_data_path_index_name = None
    log_endpoint_index_name = None
    endpoint_info_table = None
    application_config_table = None
    endpoint_info_device_index_name = None
    endpoint_info_owner_index_name = None
    endpoint_data_path_index_name = None

    customize_data_table = None

    def __init__(self, scope: Construct, construct_id: str, **kwargs) -> None:
        super().__init__(scope, construct_id, **kwargs)
        self.account = self.node.try_get_context("account")
        self.region = self.node.try_get_context("region")
        self.iot_endpoint = self.node.try_get_context("iotEndpoint")
        self.application_name = self.node.try_get_context("applicationName")
        self.environment = self.node.try_get_context("environment")
        self.secret_key = self.node.try_get_context("SecretKey")
        self.line_login_client_id = self.node.try_get_context("LineLoginClientId")
        self.line_login_client_secret = self.node.try_get_context(
            "LineLoginClientSecret"
        )
        self.line_message_id = self.node.try_get_context("LineMessageId")
        self.line_message_secret = self.node.try_get_context("LineMessageSecret")
        self.line_message_token = self.node.try_get_context("LineMessageToken")
        self.firebase_messaging_key = self.node.try_get_context("FirebaseMessagingKey")
        self.ses_identity = self.node.try_get_context("SesIdentity")
        self.canvas_nodejs_layer_path = self.node.try_get_context(
            "CanvasNodejsLayerPath"
        )
        self.alarm_topic_arn = self.node.try_get_context("AlarmTopicArn")
        self.aws_profile_name = self.node.try_get_context("awsProfileName")

        self.resource_name = f"{self.application_name}_{self.environment}"

        self._createCognitoUserPool()
        self._createS3()
        self._createDynamoDB()
        self._initial_iam()
        self._initial_iot_core()
# 
        # # create stacks
        # self._create_core_stack()
        self._create_customize_layer_stack()

    def _create_customize_layer_stack(self):

        #######有注释
        # create customize layer lambda stack 
        self.cutomize_lambda_stack = CustomizeLayerMicroservices(self, "PfLamdaStack")

        #######有注释
        # create customize layer api stack  
        self.cutomize_api_stack = CustomizeLayerApiStack(
            self, "PfApiStack", self.cutomize_lambda_stack
        )
        self.cutomize_api_stack.add_dependency(self.cutomize_lambda_stack)

        #######有注释
        # create customize layer manage stack
        self.customize_manage_stack = CustomizeLayerManageStack(
            self, "PfManageStack", self.cutomize_lambda_stack
        )
        self.customize_manage_stack.add_dependency(self.cutomize_api_stack)

        return

    def _initial_iam(self):
        full_access_role = iam.Role(
            self,
            "IotCoreFullAccess",
            role_name=f"{self.application_name}-{self.environment}-IotCoreFullAccess",
            assumed_by=iam.CompositePrincipal(
                iam.ServicePrincipal("iot.amazonaws.com"), iam.AccountRootPrincipal()
            ),
            description="Only for iot credentials genertor API",
        )

        full_access_role.add_to_policy(
            iam.PolicyStatement(actions=["iot:*", "sts:*"], resources=["*"])
        )
        self.iot_full_access_role = full_access_role

        # For greengrass
        greengrass_token_exange_policy_doc = iam.PolicyDocument(
            statements=[
                iam.PolicyStatement(
                    effect=iam.Effect.ALLOW,
                    actions=[
                        "logs:CreateLogGroup",
                        "logs:CreateLogStream",
                        "logs:PutLogEvents",
                        "logs:DescribeLogStreams",
                        "s3:GetBucketLocation",
                    ],
                    resources=["*"],
                )
            ]
        )

        s3_access_policy_doc = iam.PolicyDocument(
            statements=[
                iam.PolicyStatement(
                    effect=iam.Effect.ALLOW, actions=["s3:*"], resources=["*"]
                )
            ]
        )

        mqtt_connection_policy_doc = iam.PolicyDocument(
            statements=[
                iam.PolicyStatement(
                    effect=iam.Effect.ALLOW,
                    actions=[
                        "greengrass:PutCertificateAuthorities",
                        "greengrass:VerifyClientDeviceIdentity",
                        "greengrass:VerifyClientDeviceIoTCertificateAssociation",
                        "greengrass:GetConnectivityInfo",
                        "greengrass:UpdateConnectivityInfo",
                    ],
                    resources=["*"],
                )
            ]
        )

        self.greengrass_token_exchange_role = iam.Role(
            self,
            f"{self.resource_name}-GreengrassTokenExchange",
            assumed_by=iam.ServicePrincipal("credentials.iot.amazonaws.com"),
            description="Greengrass token exchange role",
            inline_policies={
                "GreengrassV2TokenExchangeRoleAccess": greengrass_token_exange_policy_doc,
                "S3Access": s3_access_policy_doc,
                "CustomMqttConnect": mqtt_connection_policy_doc,
            },
        )

        # Allow Cognito send email via SES
        if self.ses_identity:
            identity = self.ses_identity.split("@")[1]
            iam.PolicyStatement(
                sid="AllowSendingFromCognito",
                effect=iam.Effect.ALLOW,
                principals=[iam.ServicePrincipal("cognito-idp.amazonaws.com")],
                actions=["ses:SendEmail", "ses:SendRawEmail"],
                resources=["*"],
                conditions={
                    "StringEquals": {
                        "aws:SourceAccount": self.account,
                    },
                    "ArnLike": {
                        "aws:SourceArn": f"arn:aws:ses:{self.region}:{self.account}:identity/{identity}"
                    },
                },
            )

    def _initial_iot_core(self):
        # gateway publish policy document
        gateway_publish_policy_document = {
            "Version": "2012-10-17",
            "Statement": [
                {
                    "Effect": "Allow",
                    "Action": "iot:Connect",
                    "Resource": f"arn:aws:iot:{self.region}:{self.account}:client/${{iot:Connection.Thing.ThingName}}",
                },
                {
                    "Effect": "Allow",
                    "Action": ["iot:Publish"],
                    "Resource": [
                        f"arn:aws:iot:{self.region}:{self.account}:topic/kaso/{self.resource_name.lower()}/gateway/${{iot:Connection.Thing.ThingName}}/data",
                        f"arn:aws:iot:{self.region}:{self.account}:topic/kaso/{self.resource_name.lower()}/gateway/${{iot:Connection.Thing.ThingName}}/log",
                        f"arn:aws:iot:{self.region}:{self.account}:topic/kaso/{self.resource_name.lower()}/gateway/${{iot:Connection.Thing.ThingName}}/command",
                        f"arn:aws:iot:{self.region}:{self.account}:topic/kaso/{self.resource_name.lower()}/gateway/${{iot:Connection.Thing.ThingName}}/*/request",
                    ],
                },
                {
                    "Effect": "Allow",
                    "Action": ["iot:RetainPublish"],
                    "Resource": [
                        f"arn:aws:iot:{self.region}:{self.account}:topic/kaso/{self.resource_name.lower()}/gateway/${{iot:Connection.Thing.ThingName}}/status"
                    ],
                },
            ],
        }

        policy_name = f"{self.resource_name}-iotGatewayPublishPolicy"
        self.gateway_policy_list["Publish"] = iot.CfnPolicy(
            self,
            policy_name,
            policy_document=gateway_publish_policy_document,
            policy_name=f"{policy_name}",
        )

        # gateway subscribe policy document
        gateway_subscribe_policy_document = {
            "Version": "2012-10-17",
            "Statement": [
                {
                    "Effect": "Allow",
                    "Action": [
                        "iot:Subscribe",
                    ],
                    "Resource": [
                        f"arn:aws:iot:{self.region}:{self.account}:topicfilter/kaso/{self.resource_name.lower()}/ruleEngine/${{iot:Connection.Thing.ThingName}}/command",
                        f"arn:aws:iot:{self.region}:{self.account}:topicfilter/kaso/{self.resource_name.lower()}/app/${{iot:Connection.Thing.ThingName}}/command",
                        f"arn:aws:iot:{self.region}:{self.account}:topicfilter/kaso/{self.resource_name.lower()}/ruleEngine/${{iot:Connection.Thing.ThingName}}/status",
                        f"arn:aws:iot:{self.region}:{self.account}:topicfilter/kaso/{self.resource_name.lower()}/app/${{iot:Connection.Thing.ThingName}}/status",
                        f"arn:aws:iot:{self.region}:{self.account}:topicfilter/kaso/{self.resource_name.lower()}/microservice/${{iot:Connection.Thing.ThingName}}/*/response",
                        f"arn:aws:iot:{self.region}:{self.account}:topicfilter/kaso/{self.resource_name.lower()}/ruleEngine/latestFirmwareVersion",
                        f"arn:aws:iot:{self.region}:{self.account}:topicfilter/kaso/{self.resource_name.lower()}/ruleEngine/${{iot:Connection.Thing.ThingName}}/alert",
                        f"arn:aws:iot:{self.region}:{self.account}:topicfilter/kaso/{self.resource_name.lower()}/ruleEngine/latestFirmwareVersion/*",
                    ],
                }
            ],
        }

        policy_name = f"{self.resource_name}-iotGatewaySubscribePolicy"
        self.gateway_policy_list["Subscribe"] = iot.CfnPolicy(
            self,
            policy_name,
            policy_document=gateway_subscribe_policy_document,
            policy_name=f"{policy_name}",
        )

        # gateway receive policy document
        gateway_receive_policy_document = {
            "Version": "2012-10-17",
            "Statement": [
                {
                    "Effect": "Allow",
                    "Action": ["iot:Receive"],
                    "Resource": [
                        f"arn:aws:iot:{self.region}:{self.account}:topic/kaso/{self.resource_name.lower()}/ruleEngine/${{iot:Connection.Thing.ThingName}}/command",
                        f"arn:aws:iot:{self.region}:{self.account}:topic/kaso/{self.resource_name.lower()}/app/${{iot:Connection.Thing.ThingName}}/command",
                        f"arn:aws:iot:{self.region}:{self.account}:topic/kaso/{self.resource_name.lower()}/ruleEngine/${{iot:Connection.Thing.ThingName}}/status",
                        f"arn:aws:iot:{self.region}:{self.account}:topic/kaso/{self.resource_name.lower()}/app/${{iot:Connection.Thing.ThingName}}/status",
                        f"arn:aws:iot:{self.region}:{self.account}:topic/kaso/{self.resource_name.lower()}/microservice/${{iot:Connection.Thing.ThingName}}/*/response",
                        f"arn:aws:iot:{self.region}:{self.account}:topic/kaso/{self.resource_name.lower()}/ruleEngine/latestFirmwareVersion",
                        f"arn:aws:iot:{self.region}:{self.account}:topic/kaso/{self.resource_name.lower()}/ruleEngine/${{iot:Connection.Thing.ThingName}}/alert",
                        f"arn:aws:iot:{self.region}:{self.account}:topic/kaso/{self.resource_name.lower()}/ruleEngine/latestFirmwareVersion/*",
                    ],
                }
            ],
        }

        policy_name = f"{self.resource_name}-iotGatewayReceivePolicy"
        self.gateway_policy_list["Receive"] = iot.CfnPolicy(
            self,
            policy_name,
            policy_document=gateway_receive_policy_document,
            policy_name=f"{policy_name}",
        )

        # For greengrass
        alias_name = f"{self.resource_name}-GreengrassTokenExchangeAlias"

        alias = iot.CfnRoleAlias(
            self,
            alias_name,
            role_arn=self.greengrass_token_exchange_role.role_arn,
            credential_duration_seconds=3600,
            role_alias=alias_name,
        )

        greengrass_policy_document = {
            "Version": "2012-10-17",
            "Statement": [
                {
                    "Effect": "Allow",
                    "Action": "iot:AssumeRoleWithCertificate",
                    "Resource": f"arn:aws:iot:{self.region}:{self.account}:rolealias/{alias_name}",
                },
                {"Effect": "Allow", "Action": "greengrass:*", "Resource": ["*"]},
                {
                    "Effect": "Allow",
                    "Action": [
                        "iot:Publish",
                        "iot:Subscribe",
                        "iot:Receive",
                        "iot:DescribeJobExecution",
                        "iot:GetPendingJobExecutions",
                        "iot:StartNextPendingJobExecution",
                        "iot:UpdateJobExecution",
                    ],
                    "Resource": [
                        f"arn:aws:iot:{self.region}:{self.account}:topic/$aws/things/${{iot:Connection.Thing.ThingName}}/*",
                        f"arn:aws:iot:{self.region}:{self.account}:topicfilter/$aws/things/${{iot:Connection.Thing.ThingName}}/*",
                    ],
                },
            ],
        }

        policy_name = f"{self.resource_name}-greengrassPolicy"
        self.greengrass_policy = iot.CfnPolicy(
            self,
            policy_name,
            policy_document=greengrass_policy_document,
            policy_name=f"{policy_name}",
        )

    def _createDynamoDB(self):
        billing_mode = dynamodb.BillingMode.PAY_PER_REQUEST
        # if self.environment == "Dev" or self.environment == "Qa":
        #     billing_mode = dynamodb.BillingMode.PAY_PER_REQUEST

        # if self.environment == "Prod":
        #     billing_mode = dynamodb.BillingMode.PROVISIONED

        table_list = []
        endpoint_table_name = "EndpointData"
        sensor_data_table = dynamodb.Table(
            self,
            id=f"dynamodb-{self.application_name}{endpoint_table_name}_{self.environment}",
            table_name=f"{self.application_name}{endpoint_table_name}_{self.environment}",
            partition_key=dynamodb.Attribute(
                name="thingName", type=dynamodb.AttributeType.STRING
            ),
            sort_key=dynamodb.Attribute(
                name="date", type=dynamodb.AttributeType.STRING
            ),
            billing_mode=billing_mode,
            table_class=dynamodb.TableClass.STANDARD,
            removal_policy=self._remove_policy,
        )

        endpoint_data_path_index_name = "EndpointData_PathIndex"
        endpoint_data_path_index_name = (
            f"{self.application_name}{endpoint_data_path_index_name}_{self.environment}"
        )
        sensor_data_table.add_global_secondary_index(
            index_name=endpoint_data_path_index_name,
            partition_key=dynamodb.Attribute(
                name="dataPath", type=dynamodb.AttributeType.STRING
            ),
            sort_key=dynamodb.Attribute(
                name="date", type=dynamodb.AttributeType.STRING
            ),
            projection_type=dynamodb.ProjectionType.ALL,
        )
        self.endpoint_data_path_index_name = endpoint_data_path_index_name

        table_list.append(sensor_data_table)
        self.sensor_data_table = sensor_data_table

        iot_core_access_key_table_name = "IotCoreAccessKey"
        iot_core_access_key_table = dynamodb.Table(
            self,
            id=f"dynamodb-{self.application_name}{iot_core_access_key_table_name}_{self.environment}",
            table_name=f"{self.application_name}{iot_core_access_key_table_name}_{self.environment}",
            partition_key=dynamodb.Attribute(
                name="thingName", type=dynamodb.AttributeType.STRING
            ),
            billing_mode=billing_mode,
            table_class=dynamodb.TableClass.STANDARD,
            removal_policy=self._remove_policy,
        )
        table_list.append(iot_core_access_key_table)
        self.iot_core_access_key_table = iot_core_access_key_table

        log_table_name = "Log"
        log_table = dynamodb.Table(
            self,
            id=f"dynamodb-{self.application_name}{log_table_name}_{self.environment}",
            table_name=f"{self.application_name}{log_table_name}_{self.environment}",
            partition_key=dynamodb.Attribute(
                name="type", type=dynamodb.AttributeType.STRING
            ),
            sort_key=dynamodb.Attribute(name="id", type=dynamodb.AttributeType.STRING),
            billing_mode=billing_mode,
            table_class=dynamodb.TableClass.STANDARD,
            removal_policy=self._remove_policy,
        )
        table_list.append(log_table)
        self.log_table = log_table

        # Index For gateway log query
        log_table_category_index_name = "Log_CategoryIndex"
        log_table_category_index_name = (
            f"{self.application_name}{log_table_category_index_name}_{self.environment}"
        )
        log_table.add_global_secondary_index(
            index_name=log_table_category_index_name,
            partition_key=dynamodb.Attribute(
                name="category", type=dynamodb.AttributeType.STRING
            ),
            sort_key=dynamodb.Attribute(name="id", type=dynamodb.AttributeType.STRING),
            projection_type=dynamodb.ProjectionType.ALL,
        )
        self.log_table_category_index_name = log_table_category_index_name

        # Index For unsolved log query
        log_table_current_status_index_name = "Log_CurrentStatusIndex"
        log_table_current_status_index_name = f"{self.application_name}{log_table_current_status_index_name}_{self.environment}"
        log_table.add_global_secondary_index(
            index_name=log_table_current_status_index_name,
            partition_key=dynamodb.Attribute(
                name="currentStatus", type=dynamodb.AttributeType.STRING
            ),
            sort_key=dynamodb.Attribute(name="id", type=dynamodb.AttributeType.STRING),
            projection_type=dynamodb.ProjectionType.ALL,
        )
        self.log_table_current_status_index_name = log_table_current_status_index_name

        # Index For dataPath (endpointType#areaId) query
        log_data_path_index_name = "Log_DataPathIndex"
        log_data_path_index_name = (
            f"{self.application_name}{log_data_path_index_name}_{self.environment}"
        )
        log_table.add_global_secondary_index(
            index_name=log_data_path_index_name,
            partition_key=dynamodb.Attribute(
                name="dataPath", type=dynamodb.AttributeType.STRING
            ),
            sort_key=dynamodb.Attribute(name="id", type=dynamodb.AttributeType.STRING),
            projection_type=dynamodb.ProjectionType.ALL,
        )
        self.log_data_path_index_name = log_data_path_index_name

        # Index For endpointType query
        log_endpoint_index_name = "Log_EndpointIndex"
        log_endpoint_index_name = (
            f"{self.application_name}{log_endpoint_index_name}_{self.environment}"
        )
        log_table.add_global_secondary_index(
            index_name=log_endpoint_index_name,
            partition_key=dynamodb.Attribute(
                name="endpointType", type=dynamodb.AttributeType.STRING
            ),
            sort_key=dynamodb.Attribute(name="id", type=dynamodb.AttributeType.STRING),
            projection_type=dynamodb.ProjectionType.ALL,
        )
        self.log_endpoint_index_name = log_endpoint_index_name

        endpoint_info_table_name = "EndpointInfo"
        endpoint_info_table = dynamodb.Table(
            self,
            id=f"dynamodb-{self.application_name}{endpoint_info_table_name}_{self.environment}",
            table_name=f"{self.application_name}{endpoint_info_table_name}_{self.environment}",
            partition_key=dynamodb.Attribute(
                name="type", type=dynamodb.AttributeType.STRING
            ),
            sort_key=dynamodb.Attribute(
                name="endpointId", type=dynamodb.AttributeType.STRING
            ),
            billing_mode=billing_mode,
            table_class=dynamodb.TableClass.STANDARD,
            removal_policy=self._remove_policy,
        )

        endpoint_info_device_index_name = "EndpointInfo_ThingNameIndex"
        endpoint_info_device_index_name = f"{self.application_name}{endpoint_info_device_index_name}_{self.environment}"
        endpoint_info_table.add_global_secondary_index(
            index_name=endpoint_info_device_index_name,
            partition_key=dynamodb.Attribute(
                name="thingName", type=dynamodb.AttributeType.STRING
            ),
            sort_key=dynamodb.Attribute(
                name="endpointId", type=dynamodb.AttributeType.STRING
            ),
            projection_type=dynamodb.ProjectionType.ALL,
        )
        self.endpoint_info_table = endpoint_info_table
        self.endpoint_info_device_index_name = endpoint_info_device_index_name

        endpoint_info_owner_index_name = "EndpointInfo_OwnerIndex"
        endpoint_info_owner_index_name = f"{self.application_name}{endpoint_info_owner_index_name}_{self.environment}"
        endpoint_info_table.add_global_secondary_index(
            index_name=endpoint_info_owner_index_name,
            partition_key=dynamodb.Attribute(
                name="owner", type=dynamodb.AttributeType.STRING
            ),
            sort_key=dynamodb.Attribute(
                name="endpointId", type=dynamodb.AttributeType.STRING
            ),
            projection_type=dynamodb.ProjectionType.ALL,
        )
        self.endpoint_info_owner_index_name = endpoint_info_owner_index_name

        table_list.append(endpoint_info_table)
        self.endpoint_info_table = endpoint_info_table

        application_config_table_name = "ApplicationConfig"
        application_config_table = dynamodb.Table(
            self,
            id=f"dynamodb-{self.application_name}{application_config_table_name}_{self.environment}",
            table_name=f"{self.application_name}{application_config_table_name}_{self.environment}",
            partition_key=dynamodb.Attribute(
                name="applicationId", type=dynamodb.AttributeType.STRING
            ),
            sort_key=dynamodb.Attribute(
                name="configId", type=dynamodb.AttributeType.STRING
            ),
            billing_mode=billing_mode,
            table_class=dynamodb.TableClass.STANDARD,
            removal_policy=self._remove_policy,
        )
        table_list.append(application_config_table)
        self.application_config_table = application_config_table

        customize_data_table_name = "CustomizeData"
        customize_data_table = dynamodb.Table(
            self,
            id=f"dynamodb-{self.application_name}{customize_data_table_name}_{self.environment}",
            table_name=f"{self.application_name}{customize_data_table_name}_{self.environment}",
            partition_key=dynamodb.Attribute(
                name="partitionKey", type=dynamodb.AttributeType.STRING
            ),
            sort_key=dynamodb.Attribute(
                name="sortKey", type=dynamodb.AttributeType.STRING
            ),
            billing_mode=billing_mode,
            table_class=dynamodb.TableClass.STANDARD,
            removal_policy=self._remove_policy,
        )
        table_list.append(customize_data_table)
        self.customize_data_table = customize_data_table

        state_table_name = "State"
        state_table = dynamodb.Table(
            self,
            id=f"dynamodb-{self.application_name}{state_table_name}_{self.environment}",
            table_name=f"{self.application_name}{state_table_name}_{self.environment}",
            partition_key=dynamodb.Attribute(
                name="partitionKey", type=dynamodb.AttributeType.STRING
            ),
            sort_key=dynamodb.Attribute(
                name="sortKey", type=dynamodb.AttributeType.STRING
            ),
            billing_mode=billing_mode,
            table_class=dynamodb.TableClass.STANDARD,
            removal_policy=self._remove_policy,
        )
        table_list.append(state_table)
        self.state_table = state_table

    def _createS3(self):
        bucket = s3.Bucket(
            self,
            id=f"s3-{self.resource_name}",
            bucket_name=f"{self.application_name.lower()}-{self.environment.lower()}",
            removal_policy=self._remove_policy,
            auto_delete_objects=True,
            cors=[
                s3.CorsRule(
                    allowed_headers=["*"],
                    allowed_origins=["*"],
                    allowed_methods=[
                        s3.HttpMethods.GET,
                        s3.HttpMethods.PUT,
                        s3.HttpMethods.POST,
                    ],
                    exposed_headers=[],
                )
            ],
        )

        # create a policy statement to restrict access to the bucket based on lambda function name
        lambda_name_condition = {
            "StringLike": {
                "aws:ResourceTag/aws:lambda:createdBy": f"{self.resource_name}*"
            }
        }
        lambda_restricted_statement = iam.PolicyStatement(
            actions=["s3:*"],
            resources=[bucket.bucket_arn, f"{bucket.bucket_arn}/*"],
            conditions=lambda_name_condition,
            principals=[iam.ServicePrincipal("lambda.amazonaws.com")],
        )

        # add the policy statement to the bucket
        bucket.add_to_resource_policy(lambda_restricted_statement)
        self.bucket = bucket

        # Create an S3 bucket for static website hosting
        web_bucket_name = (
            f"{self.application_name}-{self.environment}-static-web-hosting"
        )
        web_bucket_name = web_bucket_name.lower()

        web_bucket = s3.Bucket(
            self,
            web_bucket_name,
            bucket_name=web_bucket_name,
            website_index_document="index.html",
            website_error_document="error.html",
            public_read_access=True,
            removal_policy=self._remove_policy,
            block_public_access=s3.BlockPublicAccess(
                block_public_acls=True,
                ignore_public_acls=True,
                block_public_policy=False,
                restrict_public_buckets=False,
            ),
        )

        web_bucket.add_to_resource_policy(
            iam.PolicyStatement(
                effect=iam.Effect.ALLOW,
                principals=[iam.AnyPrincipal()],
                actions=["s3:GetObject"],
                resources=[f"arn:aws:s3:::{web_bucket_name}/*"],
            )
        )

    class MockedUserPool:
        def __init__(self) -> None:
            self.user_pool_id = "None"
            self.user_pool_client_id = "None"

        def add_trigger(self, a, b):
            pass

    def _createCognitoUserPool(self):
        goog_client_id = self.node.try_get_context("googClientId")
        google_client_secret = self.node.try_get_context("googleClientSecret")
        apple_service_id = self.node.try_get_context("appleServiceId")
        apple_team_id = self.node.try_get_context("appleTeamId")
        apple_key_id = self.node.try_get_context("appleKeyId")
        apple_private_key = self.node.try_get_context("applePrivateKey")
        # ident_provider_list = [cognito.UserPoolClientIdentityProvider.COGNITO]
        web_app_rul = self.node.try_get_context("web_app_rul")
        is_need_oauth = False

        invit_mail_body = ""
        if web_app_rul:
            invit_mail_body = f'<p>ログインパスワード：「<span style="color: red">{{####}}</span>」</p><p>システムリンク:{web_app_rul}</p><p>ログインするには、<span style="color: red">メールアドレス</span>と一時的なパスワード:<span style="color: red">{{####}}</span>を使用してください。</p><p style="display: none;">ユニークな識別子は<strong>{{username}}</strong>です。</p>'
        else:
            invit_mail_body = f'<p>ログインパスワード：「<span style="color: red">{{####}}</span>」</p><p>ログインするには、<span style="color: red">メールアドレス</span>と一時的なパスワード:<span style="color: red">{{####}}</span>を使用してください。</p><p style="display: none;">ユニークな識別子は<strong>{{username}}</strong>です。</p>'

        callback_urls = []
        self.user_pool = self.MockedUserPool()
        self.app_client = self.MockedUserPool()
