from datetime import date, datetime
from aws_cdk import (
    Duration,
    NestedStack,
    RemovalPolicy as removePolicy,
    aws_apigateway as apigateway,
    aws_logs as logs,
)
from constructs import Construct
import copy
from kaso_iot_fit_one_cdkv2.shared.cdk_utility import CdkUtility


class CustomizeLayerApiStack(NestedStack):
    _remove_policy = removePolicy.DESTROY
    # cdk config
    application_name = ""
    environment = ""
    resource_name = ""
    region = ""
    account = ""
    document_version = ""

    # constant
    _schema_object = apigateway.JsonSchema(type=apigateway.JsonSchemaType.OBJECT)
    _schema_integer = apigateway.JsonSchema(type=apigateway.JsonSchemaType.INTEGER)
    _schema_string = apigateway.JsonSchema(type=apigateway.JsonSchemaType.STRING)
    _schema_object_array = apigateway.JsonSchema(
        type=apigateway.JsonSchemaType.ARRAY, items=_schema_object
    )
    _schema_string_array = apigateway.JsonSchema(
        type=apigateway.JsonSchemaType.ARRAY, items=_schema_string
    )
    _schema_boolean = apigateway.JsonSchema(type=apigateway.JsonSchemaType.BOOLEAN)
    _schema_null = apigateway.JsonSchema(type=apigateway.JsonSchemaType.NULL)

    # AWS resource
    iot_endpoint = ""
    user_pool = None
    app_client = None
    apigateway_manager = None
    gateway_policy = None
    iot_full_access_role = None
    bucket = None
    apigateway_authorizer = None
    api = None

    # CDK class
    _microservice = None
    _method_list = []
    _doc_list = []
    _model_list = []
    _dependency_list = []

    # resource in main stack
    _main_stack = None
    _api_stack = None
    _custom_api_stack = None

    def __init__(self, scope: Construct, construct_id: str, microService) -> None:
        super().__init__(scope, construct_id)

        self._microservice = microService

        todays_date = date.today()
        now = datetime.now()
        api_version = f"v{str(todays_date.year)}.{str(todays_date.month).zfill(2)}.{str(todays_date.day).zfill(2)}.{str(now.hour).zfill(2)}.{str(now.minute).zfill(2)}"

        # cdk config
        self.region = scope.region
        self.account = scope.account
        self.resource_name = scope.resource_name
        self.application_name = scope.application_name
        self.environment = scope.environment
        self._main_stack = scope

        self._microservice = microService

        self.document_version = api_version

        allow_headers = apigateway.Cors.DEFAULT_HEADERS
        allow_headers.append("path")
        allow_headers.append("filename")

        # apigateway_log_group = logs.LogGroup(
        #     self,
        #     f"{self.resource_name}-apigateway_pf-log",
        #     log_group_name=f"/aws/apigateway/{self.resource_name}_pf",
        #     retention=logs.RetentionDays.ONE_YEAR,
        #     removal_policy=self._remove_policy,
        # )

        #prepare authentication lambda for api gateway
        # self.create_api_authenticate()

        # self.apigateway_authorizer = apigateway.TokenAuthorizer(
        #     self,
        #     f"{self.resource_name}-PfApigatewayCustomAuthorizer",
        #     identity_source="method.request.header.Authorization",
        #     handler=self.apigateway_auth_function,
        #     results_cache_ttl=Duration.seconds(0),
        # )

        self.api = apigateway.RestApi(
            self,
            f"{self.resource_name}-apigateway_pf",
            rest_api_name=f"{self.resource_name}_pf",
            deploy_options=apigateway.StageOptions(
                stage_name=f"{self.application_name}",
                data_trace_enabled=False,
                metrics_enabled=False,
                logging_level=apigateway.MethodLoggingLevel.OFF,
                #   access_log_destination=apigateway.LogGroupLogDestination(apigateway_log_group),
                #   access_log_format=apigateway.AccessLogFormat.json_with_standard_fields(caller=True, http_method=True, ip=True,
                #                                                                          protocol=True, request_time=True, resource_path=True,
                #                                                                          response_length=True, status=True, user=True),
                #   documentation_version=self.document_version
            ),
            default_cors_preflight_options=apigateway.CorsOptions(
                allow_origins=apigateway.Cors.ALL_ORIGINS,
                allow_methods=apigateway.Cors.ALL_METHODS,
                allow_headers=allow_headers,
                status_code=200,
            ),
            default_method_options=apigateway.MethodOptions(authorizer=None),
            binary_media_types=[
                "image/png",
                "image/bmp",
                "image/gif",
                "image/jpeg",
                "application/octet-stream",
            ],
        )

        self.create_all_api()

    def create_api_authenticate(self):
        # Apigateway Auth
        function_name = "ApigatewayAuth_PF"
        function_id = "apigatewayAuthHandler_PF"
        function_handler_name = "listApiFunctionsHandler"
        entry_path = "./IotMicroservices/customizeLayer/handlers/Application/listApiFunctions.mjs"
        policy_list = None
        environment_map = {
            "UserPoolId": f"{self._main_stack.user_pool.user_pool_id}",
            "AppClientId": f"{self._main_stack.app_client.user_pool_client_id}",
        }
        self.apigateway_auth_function = CdkUtility.addNewFunction(
            self,
            self.resource_name,
            function_name=function_name,
            function_id=function_id,
            function_handler_name=function_handler_name,
            entry_path=entry_path,
            policy_list=policy_list,
            environment_map=environment_map,
        )

    def create_all_api(self):
        # apiVersion = apigateway.CfnDocumentationVersion(self, f"{self.resource_name}-apigateway_pf-document-{self.document_version}",
        #                                                 rest_api_id=self.api.rest_api_id, documentation_version=self.document_version, description="PlantFactory custom API")
        # self._doc_list.append(apiVersion)

        self.create_iam_api()

    def attach_dependencies(self):
        for idx, item in enumerate(self._model_list):
            if idx >= len(self._model_list) - 1:
                break
            self._model_list[idx].node.add_dependency(self._model_list[idx + 1])

        for idx, item in enumerate(self._doc_list):
            if idx >= len(self._doc_list) - 1:
                self._doc_list[idx].node.add_dependency(
                    self._model_list[len(self._model_list) - 1]
                )
                break
            self._doc_list[idx].add_depends_on(self._doc_list[idx + 1])

    def create_iam_api(self):
        # Login API
        self._addNewMethod(
            method_name="Auth",
            http_method="GET",
            path="login",
            lambda_function=self._microservice.function_map["login"],
            is_need_auth=False,
            tags="IAM",
            description="Get token by username and password.",
        )

        

    def create_application_api(self):
        # Query API usage log
        self._addNewMethod(
            method_name="QueryApiUsageLog",
            http_method="GET",
            path="queryapiusagelog",
            lambda_function=self._microservice.function_map["queryApiUsageLog"],
            is_need_auth=True,
            tags="Application",
            description="Query api usage log",
        )

        # Add alert rule
        self._addNewMethod(
            method_name="AddAlertRule",
            http_method="POST",
            path="addalertrule",
            lambda_function=self._microservice.function_map["AddAlertRule"],
            is_need_auth=True,
            tags="Application",
            description="Add new alert rule",
        )

        # List all alert rule
        self._addNewMethod(
            method_name="ListAllAlertRule",
            http_method="GET",
            path="listallalertrule",
            lambda_function=self._microservice.function_map["ListAllAlertRule"],
            is_need_auth=True,
            tags="Application",
            description="List all alert rule",  
        )

        # Copy alert rule API
        self._addNewMethod(
            method_name="CopyAlertRule",
            http_method="POST",
            path="copyalertrule",
            lambda_function=self._microservice.function_map["CopyAlertRule"],
            is_need_auth=True,
            tags="Application",
            description="Copy new alert rule by existing alert rule id",
        )

        # Update alert rule
        self._addNewMethod(
            method_name="UpdateAlertRule",
            http_method="POST",
            path="updatealertrule",
            lambda_function=self._microservice.function_map["UpdateAlertRule"],
            is_need_auth=True,
            tags="Application",
            description="Update aleart rule group by alertRuleId",
        )

        # Delete alert rule
        self._addNewMethod(
            method_name="DeleteAlertRule",
            http_method="POST",
            path="deletealertrule",
            lambda_function=self._microservice.function_map["DeleteAlertRule"],
            is_need_auth=True,
            tags="Application",
            description="Delete aleart rule group by alertRuleId",
        )

        # List Dashboard Config
        self._addNewMethod(
            method_name="ListDashboardConfig",
            http_method="GET",
            path="listdashboardconfig",
            lambda_function=self._microservice.function_map["ListDashboardConfig"],
            is_need_auth=True,
            tags="Application",
            description="List Dashboard Config",
        )

        # Delete Dashboard Config
        self._addNewMethod(
            method_name="DeleteDashboardConfig",
            http_method="POST",
            path="deletedashboardconfig",
            lambda_function=self._microservice.function_map["DeleteDashboardConfig"],
            is_need_auth=True,
            tags="Application",
            description="Delete Dashboard Config by alertRuleId",
        )

        # Save Dashboard Config
        self._addNewMethod(
            method_name="SaveDashboardConfig",
            http_method="POST",
            path="savedashboardconfig",
            lambda_function=self._microservice.function_map["SaveDashboardConfig"],
            is_need_auth=True,
            tags="Application",
            description="save Dashboard Config",
        )

        # Query gateway log
        self._addNewMethod(
            method_name="QueryGatewayLog",
            http_method="GET",
            path="querygatewaylog",
            lambda_function=self._microservice.function_map["QueryGatewayLog"],
            is_need_auth=True,
            tags="Application",
            description="Qery gateway log by thingName",
        )

        # List all alert rule
        self._addNewMethod(
            method_name="ListApiFunctions",
            http_method="GET",
            path="listapifunction",
            lambda_function=self._microservice.function_map["ListApiFunctions"],
            is_need_auth=True,
            tags="Application",
            description="List api function",
        )

        # Get sensor menu config
        self._addNewMethod(
            method_name="GetSensorMenuConfig",
            http_method="GET",
            path="getsensormenuconfig",
            lambda_function=self._microservice.function_map["GetSensorMenuConfig"],
            is_need_auth=True,
            tags="Application",
            description="Get the sensor menu setting for the factory",
        )

        # List all unsolved alert
        self._addNewMethod(
            method_name="ListUnsolvedAlert",
            http_method="GET",
            path="listunsolvedalert",
            lambda_function=self._microservice.function_map["ListUnsolvedAlert"],
            is_need_auth=True,
            tags="Application",
            description="List all unsolved alert",
        )

        # Edit Areas
        self._addNewMethod(
            method_name="EditAreas",
            http_method="POST",
            path="editareas",
            lambda_function=self._microservice.function_map["EditAreas"],
            is_need_auth=True,
            tags="Application",
            description="edit areas",
        )

        # Query alert
        self._addNewMethod(
            method_name="QueryAlertHandler",
            http_method="GET",
            path="queryalert",
            lambda_function=self._microservice.function_map["QueryAlert"],
            is_need_auth=True,
            tags="Application",
            description="Query alert log",
        )

        # Query thing alive log
        self._addNewMethod(
            method_name="QueryThingAliveLog",
            http_method="GET",
            path="querythingalivelog",
            lambda_function=self._microservice.function_map["QueryThingAliveLog"],
            is_need_auth=True,
            tags="Application",
            description="Query alive log of IoTGateway",
        )

        # Alert Solved API
        self._addNewMethod(
            method_name="AlertSolved",
            http_method="POST",
            path="alertsolved",
            lambda_function=self._microservice.function_map["AlertSolved"],
            is_need_auth=True,
            tags="Application",
            description="Make the alert be solved status",
        )

        # List all area API
        self._addNewMethod(
            method_name="ListAreas",
            http_method="GET",
            path="listareas",
            lambda_function=self._microservice.function_map["listAreas"],
            is_need_auth=True,
            tags="CustomFunction",
            description="List all Area",
        )

    def create_device_manage_api(self):
        # (deprecated)Get All IoT things
        self._addNewMethod(
            method_name="GetAllThings",
            http_method="GET",
            path="getallthings",
            lambda_function=self._microservice.function_map["getAllIoTDevices_pf"],
            is_need_auth=True,
            tags="DeviceManage",
            description="Get all IoT things in AWS IoT Core",
        )

        # List All thing info
        self._addNewMethod(
            method_name="ListThingInfo",
            http_method="GET",
            path="listthinginfo",
            lambda_function=self._microservice.function_map["ListThingInfo_pf"],
            is_need_auth=True,
            tags="DeviceManage",
            description="Get all IoT things in AWS IoT Core",
        )

        # List All thing status
        self._addNewMethod(
            method_name="ListThingStatus",
            http_method="GET",
            path="listthingstatus",
            lambda_function=self._microservice.function_map["ListThingStatus_pf"],
            is_need_auth=True,
            tags="DeviceManage",
            description="Get all IoT things in AWS IoT Core",
        )

        self._addNewMethod(
            method_name="QueryThingByOwner",
            http_method="GET",
            path="querythingbyowner",
            lambda_function=self._microservice.function_map["queryThingByOwner_pf"],
            is_need_auth=True,
            tags="DeviceManage",
            description="Get IoT things by owner in AWS IoT Core",
        )

        # Update IoT thing
        self._addNewMethod(
            method_name="UpdateThing",
            http_method="POST",
            path="updatething",
            lambda_function=self._microservice.function_map["UpdateThing_pf"],
            is_need_auth=True,
            tags="DeviceManage",
            description="Modify IoT gateway attributes",
        )

        self._addNewMethod(
            method_name="DeleteThing",
            http_method="POST",
            path="deletething",
            lambda_function=self._microservice.function_map["DeleteThing"],
            is_need_auth=True,
            tags="DeviceManage",
            description="delete Iot gateway",
        )

        # Add new endpoint instance API
        self._addNewMethod(
            method_name="AddNewEndpoint",
            http_method="POST",
            path="addnewendpoint",
            lambda_function=self._microservice.function_map["AddNewEndpoint"],
            is_need_auth=True,
            tags="DeviceManage",
            description="Add new endpint instance",
        )

        # List endpoint info
        self._addNewMethod(
            method_name="ListEndpointInfo",
            http_method="GET",
            path="listendpointinfo",
            lambda_function=self._microservice.function_map["ListEndpointInfo_pf"],
            is_need_auth=True,
            tags="DeviceManage",
            description="Get all supported endpoint master info",
        )

        # List endpoint instance info
        self._addNewMethod(
            method_name="ListEndpointInstance",
            http_method="GET",
            path="listendpointinstance",
            lambda_function=self._microservice.function_map["ListEndpointInstance_pf"],
            is_need_auth=True,
            tags="DeviceManage",
            description="Get all endpoint instance",
        )

        # Update endpoint instance API
        self._addNewMethod(
            method_name="UpdateEndpoint",
            http_method="POST",
            path="updateendpoint",
            lambda_function=self._microservice.function_map[
                "UpdateEndpointInstance_pf"
            ],
            is_need_auth=True,
            tags="DeviceManage",
            description="Update endpint instance",
        )

        # Delete endpoint instance API
        self._addNewMethod(
            method_name="DeleteEndpointInstance",
            http_method="POST",
            path="deleteendpointinstance",
            lambda_function=self._microservice.function_map[
                "DeleteEndpointInstance_pf"
            ],
            is_need_auth=True,
            tags="DeviceManage",
            description="Delete endpoint instance",
        )

        # Attach endpoint to thing API
        self._addNewMethod(
            method_name="AttachEndpoint",
            http_method="POST",
            path="attachendpoint",
            lambda_function=self._microservice.function_map["AttachEndpoint"],
            is_need_auth=True,
            tags="DeviceManage",
            description="Attached endpoint list to iot thing",
        )

        # Detach endpoint to thing API
        self._addNewMethod(
            method_name="DetachEndpoint",
            http_method="POST",
            path="detachendpoint",
            lambda_function=self._microservice.function_map["DetachEndpoint"],
            is_need_auth=True,
            tags="DeviceManage",
            description="Detached endpoint list from iot thing",
        )

        # List endpoint by thingName API
        self._addNewMethod(
            method_name="ListEndpointByThingName",
            http_method="GET",
            path="listendpointbythingname",
            lambda_function=self._microservice.function_map["ListEndpointByThingName"],
            is_need_auth=True,
            tags="DeviceManage",
            description="List all attached endpoint by thingName",
        )

        # Create new thing API
        self._addNewMethod(
            method_name="CreateNewThing",
            http_method="POST",
            path="createnewthing",
            lambda_function=self._microservice.function_map["CreateNewThing_pf"],
            is_need_auth=True,
            tags="DeviceManage",
            description="Create new IoT Gateway",
        )

        # Download access key API
        self._addNewMethod(
            method_name="DownloadAccessKey",
            http_method="GET",
            path="downloadaccesskey",
            lambda_function=self._microservice.function_map["DownloadAccessKey_pf"],
            is_need_auth=True,
            tags="DeviceManage",
            description="Download credentials as zip file for AWS IoT Core access",
        )

        # Thing exchange API
        self._addNewMethod(
            method_name="ThingExchange",
            http_method="POST",
            path="thingexchange",
            lambda_function=self._microservice.function_map["ThingExchange"],
            is_need_auth=True,
            tags="DeviceManage",
            description="Exchange thing attributes and attached endpoints ",
        )

        # Endpoint exchange API
        self._addNewMethod(
            method_name="EndpointExchange",
            http_method="POST",
            path="endpointexchange",
            lambda_function=self._microservice.function_map["EndpointExchange"],
            is_need_auth=True,
            tags="DeviceManage",
            description="Exchange endpoint attributes and attached thing",
        )

        # List all gateway type API
        self._addNewMethod(
            method_name="ListGatewayTyp",
            http_method="GET",
            path="listgatewaytype",
            lambda_function=self._microservice.function_map["ListGatewayType"],
            is_need_auth=True,
            tags="DeviceManage",
            description="Get all gateway type",
        )

        # Upload esp32 firmware
        self._addNewMethod(
            method_name="UploadEsp32Firmware",
            http_method="POST",
            path="uploadesp32firmware",
            lambda_function=self._microservice.function_map["UploadEsp32Firmware_pf"],
            is_need_auth=True,
            tags="DeviceManage",
            description="Upload esp32 binfile",
        )

    def create_data_process_api(self):
        # query sensor data API
        self._addNewMethod(
            method_name="QueryEndpointValue",
            http_method="GET",
            path="queryendpointvalue",
            lambda_function=self._microservice.function_map["QueryEndpointValue_pf"],
            is_need_auth=True,
            tags="DataProcess",
            description="Qery endpoint value by endpointType and areaId",
        )

        # Get S3 Pre-Signed Url
        self._addNewMethod(
            method_name="GetS3PreSignedUrl",
            http_method="GET",
            path="gets3presignedurl",
            lambda_function=self._microservice.function_map["GetS3PreSignedUrl_pf"],
            is_need_auth=True,
            tags="DataProcess",
            description="Get pre signed url of the file in s3",
        )

        # Get image files download link
        # request_query_string = {"fileList": True}
        self._addNewMethod(
            method_name="GetImageFilesDownloadLink",
            http_method="POST",
            path="getImageFilesDownloadLink",
            lambda_function=self._microservice.function_map[
                "GetImageFilesDownloadLink"
            ],
            is_need_auth=True,
            tags="DataProcess",
            description="Get image files download link",
        )

        # Upload File API
        self._addNewMethod(
            method_name="uploadFile",
            http_method="POST",
            path="uploadfiles3",
            lambda_function=self._microservice.function_map["upload_file_function"],
            is_need_auth=True,
            tags="DataProcess",
            description="Upload binary file, attach file to body with base64 encode then put path and fileName to header",
        )

    def create_switch_bot_api(self):
        # Webhook
        self._addNewMethod(
            method_name="SwitchBotEventWebhook",
            http_method="POST",
            path="switchboteventwebhook",
            lambda_function=self._microservice.function_map["SwitchBotEventWebhook"],
            is_need_auth=False,
            tags="SwitchBot",
            description="Webhook handler for switch bot",
        )

        # Infrared device control
        self._addNewMethod(
            method_name="InfraredDeviceControl",
            http_method="POST",
            path="infrareddevicecontrol",
            lambda_function=self._microservice.function_map["InfraredDeviceControl"],
            is_need_auth=True,
            tags="SwitchBot",
            description="SwitchBot Infrared Device Control",
        )

        # Plugcontrol
        self._addNewMethod(
            method_name="PlugControl",
            http_method="POST",
            path="plugcontrol",
            lambda_function=self._microservice.function_map["PlugControl"],
            is_need_auth=True,
            tags="SwitchBot",
            description="SwitchBot Plug Control",
        )

        # Keypad password setting
        self._addNewMethod(
            method_name="SetPassword",
            http_method="POST",
            path="setpassword",
            lambda_function=self._microservice.function_map["SetPassword"],
            is_need_auth=True,
            tags="SwitchBot",
            description="SwitchBot Keypad password setting",
        )

        # Extract keypad password list
        self._addNewMethod(
            method_name="ExtractPassword",
            http_method="GET",
            path="extractpassword",
            lambda_function=self._microservice.function_map["ExtractPassword"],
            is_need_auth=True,
            tags="SwitchBot",
            description="Extract keypad password",
        )

        # Remove keypad  password
        self._addNewMethod(
            method_name="RemovePassword",
            http_method="POST",
            path="removepassword",
            lambda_function=self._microservice.function_map["RemovePassword"],
            is_need_auth=True,
            tags="SwitchBot",
            description="Remove password from SwitchBot server",
        )

        # Locker control
        self._addNewMethod(
            method_name="LockerControl",
            http_method="POST",
            path="lockercontrol",
            lambda_function=self._microservice.function_map["LockerControl"],
            is_need_auth=True,
            tags="SwitchBot",
            description="Send control command to locker",
        )

        # Set Admin Password
        self._addNewMethod(
            method_name="SetAdminPassword",
            http_method="POST",
            path="setadminpassword",
            lambda_function=self._microservice.function_map["SetAdminPassword"],
            is_need_auth=True,
            tags="SwitchBot",
            description="Add an admin password to SwitchBot keypad",
        )

    def create_messaging_api(self):
        # List Message Group
        self._addNewMethod(
            method_name="ListMessageGroup",
            http_method="GET",
            path="listmessagegroup",
            lambda_function=self._microservice.function_map["ListMessageGroup_pf"],
            is_need_auth=True,
            tags="Messaging",
            description="List message group",
        )

        # Add Message Group
        self._addNewMethod(
            method_name="AddMessageGroup",
            http_method="POST",
            path="addmessagegroup",
            lambda_function=self._microservice.function_map["AddMessageGroup_pf"],
            is_need_auth=True,
            tags="Messaging",
            description="Add message group",
        )

        # Update Message Group
        self._addNewMethod(
            method_name="UpdateMessageGroup",
            http_method="POST",
            path="updatemessagegroup",
            lambda_function=self._microservice.function_map["UpdateMessageGroup_pf"],
            is_need_auth=True,
            tags="Messaging",
            description="Update message group",
        )

        # Delete Message Group
        self._addNewMethod(
            method_name="DeleteMessageGroup",
            http_method="POST",
            path="deletemessagegroup",
            lambda_function=self._microservice.function_map["DeleteMessageGroup_pj"],
            is_need_auth=True,
            tags="Messaging",
            description="Delete message group",
        )

    def _addNewMethod(
        self,
        method_name,
        http_method,
        path,
        lambda_function,
        is_need_auth,
        tags,
        description,
        response_schema=None,
        request_schema=None,
        request_query_string=None,
        request_parameters={},
    ):
        request_model, response_model, doc_obj, method = CdkUtility.addNewMethod(
            self,
            method_name,
            http_method,
            path,
            lambda_function,
            self.resource_name,
            is_need_auth,
            tags,
            description,
            self.apigateway_authorizer,
            self.api,
            request_query_string,
            request_parameters,
            is_pf_api=True,
        )

    ###########################################Custom part########################################
    def create_custom_api(self):
        pass
