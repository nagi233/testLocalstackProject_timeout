from aws_cdk import (
    Duration,
    aws_iam as iam,
    aws_lambda_nodejs as lambda_nodejs,
    aws_lambda as lambda_,
    aws_iot as iot,
    aws_ec2 as ec2,
    NestedStack,
    aws_apigateway as apigateway,
)

from kaso_iot_fit_one_cdkv2.shared.cdk_utility import CdkUtility
from constructs import Construct


class CustomizeLayerMicroservices(NestedStack):
    function_map = {}

    _region = None
    _account = None
    _resource_name = None

    _core_api_stack = None
    _custom_api_stack = None
    _main_stack = None
    _lambda_memory_size = 1024

    apigateway_auth_function = None

    def __init__(self, scope: Construct, construct_id: str) -> None:
        super().__init__(scope, construct_id)

        self._main_stack = scope
        self._custom_api_stack = self

        self._region = scope.region
        self._account = scope.account
        self._resource_name = self._main_stack.resource_name

        self.create_all_microservices()

    def create_all_microservices(self):
        self.create_iam_microservices()
        
        # self.create_application_microservices()#有注释
        # self.create_device_manage_microservices()#有注释
        # self.create_data_process_microservice()
        # self.create_switch_bot_microservice()
        # self.create_message_microservice()#有注释
        # self.create_custom_microservices()

    def create_iam_microservices(self):
        entry_path_test = "./IotMicroservices/customizeLayer/handlers/Application/listApiFunctions.mjs"
        # Login Function
        lambdaFunctionName = f"{self._resource_name}-Auth"
        function_name = "Login_PF"
        function_id = "loginHandler_pf"
        function_handler_name = "loginHandler"
        entry_path = "./IotMicroservices/customizeLayer/handlers/Application/listApiFunctions.mjs"
        policy_list = [
            iam.PolicyStatement(
                effect=iam.Effect.ALLOW,
                actions=["dynamodb:PutItem"],
                resources=[
                    f"arn:aws:dynamodb:{self._region}:{self._account}:table/{self._main_stack.log_table.table_name}"
                ],
            ),
            iam.PolicyStatement(
                effect=iam.Effect.ALLOW,
                actions=["lambda:InvokeFunction"],
                resources=[
                    f"arn:aws:lambda:{self._region}:{self._account}:function:{lambdaFunctionName}"
                ],
            ),
        ]
        environment_map = {
            "LambdaFunctionName": lambdaFunctionName,
            "LogTableName": self._main_stack.log_table.table_name,
        }
        function = CdkUtility.addNewFunction(
            self._custom_api_stack,
            self._resource_name,
            function_name=function_name,
            function_id=function_id,
            function_handler_name=function_handler_name,
            entry_path=entry_path_test,
            policy_list=policy_list,
            environment_map=environment_map,
        )
        self.function_map["login"] = function

        # Reset Password Request Function
        # lambdaFunctionName = f"{self._resource_name}-ResetPasswordRequest"

        # function_name = "ResetPasswordRequest_PF"
        # function_id = "resetPasswordRequestHandler_pf"
        # function_handler_name = "resetPasswordRequestHandler"
        # entry_path = (
        #     "./IotMicroservices/customizeLayer/handlers/IAM/resetPasswordRequest.mjs"
        # )
        # policy_list = [
        #     iam.PolicyStatement(
        #         effect=iam.Effect.ALLOW,
        #         actions=["lambda:InvokeFunction"],
        #         resources=[
        #             f"arn:aws:lambda:{self._region}:{self._account}:function:{lambdaFunctionName}"
        #         ],
        #     ),
        #     iam.PolicyStatement(
        #         effect=iam.Effect.ALLOW,
        #         actions=["dynamodb:PutItem"],
        #         resources=[
        #             f"arn:aws:dynamodb:{self._region}:{self._account}:table/{self._main_stack.log_table.table_name}"
        #         ],
        #     ),
        # ]
        # environment_map = {
        #     "LambdaFunctionName": lambdaFunctionName,
        #     "LogTableName": self._main_stack.log_table.table_name,
        # }
        # function = CdkUtility.addNewFunction(
        #     self._custom_api_stack,
        #     self._resource_name,
        #     function_name=function_name,
        #     function_id=function_id,
        #     function_handler_name=function_handler_name,
        #     entry_path=entry_path_test,
        #     policy_list=policy_list,
        #     environment_map=environment_map,
        # )
        # self.function_map["reset_password_request"] = function

        # # Reset Password Confirm Function
        # lambdaFunctionName = f"{self._resource_name}-ResetPasswordConfirm"
        # function_name = "ResetPasswordConfirm_PF"
        # function_id = "resetPasswordConfirmHandler_pf"
        # function_handler_name = "resetPasswordConfirmHandler"
        # entry_path = (
        #     "./IotMicroservices/customizeLayer/handlers/IAM/resetPasswordConfirm.mjs"
        # )
        # policy_list = [
        #     iam.PolicyStatement(
        #         effect=iam.Effect.ALLOW,
        #         actions=["lambda:InvokeFunction"],
        #         resources=[
        #             f"arn:aws:lambda:{self._region}:{self._account}:function:{lambdaFunctionName}"
        #         ],
        #     ),
        #     iam.PolicyStatement(
        #         effect=iam.Effect.ALLOW,
        #         actions=["dynamodb:PutItem"],
        #         resources=[
        #             f"arn:aws:dynamodb:{self._region}:{self._account}:table/{self._main_stack.log_table.table_name}"
        #         ],
        #     ),
        # ]
        # environment_map = {
        #     "LambdaFunctionName": lambdaFunctionName,
        #     "LogTableName": self._main_stack.log_table.table_name,
        # }
        # function = CdkUtility.addNewFunction(
        #     self._custom_api_stack,
        #     self._resource_name,
        #     function_name=function_name,
        #     function_id=function_id,
        #     function_handler_name=function_handler_name,
        #     entry_path=entry_path_test,
        #     policy_list=policy_list,
        #     environment_map=environment_map,
        # )
        # self.function_map["reset_password_confirm"] = function

        # # Admin create user
        # lambdaFunctionName = f"{self._resource_name}-AdminCreateUser"
        # function_name = "AdminCreateUser_PF"
        # function_id = "adminCreateUserHandler_pf"
        # function_handler_name = "adminCreateUserHandler"
        # entry_path = (
        #     "./IotMicroservices/customizeLayer/handlers/IAM/adminCreateUser.mjs"
        # )
        # policy_list = [
        #     iam.PolicyStatement(
        #         effect=iam.Effect.ALLOW,
        #         actions=["lambda:InvokeFunction"],
        #         resources=[
        #             f"arn:aws:lambda:{self._region}:{self._account}:function:{lambdaFunctionName}"
        #         ],
        #     ),
        #     iam.PolicyStatement(
        #         effect=iam.Effect.ALLOW,
        #         actions=["dynamodb:PutItem"],
        #         resources=[
        #             f"arn:aws:dynamodb:{self._region}:{self._account}:table/{self._main_stack.log_table.table_name}"
        #         ],
        #     ),
        # ]
        # environment_map = {
        #     "LambdaFunctionName": lambdaFunctionName,
        #     "LogTableName": self._main_stack.log_table.table_name,
        # }
        # function = CdkUtility.addNewFunction(
        #     self._custom_api_stack,
        #     self._resource_name,
        #     function_name=function_name,
        #     function_id=function_id,
        #     function_handler_name=function_handler_name,
        #     entry_path=entry_path_test,
        #     policy_list=policy_list,
        #     environment_map=environment_map,
        # )
        # self.function_map["adminCreateUser_pf"] = function

        # # Admin delete user
        # lambdaFunctionName = f"{self._resource_name}-DeleteUser"
        # LambdaFunctionCheckUsetIs = f"{self._resource_name}-ListUser"
        # function_name = "AdminDeleteUser_pf"
        # function_id = "adminDeleteUserHandler_pf"
        # function_handler_name = "adminDeleteUserHandler"
        # entry_path = (
        #     "./IotMicroservices/customizeLayer/handlers/IAM/adminDeleteUser.mjs"
        # )
        # policy_list = [
        #     iam.PolicyStatement(
        #         effect=iam.Effect.ALLOW,
        #         actions=["lambda:InvokeFunction"],
        #         resources=[
        #             f"arn:aws:lambda:{self._region}:{self._account}:function:{lambdaFunctionName}"
        #         ],
        #     ),
        #     iam.PolicyStatement(
        #         effect=iam.Effect.ALLOW,
        #         actions=["lambda:InvokeFunction"],
        #         resources=[
        #             f"arn:aws:lambda:{self._region}:{self._account}:function:{LambdaFunctionCheckUsetIs}"
        #         ],
        #     ),
        #     iam.PolicyStatement(
        #         effect=iam.Effect.ALLOW,
        #         actions=["dynamodb:PutItem", "cognito-idp:AdminGetUser"],
        #         resources=[
        #             f"arn:aws:dynamodb:{self._region}:{self._account}:table/{self._main_stack.log_table.table_name}",
        #             f"arn:aws:cognito-idp:{self._region}:{self._account}:userpool/{self._main_stack.user_pool.user_pool_id}",
        #         ],
        #     ),
        # ]
        # environment_map = {
        #     "LambdaFunctionCheckUsetIs": LambdaFunctionCheckUsetIs,
        #     "LambdaFunctionName": lambdaFunctionName,
        #     "LogTableName": self._main_stack.log_table.table_name,
        #     "UserPoolId": self._main_stack.user_pool.user_pool_id,
        # }
        # function = CdkUtility.addNewFunction(
        #     self._custom_api_stack,
        #     self._resource_name,
        #     function_name=function_name,
        #     function_id=function_id,
        #     function_handler_name=function_handler_name,
        #     entry_path=entry_path_test,
        #     policy_list=policy_list,
        #     environment_map=environment_map,
        # )
        # self.function_map["adminDeleteUser_pf"] = function

        # # List user
        # lambdaFunctionName = f"{self._resource_name}-ListUser"
        # function_name = "ListUser_pf"
        # function_id = "listUserHandler_pf"
        # function_handler_name = "listUserHandler"
        # entry_path = "./IotMicroservices/customizeLayer/handlers/IAM/listUser.mjs"
        # policy_list = [
        #     iam.PolicyStatement(
        #         effect=iam.Effect.ALLOW,
        #         actions=["dynamodb:PutItem"],
        #         resources=[
        #             f"arn:aws:dynamodb:{self._region}:{self._account}:table/{self._main_stack.log_table.table_name}"
        #         ],
        #     ),
        #     iam.PolicyStatement(
        #         effect=iam.Effect.ALLOW,
        #         actions=["lambda:InvokeFunction"],
        #         resources=[
        #             f"arn:aws:lambda:{self._region}:{self._account}:function:{lambdaFunctionName}"
        #         ],
        #     ),
        # ]
        # environment_map = {
        #     "LambdaFunctionName": f"{lambdaFunctionName}",
        #     "LogTableName": self._main_stack.log_table.table_name,
        # }
        # function = CdkUtility.addNewFunction(
        #     self._custom_api_stack,
        #     self._resource_name,
        #     function_name=function_name,
        #     function_id=function_id,
        #     function_handler_name=function_handler_name,
        #     entry_path=entry_path_test,
        #     policy_list=policy_list,
        #     environment_map=environment_map,
        # )
        # self.function_map["listUser_pf"] = function

        # # Change password
        # lambdaFunctionName = f"{self._resource_name}-ChangePassword"
        # function_name = "ChangePassword_pf"
        # function_id = "changePasswordHandler_pf"
        # function_handler_name = "changePasswordHandler"
        # entry_path = "./IotMicroservices/customizeLayer/handlers/IAM/changePassword.mjs"
        # policy_list = [
        #     iam.PolicyStatement(
        #         effect=iam.Effect.ALLOW,
        #         actions=["lambda:InvokeFunction"],
        #         resources=[
        #             f"arn:aws:lambda:{self._region}:{self._account}:function:{lambdaFunctionName}"
        #         ],
        #     ),
        #     iam.PolicyStatement(
        #         effect=iam.Effect.ALLOW,
        #         actions=["dynamodb:PutItem"],
        #         resources=[
        #             f"arn:aws:dynamodb:{self._region}:{self._account}:table/{self._main_stack.log_table.table_name}"
        #         ],
        #     ),
        # ]
        # environment_map = {
        #     "LambdaFunctionName": lambdaFunctionName,
        #     "LogTableName": self._main_stack.log_table.table_name,
        # }
        # function = CdkUtility.addNewFunction(
        #     self._custom_api_stack,
        #     self._resource_name,
        #     function_name=function_name,
        #     function_id=function_id,
        #     function_handler_name=function_handler_name,
        #     entry_path=entry_path_test,
        #     policy_list=policy_list,
        #     environment_map=environment_map,
        # )
        # self.function_map["changePassword_pf"] = function

        # # Get IoTCoreCredentials
        # lambdaFunctionName = f"{self._resource_name}-GetIoTCoreCredentials"
        # function_name = "getIoTCoreCredentials_pf"
        # function_id = "getIoTCoreCredentialsHandler_pf"
        # function_handler_name = "getIoTCoreCredentialsHandler"
        # entry_path = (
        #     "./IotMicroservices/customizeLayer/handlers/IAM/getIoTCoreCredentials.mjs"
        # )
        # policy_list = [
        #     iam.PolicyStatement(
        #         effect=iam.Effect.ALLOW,
        #         actions=["lambda:InvokeFunction"],
        #         resources=[
        #             f"arn:aws:lambda:{self._region}:{self._account}:function:{lambdaFunctionName}"
        #         ],
        #     ),
        #     iam.PolicyStatement(
        #         effect=iam.Effect.ALLOW,
        #         actions=["dynamodb:PutItem"],
        #         resources=[
        #             f"arn:aws:dynamodb:{self._region}:{self._account}:table/{self._main_stack.log_table.table_name}"
        #         ],
        #     ),
        # ]
        # environment_map = {
        #     "LambdaFunctionName": lambdaFunctionName,
        #     "LogTableName": self._main_stack.log_table.table_name,
        # }
        # function = CdkUtility.addNewFunction(
        #     self._custom_api_stack,
        #     self._resource_name,
        #     function_name=function_name,
        #     function_id=function_id,
        #     function_handler_name=function_handler_name,
        #     entry_path=entry_path_test,
        #     policy_list=policy_list,
        #     environment_map=environment_map,
        # )
        # self.function_map["getIoTCoreCredentials_pf"] = function

        # # Refresh token
        # lambdaFunctionName = f"{self._resource_name}-RefreshToken"
        # function_name = "refreshTokenHandler_pf"
        # function_id = "refreshTokenHandler_pf"
        # function_handler_name = "refreshTokenHandler"
        # entry_path = "./IotMicroservices/customizeLayer/handlers/IAM/refreshToken.mjs"
        # policy_list = [
        #     iam.PolicyStatement(
        #         effect=iam.Effect.ALLOW,
        #         actions=["lambda:InvokeFunction"],
        #         resources=[
        #             f"arn:aws:lambda:{self._region}:{self._account}:function:{lambdaFunctionName}"
        #         ],
        #     ),
        #     iam.PolicyStatement(
        #         effect=iam.Effect.ALLOW,
        #         actions=["dynamodb:PutItem"],
        #         resources=[
        #             f"arn:aws:dynamodb:{self._region}:{self._account}:table/{self._main_stack.log_table.table_name}"
        #         ],
        #     ),
        # ]
        # environment_map = {
        #     "LambdaFunctionName": lambdaFunctionName,
        #     "LogTableName": self._main_stack.log_table.table_name,
        # }
        # function = CdkUtility.addNewFunction(
        #     self._custom_api_stack,
        #     self._resource_name,
        #     function_name=function_name,
        #     function_id=function_id,
        #     function_handler_name=function_handler_name,
        #     entry_path=entry_path_test,
        #     policy_list=policy_list,
        #     environment_map=environment_map,
        # )
        # self.function_map["refreshToken_pf"] = function

        # # Enable user
        # lambdaFunctionName = f"{self._resource_name}-EnableUser"
        # LambdaFunctionCheckUsetIs = f"{self._resource_name}-ListUser"
        # function_name = "EnableUser_pf"
        # function_id = "enableUserHandler_pf"
        # function_handler_name = "enableUserHandler"
        # entry_path = "./IotMicroservices/customizeLayer/handlers/IAM/enableUser.mjs"
        # policy_list = [
        #     iam.PolicyStatement(
        #         effect=iam.Effect.ALLOW,
        #         actions=["lambda:InvokeFunction"],
        #         resources=[
        #             f"arn:aws:lambda:{self._region}:{self._account}:function:{lambdaFunctionName}"
        #         ],
        #     ),
        #     iam.PolicyStatement(
        #         effect=iam.Effect.ALLOW,
        #         actions=["lambda:InvokeFunction"],
        #         resources=[
        #             f"arn:aws:lambda:{self._region}:{self._account}:function:{LambdaFunctionCheckUsetIs}"
        #         ],
        #     ),
        #     iam.PolicyStatement(
        #         effect=iam.Effect.ALLOW,
        #         actions=["dynamodb:PutItem", "cognito-idp:AdminGetUser"],
        #         resources=[
        #             f"arn:aws:dynamodb:{self._region}:{self._account}:table/{self._main_stack.log_table.table_name}",
        #             f"arn:aws:cognito-idp:{self._region}:{self._account}:userpool/{self._main_stack.user_pool.user_pool_id}",
        #         ],
        #     ),
        # ]
        # environment_map = {
        #     "LambdaFunctionCheckUsetIs": LambdaFunctionCheckUsetIs,
        #     "LambdaFunctionName": lambdaFunctionName,
        #     "LogTableName": self._main_stack.log_table.table_name,
        #     "UserPoolId": self._main_stack.user_pool.user_pool_id,
        # }
        # function = CdkUtility.addNewFunction(
        #     self._custom_api_stack,
        #     self._resource_name,
        #     function_name=function_name,
        #     function_id=function_id,
        #     function_handler_name=function_handler_name,
        #     entry_path=entry_path_test,
        #     policy_list=policy_list,
        #     environment_map=environment_map,
        # )
        # self.function_map["enableUser_pf"] = function

        # # Update user attribute
        # lambdaFunctionName = f"{self._resource_name}-UpdateUserAttribute"
        # LambdaFunctionCheckUsetIs = f"{self._resource_name}-ListUser"
        # function_name = "UpdateUserAttributes_pf"
        # function_id = "updateUserHandler"
        # function_handler_name = "updateUserHandler"
        # entry_path = "./IotMicroservices/customizeLayer/handlers/IAM/updateUser.mjs"
        # policy_list = [
        #     iam.PolicyStatement(
        #         effect=iam.Effect.ALLOW,
        #         actions=["lambda:InvokeFunction"],
        #         resources=[
        #             f"arn:aws:lambda:{self._region}:{self._account}:function:{lambdaFunctionName}"
        #         ],
        #     ),
        #     iam.PolicyStatement(
        #         effect=iam.Effect.ALLOW,
        #         actions=["lambda:InvokeFunction"],
        #         resources=[
        #             f"arn:aws:lambda:{self._region}:{self._account}:function:{LambdaFunctionCheckUsetIs}"
        #         ],
        #     ),
        #     iam.PolicyStatement(
        #         effect=iam.Effect.ALLOW,
        #         actions=["dynamodb:PutItem"],
        #         resources=[
        #             f"arn:aws:dynamodb:{self._region}:{self._account}:table/{self._main_stack.log_table.table_name}"
        #         ],
        #     ),
        # ]
        # environment_map = {
        #     "LambdaFunctionName": lambdaFunctionName,
        #     "LogTableName": self._main_stack.log_table.table_name,
        #     "EndpointInfoTableName": self._main_stack.endpoint_info_table.table_name,
        #     "LambdaFunctionCheckUsetIs": LambdaFunctionCheckUsetIs,
        # }
        # self.function_map[function_name] = CdkUtility.addNewFunction(
        #     self._custom_api_stack,
        #     self._resource_name,
        #     function_name=function_name,
        #     function_id=function_id,
        #     function_handler_name=function_handler_name,
        #     entry_path=entry_path_test,
        #     policy_list=policy_list,
        #     environment_map=environment_map,
        # )

        # # User singup
        # lambdaFunctionName = f"{self._resource_name}-CognitoSignup"
        # function_name = "CognitoSignup_pf"
        # function_id = "CognitoSignup_pf"
        # function_handler_name = "cognitoSignupHandler"
        # entry_path = "./IotMicroservices/customizeLayer/handlers/IAM/cognitoSignup.mjs"
        # policy_list = [
        #     iam.PolicyStatement(
        #         effect=iam.Effect.ALLOW,
        #         actions=["lambda:InvokeFunction"],
        #         resources=[
        #             f"arn:aws:lambda:{self._region}:{self._account}:function:{lambdaFunctionName}"
        #         ],
        #     ),
        #     iam.PolicyStatement(
        #         effect=iam.Effect.ALLOW,
        #         actions=["dynamodb:PutItem"],
        #         resources=[
        #             f"arn:aws:dynamodb:{self._region}:{self._account}:table/{self._main_stack.log_table.table_name}"
        #         ],
        #     ),
        # ]
        # environment_map = {
        #     "LambdaFunctionName": lambdaFunctionName,
        #     "LogTableName": self._main_stack.log_table.table_name,
        # }
        # self.function_map[function_name] = CdkUtility.addNewFunction(
        #     self._custom_api_stack,
        #     self._resource_name,
        #     function_name=function_name,
        #     function_id=function_id,
        #     function_handler_name=function_handler_name,
        #     entry_path=entry_path_test,
        #     policy_list=policy_list,
        #     environment_map=environment_map,
        # )

    def create_application_microservices(self):
        entry_path_test = "./IotMicroservices/customizeLayer/handlers/Application/listApiFunctions.mjs"
        # Query api usage log
        lambdaFunctionName = f"{self._resource_name}-RawQueryLog"
        function_name = "QueryApiUsageLogHandler"
        function_id = "queryApiUsageLogHandler_pf"
        function_handler_name = "queryApiUsageLogHandler"
        entry_path = "./IotMicroservices/customizeLayer/handlers/Application/Log/queryApiUsageLog.mjs"
        policy_list = [
            iam.PolicyStatement(
                effect=iam.Effect.ALLOW,
                actions=["lambda:InvokeFunction"],
                resources=[
                    f"arn:aws:lambda:{self._region}:{self._account}:function:{lambdaFunctionName}"
                ],
            ),
            iam.PolicyStatement(
                effect=iam.Effect.ALLOW,
                actions=["dynamodb:PutItem"],
                resources=[
                    f"arn:aws:dynamodb:{self._region}:{self._account}:table/{self._main_stack.log_table.table_name}"
                ],
            ),
            iam.PolicyStatement(
                effect=iam.Effect.ALLOW,
                actions=["dynamodb:Query"],
                resources=[
                    f"arn:aws:dynamodb:{self._region}:{self._account}:table/{self._main_stack.application_config_table.table_name}"
                ],
            ),
        ]
        environment_map = {
            "LogTableName": self._main_stack.log_table.table_name,
            "LambdaFunctionName": lambdaFunctionName,
            "AppConfigTableName": self._main_stack.application_config_table.table_name,
        }
        function = CdkUtility.addNewFunction(
            self._custom_api_stack,
            self._resource_name,
            function_name=function_name,
            function_id=function_id,
            function_handler_name=function_handler_name,
            entry_path=entry_path_test,
            policy_list=policy_list,
            environment_map=environment_map,
        )
        self.function_map["queryApiUsageLog"] = function

        # List Dashboard Config function
        lambdaFunctionName = f"{self._resource_name}-ListConfig"

        function_name = "ListDashboardConfig"
        function_id = "listDashboardConfigHandler"
        function_handler_name = "listDashboardConfigHandler"
        entry_path = "./IotMicroservices/customizeLayer/handlers/Application/Dashboard/listDashboardConfig.mjs"
        policy_list = [
            iam.PolicyStatement(
                effect=iam.Effect.ALLOW,
                actions=["lambda:InvokeFunction"],
                resources=[
                    f"arn:aws:lambda:{self._region}:{self._account}:function:{lambdaFunctionName}"
                ],
            ),
            iam.PolicyStatement(
                effect=iam.Effect.ALLOW,
                actions=["dynamodb:PutItem"],
                resources=[
                    f"arn:aws:dynamodb:{self._region}:{self._account}:table/{self._main_stack.log_table.table_name}"
                ],
            ),
        ]
        environment_map = {
            "LambdaFunctionName": lambdaFunctionName,
            "LogTableName": self._main_stack.log_table.table_name,
        }
        self.function_map[function_name] = CdkUtility.addNewFunction(
            self._custom_api_stack,
            self._resource_name,
            function_name=function_name,
            function_id=function_id,
            function_handler_name=function_handler_name,
            entry_path=entry_path_test,
            policy_list=policy_list,
            environment_map=environment_map,
        )

        #Save Dashboard function
        lambdaFunctionName = f"{self._resource_name}-AddApplicationConfig"

        function_name = "SaveDashboardConfig"
        function_id = "saveDashboardConfigHandler"
        function_handler_name = "saveDashboardConfigHandler"
        entry_path = "./IotMicroservices/customizeLayer/handlers/Application/Dashboard/saveDashboardConfig.mjs"
        policy_list = [
            iam.PolicyStatement(
                effect=iam.Effect.ALLOW,
                actions=["lambda:InvokeFunction"],
                resources=[
                    f"arn:aws:lambda:{self._region}:{self._account}:function:{lambdaFunctionName}"
                ],
            ),
            iam.PolicyStatement(
                effect=iam.Effect.ALLOW,
                actions=["dynamodb:PutItem"],
                resources=[
                    f"arn:aws:dynamodb:{self._region}:{self._account}:table/{self._main_stack.log_table.table_name}"
                ],
            ),
        ]
        environment_map = {
            "LambdaFunctionName": lambdaFunctionName,
            "LogTableName": self._main_stack.log_table.table_name,
        }
        self.function_map[function_name] = CdkUtility.addNewFunction(
            self._custom_api_stack,
            self._resource_name,
            function_name=function_name,
            function_id=function_id,
            function_handler_name=function_handler_name,
            entry_path=entry_path_test,
            policy_list=policy_list,
            environment_map=environment_map,
        )

        # Delete Dashboard function
        lambdaFunctionName = f"{self._resource_name}-DeleteConfig"

        function_name = "DeleteDashboardConfig"
        function_id = "deleteDashboardConfigHandler"
        function_handler_name = "deleteDashboardConfigHandler"
        entry_path = "./IotMicroservices/customizeLayer/handlers/Application/Dashboard/deleteDashboardConfig.mjs"
        policy_list = [
            iam.PolicyStatement(
                effect=iam.Effect.ALLOW,
                actions=["lambda:InvokeFunction"],
                resources=[
                    f"arn:aws:lambda:{self._region}:{self._account}:function:{lambdaFunctionName}"
                ],
            ),
            iam.PolicyStatement(
                effect=iam.Effect.ALLOW,
                actions=["dynamodb:PutItem"],
                resources=[
                    f"arn:aws:dynamodb:{self._region}:{self._account}:table/{self._main_stack.log_table.table_name}"
                ],
            ),
        ]
        environment_map = {
            "LambdaFunctionName": lambdaFunctionName,
            "LogTableName": self._main_stack.log_table.table_name,
        }
        self.function_map[function_name] = CdkUtility.addNewFunction(
            self._custom_api_stack,
            self._resource_name,
            function_name=function_name,
            function_id=function_id,
            function_handler_name=function_handler_name,
            entry_path=entry_path_test,
            policy_list=policy_list,
            environment_map=environment_map,
        )

        # Add Alert Rule function
        lambdaFunctionName = f"{self._resource_name}-AddApplicationConfig"
        ListLambdaFunctionName = f"{self._resource_name}-ListConfig"
        ListSensorLambdaFunctionName = f"{self._resource_name}-ListEndpointInfo"

        function_name = "AddAlertRule"
        function_id = "addAlertRuleHandler"
        function_handler_name = "addAlertRuleHandler"
        entry_path = "./IotMicroservices/customizeLayer/handlers/Application/Alert/addAlertRule.mjs"
        policy_list = [
            iam.PolicyStatement(
                effect=iam.Effect.ALLOW,
                actions=["lambda:InvokeFunction"],
                resources=[
                    f"arn:aws:lambda:{self._region}:{self._account}:function:{lambdaFunctionName}"
                ],
            ),
            iam.PolicyStatement(
                effect=iam.Effect.ALLOW,
                actions=["lambda:InvokeFunction"],
                resources=[
                    f"arn:aws:lambda:{self._region}:{self._account}:function:{ListLambdaFunctionName}"
                ],
            ),
            iam.PolicyStatement(
                effect=iam.Effect.ALLOW,
                actions=["lambda:InvokeFunction"],
                resources=[
                    f"arn:aws:lambda:{self._region}:{self._account}:function:{ListSensorLambdaFunctionName}"
                ],
            ),
            iam.PolicyStatement(
                effect=iam.Effect.ALLOW,
                actions=["dynamodb:PutItem"],
                resources=[
                    f"arn:aws:dynamodb:{self._region}:{self._account}:table/{self._main_stack.log_table.table_name}"
                ],
            ),
        ]
        environment_map = {
            "LambdaFunctionName": lambdaFunctionName,
            "LogTableName": self._main_stack.log_table.table_name,
            "ListLambdaFunctionName": ListLambdaFunctionName,
            "ListSensorLambdaFunctionName": ListSensorLambdaFunctionName,
        }
        self.function_map[function_name] = CdkUtility.addNewFunction(
            self._custom_api_stack,
            self._resource_name,
            function_name=function_name,
            function_id=function_id,
            function_handler_name=function_handler_name,
            entry_path=entry_path_test,
            policy_list=policy_list,
            environment_map=environment_map,
        )

        # List All alert rule function
        lambdaFunctionName = f"{self._resource_name}-ListConfig"

        function_name = "ListAllAlertRule"
        function_id = "listAlertRuleHandler"
        function_handler_name = "listAlertRuleHandler"
        entry_path = "./IotMicroservices/customizeLayer/handlers/Application/Alert/listAlertRule.mjs"
        policy_list = [
            iam.PolicyStatement(
                effect=iam.Effect.ALLOW,
                actions=["lambda:InvokeFunction"],
                resources=[
                    f"arn:aws:lambda:{self._region}:{self._account}:function:{lambdaFunctionName}"
                ],
            ),
            iam.PolicyStatement(
                effect=iam.Effect.ALLOW,
                actions=["dynamodb:PutItem"],
                resources=[
                    f"arn:aws:dynamodb:{self._region}:{self._account}:table/{self._main_stack.log_table.table_name}"
                ],
            ),
        ]

        environment_map = {
            "LambdaFunctionName": lambdaFunctionName,
            "LogTableName": self._main_stack.log_table.table_name,
        }
        self.function_map[function_name] = CdkUtility.addNewFunction(
            self._custom_api_stack,
            self._resource_name,
            function_name=function_name,
            function_id=function_id,
            function_handler_name=function_handler_name,
            entry_path=entry_path_test,
            policy_list=policy_list,
            environment_map=environment_map,
        )

        # Copy alert rule function
        lambdaFunctionName = f"{self._resource_name}-AddApplicationConfig"
        ListLambdaFunctionName = f"{self._resource_name}-ListConfig"

        function_name = "CopyAlertRule"
        function_id = "copyAlertRuleHandler"
        function_handler_name = "copyAlertRuleHandler"
        entry_path = "./IotMicroservices/customizeLayer/handlers/Application/Alert/copyAlertRule.mjs"
        policy_list = [
            iam.PolicyStatement(
                effect=iam.Effect.ALLOW,
                actions=["lambda:InvokeFunction"],
                resources=[
                    f"arn:aws:lambda:{self._region}:{self._account}:function:{lambdaFunctionName}"
                ],
            ),
            iam.PolicyStatement(
                effect=iam.Effect.ALLOW,
                actions=["lambda:InvokeFunction"],
                resources=[
                    f"arn:aws:lambda:{self._region}:{self._account}:function:{ListLambdaFunctionName}"
                ],
            ),
            iam.PolicyStatement(
                effect=iam.Effect.ALLOW,
                actions=["dynamodb:PutItem"],
                resources=[
                    f"arn:aws:dynamodb:{self._region}:{self._account}:table/{self._main_stack.log_table.table_name}"
                ],
            ),
        ]
        environment_map = {
            "LambdaFunctionName": lambdaFunctionName,
            "ListLambdaFunctionName": ListLambdaFunctionName,
            "LogTableName": self._main_stack.log_table.table_name,
        }
        self.function_map[function_name] = CdkUtility.addNewFunction(
            self._custom_api_stack,
            self._resource_name,
            function_name=function_name,
            function_id=function_id,
            function_handler_name=function_handler_name,
            entry_path=entry_path_test,
            policy_list=policy_list,
            environment_map=environment_map,
        )

        # Delete alert rule function
        lambdaFunctionName = f"{self._resource_name}-DeleteConfig"
        ListLambdaFunctionName = f"{self._resource_name}-ListConfig"

        function_name = "DeleteAlertRule"
        function_id = "deleteAlertRuleHandler"
        function_handler_name = "deleteAlertRuleHandler"
        entry_path = "./IotMicroservices/customizeLayer/handlers/Application/Alert/deleteAlertRule.mjs"
        policy_list = [
            iam.PolicyStatement(
                effect=iam.Effect.ALLOW,
                actions=["lambda:InvokeFunction"],
                resources=[
                    f"arn:aws:lambda:{self._region}:{self._account}:function:{lambdaFunctionName}"
                ],
            ),
            iam.PolicyStatement(
                effect=iam.Effect.ALLOW,
                actions=["lambda:InvokeFunction"],
                resources=[
                    f"arn:aws:lambda:{self._region}:{self._account}:function:{ListLambdaFunctionName}"
                ],
            ),
            iam.PolicyStatement(
                effect=iam.Effect.ALLOW,
                actions=["dynamodb:PutItem"],
                resources=[
                    f"arn:aws:dynamodb:{self._region}:{self._account}:table/{self._main_stack.log_table.table_name}"
                ],
            ),
        ]
        environment_map = {
            "LambdaFunctionName": lambdaFunctionName,
            "ListLambdaFunctionName": ListLambdaFunctionName,
            "LogTableName": self._main_stack.log_table.table_name,
        }
        self.function_map[function_name] = CdkUtility.addNewFunction(
            self._custom_api_stack,
            self._resource_name,
            function_name=function_name,
            function_id=function_id,
            function_handler_name=function_handler_name,
            entry_path=entry_path_test,
            policy_list=policy_list,
            environment_map=environment_map,
        )

        # Update alert rule function
        lambdaFunctionName = f"{self._resource_name}-UpdateAppConfig"
        ListLambdaFunctionName = f"{self._resource_name}-ListConfig"
        ListSensorLambdaFunctionName = f"{self._resource_name}-ListEndpointInfo"
        function_name = "UpdateAlertRule"
        function_id = "updateAlertRuleHandler"
        function_handler_name = "updateAlertRuleHandler"
        entry_path = "./IotMicroservices/customizeLayer/handlers/Application/Alert/updateAlertRule.mjs"
        policy_list = [
            iam.PolicyStatement(
                effect=iam.Effect.ALLOW,
                actions=["lambda:InvokeFunction"],
                resources=[
                    f"arn:aws:lambda:{self._region}:{self._account}:function:{lambdaFunctionName}"
                ],
            ),
            iam.PolicyStatement(
                effect=iam.Effect.ALLOW,
                actions=["lambda:InvokeFunction"],
                resources=[
                    f"arn:aws:lambda:{self._region}:{self._account}:function:{ListLambdaFunctionName}"
                ],
            ),
            iam.PolicyStatement(
                effect=iam.Effect.ALLOW,
                actions=["lambda:InvokeFunction"],
                resources=[
                    f"arn:aws:lambda:{self._region}:{self._account}:function:{ListSensorLambdaFunctionName}"
                ],
            ),
            iam.PolicyStatement(
                effect=iam.Effect.ALLOW,
                actions=["dynamodb:PutItem"],
                resources=[
                    f"arn:aws:dynamodb:{self._region}:{self._account}:table/{self._main_stack.log_table.table_name}"
                ],
            ),
        ]
        environment_map = {
            "LambdaFunctionName": lambdaFunctionName,
            "ListLambdaFunctionName": ListLambdaFunctionName,
            "LogTableName": self._main_stack.log_table.table_name,
            "ListSensorLambdaFunctionName": ListSensorLambdaFunctionName,
        }
        self.function_map[function_name] = CdkUtility.addNewFunction(
            self._custom_api_stack,
            self._resource_name,
            function_name=function_name,
            function_id=function_id,
            function_handler_name=function_handler_name,
            entry_path=entry_path_test,
            policy_list=policy_list,
            environment_map=environment_map,
        )

        # editAreas function
        lambdaFunctionName = f"{self._resource_name}-AddApplicationConfig"
        function_name = "EditAreas"
        function_id = "editAreasHandler"
        function_handler_name = "editAreasHandler"
        entry_path = (
            "./IotMicroservices/customizeLayer/handlers/Application/Area/editAreas.mjs"
        )
        policy_list = [
            iam.PolicyStatement(
                effect=iam.Effect.ALLOW,
                actions=["lambda:InvokeFunction"],
                resources=[
                    f"arn:aws:lambda:{self._region}:{self._account}:function:{lambdaFunctionName}"
                ],
            ),
            iam.PolicyStatement(
                effect=iam.Effect.ALLOW,
                actions=["dynamodb:PutItem"],
                resources=[
                    f"arn:aws:dynamodb:{self._region}:{self._account}:table/{self._main_stack.log_table.table_name}"
                ],
            ),
        ]
        environment_map = {
            "LambdaFunctionName": lambdaFunctionName,
            "LogTableName": self._main_stack.log_table.table_name,
        }
        self.function_map[function_name] = CdkUtility.addNewFunction(
            self._custom_api_stack,
            self._resource_name,
            function_name=function_name,
            function_id=function_id,
            function_handler_name=function_handler_name,
            entry_path=entry_path_test,
            policy_list=policy_list,
            environment_map=environment_map,
        )

        # Query gateway log function
        lambdaFunctionName = f"{self._resource_name}-RawQueryLog"
        function_name = "QueryGatewayLog"
        function_id = "queryGatewayLogHandler"
        function_handler_name = "queryGatewayLogHandler"
        entry_path = "./IotMicroservices/customizeLayer/handlers/Application/Log/queryGatewayLog.mjs"
        policy_list = [
            iam.PolicyStatement(
                effect=iam.Effect.ALLOW,
                actions=["lambda:InvokeFunction"],
                resources=[
                    f"arn:aws:lambda:{self._region}:{self._account}:function:{lambdaFunctionName}"
                ],
            ),
            iam.PolicyStatement(
                effect=iam.Effect.ALLOW,
                actions=["dynamodb:PutItem"],
                resources=[
                    f"arn:aws:dynamodb:{self._region}:{self._account}:table/{self._main_stack.log_table.table_name}"
                ],
            ),
            iam.PolicyStatement(
                effect=iam.Effect.ALLOW,
                actions=["dynamodb:Query"],
                resources=[
                    f"arn:aws:dynamodb:{self._region}:{self._account}:table/{self._main_stack.application_config_table.table_name}"
                ],
            ),
        ]
        environment_map = {
            "LambdaFunctionName": lambdaFunctionName,
            "IndexTableName": self._main_stack.log_table_category_index_name,
            "AppConfigTableName": self._main_stack.application_config_table.table_name,
            "LogTableName": self._main_stack.log_table.table_name,
        }
        self.function_map[function_name] = CdkUtility.addNewFunction(
            self._custom_api_stack,
            self._resource_name,
            function_name=function_name,
            function_id=function_id,
            function_handler_name=function_handler_name,
            entry_path=entry_path_test,
            policy_list=policy_list,
            environment_map=environment_map,
        )

        # List api function
        lambdaFunctionName = f"{self._resource_name}-ListConfig"

        function_name = "ListApiFunctions"
        function_id = "listApiFunctionsHandler"
        function_handler_name = "listApiFunctionsHandler"
        entry_path = "./IotMicroservices/customizeLayer/handlers/Application/listApiFunctions.mjs"
        policy_list = [
            iam.PolicyStatement(
                effect=iam.Effect.ALLOW,
                actions=["lambda:InvokeFunction"],
                resources=[
                    f"arn:aws:lambda:{self._region}:{self._account}:function:{lambdaFunctionName}"
                ],
            ),
            iam.PolicyStatement(
                effect=iam.Effect.ALLOW,
                actions=["dynamodb:PutItem"],
                resources=[
                    f"arn:aws:dynamodb:{self._region}:{self._account}:table/{self._main_stack.log_table.table_name}"
                ],
            ),
        ]
        environment_map = {
            "LambdaFunctionName": lambdaFunctionName,
            "LogTableName": self._main_stack.log_table.table_name,
        }
        self.function_map[function_name] = CdkUtility.addNewFunction(
            self._custom_api_stack,
            self._resource_name,
            function_name=function_name,
            function_id=function_id,
            function_handler_name=function_handler_name,
            entry_path=entry_path_test,
            policy_list=policy_list,
            environment_map=environment_map,
        )

        # Get sensor menu config Function
        listAreaLambdaFunctionName = f"{self._resource_name}-QueryCustomizeData"
        listendpointinfoLambdaFunctionName = f"{self._resource_name}-ListEndpointInfo"
        listendpointinstanceLambdaFunctionName = (
            f"{self._resource_name}-ListEndpointInstance"
        )
        function_name = "GetSensorMenuConfig"
        function_id = "getSensorMenuConfigHandler"
        function_handler_name = "getSensorMenuConfigHandler"
        entry_path = "./IotMicroservices/customizeLayer/handlers/Application/getSensorMenuConfig.mjs"
        policy_list = [
            iam.PolicyStatement(
                effect=iam.Effect.ALLOW,
                actions=["lambda:InvokeFunction"],
                resources=[
                    f"arn:aws:lambda:{self._region}:{self._account}:function:{listAreaLambdaFunctionName}"
                ],
            ),
            iam.PolicyStatement(
                effect=iam.Effect.ALLOW,
                actions=["lambda:InvokeFunction"],
                resources=[
                    f"arn:aws:lambda:{self._region}:{self._account}:function:{listendpointinfoLambdaFunctionName}"
                ],
            ),
            iam.PolicyStatement(
                effect=iam.Effect.ALLOW,
                actions=["lambda:InvokeFunction"],
                resources=[
                    f"arn:aws:lambda:{self._region}:{self._account}:function:{listendpointinstanceLambdaFunctionName}"
                ],
            ),
            iam.PolicyStatement(
                effect=iam.Effect.ALLOW,
                actions=["dynamodb:PutItem"],
                resources=[
                    f"arn:aws:dynamodb:{self._region}:{self._account}:table/{self._main_stack.log_table.table_name}"
                ],
            ),
        ]
        environment_map = {
            "ListAreaLambdaFunctionName": listAreaLambdaFunctionName,
            "ListendpointinfoLambdaFunctionName": listendpointinfoLambdaFunctionName,
            "ListendpointinstanceLambdaFunctionName": listendpointinstanceLambdaFunctionName,
            "LogTableName": self._main_stack.log_table.table_name,
        }
        self.function_map[function_name] = CdkUtility.addNewFunction(
            self._custom_api_stack,
            self._resource_name,
            function_name=function_name,
            function_id=function_id,
            function_handler_name=function_handler_name,
            entry_path=entry_path_test,
            policy_list=policy_list,
            environment_map=environment_map,
        )

        

        # List Unsolved Alert function
        lambdaFunctionName = f"{self._resource_name}-RawQueryLog"

        function_name = "ListUnsolvedAlert"
        function_id = "listUnsolvedAlertHandler"
        function_handler_name = "listUnsolvedAlertHandler"
        entry_path = "./IotMicroservices/customizeLayer/handlers/Application/Alert/listUnsolvedAlert.mjs"
        policy_list = [
            iam.PolicyStatement(
                effect=iam.Effect.ALLOW,
                actions=["lambda:InvokeFunction"],
                resources=[
                    f"arn:aws:lambda:{self._region}:{self._account}:function:{lambdaFunctionName}"
                ],
            ),
            iam.PolicyStatement(
                effect=iam.Effect.ALLOW,
                actions=["dynamodb:PutItem"],
                resources=[
                    f"arn:aws:dynamodb:{self._region}:{self._account}:table/{self._main_stack.log_table.table_name}"
                ],
            ),
        ]
        environment_map = {
            "LambdaFunctionName": lambdaFunctionName,
            "LogTableName": self._main_stack.log_table.table_name,
            "IndexTableName": self._main_stack.log_table_current_status_index_name,
        }
        self.function_map[function_name] = CdkUtility.addNewFunction(
            self._custom_api_stack,
            self._resource_name,
            function_name=function_name,
            function_id=function_id,
            function_handler_name=function_handler_name,
            entry_path=entry_path_test,
            policy_list=policy_list,
            environment_map=environment_map,
        )

        # Query Alert Function
        lambdaFunctionName = f"{self._resource_name}-RawQueryLog"

        function_name = "QueryAlert"
        function_id = "queryAlertHandler"
        function_handler_name = "queryAlertHandler"
        entry_path = "./IotMicroservices/customizeLayer/handlers/Application/Alert/queryAlert.mjs"
        policy_list = [
            iam.PolicyStatement(
                effect=iam.Effect.ALLOW,
                actions=["lambda:InvokeFunction"],
                resources=[
                    f"arn:aws:lambda:{self._region}:{self._account}:function:{lambdaFunctionName}"
                ],
            ),
            iam.PolicyStatement(
                effect=iam.Effect.ALLOW,
                actions=["dynamodb:PutItem"],
                resources=[
                    f"arn:aws:dynamodb:{self._region}:{self._account}:table/{self._main_stack.log_table.table_name}"
                ],
            ),
        ]
        environment_map = {
            "LambdaFunctionName": lambdaFunctionName,
            "LogTableName": self._main_stack.log_table.table_name,
            "DataPathIndexTableName": self._main_stack.log_data_path_index_name,
            "EndpointIndexTableName": self._main_stack.log_endpoint_index_name,
            "CurrentStatusIndexTableName": self._main_stack.log_table_current_status_index_name,
        }
        self.function_map[function_name] = CdkUtility.addNewFunction(
            self._custom_api_stack,
            self._resource_name,
            function_name=function_name,
            function_id=function_id,
            function_handler_name=function_handler_name,
            entry_path=entry_path_test,
            policy_list=policy_list,
            environment_map=environment_map,
        )

        # Query thing alive Log Function
        lambdaFunctionName = f"{self._resource_name}-QueryLog"
        function_name = "QueryThingAliveLog"
        function_id = "queryThingAliveLogHandler"
        function_handler_name = "queryThingAliveLogHandler"
        entry_path = "./IotMicroservices/customizeLayer/handlers/Application/Log/queryThingAliveLog.mjs"
        policy_list = [
            iam.PolicyStatement(
                effect=iam.Effect.ALLOW,
                actions=["lambda:InvokeFunction"],
                resources=[
                    f"arn:aws:lambda:{self._region}:{self._account}:function:{lambdaFunctionName}"
                ],
            ),
            iam.PolicyStatement(
                effect=iam.Effect.ALLOW,
                actions=["dynamodb:PutItem"],
                resources=[
                    f"arn:aws:dynamodb:{self._region}:{self._account}:table/{self._main_stack.log_table.table_name}"
                ],
            ),
        ]
        environment_map = {
            "LambdaFunctionName": lambdaFunctionName,
            "LogTableName": self._main_stack.log_table.table_name,
        }
        self.function_map[function_name] = CdkUtility.addNewFunction(
            self._custom_api_stack,
            self._resource_name,
            function_name=function_name,
            function_id=function_id,
            function_handler_name=function_handler_name,
            entry_path=entry_path_test,
            policy_list=policy_list,
            environment_map=environment_map,
        )

        # Alert solved function
        lambdaFunctionName = f"{self._resource_name}-RawUpdateLog"
        function_name = "AlertSolved"
        function_id = "alertSolvedHandler"
        function_handler_name = "alertSolvedHandler"
        entry_path = "./IotMicroservices/customizeLayer/handlers/Application/Alert/alertSolved.mjs"
        policy_list = [
            iam.PolicyStatement(
                effect=iam.Effect.ALLOW,
                actions=["lambda:InvokeFunction"],
                resources=[
                    f"arn:aws:lambda:{self._region}:{self._account}:function:{lambdaFunctionName}"
                ],
            ),
            iam.PolicyStatement(
                effect=iam.Effect.ALLOW,
                actions=["dynamodb:PutItem"],
                resources=[
                    f"arn:aws:dynamodb:{self._region}:{self._account}:table/{self._main_stack.log_table.table_name}"
                ],
            ),
        ]
        environment_map = {
            "LambdaFunctionName": lambdaFunctionName,
            "LogTableName": self._main_stack.log_table.table_name,
        }
        self.function_map[function_name] = CdkUtility.addNewFunction(
            self._custom_api_stack,
            self._resource_name,
            function_name=function_name,
            function_id=function_id,
            function_handler_name=function_handler_name,
            entry_path=entry_path_test,
            policy_list=policy_list,
            environment_map=environment_map,
        )

        # List all area
        lambdaFunctionName = f"{self._resource_name}-ListConfig"
        function_name = "ListAreas"
        function_id = "listAreasHandler"
        function_handler_name = "listAreasHandler"
        entry_path = (
            "./IotMicroservices/customizeLayer/handlers/Application/Area/listAreas.mjs"
        )
        policy_list = [
            iam.PolicyStatement(
                effect=iam.Effect.ALLOW,
                actions=["lambda:InvokeFunction"],
                resources=[
                    f"arn:aws:lambda:{self._region}:{self._account}:function:{lambdaFunctionName}"
                ],
            ),
            iam.PolicyStatement(
                effect=iam.Effect.ALLOW,
                actions=["dynamodb:PutItem"],
                resources=[
                    f"arn:aws:dynamodb:{self._region}:{self._account}:table/{self._main_stack.log_table.table_name}"
                ],
            ),
        ]
        environment_map = {
            "LambdaFunctionName": lambdaFunctionName,
            "LogTableName": self._main_stack.log_table.table_name,
        }
        function = CdkUtility.addNewFunction(
            self._custom_api_stack,
            self._resource_name,
            function_name=function_name,
            function_id=function_id,
            function_handler_name=function_handler_name,
            entry_path=entry_path_test,
            policy_list=policy_list,
            environment_map=environment_map,
        )
        self.function_map["listAreas"] = function

    def _extractApiUrl(self, method):
        path = method.api.deployment_stage.url_for_path()
        resource = method.resource.path.split("/")[1]
        api_url = f"{path}{resource}"
        return api_url

    ###########################################Custom part########################################
    def create_custom_microservices(self):
        pass
