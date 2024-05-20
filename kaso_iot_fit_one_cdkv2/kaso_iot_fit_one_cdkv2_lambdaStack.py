from datetime import date, datetime
from aws_cdk import (
    NestedStack,
    RemovalPolicy as removePolicy,
    aws_iot as iot,
    aws_iam as iam,
)
from constructs import Construct
from kaso_iot_fit_one_cdkv2.shared.cdk_utility import CdkUtility
from aws_cdk import (
    aws_lambda as lambda_,
)


# Manager Stack
class KasoIotFitOneCdkv2LambdaStack(NestedStack):
    _remove_policy = removePolicy.DESTROY

    # cdk config
    application_name = ""
    environment = ""
    resource_name = ""
    region = ""
    account = ""
    secret_key = ""
    microservice = None

    def __init__(self, scope: Construct, construct_id: str) -> None:
        super().__init__(scope, construct_id)

        self.application_name = scope.application_name
        self.environment = scope.environment
        self.resource_name = scope.resource_name
        self.region = scope.region
        self.account = scope.account
        self.secret_key = scope.secret_key
        self.canvas_nodejs_layer_path = scope.canvas_nodejs_layer_path

        # todo: remove this function from here
        # self.microservice = MicroServices(scope, "Microservices")

        self.function_map = {}

        main_stack = scope
        api_stack = scope

        self._main_stack = main_stack
        self._api_stack = api_stack
        self._region = main_stack.region
        self._account = main_stack.account
        self._resource_name = main_stack.resource_name

        self.create_all_microservice()

    def create_all_microservice(self):
        self.create_iot_core_api_microservices()

    def create_iot_core_api_microservices(self):
        # Get S3 pre-signed url
        function_name = "GetS3PreSignedUrl_iotAPI"
        function_id = "getS3PreSignedUrlHandler_iotAPI"
        function_handler_name = "listApiFunctionsHandler"
        entry_path = (
            "./IotMicroservices/customizeLayer/handlers/Application/listApiFunctions.mjs"
        )
        policy_list = [
            iam.PolicyStatement(
                effect=iam.Effect.ALLOW,
                actions=["s3:PutObject", "s3:GetObject"],
                resources=[f"arn:aws:s3:::{self._main_stack.bucket.bucket_name}/*"],
            ),
            iam.PolicyStatement(
                effect=iam.Effect.ALLOW,
                actions=["iot:Publish"],
                resources=[
                    f"arn:aws:iot:{self._region}:{self._account}:topic/kaso/{self._resource_name.lower()}/microservice/*/getS3PreSignedUrl/response"
                ],
            ),
            iam.PolicyStatement(
                effect=iam.Effect.ALLOW, actions=["iot:Connect"], resources=[f"*"]
            ),
        ]
        environment_map = {
            "BucketName": self._main_stack.bucket.bucket_name,
            "IotEndpoint": self._main_stack.iot_endpoint,
        }
        self.function_map[function_name] = CdkUtility.addNewFunction(
            self._api_stack,
            self._resource_name,
            function_name=function_name,
            function_id=function_id,
            function_handler_name=function_handler_name,
            entry_path=entry_path,
            policy_list=policy_list,
            environment_map=environment_map,
        )

        

    
