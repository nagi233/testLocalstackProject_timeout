from aws_cdk import (
    Duration,
    aws_iam as iam,
    aws_lambda_nodejs as lambda_nodejs,
    aws_lambda as lambda_,
    aws_apigateway as apigateway,
    Stack,
)

import json


class CdkUtility:
    @staticmethod
    def addNewFunction(
        api_stack: Stack,
        resource_name: str,
        function_name: str,
        function_handler_name: str,
        entry_path: str,
        policy_list: list = None,
        environment_map: dict = None,
        function_id: str = None,
        lambda_memory_size: int = 1024,
        lambda_layers: list = [],
    ) -> lambda_nodejs.NodejsFunction:
        if function_id == None:
            function_id = function_handler_name

        function = lambda_nodejs.NodejsFunction(
            api_stack,
            function_id,
            entry=entry_path,
            project_root="./IotMicroservices/",
            deps_lock_file_path="./IotMicroservices/package-lock.json",
            handler=function_handler_name,
            function_name=f"{resource_name}-{function_name}",
            memory_size=lambda_memory_size,
            architecture=lambda_.Architecture.X86_64,
            runtime=lambda_.Runtime.NODEJS_16_X,
            layers=lambda_layers,
            bundling=lambda_nodejs.BundlingOptions(
                external_modules=["canvas"],
            ),
            timeout=Duration.seconds(300),
        )

        if policy_list is not None:
            function.role.attach_inline_policy(
                iam.Policy(
                    api_stack,
                    f"{resource_name}-{function_name}-ExecutePolicy",
                    statements=policy_list,
                )
            )

        function.add_environment("EnableLog", "true")
        if environment_map is not None:
            for key in environment_map:
                function.add_environment(key, environment_map[key])

        return function

    @staticmethod
    def addNewMethod(
        stack: Stack,
        method_name: str,
        http_method: str,
        path: str,
        lambda_function: lambda_nodejs.NodejsFunction,
        resource_name: str,
        is_need_auth: bool,
        tags,
        description: str,
        apigateway_authorizer: apigateway.TokenAuthorizer,
        api: apigateway.RestApi,
        request_query_string: dict = None,
        request_parameters: list = {},
        is_pf_api: bool = False,
    ):
        request_model = None
        response_model = None
        authorizer = None
        if is_need_auth == True:
            request_parameters["method.request.header.Authorization"] = True
            authorizer = apigateway_authorizer

        if request_query_string != None:
            for key in request_query_string:
                request_parameters[
                    f"method.request.querystring.{key}"
                ] = request_query_string[key]

        request_model = None

        if request_model == None:
            method = api.root.add_resource(path).add_method(
                http_method,
                apigateway.LambdaIntegration(lambda_function, proxy=True),
                request_parameters=request_parameters,
                authorizer=authorizer,
            )
        else:
            method = api.root.add_resource(path).add_method(
                http_method,
                apigateway.LambdaIntegration(lambda_function, proxy=True),
                request_parameters=request_parameters,
                authorizer=authorizer,
            )

        return request_model, response_model, None, method
