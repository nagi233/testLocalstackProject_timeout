from aws_cdk import (
    aws_iam as iam,
    aws_lambda_nodejs as lambda_nodejs,
    aws_iot as iot,
    NestedStack,
    aws_apigateway as apigateway,
    Duration,
    aws_events as events,
    aws_events_targets as targets,
    aws_cognito as cognito,
    custom_resources as custom_resources,
    aws_logs as logs,
    aws_sns as sns,
    aws_cloudwatch_actions as actions,
    aws_cloudwatch as cloudwatch,
)

from constructs import Construct
import boto3


class KasoIotFitOneCdkv2ManageStack(NestedStack):
    def __init__(self, scope: Construct, id: str, micro_service) -> None:
        super().__init__(scope, id)

        self._resource_name = scope.resource_name
        self._main_stack = scope
        self._micro_service = micro_service

        self._iotActionSetup()
        return

    def _iotActionSetup(self):
        # Get S3 signed url
        get_s3_pre_signed_url_topic = (
            f"kaso/{self._resource_name.lower()}/gateway/+/getS3PreSignedUrl/request"
        )
        get_s3_pre_signed_url_function = self._micro_service.function_map[
            "GetS3PreSignedUrl_iotAPI"
        ]
        rule = iot.CfnTopicRule(
            self,
            f"{self._resource_name}_GetS3PreSignedUrl",
            rule_name=f"{self._resource_name}_GetS3PreSignedUrl",
            topic_rule_payload=iot.CfnTopicRule.TopicRulePayloadProperty(
                actions=[
                    iot.CfnTopicRule.ActionProperty(
                        lambda_=iot.CfnTopicRule.LambdaActionProperty(
                            function_arn=get_s3_pre_signed_url_function.function_arn
                        )
                    )
                ],
                sql=f"SELECT *, clientid() as thingName, topic() as topic FROM '{get_s3_pre_signed_url_topic}'",
            ),
        )
        self._micro_service.function_map["GetS3PreSignedUrl_iotAPI"].add_permission(
            f"{self._resource_name}-AllowIotInvoke",
            principal=iam.ServicePrincipal("iot.amazonaws.com"),
            source_arn=rule.attr_arn,
        )
