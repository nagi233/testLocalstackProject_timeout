from aws_cdk import (
    NestedStack,
    aws_events as events,
    aws_events_targets as targets,
    aws_iot as iot,
    aws_iam as iam,
)

from constructs import Construct


class CustomizeLayerManageStack(NestedStack):
    def __init__(self, scope: Construct, id: str, micro_service) -> None:
        super().__init__(scope, id)

        self._resource_name = scope.resource_name
        self._main_stack = scope
        self._micro_service = micro_service
        self._rules = {}

        self._iotActionSetup()
        self._cloudWatchSetup()
        return

    @property
    def rules(self):
        return self._rules

    def _iotActionSetup(self):
        # get_s3_pre_signed_url_topic = (
        #     f"kaso/{self._resource_name.lower()}/gateway/+/getS3PreSignedUrl/request"
        # )
        # get_s3_pre_signed_url_function = self._micro_service.function_map[
        #     "login"
        # ]
        # rule = iot.CfnTopicRule(
        #     self,
        #     f"{self._resource_name}_login",
        #     rule_name=f"{self._resource_name}_login",
        #     topic_rule_payload=iot.CfnTopicRule.TopicRulePayloadProperty(
        #         actions=[
        #             iot.CfnTopicRule.ActionProperty(
        #                 lambda_=iot.CfnTopicRule.LambdaActionProperty(
        #                     function_arn=get_s3_pre_signed_url_function.function_arn
        #                 )
        #             )
        #         ],
        #         sql=f"SELECT *, clientid() as thingName, topic() as topic FROM '{get_s3_pre_signed_url_topic}'",
        #     ),
        # )
        # self._micro_service.function_map["login"].add_permission(
        #     f"{self._resource_name}-AllowIotInvoke",
        #     principal=iam.ServicePrincipal("iot.amazonaws.com"),
        #     source_arn=rule.attr_arn,
        # )
        pass
    
    def _cloudWatchSetup(self):
        execute_every_5_minute = events.Schedule.cron(
            minute="0,5,10,15,20,25,30,35,40,45,50,55", hour="*", day=None, month=None, year=None
        )
        five_minute_rule = events.Rule(self, f"ExecuteEvery5Minutes", schedule=execute_every_5_minute)#注销内容
        five_minute_rule.add_target(targets.LambdaFunction(self._micro_service.function_map["login"]))
