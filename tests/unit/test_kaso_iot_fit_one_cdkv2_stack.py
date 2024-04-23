import aws_cdk as core
import aws_cdk.assertions as assertions

from kaso_iot_fit_one_cdkv2.kaso_iot_fit_one_cdkv2_stack import KasoIotFitOneCdkv2Stack

# example tests. To run these tests, uncomment this file along with the example
# resource in kaso_iot_fit_one_cdkv2/kaso_iot_fit_one_cdkv2_stack.py
def test_sqs_queue_created():
    app = core.App()
    stack = KasoIotFitOneCdkv2Stack(app, "kaso-iot-fit-one-cdkv2")
    template = assertions.Template.from_stack(stack)

#     template.has_resource_properties("AWS::SQS::Queue", {
#         "VisibilityTimeout": 300
#     })
