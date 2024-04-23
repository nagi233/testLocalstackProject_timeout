#!/usr/bin/env python3
import os

import aws_cdk as cdk

from kaso_iot_fit_one_cdkv2.kaso_iot_fit_one_cdkv2_stack import KasoIotFitOneCdkv2Stack

app = cdk.App()

account = app.node.try_get_context("account")
region = app.node.try_get_context("region")
application_name = app.node.try_get_context("applicationName")
environment = app.node.try_get_context("environment")

env_info = cdk.Environment(account=account, region=region)
KasoIotFitOneCdkv2Stack(
    app, f"{application_name}-{environment}", env=env_info)

app.synth()
