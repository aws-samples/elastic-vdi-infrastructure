# Copyright (C) 2022 by Amazon.com, Inc. or its affiliates.  All Rights Reserved.
# SPDX-License-Identifier: MIT

import aws_cdk as cdk

from aws_cdk import (
    Stack,
    aws_s3_assets as assets,
)
from constructs import Construct

# Class used to build the VPC and Subnets
class AssetsStack(Stack):

    def __init__(self, scope: Construct, construct_id: str, **kwargs) -> None:
        super().__init__(scope, construct_id, **kwargs)
        
        # Copy the required files to S3
        self.closing_hook = assets.Asset(
            self, "ClosingHook", path='scripts/alb.session.closing.hook.sh')
        self.starting_hook = assets.Asset(
            self, "StartingHook", path='scripts/alb.session.starting.hook.sh')
        self.interactive_builtin_linux_desktop = assets.Asset(
            self, "LinuxDesktop", path='scripts/interactive_builtin_linux_desktop.xml')
        self.interactive_builtin_windows_desktop = assets.Asset(
            self, "WindowsDesktop", path='scripts/interactive_builtin_windows_desktop.xml')
        self.swagger_client = assets.Asset(
            self, "SwaggerClient", path='scripts/swagger_client.zip')
        self.dcvasg_cloudwatch_metrics = assets.Asset(
            self, "DcvasgCloudwatchMetrics", path='scripts/dcvasg-cloudwatch-metrics.xml')        
        self.dcvasg_triggers = assets.Asset(
            self, "DcvasgTriggers", path='scripts/dcvasg.triggers.xml')
        self.dcvasg = assets.Asset(
            self, "dcvasg", path='scripts/dcvasg.py')
        self.dcvsm = assets.Asset(
            self, "dcvsm", path='scripts/dcvsm.py')
        self.linux_userdata = assets.Asset(
            self, "linux_userdata", path='scripts/dcv_linux.sh')
        self.windows_userdata = assets.Asset(
            self, "windows_userdata", path='scripts/dcv_windows.ps1')
        self.grid_list_hosts_ui = assets.Asset(
            self, "grid_list_hosts_ui", path='scripts/grid.list.hosts.ui')
        self.enginframe_node_configuration = assets.Asset(
            self, "enginframe_node_configuration", path='scripts/enginframe.sh')
        self.broker_userdata = assets.Asset(
            self, "broker_userdata", path='scripts/broker.sh')
        self.imds_access = assets.Asset(
            self, "imds_access", path='scripts/imds-access.sh')
        self.aws_py = assets.Asset(
            self, "AWSPY", path='scripts/aws.py')
