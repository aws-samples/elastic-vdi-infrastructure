# Copyright (C) 2022 by Amazon.com, Inc. or its affiliates.  All Rights Reserved.
# SPDX-License-Identifier: MIT

from aws_cdk import (
    Stack,
    aws_ec2 as ec2,
)
from constructs import Construct

# Class used to build the VPC and Subnets


class NetworkingStack(Stack):

    def __init__(self, scope: Construct, construct_id: str, **kwargs) -> None:
        super().__init__(scope, construct_id, **kwargs)

        # VPC creation
        self.vpc = ec2.Vpc(self, "VPC",
                           max_azs=2,
                           cidr="10.0.0.0/16",
                           subnet_configuration=[
                               ec2.SubnetConfiguration(
                                   subnet_type=ec2.SubnetType.PUBLIC,
                                   name="Elastic-VDI-Infrastructure-Public",
                                   cidr_mask=24
                               ),
                               ec2.SubnetConfiguration(
                                   subnet_type=ec2.SubnetType.PRIVATE_WITH_NAT,
                                   name="Elastic-VDI-Infrastructure-Private",
                                   cidr_mask=24
                               )
                           ])
