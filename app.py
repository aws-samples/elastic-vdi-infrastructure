#!/usr/bin/env python3

# Copyright (C) 2022 by Amazon.com, Inc. or its affiliates.  All Rights Reserved.
# SPDX-License-Identifier: MIT

import aws_cdk as cdk

from elastic_vdi_infrastructure.networking_stack import NetworkingStack
from elastic_vdi_infrastructure.assets_stack import AssetsStack
from elastic_vdi_infrastructure.parameters_stack import ParametersStack
from elastic_vdi_infrastructure.security_stack import SecurityStack
from elastic_vdi_infrastructure.storage_stack import StorageStack
from elastic_vdi_infrastructure.elastic_vdi_infrastructure_stack import ElasticVdiInfrastructureStack


CONFIG = {
    "region": "CHANGE_ME",  # AWS Region
    "account": "CHANGE_ME",  # AWS account number
    "ec2_type_enginframe": "t3.large",  # EnginFrame instance type
    "ec2_type_broker": "t3.large",  # Broker instance type
    "key_name": "CHANGE_ME",  # SSH key name that you already have in your account
    "ebs_enginframe_size": 50,  # EBS size for EnginFrame,
    "ebs_broker_size": 50,  # EBS size for the Broker
    "TagName": "TagName",  # Tag Name for billing
    "TagValue": "TagValue",  # Tag Value for billing
    "efadmin_uid": "50000",
    "linux_shared_storage_size": 64,  # OpenZFS size in GiB
    "Shared_Storage_Linux": "/shared",  # Shared Linux storage
    "Enginframe_installer": "https://dn3uclhgxk1jt.cloudfront.net/enginframe/packages/enginframe-latest.jar",
    "Session_Manager_Broker_Installer": "https://d1uj6qtbmh3dt5.cloudfront.net/nice-dcv-session-manager-broker-el7.noarch.rpm"
}


app = cdk.App()
NetworkingStack = NetworkingStack(
    app,
    "Networking-Stack",
    env={"region": CONFIG['region'],
         "account": CONFIG['account']}
)

AssetsStack = AssetsStack(
    app,
    "Assets-Stack",
    env={"region": CONFIG['region'],
         "account": CONFIG['account']}
)

SecurityStack = SecurityStack(
    app,
    "Security-Stack",
    config=CONFIG,
    vpc=NetworkingStack.vpc,
    closing_hook=AssetsStack.closing_hook,
    starting_hook=AssetsStack.starting_hook,
    interactive_builtin_linux_desktop=AssetsStack.interactive_builtin_linux_desktop,
    interactive_builtin_windows_desktop=AssetsStack.interactive_builtin_windows_desktop,
    swagger_client=AssetsStack.swagger_client,
    dcvasg_cloudwatch_metrics=AssetsStack.dcvasg_cloudwatch_metrics,
    dcvasg_triggers=AssetsStack.dcvasg_triggers,
    dcvasg=AssetsStack.dcvasg,
    dcvsm=AssetsStack.dcvsm,
    grid_list_hosts_ui=AssetsStack.grid_list_hosts_ui,
    enginframe_node_configuration=AssetsStack.enginframe_node_configuration,
    linux_userdata=AssetsStack.linux_userdata,
    windows_userdata=AssetsStack.windows_userdata,
    imds_access=AssetsStack.imds_access,
    broker_userdata=AssetsStack.broker_userdata,
    aws_py=AssetsStack.aws_py,
    env={"region": CONFIG['region'],
         "account": CONFIG['account']}
)

StorageStack = StorageStack(
    app,
    "Storage-Stack",
    config=CONFIG,
    vpc=NetworkingStack.vpc,
    securityGroupId=SecurityStack.storage_security_group,
    env={"region": CONFIG['region'],
         "account": CONFIG['account']}
)


ParametersStack = ParametersStack(
    app,
    "Parameters-Stack",
    config=CONFIG,
    dcv_security_group=SecurityStack.dcv_security_group,
    linux_userdata=AssetsStack.linux_userdata,
    windows_userdata=AssetsStack.windows_userdata,
    imds_access=AssetsStack.imds_access,
    efadmin_password=SecurityStack.efadmin_password,
    role_dcv=SecurityStack.role_dcv,
    shared_file_system=StorageStack.cfn_file_system,
    vpc=NetworkingStack.vpc,
    env={"region": CONFIG['region'],
         "account": CONFIG['account']}
)

ElasticVdiInfrastructureStack = ElasticVdiInfrastructureStack(
    app,
    "Elastic-Vdi-Infrastructure",
    config=CONFIG,
    vpc=NetworkingStack.vpc,
    role_broker=SecurityStack.role_broker,
    alb_security_group=SecurityStack.alb_security_group,
    broker_security_group=SecurityStack.broker_security_group,
    broker_alb_security_group=SecurityStack.broker_alb_security_group,
    broker_userdata=AssetsStack.broker_userdata,
    role_ef=SecurityStack.role_ef,
    role_lambda=SecurityStack.role_lambda,
    ef_security_group=SecurityStack.ef_security_group,
    closing_hook=AssetsStack.closing_hook,
    starting_hook=AssetsStack.starting_hook,
    interactive_builtin_linux_desktop=AssetsStack.interactive_builtin_linux_desktop,
    interactive_builtin_windows_desktop=AssetsStack.interactive_builtin_windows_desktop,
    swagger_client=AssetsStack.swagger_client,
    dcvasg_cloudwatch_metrics=AssetsStack.dcvasg_cloudwatch_metrics,
    dcvasg_triggers=AssetsStack.dcvasg_triggers,
    aws_py=AssetsStack.aws_py,
    dcvasg=AssetsStack.dcvasg,
    dcvsm=AssetsStack.dcvsm,
    grid_list_hosts_ui=AssetsStack.grid_list_hosts_ui,
    enginframe_node_configuration=AssetsStack.enginframe_node_configuration,
    imds_access=AssetsStack.imds_access,
    efadmin_password=SecurityStack.efadmin_password,
    shared_file_system=StorageStack.cfn_file_system,
    env={"region": CONFIG['region'],
         "account": CONFIG['account']}
)

cdk.Tags.of(app).add(CONFIG['TagName'], CONFIG['TagValue'])

app.synth()
