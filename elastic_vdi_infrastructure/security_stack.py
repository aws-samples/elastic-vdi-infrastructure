# Copyright (C) 2022 by Amazon.com, Inc. or its affiliates.  All Rights Reserved.
# SPDX-License-Identifier: MIT

from aws_cdk import (
    Stack,
    aws_ec2 as ec2,
    aws_iam as iam,
    aws_secretsmanager as secretsmanager,
)

from constructs import Construct

# Class used to create the Security Groups and the IAM roles


class SecurityStack(Stack):

    def __init__(self, scope: Construct, construct_id: str,
                 config: list,
                 vpc,
                 closing_hook,
                 starting_hook,
                 interactive_builtin_linux_desktop,
                 interactive_builtin_windows_desktop,
                 swagger_client,
                 dcvasg_cloudwatch_metrics,
                 dcvasg_triggers,
                 dcvasg,
                 dcvsm,
                 grid_list_hosts_ui,
                 enginframe_node_configuration,
                 linux_userdata,
                 windows_userdata,
                 imds_access,
                 broker_userdata,
                 aws_py,
                 **kwargs) -> None:
        super().__init__(scope, construct_id, **kwargs)

        # generate the efadmin user password
        self.efadmin_password = secretsmanager.Secret(
            self,
            "EfadminPassword",
            generate_secret_string=secretsmanager.SecretStringGenerator(
                password_length=16,
                exclude_punctuation=True))

        # Create ALB SG
        self.alb_security_group, self.broker_alb_security_group = self.create_alb_sg(
            vpc, config)

        # Create the EF, DCV and Broker security groups
        self.ef_security_group, self.dcv_security_group, self.broker_security_group = self.create_nodes_security_groups(
            vpc, self.alb_security_group, self.broker_alb_security_group)

        # Create the Storage security group
        self.storage_security_group = self.create_storage_security_group(
            vpc,
            self.dcv_security_group,
            self.ef_security_group
        )

        # ROLES
        self.role_ef = self.create_ef_role(
            config,
            closing_hook,
            starting_hook,
            interactive_builtin_linux_desktop,
            interactive_builtin_windows_desktop,
            swagger_client,
            dcvasg_cloudwatch_metrics,
            dcvasg_triggers,
            dcvasg,
            dcvsm,
            grid_list_hosts_ui,
            enginframe_node_configuration,
            self.efadmin_password,
            imds_access,
            aws_py
        )
        self.role_dcv = self.create_dcv_role(
            linux_userdata,
            windows_userdata,
            config,
            self.efadmin_password,
            imds_access
        )
        self.role_broker = self.create_broker_role(
            broker_userdata,
            config
        )
        self.role_lambda = self.create_lambda_role(
            config
        )

    # Function used to create the ALB security groups

    def create_alb_sg(
        self,
        vpc,
        config
    ):
        # ALB Security group EnginFrame
        alb_security_group = ec2.SecurityGroup(
            self,
            "ALBSecurityGroup",
            vpc=vpc,
            description="ALB SecurityGroup ",
            allow_all_outbound=True,
        )
        # Allow 443 access to the ALB
        alb_security_group.add_ingress_rule(ec2.Peer.ipv4(
            '0.0.0.0/0'), ec2.Port.tcp(443), "allow http access")

        # ALB Security group Broker
        broker_alb_security_group = ec2.SecurityGroup(
            self,
            "ALBSecurityGroupBroker",
            vpc=vpc,
            description="ALB SecurityGroup Broker",
            allow_all_outbound=True,
        )
        # Allow access to the ALB
        broker_alb_security_group.add_ingress_rule(ec2.Peer.ipv4(
            vpc.vpc_cidr_block), ec2.Port.tcp(8443), "allow access")
        broker_alb_security_group.add_ingress_rule(ec2.Peer.ipv4(
            vpc.vpc_cidr_block), ec2.Port.tcp(8445), "allow access")

        return alb_security_group, broker_alb_security_group

    # Function to create the EF, DCV and Broker security groups

    def create_nodes_security_groups(
        self,
        vpc,
        alb_security_group,
        broker_alb_security_group
    ):
        ef_security_group = ec2.SecurityGroup(
            self,
            "EFSecurityGroup",
            vpc=vpc,
            description="SecurityGroup for EF ",
            allow_all_outbound=True,
        )
        dcv_security_group = ec2.SecurityGroup(
            self,
            "DCVSecurityGroup",
            vpc=vpc,
            description="SecurityGroup for DCV ",
            allow_all_outbound=True,
        )
        broker_security_group = ec2.SecurityGroup(
            self,
            "BrokerSecurityGroup",
            vpc=vpc,
            description="SecurityGroup for DCVSM Broker ",
            allow_all_outbound=True,
        )

        ef_security_group.add_ingress_rule(
            alb_security_group,
            ec2.Port.tcp(8443),
            "allow http access from the vpc")
        ef_security_group.add_ingress_rule(
            dcv_security_group, ec2.Port.all_traffic(), "allow local access ")
        dcv_security_group.add_ingress_rule(
            alb_security_group, ec2.Port.tcp(8443), "allow dcv access ")
        dcv_security_group.add_ingress_rule(
            ef_security_group, ec2.Port.all_traffic(), "allow local access ")
        broker_security_group.add_ingress_rule(
            broker_alb_security_group,
            ec2.Port.tcp(8445),
            "allow broker access ")
        broker_security_group.add_ingress_rule(
            broker_alb_security_group,
            ec2.Port.tcp(8443),
            "allow broker access ")
        broker_security_group.add_ingress_rule(
            broker_security_group, ec2.Port.tcp_range(
                47100, 47200), "allow broker to broker ")
        broker_security_group.add_ingress_rule(
            broker_security_group, ec2.Port.tcp_range(
                47500, 47600), "allow broker to broker ")

        return ef_security_group, dcv_security_group, broker_security_group

    # Function to create the Storage security group

    def create_storage_security_group(
        self,
        vpc,
        dcv_security_group,
        ef_security_group
    ):
        storage_security_group = ec2.SecurityGroup(
            self,
            "StorageSecurityGroup",
            vpc=vpc,
            description="SecurityGroup for Storage ",
            allow_all_outbound=True,
        )

        storage_security_group.add_ingress_rule(
            dcv_security_group,
            ec2.Port.tcp(111),
            "Remote procedure call for NFS - DCV nodes")
        storage_security_group.add_ingress_rule(
            ef_security_group,
            ec2.Port.tcp(111),
            "Remote procedure call for NFS - EF node")

        storage_security_group.add_ingress_rule(
            dcv_security_group,
            ec2.Port.udp(111),
            "Remote procedure call for NFS - DCV nodes")
        storage_security_group.add_ingress_rule(
            ef_security_group,
            ec2.Port.udp(111),
            "Remote procedure call for NFS - EF node")

        storage_security_group.add_ingress_rule(
            dcv_security_group,
            ec2.Port.tcp(2049),
            "NFS server daemon - DCV nodes")
        storage_security_group.add_ingress_rule(
            ef_security_group,
            ec2.Port.tcp(2049),
            "NFS server daemon - EF node")

        storage_security_group.add_ingress_rule(
            dcv_security_group,
            ec2.Port.udp(2049),
            "NFS server daemon - DCV nodes")
        storage_security_group.add_ingress_rule(
            ef_security_group,
            ec2.Port.udp(2049),
            "NFS server daemon - EF node")

        storage_security_group.add_ingress_rule(dcv_security_group, ec2.Port.tcp_range(
            20001, 20003), "NFS mount, status monitor, and lock daemon - DCV nodes")
        storage_security_group.add_ingress_rule(ef_security_group, ec2.Port.tcp_range(
            20001, 20003), "NFS mount, status monitor, and lock daemon - EF node")

        storage_security_group.add_ingress_rule(dcv_security_group, ec2.Port.udp_range(
            20001, 20003), "NFS mount, status monitor, and lock daemon - DCV nodes")
        storage_security_group.add_ingress_rule(ef_security_group, ec2.Port.udp_range(
            20001, 20003), "NFS mount, status monitor, and lock daemon - EF node")

        return storage_security_group

    # Function used to create the EnginFrame required role
    def create_ef_role(
        self,
        config,
        closing_hook,
        starting_hook,
        interactive_builtin_linux_desktop,
        interactive_builtin_windows_desktop,
        swagger_client,
        dcvasg_cloudwatch_metrics,
        dcvasg_triggers,
        dcvasg,
        dcvsm,
        grid_list_hosts_ui,
        enginframe_node_configuration,
        efadmin_password,
        imds_access,
        aws_py
    ):
        # Instances Role
        role_ef = iam.Role(
            self,
            "EF_ROLE",
            assumed_by=iam.ServicePrincipal("ec2.amazonaws.com"))
        # Allow console access with SSM
        role_ef.add_managed_policy(iam.ManagedPolicy.from_aws_managed_policy_name(
            "AmazonSSMManagedInstanceCore"))
        # Allow to the EF node to modify the SSM parameters
        role_ef.add_to_policy(
            iam.PolicyStatement(
                effect=iam.Effect.ALLOW,
                actions=[
                    "ssm:PutParameter",
                    "ssm:GetParameter",
                    "ssm:GetParametersByPath"],
                resources=[
                    "arn:aws:ssm:" +
                    config['region'] +
                    ":" +
                    config['account'] +
                    ":parameter/dcv/*",
                    "arn:aws:ssm:" +
                    config['region'] +
                    ":" +
                    config['account'] +
                    ":parameter/dcvbroker/*"],
            ))

        # Allow the EF node to download the required files from S3
        role_ef.add_to_policy(
            iam.PolicyStatement(
                effect=iam.Effect.ALLOW,
                actions=["s3:GetObject"],
                resources=[
                    "arn:aws:s3:::" +
                    closing_hook.s3_bucket_name +
                    "/" +
                    closing_hook.s3_object_key,
                    "arn:aws:s3:::" +
                    starting_hook.s3_bucket_name +
                    "/" +
                    starting_hook.s3_object_key,
                    "arn:aws:s3:::" +
                    interactive_builtin_linux_desktop.s3_bucket_name +
                    "/" +
                    interactive_builtin_linux_desktop.s3_object_key,
                    "arn:aws:s3:::" +
                    interactive_builtin_windows_desktop.s3_bucket_name +
                    "/" +
                    interactive_builtin_windows_desktop.s3_object_key,
                    "arn:aws:s3:::" +
                    swagger_client.s3_bucket_name +
                    "/" +
                    swagger_client.s3_object_key,
                    "arn:aws:s3:::" +
                    dcvasg_cloudwatch_metrics.s3_bucket_name +
                    "/" +
                    dcvasg_cloudwatch_metrics.s3_object_key,
                    "arn:aws:s3:::" +
                    dcvasg_triggers.s3_bucket_name +
                    "/" +
                    dcvasg_triggers.s3_object_key,
                    "arn:aws:s3:::" +
                    dcvasg.s3_bucket_name +
                    "/" +
                    dcvasg.s3_object_key,
                    "arn:aws:s3:::" +
                    dcvsm.s3_bucket_name +
                    "/" +
                    dcvsm.s3_object_key,
                    "arn:aws:s3:::" +
                    grid_list_hosts_ui.s3_bucket_name +
                    "/" +
                    grid_list_hosts_ui.s3_object_key,
                    "arn:aws:s3:::" +
                    enginframe_node_configuration.s3_bucket_name +
                    "/" +
                    enginframe_node_configuration.s3_object_key,
                    "arn:aws:s3:::" +
                    imds_access.s3_bucket_name +
                    "/" +
                    imds_access.s3_object_key,
                    "arn:aws:s3:::" +
                    aws_py.s3_bucket_name +
                    "/" +
                    aws_py.s3_object_key],
            ))

        # Allow to retrieve the efadmin password
        role_ef.add_to_policy(
            iam.PolicyStatement(
                effect=iam.Effect.ALLOW,
                actions=[
                    "secretsmanager:GetSecretValue"
                ],
                resources=[efadmin_password.secret_arn],
            )
        )

        # Allow to describe the instances and tags
        role_ef.add_to_policy(
            iam.PolicyStatement(
                effect=iam.Effect.ALLOW,
                actions=[
                    "ec2:DescribeInstances",
                    "ec2:DescribeTags"
                ],
                resources=["*"],
            )
        )

        # Policies required for the elasticity
        role_ef.add_to_policy(
            iam.PolicyStatement(
                effect=iam.Effect.ALLOW,
                actions=[
                    "elasticloadbalancing:*",
                    "autoscaling:DescribeAutoScalingGroups",
                    "autoscaling:SetInstanceProtection",
                    "cloudwatch:PutMetricData"
                ],
                resources=["*"],
            )
        )

        # Allow create tags
        role_ef.add_to_policy(
            iam.PolicyStatement(
                effect=iam.Effect.ALLOW,
                actions=[
                    "ec2:CreateTags",
                    "ec2:DeleteTags"
                ],
                resources=["*"],
            )
        )

        return role_ef

    # Function used to create the DCV required role

    def create_dcv_role(
        self,
        linux_userdata,
        windows_userdata,
        config,
        efadmin_password,
        imds_access
    ):
        # Instances Role
        role_dcv = iam.Role(
            self,
            "DCV_ROLE",
            assumed_by=iam.ServicePrincipal("ec2.amazonaws.com"))

        # Allow console access with SSM
        role_dcv.add_managed_policy(iam.ManagedPolicy.from_aws_managed_policy_name(
            "AmazonSSMManagedInstanceCore"))

        # Allow the DCV nodes to access the parameters
        role_dcv.add_to_policy(
            iam.PolicyStatement(
                effect=iam.Effect.ALLOW,
                actions=[
                    "ssm:GetParameter",
                    "ssm:GetParametersByPath"
                ],
                resources=["arn:aws:ssm:" + config['region'] +
                           ":" + config['account'] + ":parameter/dcv/*"],
            )
        )
        # Allow to retrieve the efadmin password
        role_dcv.add_to_policy(
            iam.PolicyStatement(
                effect=iam.Effect.ALLOW,
                actions=[
                    "secretsmanager:GetSecretValue"
                ],
                resources=[efadmin_password.secret_arn],
            )
        )
        # Allow to describe the instances
        role_dcv.add_to_policy(
            iam.PolicyStatement(
                effect=iam.Effect.ALLOW,
                actions=[
                    "ec2:DescribeInstances",
                    "logs:CreateLogStream",
                    "logs:CreateLogGroup",
                    "logs:PutLogEvents",
                    "logs:DescribeLogGroups",
                    "logs:DescribeLogStreams"
                ],
                resources=["*"],
            )
        )

        # Allow to the DCV node to download the required files from S3
        role_dcv.add_to_policy(
            iam.PolicyStatement(
                effect=iam.Effect.ALLOW,
                actions=["s3:GetObject"],
                resources=[
                    "arn:aws:s3:::" +
                    linux_userdata.s3_bucket_name +
                    "/" +
                    linux_userdata.s3_object_key,
                    "arn:aws:s3:::" +
                    windows_userdata.s3_bucket_name +
                    "/" +
                    windows_userdata.s3_object_key,
                    "arn:aws:s3:::dcv-license." +
                    config['region'] +
                    "/*",
                    "arn:aws:s3:::" +
                    imds_access.s3_bucket_name +
                    "/" +
                    imds_access.s3_object_key],
            ))

        return role_dcv

    # Function used to create the Broker required role

    def create_broker_role(
        self,
        broker_userdata,
        config
    ):
        # Instances Role
        role_broker = iam.Role(
            self,
            "Broker_ROLE",
            assumed_by=iam.ServicePrincipal("ec2.amazonaws.com"))
        # Allow console access with SSM
        role_broker.add_managed_policy(
            iam.ManagedPolicy.from_aws_managed_policy_name("AmazonSSMManagedInstanceCore"))

        # Allow to describe the instances and elasticloadbalancing health
        # targets
        role_broker.add_to_policy(
            iam.PolicyStatement(
                effect=iam.Effect.ALLOW,
                actions=[
                    "ec2:DescribeInstances",
                    "elasticloadbalancing:DescribeTargetHealth"
                ],
                resources=["*"],
            )
        )

        # Allow the Broker nodes to access the parameters
        role_broker.add_to_policy(
            iam.PolicyStatement(
                effect=iam.Effect.ALLOW,
                actions=[
                    "ssm:GetParameter",
                    "ssm:GetParametersByPath",
                    "ssm:PutParameter"
                ],
                resources=["arn:aws:ssm:" + config['region'] +
                           ":" + config['account'] + ":parameter/dcvbroker/*"],
            )
        )

        # Allow the Broker node to download the required files from S3
        role_broker.add_to_policy(
            iam.PolicyStatement(
                effect=iam.Effect.ALLOW,
                actions=[
                    "s3:GetObject"
                ],
                resources=["arn:aws:s3:::" + broker_userdata.s3_bucket_name +
                           "/" + broker_userdata.s3_object_key],
            )
        )

        return role_broker

    # Function used to create the Lambda required role

    def create_lambda_role(
        self,
        config
    ):

        lambda_role = iam.Role(
            self,
            id="LambdaRole",
            assumed_by=iam.ServicePrincipal("lambda.amazonaws.com"))
        lambda_role.add_to_policy(
            iam.PolicyStatement(
                effect=iam.Effect.ALLOW,
                actions=[
                    "acm:ImportCertificate",
                    "acm:ListCertificates",
                    "acm:DeleteCertificate",
                    "acm:DescribeCertificate",
                    "logs:CreateLogStream",
                    "logs:CreateLogGroup",
                    "logs:PutLogEvents"
                ],
                resources=["*"],
            )
        )
        lambda_role.add_to_policy(
            iam.PolicyStatement(
                effect=iam.Effect.ALLOW,
                actions=["ssm:PutParameter"],
                resources=[
                    "arn:aws:ssm:" +
                    config['region'] +
                    ":" +
                    config['account'] +
                    ":parameter/dcv/linux/DcvBrokerCACertificate"],
            ))

        return lambda_role
