# Copyright (C) 2022 by Amazon.com, Inc. or its affiliates.  All Rights Reserved.
# SPDX-License-Identifier: MIT

import base64

import aws_cdk as cdk

from aws_cdk import (
    Stack,
    aws_autoscaling as autoscaling,
    aws_ec2 as ec2,
    aws_elasticloadbalancingv2 as elbv2,
    aws_ssm as ssm,
    aws_s3 as s3,
    aws_logs as logs,
    aws_certificatemanager as acm,
    cloudformation_include as cfn_inc,
    aws_elasticloadbalancingv2_targets as targets,
    aws_lambda as _lambda,
    custom_resources as cr,
    aws_certificatemanager as acm,
)
from constructs import Construct

class ElasticVdiInfrastructureStack(Stack):

    def __init__(self, scope: Construct, construct_id: str,
                 config,
                 vpc,
                 role_broker,
                 alb_security_group,
                 broker_security_group,
                 broker_alb_security_group,
                 broker_userdata,
                 role_ef,
                 role_lambda,
                 ef_security_group,
                 closing_hook,
                 starting_hook,
                 interactive_builtin_linux_desktop,
                 interactive_builtin_windows_desktop,
                 swagger_client,
                 aws_py,
                 dcvasg_cloudwatch_metrics,
                 dcvasg_triggers,
                 dcvasg,
                 dcvsm,
                 grid_list_hosts_ui,
                 enginframe_node_configuration,
                 imds_access,
                 efadmin_password,
                 shared_file_system,
                 **kwargs) -> None:
        super().__init__(scope, construct_id, **kwargs)

        # Create ALB
        lb_enginframe, lb_broker = self.create_alb(
             vpc,
             config,
             alb_security_group,
             broker_alb_security_group)

        # Create DCV Broker and target group
        asg_broker, broker_tg_8443, broker_tg_8445 = self.create_broker(
             config,
             vpc,
             role_broker,
             broker_security_group,
             broker_userdata
        )
        
        # create EF instance
        asg_enginframe = self.create_enginframe(
            config,
            lb_enginframe,
            vpc,
            role_ef,
            ef_security_group,
            closing_hook,
            starting_hook,
            interactive_builtin_linux_desktop,
            interactive_builtin_windows_desktop,
            swagger_client,
            aws_py,
            dcvasg_cloudwatch_metrics,
            dcvasg_triggers,
            dcvasg,
            dcvsm,
            grid_list_hosts_ui,
            enginframe_node_configuration,
            imds_access,
            shared_file_system
        )
        
        # Lambda to create the certificate
        lambda_function = self.create_lambda(
             lb_broker,
             config,
             role_lambda
        )
        
        # Get the ACM certificate ARM from the lambda function
        certificate_arn = lambda_function.get_att_string("ACMCertificateArn")
        
        # Get the ACM certificate
        certificate = acm.Certificate.from_certificate_arn(
            self, 'Certificate', certificate_arn)
            
        # ALB listener
        listener_enginframe = lb_enginframe.add_listener(
            "Listener", port=443, certificates=[certificate])
        listener_enginframe.add_targets(
            "Target", port=8443, targets=[asg_enginframe], deregistration_delay=cdk.Duration.seconds(0))
        listener_enginframe.connections.allow_default_port_from_any_ipv4(
            "Open to the world")
            
        # Load listener certificate
        listener_certificate = elbv2.ListenerCertificate(certificate_arn)
        
        # Create Broker listeners
        listener_broker8443 = lb_broker.add_listener(
            "ListenerBroker8443", port=8443, certificates=[listener_certificate], protocol=elbv2.ApplicationProtocol.HTTPS)
        listener_broker8443.add_target_groups(
             "TargetBroker8443", target_groups=[broker_tg_8443])        
        
        listener_broker8445 = lb_broker.add_listener(
            "ListenerBroker8445", port=8445, certificates=[listener_certificate], protocol=elbv2.ApplicationProtocol.HTTPS)
        listener_broker8445.add_target_groups(
             "TargetBroker8445", target_groups=[broker_tg_8445])
             
        # Efadmin password
        cdk.CfnOutput(self, "SecretEFadminPassword",
                       value=efadmin_password.secret_arn)
                       
        # Efadmin password
        cdk.CfnOutput(self, "EnginFrameURL",
                       value="https://"+lb_enginframe.load_balancer_dns_name)

    # Function to create the ASG
    def create_asg(
            self,
            asg_type,
            vpc,
            instance_type,
            ami,
            userdata,
            role,
            key_name,
            capacity,
            security_group,
            device_name,
            volume_size,
            subnet_type
        ):
        # ASG        
        asg = autoscaling.AutoScalingGroup(
            self,
            "ASG_"+asg_type,
            auto_scaling_group_name="ASG_"+asg_type,
            vpc=vpc,
            vpc_subnets=ec2.SubnetSelection(subnet_type=subnet_type),
            instance_type=ec2.InstanceType(instance_type),
            machine_image=ami,
            user_data=userdata,
            role=role,
            health_check=autoscaling.HealthCheck.elb(grace=cdk.Duration.minutes(30)),
            key_name=key_name,
            desired_capacity=capacity,
            min_capacity=capacity,
            max_capacity=capacity,
            security_group=security_group,
            new_instances_protected_from_scale_in=False,
            signals=autoscaling.Signals.wait_for_count(
                capacity, timeout=cdk.Duration.minutes(30)),
            block_devices=[
                autoscaling.BlockDevice(
                    device_name=device_name,
                    volume=autoscaling.BlockDeviceVolume.ebs(
                        volume_type=autoscaling.EbsDeviceVolumeType.GP2,
                        volume_size=volume_size,
                        delete_on_termination=True
                    )
                )]
        )
        return asg


    # Function used to define the Broker instance
    def create_broker(self, config, vpc, role_broker, broker_security_group, broker_userdata_script):
    
        # Broker target groups
        broker_tg_8443 = elbv2.ApplicationTargetGroup(self, "broker_tg_8443",
                  target_type=elbv2.TargetType.INSTANCE,
                  port=8443,
                  vpc=vpc,
                  protocol=elbv2.ApplicationProtocol.HTTPS
        )
        
        broker_tg_8445 = elbv2.ApplicationTargetGroup(self, "broker_tg_8445",
                  target_type=elbv2.TargetType.INSTANCE,
                  port=8445,
                  vpc=vpc,
                  protocol=elbv2.ApplicationProtocol.HTTPS
        )
        
        # Userdata of the instances
        data_broker = open("userdata/broker.sh", "rb").read()
        broker_userdata = ec2.UserData.for_linux()
        data_broker_format = str(data_broker, 'utf-8').format(StackName=cdk.Aws.STACK_NAME,
                                                                      RegionName=cdk.Aws.REGION,
                                                                      alb_target_group_arn=broker_tg_8443.target_group_arn,
                                                                      broker_userdata=broker_userdata_script.s3_object_url,
                                                                      broker_installer=config['Session_Manager_Broker_Installer'])
        # Add the userdata to the instances
        broker_userdata.add_commands(data_broker_format)
        
        # Search for the latest AMIs for the instances
        linux_ami_broker =  ec2.AmazonLinuxImage(generation=ec2.AmazonLinuxGeneration.AMAZON_LINUX_2,
                                                    edition=ec2.AmazonLinuxEdition.STANDARD,
                                                    virtualization=ec2.AmazonLinuxVirt.HVM,
                                                    storage=ec2.AmazonLinuxStorage.GENERAL_PURPOSE,
                                                    cpu_type=ec2.AmazonLinuxCpuType.X86_64
                                                    )

        
        subnet_type = ec2.SubnetType.PRIVATE_WITH_NAT
        
        # EnginFrame instance ASG
        asg_broker = self.create_asg("Broker", vpc, config['ec2_type_broker'], linux_ami_broker, broker_userdata,
                                         role_broker, config['key_name'], 2, broker_security_group, "/dev/sda1", config['ebs_broker_size'], subnet_type)
                                         
        asg_broker.node.default_child.target_group_arns= [broker_tg_8443.target_group_arn, broker_tg_8445.target_group_arn]

        return asg_broker, broker_tg_8443, broker_tg_8445   
        
    # Function to create the ALBs

    def create_alb(self, vpc, config, alb_security_group, broker_alb_security_group):
      
        # Create ALB Enginframe
        lb_enginframe = elbv2.ApplicationLoadBalancer(
            self, "EFLB",
            vpc=vpc,
            internet_facing=True,
            security_group=alb_security_group,
            vpc_subnets=ec2.SubnetSelection(subnet_type=ec2.SubnetType.PUBLIC))
            
        # Create ALB Broker
        lb_broker = elbv2.ApplicationLoadBalancer(
            self, "EFLB_Broker",
            vpc=vpc,
            internet_facing=False,
            security_group=broker_alb_security_group,
            vpc_subnets=ec2.SubnetSelection(subnet_type=ec2.SubnetType.PRIVATE_WITH_NAT))
            
        ssm.StringParameter(self, "Client to Broker Host",
                                                allowed_pattern=".*",
                                                description="Client to Broker Host",
                                                parameter_name="/dcv/linux/ClientToBrokerHost",
                                                string_value=lb_broker.load_balancer_dns_name)
                                                
        ssm.StringParameter(self, "Agent to Broker Host",
                                                allowed_pattern=".*",
                                                description="Agent to Broker Host",
                                                parameter_name="/dcv/linux/AgentToBrokerHost",
                                                string_value=lb_broker.load_balancer_dns_name)

        return lb_enginframe, lb_broker
        
    # Function used to define the EnginFrame instance
    def create_enginframe(
            self,
            config,
            lb_enginframe,
            vpc,
            role_ef,
            ef_security_group,
            closing_hook,
            starting_hook,
            interactive_builtin_linux_desktop,
            interactive_builtin_windows_desktop,
            swagger_client,
            aws_py,
            dcvasg_cloudwatch_metrics,
            dcvasg_triggers,
            dcvasg,
            dcvsm,
            grid_list_hosts_ui,
            enginframe_node_configuration,
            imds_access,
            shared_file_system
        ):
        # Userdata of the instances
        data_enginframe = open("userdata/enginframe.sh", "rb").read()
        enginframe_userdata = ec2.UserData.for_linux()
        # Change some placeholders inside the userdata of the instances
        data_enginframe_format = str(data_enginframe, 'utf-8').format(StackName=cdk.Aws.STACK_NAME,
                                                                      RegionName=cdk.Aws.REGION,
                                                                      ALB_DNS_NAME=lb_enginframe.load_balancer_dns_name,
                                                                      ALB_ARN=lb_enginframe.load_balancer_arn,
                                                                      KeyName=config['key_name'],
                                                                      account=config['account'],
                                                                      efadmin_uid=config['efadmin_uid'],
                                                                      Shared_Storage_Linux=config['Shared_Storage_Linux'],
                                                                      closing_hook=closing_hook.s3_object_url,
                                                                      starting_hook=starting_hook.s3_object_url,
                                                                      interactive_builtin_linux_desktop=interactive_builtin_linux_desktop.s3_object_url,
                                                                      interactive_builtin_windows_desktop=interactive_builtin_windows_desktop.s3_object_url,
                                                                      swagger_client=swagger_client.s3_object_url,
                                                                      aws_py=aws_py.s3_object_url,
                                                                      dcvasg_cloudwatch_metrics=dcvasg_cloudwatch_metrics.s3_object_url,
                                                                      dcvasg_triggers=dcvasg_triggers.s3_object_url,
                                                                      dcvasg=dcvasg.s3_object_url,
                                                                      dcvsm=dcvsm.s3_object_url,
                                                                      grid_list_hosts_ui=grid_list_hosts_ui.s3_object_url,
                                                                      enginframe_node_configuration=enginframe_node_configuration.s3_object_url,
                                                                      imds_access_script=imds_access.s3_object_url,
                                                                      fsx_dns=shared_file_system.attr_dns_name,
                                                                      ef_installer=config['Enginframe_installer'])
        # Add the userdata to the instances
        enginframe_userdata.add_commands(data_enginframe_format)

        linux_ami_enginframe =  ec2.AmazonLinuxImage(generation=ec2.AmazonLinuxGeneration.AMAZON_LINUX_2,
                                                    edition=ec2.AmazonLinuxEdition.STANDARD,
                                                    virtualization=ec2.AmazonLinuxVirt.HVM,
                                                    storage=ec2.AmazonLinuxStorage.GENERAL_PURPOSE,
                                                    cpu_type=ec2.AmazonLinuxCpuType.X86_64
                                                    )

        
        subnet_type = ec2.SubnetType.PRIVATE_WITH_NAT
        
        # EnginFrame instance ASG
        asg_enginframe = self.create_asg("Enginframe", vpc, config['ec2_type_enginframe'], linux_ami_enginframe, enginframe_userdata,
                                         role_ef, config['key_name'], 1, ef_security_group, "/dev/sda1", config['ebs_enginframe_size'], subnet_type)

        return asg_enginframe   
        
    # Lambda used to create the certificate
    def create_lambda(self, lb_broker, config, role_lambda):

        # Lambda to create the ALB https certificate
        lambda_cert = _lambda.Function(self, "lambda_create_cert",
                                           runtime=_lambda.Runtime.PYTHON_3_7,
                                           handler="cert.lambda_handler",
                                           code=_lambda.Code.from_asset("./lambda"),
                                           timeout=cdk.Duration.seconds(600),
                                           role=role_lambda)

        lambda_cs = cdk.CustomResource(
            self, "Resource1",
            service_token=lambda_cert.function_arn,
            properties={
                "LoadBalancerDNSName": lb_broker.load_balancer_dns_name
            }
        )
        return lambda_cs                                                                                                                                                                                                                                                                                                                                                                   