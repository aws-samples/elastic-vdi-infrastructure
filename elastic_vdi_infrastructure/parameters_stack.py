# Copyright (C) 2022 by Amazon.com, Inc. or its affiliates.  All Rights Reserved.
# SPDX-License-Identifier: MIT

import aws_cdk as cdk

from aws_cdk import (
    Stack,
    aws_ssm as ssm,
    aws_ec2 as ec2,
    aws_iam as iam,
)
from constructs import Construct

# Class used to build the Parameters
class ParametersStack(Stack):

    def __init__(self, scope: Construct, construct_id: str,
                 config: list,
                 dcv_security_group,
                 linux_userdata,
                 windows_userdata,
                 imds_access,
                 efadmin_password,
                 role_dcv,
                 shared_file_system,
                 vpc,
                 **kwargs) -> None:
        super().__init__(scope, construct_id, **kwargs)
        
        
        vdi_subnet_id = vpc.select_subnets(subnet_type=ec2.SubnetType.PRIVATE_WITH_NAT).subnet_ids[0]
        
        # creation SSM Parameters
        self.create_parameters(
                 config,
                 dcv_security_group,
                 linux_userdata,
                 windows_userdata,
                 imds_access,
                 efadmin_password,
                 role_dcv,
                 shared_file_system,
                 vdi_subnet_id
        )
                      
                      
    # Function to create the required SSM parameters
    def create_parameters(
            self,
            config,
            dcv_security_group,
            linux_userdata,
            windows_userdata,
            imds_access,
            efadmin_password,
            role_dcv,
            shared_file_system,
            vdi_subnet_id
        ):
        # Parameter that will contain the hostname of the EnginFrame instance
        ssm.StringParameter(self, "EnginFrameHost",
                                   allowed_pattern=".*",
                                   description="EnginFrameHost",
                                   parameter_name="/dcv/linux/EnginFrameHost",
                                   string_value="dummy")
        
        # Parameter that will contain the ip of the EnginFrame instance
        ssm.StringParameter(self, "EnginFrameIp",
                                  allowed_pattern=".*",
                                  description="EnginFrameIp",
                                  parameter_name="/dcv/linux/EnginFrameIp",
                                  string_value="dummy")
                                                
        # Parameters required for the sessions autoscaling
        ssm.StringParameter(self, "Client ID",
                                  allowed_pattern=".*",
                                  description="Client ID",
                                  parameter_name="/dcvbroker/ClientId",
                                  string_value="dummy")
                                                
        ssm.StringParameter(self, "Client Secret",
                                   allowed_pattern=".*",
                                   description="Client Secret",
                                   parameter_name="/dcvbroker/ClientSecret",
                                   string_value="dummy")
                                                                                
        ssm.StringParameter(self, "Broker Port",
                                  allowed_pattern=".*",
                                  description="Broket port",
                                  parameter_name="/dcv/linux/ClientToBrokerPort",
                                  string_value="8443")
                                                
                                                
        ssm.StringParameter(self, "DCV SG",
                                  allowed_pattern=".*",
                                  description="DCV SG",
                                  parameter_name="/dcv/Sg",
                                  string_value=dcv_security_group.security_group_id)
                                                
        ssm.StringParameter(self, "DCV Linux Efadmin UID",
                                  allowed_pattern=".*",
                                  description="DCV Linux Efadmin UID",
                                  parameter_name="/dcv/linux/EfadminUID",
                                  string_value=config['efadmin_uid']) 
                                  
        ssm.StringParameter(self, "Shared Storage Path",
                                  allowed_pattern=".*",
                                  description="Shared Storage Path",
                                  parameter_name="/dcv/SharedStoragePath",
                                  string_value=config['Shared_Storage_Linux']) 
                                  
        ssm.StringParameter(self, "Shared Storage DNS",
                                  allowed_pattern=".*",
                                  description="Shared Storage DNS",
                                  parameter_name="/dcv/SharedStorageDNS",
                                  string_value=shared_file_system.attr_dns_name) 
                                                
        ssm.StringParameter(self, "DCV Linux Userdata",
                                   allowed_pattern=".*",
                                   description="DCV Linux Userdata",
                                   parameter_name="/dcv/linux/Userdata",
                                   string_value="s3://" + linux_userdata.s3_bucket_name + "/" + linux_userdata.s3_object_key)
                                   
        ssm.StringParameter(self, "DCV Windows Userdata",
                                   allowed_pattern=".*",
                                   description="DCV Windows Userdata",
                                   parameter_name="/dcv/windows/Userdata",
                                   string_value="s3://" + windows_userdata.s3_bucket_name + "/" + windows_userdata.s3_object_key)
                                   
        ssm.StringParameter(self, "IMDS access script",
                                   allowed_pattern=".*",
                                   description="IMDS access script",
                                   parameter_name="/dcv/linux/Imds",
                                   string_value="s3://" + imds_access.s3_bucket_name + "/" + imds_access.s3_object_key)
                                                                  
        ssm.StringParameter(self, "DcvBrokerCACertificate",
                                  description="DcvBrokerCACertificate",
                                  parameter_name="/dcv/linux/DcvBrokerCACertificate",
                                  string_value="dummy")
     
        
        ssm.StringParameter(self, "EFadmin password",
                                  allowed_pattern=".*",
                                  description="EFadmin password",
                                  parameter_name="/dcv/linux/Efadmin",
                                  string_value=efadmin_password.secret_arn)
                                  
        ssm.StringParameter(self, "AMI ID VDI LINUX",
                                  allowed_pattern=".*",
                                  description="AMI ID VDI LINUX",
                                  parameter_name="/dcv/linux/AmiIdVdi",
                                  string_value=ec2.MachineImage.lookup(
                                                 name="DCV-AmazonLinux2-x86_64-*-NVIDIA-*",
                                                 owners=["amazon"]).get_image(self).image_id
                                  ) 

        ssm.StringParameter(self, "AMI ID VDI WINDOWS",
                                  allowed_pattern=".*",
                                  description="AMI ID VDI WINDOWS",
                                  parameter_name="/dcv/windows/AmiIdVdi",
                                  string_value=ec2.MachineImage.lookup(
                                                 name="DCV-Windows*NVIDIA-gaming*",
                                                 owners=["amazon"]).get_image(self).image_id
                                  )
                                  
        ssm.StringParameter(self, "DCV Role",
                                  allowed_pattern=".*",
                                  description="DCV Role",
                                  parameter_name="/dcv/Role",
                                  string_value=iam.CfnInstanceProfile(self, "InstanceProfile", roles=[role_dcv.role_name]).attr_arn
                                  )
                                  
        ssm.StringParameter(self, "VDI subnet Id",
                                  allowed_pattern=".*",
                                  description="VDI subnet Id",
                                  parameter_name="/dcv/VdiSubnetId",
                                  string_value=vdi_subnet_id
                                  )

