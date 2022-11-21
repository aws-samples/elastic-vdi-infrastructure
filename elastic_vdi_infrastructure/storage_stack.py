# Copyright (C) 2022 by Amazon.com, Inc. or its affiliates.  All Rights Reserved.
# SPDX-License-Identifier: MIT
import aws_cdk as cdk

from aws_cdk import (
    Stack,
    aws_fsx as fsx,
    aws_ec2 as ec2,
)
from constructs import Construct

# Class used to build the Storage
class StorageStack(Stack):

    def __init__(self, scope: Construct, construct_id: str,
                 config: list,
                 vpc,
                 securityGroupId,
                 **kwargs) -> None:
        super().__init__(scope, construct_id, **kwargs)
        
        subnetId = vpc.select_subnets(subnet_type=ec2.SubnetType.PRIVATE_WITH_NAT).subnet_ids[0] 
        
        # Storage creation
        self.cfn_file_system = fsx.CfnFileSystem(self, "Storage",
             file_system_type="OPENZFS",
             subnet_ids=[subnetId],
             open_zfs_configuration=fsx.CfnFileSystem.OpenZFSConfigurationProperty(
                 deployment_type="SINGLE_AZ_1",
                 automatic_backup_retention_days=0,
                 throughput_capacity=64,
                 options=["DELETE_CHILD_VOLUMES_AND_SNAPSHOTS"],
                 root_volume_configuration=fsx.CfnFileSystem.RootVolumeConfigurationProperty(
                     data_compression_type="ZSTD",
                     nfs_exports=[fsx.CfnFileSystem.NfsExportsProperty(
                         client_configurations=[fsx.CfnFileSystem.ClientConfigurationsProperty(
                              clients="*",
                              options=["rw","crossmnt","no_root_squash"]
                         )]
                     )]
                 )
             ),
             security_group_ids=[securityGroupId.security_group_id],
             storage_capacity=config['linux_shared_storage_size'],
        )