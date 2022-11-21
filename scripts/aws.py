#!/usr/bin/env python3

# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: MIT

from json import dumps
from logging import getLogger
from urllib.request import Request, urlopen

from boto3 import client
from botocore.config import Config


class Aws:

    METADATA_BASEURL = 'http://169.254.169.254/latest'

    def __init__(self, region=None):
        self.token = self.__get_token()
        region_name = region or self.__get_metadata('meta-data/placement/region')
        config = Config(retries={'total_max_attempts': 10, 'mode': 'standard'})
        self.ec2 = client('ec2', region_name=region_name, config=config)
        self.ssm = client('ssm', region_name=region_name, config=config)
        self.autoscaling = client('autoscaling', region_name=region_name, config=config)
        self.cloudwatch = client('cloudwatch', region_name=region_name, config=config)
        self.tags = self.__describe_tags()
        self.logger = getLogger(__name__)

    def __get_token(self):
        url = f'{self.METADATA_BASEURL}/api/token'
        request = Request(url=url, method='PUT')
        request.add_header('X-aws-ec2-metadata-token-ttl-seconds', '21600')
        with urlopen(request) as response:
            token = response.read().decode('utf-8')
        return token

    def __get_metadata(self, path):
        url = f'{self.METADATA_BASEURL}/{path}'
        request = Request(url=url, method='GET')
        request.add_header('X-aws-ec2-metadata-token', self.token)
        with urlopen(request) as response:
            result = response.read().decode('utf-8')
        return result

    def __describe_tags(self):
        instance_id = self.__get_metadata('meta-data/instance-id')
        paginator = self.ec2.get_paginator('describe_tags')
        iterator = paginator.paginate(
            Filters=[
                {'Name': 'resource-id', 'Values': [instance_id]},
            ],
        )
        return {
            tag['Key']: tag['Value']
            for tag in iterator.search('Tags[]')
        }

    def get_parameters_by_path(self, path):
        paginator = self.ssm.get_paginator('get_parameters_by_path')
        iterator = paginator.paginate(
            Path=path,
            WithDecryption=True,
        )
        response = {
            parameter['Name'][len(path):]: parameter['Value']
            for parameter in iterator.search('Parameters[]')
        }
        self.logger.debug(f'SSM Parameter:\n{dumps(response, indent=4, sort_keys=True, default=str)}')
        return response

    def describe_instances(self, filters):
        paginator = self.ec2.get_paginator('describe_instances')
        iterator = paginator.paginate(
            Filters=filters,
        )
        return iterator.search('Reservations[].Instances[]')

    def describe_autoscaling_groups(self, asg_tag_filters):
        paginator = self.autoscaling.get_paginator('describe_auto_scaling_groups')
        iterator = paginator.paginate()
        for group in iterator.search('AutoScalingGroups[]'):
            tags = {tag['Key']: tag['Value'] for tag in group['Tags']}
            if all(tags.get(key) == value for key, value in asg_tag_filters.items()):
                yield group

    def put_metric_data(self, namespace, dimensions, metrics):
        self.cloudwatch.put_metric_data(
            Namespace=namespace,
            MetricData=[
                {
                    'MetricName': metric['Name'],
                    'Dimensions': dimensions,
                    'Unit': metric['Unit'],
                    'Value': metric['Value'],
                }
                for metric in metrics
            ]
        )

    def set_instance_protection(self, group_name, instance_ids, protected):
        response = self.autoscaling.set_instance_protection(
            AutoScalingGroupName=group_name,
            InstanceIds=instance_ids,
            ProtectedFromScaleIn=protected,
        )
        self.logger.debug(f'Set Instance Protection:\n{response}')

    def terminate_instances_in_auto_scaling_group(self, instance_ids, decrement):
        for instance_id in instance_ids:
            response = self.autoscaling.terminate_instance_in_auto_scaling_group(
                InstanceId=instance_id,
                ShouldDecrementDesiredCapacity=decrement
            )
            self.logger.debug(f'terminate_instances_in_auto_scaling_group:\n{response}')
