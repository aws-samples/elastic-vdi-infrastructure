#!/usr/bin/env python3

# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: MIT

from argparse import ArgumentParser
from collections import defaultdict
from json import dumps
from logging import basicConfig, getLogger

from aws import Aws
from dcvsm import DcvSM


def main():
    parser = ArgumentParser()
    parser.add_argument('--dcv-cluster')
    parser.add_argument('--region')
    parser.add_argument('--ca-file')
    parser.add_argument('--client-id')
    parser.add_argument('--client-secret')
    parser.add_argument('--broker-host')
    parser.add_argument('--broker-port')
    parser.add_argument('--namespace', default='DCV AutoScaling')
    parser.add_argument('--log-level', type=str.upper, default='INFO',
                        choices=['ERROR', 'WARNING', 'INFO', 'DEBUG'])
    parser.add_argument('--log-file')
    parser.add_argument('--log-max-bytes', type=int, default=10*1024*1024)
    parser.add_argument('--log-backup-count', type=int, default=5)
    args = parser.parse_args()

    basicConfig(
        filename=args.log_file,
        level=args.log_level.upper(),
        format='[%(asctime)s][%(levelname)s] %(message)s',
        datefmt='%Y/%m/%dT%H:%M:%S%z',
    )

    logger = getLogger(__name__)

    aws = Aws(args.region)

    dcv_cluster = args.dcv_cluster or aws.tags['dcv:cluster']
    parameters = aws.get_parameters_by_path(f'/dcv/linux/')
    parameters_secrets = aws.get_parameters_by_path(f'/dcvbroker/')

    dcv = DcvSM(
        client_id=args.client_id or parameters_secrets['ClientId'],
        client_secret=args.client_secret or parameters_secrets['ClientSecret'],
        broker_host=args.broker_host or parameters['ClientToBrokerHost'],
        broker_port=args.broker_port or parameters['ClientToBrokerPort'],
        ca_file=args.ca_file or parameters['DcvBrokerCACertificate'],
    )

    servers = dcv.describe_servers().servers

    sessions = dcv.describe_sessions().sessions

    server_map = {}
    loser_instance_ids = []
    for server in servers:
        instance_id = server.host.aws.ec2_instance_id
        server_map[server.id] = server
        server_map[instance_id] = server
        loser_instance_ids.append(instance_id)

    valid_instances = aws.describe_instances([
        {'Name': 'instance-id', 'Values': loser_instance_ids},
        {'Name': 'instance-state-name', 'Values': ['pending', 'running', 'stopping', 'stopped']},
    ])

    valid_servers = [
        server_map[instance['InstanceId']]
        for instance in valid_instances
    ]

    valid_server_ids = (
        server.id
        for server in valid_servers
    )

    invalid_sessions = [
        session
        for session in sessions
        if (session.state not in ('DELETED', 'DELETING') and
            session.server.availability == 'UNAVAILABLE' and
            session.server.unavailability_reason == 'UNREACHABLE_AGENT' and
            session.server.id not in valid_server_ids)
    ]

    if invalid_sessions:
        response = dcv.delete_sessions(invalid_sessions, force=True)
        print(response)

    groups = set()
    min_size = defaultdict(int)

    asg_tag_filters = {
        'dcv:cluster': dcv_cluster,
        'dcv:type': 'dcvserver',
    }
    for asg_group in aws.describe_autoscaling_groups(asg_tag_filters):
        group = asg_group['AutoScalingGroupName']
        groups.add(group)
        min_size[group] = asg_group['MinSize']

    dcv_server_count = defaultdict(int)
    max_virtual_session_count = defaultdict(int)
    virtual_session_count = defaultdict(int)
    console_session_count = defaultdict(int)
    available_server_count = defaultdict(int)
    full_server_count = defaultdict(int)
    closed_server_count = defaultdict(int)
    unreachable_server_count = defaultdict(int)
    unhealthy_server_count = defaultdict(int)
    occupied_server_count = defaultdict(int)
    unknown_server_count = defaultdict(int)
    unavailable_server_count = defaultdict(int)
    idle_server_count = defaultdict(int)
    busy_server_count = defaultdict(int)
    idle_server_ids = defaultdict(list)
    busy_server_ids = defaultdict(list)

    for server in valid_servers:
        tags = {tag.key: tag.value for tag in server.tags}
        group = tags.get('AutoScalingGroupName')
        if not group:
            logger.warning('ignoring server because missing tag AutoScalingGroupName')
            continue
        groups.add(group)
        dcv_server_count[group] += 1
        max_virtual_session_count[group] += int(tags['dcv:max-virtual-sessions'])
        virtual_session_count[group] += server.virtual_session_count
        console_session_count[group] += server.console_session_count
        if server.virtual_session_count == 0 and server.console_session_count == 0:
            idle_server_count[group] += 1
            idle_server_ids[group].append(server.id)
        else:
            busy_server_count[group] += 1
            busy_server_ids[group].append(server.id)
        if server.availability == 'AVAILABLE':
            available_server_count[group] += 1
        else:
            if server.unavailability_reason == 'SERVER_FULL':
                full_server_count[group] += 1
            elif server.unavailability_reason == 'SERVER_CLOSED':
                closed_server_count[group] += 1
            elif server.unavailability_reason == 'UNREACHABLE_AGENT':
                unreachable_server_count[group] += 1
            elif server.unavailability_reason == 'UNHEALTHY_DCV_SERVER':
                unhealthy_server_count[group] += 1
            elif server.unavailability_reason == 'EXISTING_LOGGED_IN_USER':
                occupied_server_count[group] += 1
            elif server.unavailability_reason == 'UNKNOWN':
                unknown_server_count[group] += 1
            else:
                unavailable_server_count[group] += 1

    for group in groups:
        lucky_server_ids = busy_server_ids[group] + idle_server_ids[group][:min_size[group]]
        loser_server_ids = idle_server_ids[group][min_size[group]:]
        lucky_instance_ids = []
        loser_instance_ids = []
        if loser_server_ids:
            response = dcv.close_servers(loser_server_ids)
            loser_server_ids = [item.server_id for item in response.successful_list]
            lucky_server_ids.extend(item.server_id for item in response.unsuccessful_list)
        if lucky_server_ids:
            dcv.open_servers(lucky_server_ids)
            lucky_instance_ids.extend(
                server_map[server_id].host.aws.ec2_instance_id
                for server_id in lucky_server_ids
            )
            aws.set_instance_protection(
                group_name=group,
                instance_ids=lucky_instance_ids,
                protected=True,
            )
        if loser_server_ids:
            loser_instance_ids.extend(
                server_map[server_id].host.aws.ec2_instance_id
                for server_id in loser_server_ids
            )
            aws.set_instance_protection(
                group_name=group,
                instance_ids=loser_instance_ids,
                protected=False,
            )

        if max_virtual_session_count[group]:
            available_virtual_sessions = max_virtual_session_count[group] - virtual_session_count[group]
            capacity_utilization = 100 * virtual_session_count[group] / max_virtual_session_count[group]
        else:
            available_virtual_sessions = 0
            capacity_utilization = 0.0
        dimensions = [
            {'Name': 'DCV Cluster', 'Value': dcv_cluster},
            {'Name': 'Fleet Name', 'Value': group},
        ]
        metrics = [
            {'Name': 'dcv_servers', 'Unit': 'Count', 'Value': dcv_server_count[group]},
            {'Name': 'max_virtual_sessions', 'Unit': 'Count', 'Value': max_virtual_session_count[group]},
            {'Name': 'available_virtual_sessions', 'Unit': 'Count', 'Value': available_virtual_sessions},
            {'Name': 'virtual_sessions', 'Unit': 'Count', 'Value': virtual_session_count[group]},
            {'Name': 'console_sessions', 'Unit': 'Count', 'Value': console_session_count[group]},
            {'Name': 'available_servers', 'Unit': 'Count', 'Value': available_server_count[group]},
            {'Name': 'full_servers', 'Unit': 'Count', 'Value': full_server_count[group]},
            {'Name': 'closed_servers', 'Unit': 'Count', 'Value': closed_server_count[group]},
            {'Name': 'unreachable_servers', 'Unit': 'Count', 'Value': unreachable_server_count[group]},
            {'Name': 'unhealthy_servers', 'Unit': 'Count', 'Value': unhealthy_server_count[group]},
            {'Name': 'occupied_servers', 'Unit': 'Count', 'Value': occupied_server_count[group]},
            {'Name': 'unknown_servers', 'Unit': 'Count', 'Value': unknown_server_count[group]},
            {'Name': 'unavailable_servers', 'Unit': 'Count', 'Value': unavailable_server_count[group]},
            {'Name': 'idle_servers', 'Unit': 'Count', 'Value': idle_server_count[group]},
            {'Name': 'busy_servers', 'Unit': 'Count', 'Value': busy_server_count[group]},
            {'Name': 'capacity_utilization', 'Unit': 'Percent', 'Value': capacity_utilization},
        ]
        info = {
            'lucky_instance_ids': lucky_instance_ids,
            'loser_instance_ids': loser_instance_ids,
            'cloudwatch_metrics': {metric['Name']: metric['Value'] for metric in metrics},
        }
        logger.info('group:\n%s', dumps(info, indent=4, sort_keys=True, default=str))
        aws.put_metric_data(args.namespace, dimensions, metrics)


if __name__ == '__main__':
    main()
