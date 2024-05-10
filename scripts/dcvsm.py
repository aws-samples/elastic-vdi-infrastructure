#!/usr/bin/env python3

# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: MIT

"""
DCV-SM Module

This script is a wrapper around the DCV Session Manager APIs.
"""

from argparse import ArgumentParser
from base64 import b64encode
from json import loads, dumps
from logging import basicConfig, getLogger
from os import unlink
from os.path import isfile
from tempfile import NamedTemporaryFile
from jmespath import search
import urllib3
from urllib3 import PoolManager

from aws import Aws

import swagger_client
from swagger_client.models import OpenServerRequestData
from swagger_client.models import CloseServerRequestData
from swagger_client.models.describe_servers_request_data import DescribeServersRequestData
from swagger_client.models.describe_sessions_request_data import DescribeSessionsRequestData
from swagger_client.models.delete_session_request_data import DeleteSessionRequestData
from swagger_client.models.key_value_pair import KeyValuePair

urllib3.disable_warnings()


class DcvSM:

    def __init__(self, client_id, client_secret, broker_host, broker_port, ca_file):
        self.client_id = client_id
        self.client_secret = client_secret
        self.server_url = f'https://{broker_host}:{broker_port}'
        self.ca_file = None
        self.tmp_file = None
        self.__get_ca_file(ca_file)
        self.http = PoolManager(cert_reqs='CERT_NONE', assert_hostname=False)
        self.logger = getLogger(__name__)

    def __del__(self):
        if self.tmp_file:
            self.logger.debug('remove temporary file %s', self.tmp_file.name)
            unlink(self.tmp_file.name)

    def __get_ca_file(self, ca_file):
        if not ca_file:
            raise ValueError('missing ca file')
        if isfile(ca_file):
            self.ca_file = ca_file
        else:
            self.tmp_file = NamedTemporaryFile(delete=False)
            self.tmp_file.write(ca_file.encode('utf-8'))
            self.tmp_file.close()
            self.ca_file = self.tmp_file.name

    def __build_client_credentials(self):
        client_credentials = f'{self.client_id}:{self.client_secret}'
        return b64encode(client_credentials.encode('utf-8')).decode('utf-8')

    def __get_access_token(self):
        client_credentials = self.__build_client_credentials()
        headers = {
            'Authorization': 'Basic {}'.format(client_credentials),
            'Content-Type': 'application/x-www-form-urlencoded'
        }
        endpoint = f'{self.server_url}/oauth2/token?grant_type=client_credentials'
        response = self.http.request('POST', endpoint, headers=headers)
        if response.status != 200:
            #self.logger.error('Cannot get access token: %s', response.text)
            return None
        access_token = loads(response.data.decode('utf-8'))['access_token']
        return access_token

    def __get_client_configuration(self):
        configuration = swagger_client.Configuration()
        configuration.host = self.server_url
        configuration.verify_ssl = False
        configuration.ssl_ca_cert = self.ca_file
        return configuration

    def __set_request_headers(self, api_client):
        access_token = self.__get_access_token()
        api_client.set_default_header(
            header_name='Authorization',
            header_value='Bearer {}'.format(access_token)
        )

    def __get_servers_api(self):
        api_client = swagger_client.ApiClient(self.__get_client_configuration())
        api_instance = swagger_client.ServersApi(api_client)
        self.__set_request_headers(api_instance.api_client)
        return api_instance

    def __get_sessions_api(self):
        api_client = swagger_client.ApiClient(self.__get_client_configuration())
        api_instance = swagger_client.SessionsApi(api_client)
        self.__set_request_headers(api_instance.api_client)
        return api_instance

    def describe_servers(self, server_ids=None, next_token=None, max_results=None):
        request = DescribeServersRequestData(
            server_ids=server_ids,
            next_token=next_token,
            max_results=max_results,
        )
        self.logger.debug('Describe Servers Request:\n%s', request)
        api_instance = self.__get_servers_api()
        api_response = api_instance.describe_servers(body=request)
        self.logger.debug('Describe Servers Response:\n%s', api_response)
        return api_response

    def describe_sessions(self, session_ids=None, next_token=None, tags=None, owner=None):
        filters = list()
        if tags:
            for tag in tags:
                filter_key_value_pair = KeyValuePair(key='tag:' + tag['Key'], value=tag['Value'])
                filters.append(filter_key_value_pair)
        if owner:
            filter_key_value_pair = KeyValuePair(key='owner', value=owner)
            filters.append(filter_key_value_pair)

        request = DescribeSessionsRequestData(
            session_ids=session_ids,
            filters=filters,
            next_token=next_token,
        )
        self.logger.debug('Describe Sessions Request:\n%s', request)
        api_instance = self.__get_sessions_api()
        api_response = api_instance.describe_sessions(body=request)
        self.logger.debug('Describe Sessions Response:\n%s', api_response)
        return api_response

    def delete_sessions(self, sessions, force=False):
        delete_sessions_request = list()
        for session in sessions:
            a_request = DeleteSessionRequestData(
                session_id=session.id,
                owner=session.owner,
                force=force,
            )
            delete_sessions_request.append(a_request)
        self.logger.debug('Delete Sessions Request:\n%s', delete_sessions_request)
        api_instance = self.__get_sessions_api()
        api_response = api_instance.delete_sessions(body=delete_sessions_request)
        self.logger.debug('Delete Sessions Response:\n%s', api_response)
        return api_response

    def open_servers(self, server_ids):
        request = [OpenServerRequestData(server_id=server_id) for server_id in server_ids]
        self.logger.debug('Open Servers Request:\n%s', request)
        api_instance = self.__get_servers_api()
        api_response = api_instance.open_servers(body=request)
        self.logger.debug('Open Servers Response:\n%s', api_response)
        return api_response

    def close_servers(self, server_ids):
        request = [CloseServerRequestData(server_id=server_id) for server_id in server_ids]
        self.logger.debug('Close Servers Request:\n%s', request)
        api_instance = self.__get_servers_api()
        api_response = api_instance.close_servers(body=request)
        self.logger.debug('Close Servers Response:\n%s', api_response)
        return api_response


def print_output(data, query=None, output=None):
    if query:
        data = search(query, data)
    if output == 'text':
        walk_data(data)
    else:
        print(dumps(data, indent=4, sort_keys=True, ensure_ascii=False, default=str))


def walk_data(data):
    if isinstance(data, list):
        for item in data:
            walk_data(item)
    elif isinstance(data, dict):
        for _, value in sorted(data.items(), key=lambda x: x[0]):
            if isinstance(value, dict):
                walk_data(value)
            elif isinstance(value, list):
                for item in value:
                    walk_data(item)
            else:
                print(value)
    else:
        print(data)


def main():
    parser = ArgumentParser()
    parser.add_argument('action', choices=[
        'describe-servers',
        'describe-sessions',
        'close-servers',
        'open-servers',
        'delete-sessions',
    ])
    parser.add_argument('--dcv-cluster')
    parser.add_argument('--region')
    parser.add_argument('--ca-file')
    parser.add_argument('--client-id')
    parser.add_argument('--client-secret')
    parser.add_argument('--broker-host')
    parser.add_argument('--broker-port')
    parser.add_argument('--server-ids', nargs='*')
    parser.add_argument('--session-ids', nargs='*')
    parser.add_argument('--query')
    parser.add_argument('--output', default='json',
                        choices=['json', 'yaml', 'text'])
    parser.add_argument('--log-level', type=str.upper, default='INFO',
                        choices=['ERROR', 'WARNING', 'INFO', 'DEBUG'])
    parser.add_argument('--log-file')
    parser.add_argument('--log-max-bytes', type=int, default=10 * 1024 * 1024)
    parser.add_argument('--log-backup-count', type=int, default=5)
    args = parser.parse_args()

    basicConfig(
        filename=args.log_file,
        level=args.log_level.upper(),
        format='[%(asctime)s][%(levelname)s] %(message)s',
        datefmt='%Y/%m/%dT%H:%M:%S%z',
    )

    aws = Aws(args.region)

    dcv_cluster = args.dcv_cluster or aws.tags['dcv:cluster']
    parameters = aws.get_parameters_by_path(f'/dcv/{dcv_cluster}/')
    parameters_secrets = aws.get_parameters_by_path(f'/dcvbroker/')

    dcv = DcvSM(
        client_id=args.client_id or parameters_secrets['ClientId'],
        client_secret=args.client_secret or parameters_secrets['ClientSecret'],
        broker_host=args.broker_host or parameters['ClientToBrokerHost'],
        broker_port=args.broker_port or parameters['ClientToBrokerPort'],
        ca_file=args.ca_file or parameters['DcvBrokerCACertificate'],
    )

    if args.action == 'describe-servers':
        servers = dcv.describe_servers(args.server_ids).servers
        data = {'Servers': [server.to_dict() for server in servers]}
        print_output(data, args.query, args.output)
    elif args.action == 'describe-sessions':
        sessions = dcv.describe_sessions(args.session_ids).sessions
        data = {'Sessions': [session.to_dict() for session in sessions]}
        print_output(data, args.query, args.output)
    elif args.action == 'close-servers':
        response = dcv.close_servers(args.server_ids)
        data = response.to_dict()
        print_output(data, args.query, args.output)
    elif args.action == 'open-servers':
        response = dcv.open_servers(args.server_ids)
        data = response.to_dict()
        print_output(data, args.query, args.output)
    elif args.action == 'delete-sessions':
        sessions = dcv.describe_sessions(args.session_ids).sessions
        response = dcv.delete_sessions(sessions)
        data = response.to_dict()
        print_output(data, args.query, args.output)


if __name__ == '__main__':
    main()
