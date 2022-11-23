#!/bin/bash

# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: MIT

#exec 2>"/tmp/debug.log.$$";set -x

systemctl stop firewalld
systemctl disable firewalld

#Configure default region for the AWS cli
aws configure set region "${RegionName}"

#Install some required packages
yum -y install curl wget

#Install Java 11 requirement
amazon-linux-extras install java-openjdk11 -y

wget "$broker_installer"

dcvsmb_rpm=$(ls *.rpm)

#Install DCVSM broker
yum install -y "$dcvsmb_rpm"

# fix java version on startup script and cli
sed -i "s#^java#/etc/alternatives/jre_11/bin/java#" /usr/share/dcv-session-manager-broker/bin/dcv-session-manager-broker.sh
sed -i "s# java # /etc/alternatives/jre_11/bin/java #g" /usr/bin/dcv-session-manager-broker

sed -i "s|^# broker-java-home =|broker-java-home =/etc/alternatives/jre_11|" /etc/dcv-session-manager-broker/session-manager-broker.properties

# Configure the broker to use ALB
sed -i 's/broker-to-broker-discovery-addresses = .*$/#broker-to-broker-discovery-addresses/' \
        /etc/dcv-session-manager-broker/session-manager-broker.properties
        
echo "broker-to-broker-discovery-aws-region = ${RegionName}" >> /etc/dcv-session-manager-broker/session-manager-broker.properties
echo "broker-to-broker-discovery-aws-alb-target-group-arn = ${alb_target_group_arn}" >> /etc/dcv-session-manager-broker/session-manager-broker.properties
 
chmod 755 /var/lib/dcvsmbroker
    
#Start DCVSM broker
systemctl enable dcv-session-manager-broker
systemctl start dcv-session-manager-broker


sleep "$(shuf -i 60-120 -n 1)"

# Verify the client_id
client_id_param=$(aws ssm get-parameter --name "/dcvbroker/ClientId" --output text --query Parameter.Value)

# The client has not been registered yet
if [ "${client_id_param}" == "dummy" ];then
  aws ssm put-parameter --name "/dcvbroker/ClientId" --value "working" --allowed-pattern '' --overwrite
  #Register EnginFrame as client to the DCVSM broker
  dcv-session-manager-broker register-api-client --client-name EnginFrame > /tmp/ef_client_reg
  #Retrieve the generated credentials
  client_id=$(cat /tmp/ef_client_reg | sed -n 's/^[ \t]*client-id:[ \t]*//p')
  client_pw=$(cat /tmp/ef_client_reg | sed -n 's/^[ \t]*client-password:[ \t]*//p')
  
  aws ssm put-parameter --name "/dcvbroker/ClientId" --value "$client_id" --allowed-pattern '' --overwrite
  aws ssm put-parameter --name "/dcvbroker/ClientSecret" --value "$client_pw" --allowed-pattern '' --overwrite
fi

#Retrieve the InstanceID
MyInstID=$(curl -s http://169.254.169.254/latest/meta-data/instance-id)

#Retrieve the logical ID of the resource
ASGLOGICALID=$(aws ec2 describe-instances --instance-ids "$MyInstID" --query "Reservations[].Instances[].Tags[?Key=='aws:cloudformation:logical-id'].Value" --output text)

#Send the signal to the Cloudformation Stack
/opt/aws/bin/cfn-signal -e $? --stack "${StackName}" --resource "$ASGLOGICALID" --region "${RegionName}"