#!/bin/bash

# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: MIT

ALB_PUBLIC_DNS_NAME=@ALB_DNS_NAME@
ALB_PORT=443
export AWS_DEFAULT_REGION=@RegionName@
_die() {
    echo "ERROR"
    exit 1
}
_help() {
    _cmd=$(basename "$0")
    echo "$_cmd"
    echo "Usage:"
    echo "  $_cmd \"<session-id>\" \"<alb-host>\" \"<alb-port>\" \"<target-host>\" \"<target-port>\" \"<target-web-url-path>\""
    echo "  $_cmd \"tmp3569402005256372176\" \"alb-enginframe-xxx.eu-west-1.elb.amazonaws.com\" 443 \"10.0.0.10\" 8443 \"/dcv-server1\""
}
main() {

    if [[ $# -lt 6 ]] ; then
        _help
        exit 0
    fi
    local -- _session_id=$1
    local -- _alb_host=$2
    local -- _alb_port=$3
    local -- _target_host
    local -- _target_port=$5
    local -- _target_web_url_path=$6
    _target_host=$(echo "$6" | cut -c 2-)
    [ -z "$_session_id" ] && _die "Missing input Session Id parameter."
    [ -z "$_alb_host" ] && _die "Missing input ALB Host parameter."
    [ -z "$_alb_port" ] && _die "Missing input ALB Port parameter."
    [ -z "$_target_host" ] && _die "Missing input Target Host parameter."
    [ -z "$_target_port" ] && _die "Missing input Target Port parameter."
    [ -z "$_target_web_url_path" ] && _die "Missing input Target Web Url Path parameter."
    local -- _target_host_filter
    _target_host_filter=$([[ $_target_host == *\.* ]] && echo "$_target_host" || echo "$_target_host.*")

    aws help >/dev/null || _die "AWS Cli is not installed."
    
    local -- _alb_arn
    _alb_arn=$(aws elbv2 describe-load-balancers --query "LoadBalancers[? DNSName == '$_alb_host'].LoadBalancerArn" --output text)
    [ -n "$_alb_arn" ] || _die "Unable to get ALB identifier for the ALB ($_alb_host)."

    local -- _vpc_id
    _vpc_id=$(aws elbv2 describe-load-balancers --load-balancer-arns "$_alb_arn" \
        --query "LoadBalancers[].VpcId" --output text)
    [ -n "$_vpc_id" ] || _die "Unable to detect VPC of the ALB ($_alb_host)."

    local -- _instance_id
    _instance_id=$(aws ec2 describe-instances --filters "Name=private-dns-name,Values=$(echo $_target_host_filter | sed "s/-dcv//")" \
        --query "Reservations[].Instances[? VpcId == '$_vpc_id'].InstanceId" --output text)
    [ -n "$_instance_id" ] || _die "Unable to get Instance Id for the given Private DNS name filter ($_target_host_filter) in the VPC ($_vpc_id)."

    local -- _listener_arn
    _listener_arn=$(aws elbv2 describe-listeners --load-balancer-arn "$_alb_arn" \
        --query 'Listeners[? Port == `'$_alb_port'`].ListenerArn' --output text)
    [ -n "$_listener_arn" ] || _die "Listener for port ($_alb_port) does not exist in the ALB ($_alb_host)."

    local -- _target_group_name
    _target_group_name=$(printf "%s" "$_session_id" | tr -c 'a-zA-Z0-9' - | tr -d '-')
    
    local -- _target_group_arn
    _target_group_arn=$(aws elbv2 describe-target-groups --load-balancer-arn "$_alb_arn" \
        --query "TargetGroups[? TargetGroupName == '$_target_group_name'].TargetGroupArn" --output text)
    [ -n "$_target_group_arn" ] || _die "Unable to get Target Group ($_target_group_name)"

    local -- _rule_arn
    _rule_arn=$(aws elbv2 describe-rules --listener-arn "$_listener_arn" \
        --query "Rules[? Actions[? TargetGroupArn == '$_target_group_arn']].RuleArn" --output text)
    [ -n "$_rule_arn" ] || _die "Unable to get Rule for Target Group ($_target_group_arn) in the Listener ($_listener_arn)."

    aws elbv2 delete-rule --rule-arn "$_rule_arn" >/dev/null
    [ $? -eq 0 ] || _die "Unable to delete Listener Rule ($_rule_arn)."

    aws elbv2 delete-target-group --target-group-arn "$_target_group_arn" >/dev/null
    [ $? -eq 0 ] || _die "Unable to delete Target Group ($_target_group_arn)."
    
    instance_id=$(aws ec2 describe-instances --filters Name=network-interface.addresses.private-ip-address,Values="${INTERACTIVE_SESSION_DCV2SM_EXECUTION_IP}" --query "Reservations[].Instances[].InstanceId" --output text)
    aws ec2 delete-tags --resources "${instance_id}" --tags Key=UserID,Value="${EF_USER}"
}
if [ "$INTERACTIVE_SESSION_REMOTE" = "dcv2sm" ]; then
    main "$INTERACTIVE_SESSION_DELEGATESESSIONID" "$ALB_PUBLIC_DNS_NAME" "$ALB_PORT" "$INTERACTIVE_SESSION_EXECUTION_HOST" "$INTERACTIVE_SESSION_DCV2SM_EXECUTION_PORT" "$INTERACTIVE_SESSION_DCV2SM_WEBURLPATH"
fi