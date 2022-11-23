
# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: MIT

#exec 2>"/tmp/userdata.log.$$";set -x

export StackName={StackName}
export RegionName={RegionName}
export ALB_DNS_NAME={ALB_DNS_NAME}
export ALB_ARN={ALB_ARN}
export closing_hook={closing_hook}
export starting_hook={starting_hook}
export interactive_builtin_linux_desktop={interactive_builtin_linux_desktop}
export interactive_builtin_windows_desktop={interactive_builtin_windows_desktop}
export swagger_client={swagger_client}
export aws_py={aws_py}
export dcvasg_cloudwatch_metrics={dcvasg_cloudwatch_metrics}
export dcvasg_triggers={dcvasg_triggers}
export dcvasg={dcvasg}
export dcvsm={dcvsm}
export grid_list_hosts_ui={grid_list_hosts_ui}
export KeyName={KeyName}
export account={account}
export efadmin_uid={efadmin_uid}
export enginframe_node_configuration={enginframe_node_configuration}
export Shared_Storage_Linux={Shared_Storage_Linux}
export NICE_ROOT="$Shared_Storage_Linux"/nice
export imds_access_script={imds_access_script}
export ef_installer={ef_installer}
export fsx_dns={fsx_dns}

sleep 30

while [ ! -f /tmp/enginframe.sh ]
do
  sleep 2
  aws s3 cp "$enginframe_node_configuration" /tmp/enginframe.sh
done


chmod +x /tmp/enginframe.sh
bash /tmp/enginframe.sh
rm -f /tmp/enginframe.sh
