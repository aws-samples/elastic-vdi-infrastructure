
# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: MIT

#exec 2>"/tmp/userdata.log.$$";set -x

export StackName={StackName}
export RegionName={RegionName}
export alb_target_group_arn={alb_target_group_arn}
export broker_userdata={broker_userdata}
export broker_installer={broker_installer}


while [ ! -f /tmp/broker.sh ]
do
  sleep 2
  aws s3 cp $broker_userdata /tmp/broker.sh
done

chmod +x /tmp/broker.sh
bash /tmp/broker.sh
rm -f /tmp/broker.sh