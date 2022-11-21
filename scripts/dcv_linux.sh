#!/bin/bash
# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: MIT

#exec 2>"/tmp/debug.log.$$";set -x


systemctl stop firewalld
systemctl disable firewalld

#Install some required packages
yum -y install java-1.8.0-openjdk.x86_64 curl wget nfs-utils

#Retrieve from parameter store the shared storage path
Shared_Storage_Linux=$(aws ssm get-parameter --name "/dcv/SharedStoragePath" --output text --query Parameter.Value)
#Retrieve from parameter store the shared storage dns
fsx_dns=$(aws ssm get-parameter --name "/dcv/SharedStorageDNS" --output text --query Parameter.Value)

# Mount shared storages

mkdir -p ${Shared_Storage_Linux}

# Mount shared file system
echo "${fsx_dns}:/fsx/ ${Shared_Storage_Linux} nfs defaults 0 0" >> /etc/fstab

mount ${Shared_Storage_Linux}


#Crate the EnginFrame administrator user
efadmin_uid=$(aws ssm get-parameter --name "/dcv/linux/EfadminUID" --output text --query Parameter.Value)
adduser -u ${efadmin_uid} efadmin

#Retrieve the efadmin password from secret manager
arn_secret_password=$(aws ssm get-parameter --name "/dcv/linux/Efadmin" --output text --query Parameter.Value)
efadmin_password=$(aws secretsmanager get-secret-value --secret-id ${arn_secret_password} --query SecretString --output text)

#Configure the password for the efadmin user
printf "$efadmin_password" | passwd efadmin --stdin


#Retrieve from parameter store the DCVSM broker certificate
dcvsm_certificate=$(aws ssm get-parameter --name "/dcv/linux/DcvBrokerCACertificate" --output text --query Parameter.Value)


# Retrieve Broker ALB address
broker_alb=$(aws ssm get-parameter --name "/dcv/linux/AgentToBrokerHost" --output text --query Parameter.Value)


#Configure the DCV configuration file
sed -i '/^\[security\]/a administrators=["dcvsmagent"]' /etc/dcv/dcv.conf
sed -i '/^\[security\]/a ca-file="/etc/dcv-session-manager-agent/broker_cert.pem"' /etc/dcv/dcv.conf
sed -i '/^\[security\]/a no-tls-strict=true' /etc/dcv/dcv.conf
sed -i "/^\[security\]/a auth-token-verifier=\"https://$broker_alb:8445/agent/validate-authentication-token\"" /etc/dcv/dcv.conf
sed -i "/^\[connectivity\]/a web-url-path=\"/$(hostname -s)-dcv\"" /etc/dcv/dcv.conf

# Configure idle timeout

sed -i "/^\[connectivity\]/a idle-timeout = 120" /etc/dcv/dcv.conf

#Configure the DCVSM configuration file
sed -i "s/^broker_host =.*$/broker_host = '$broker_alb'/" /etc/dcv-session-manager-agent/agent.conf
sed -i "/^\[agent\]/a ca_file = '/etc/dcv-session-manager-agent/broker_cert.pem'" /etc/dcv-session-manager-agent/agent.conf
sed -i "/^\[agent\]/a tls_strict = false" /etc/dcv-session-manager-agent/agent.conf


#Create the tags
mkdir /etc/dcv-session-manager-agent/tags/
instance_id=$(curl -s http://169.254.169.254/latest/meta-data/instance-id)
asg_name=$(aws ec2 describe-instances --instance-ids $instance_id --query "Reservations[].Instances[].Tags[?Key=='aws:autoscaling:groupName'].Value" --output text)
echo "AutoScalingGroupName=\"$asg_name\"" >> /etc/dcv-session-manager-agent/tags/agent_tags.toml
echo "InstanceType=\"$InstanceType\"" >> /etc/dcv-session-manager-agent/tags/agent_tags.toml
echo "DCVFleet=\"$DcvFleet\"" >> /etc/dcv-session-manager-agent/tags/agent_tags.toml

#Save the retrieved certificate
echo "$dcvsm_certificate" > /etc/dcv-session-manager-agent/broker_cert.pem


# Fix colord auth issue
cat <<EOF > /etc/polkit-1/rules.d/02-allow-colord.rules
polkit.addRule(function(action, subject) {
   if (action.id == "org.freedesktop.color-manager.create-device" ||
        action.id == "org.freedesktop.color-manager.create-profile" ||
        action.id == "org.freedesktop.color-manager.delete-device" ||
        action.id == "org.freedesktop.color-manager.delete-profile" ||
        action.id == "org.freedesktop.color-manager.modify-device" ||
        action.id == "org.freedesktop.color-manager.modify-profile") {
      return polkit.Result.YES;
   }
});

EOF

# Configure X11
rm -f /etc/X11/xorg.conf
nvidia-xconfig --enable-all-gpus  --preserve-busid
sed -i '/Section "Device"/a Option         "HardDPMS" "false"' /etc/X11/xorg.conf



#Retrieve the InstanceID
MyInstID=$(curl -s http://169.254.169.254/latest/meta-data/instance-id)

#Retrieve the logical ID of the resource
ASGLOGICALID=$(aws ec2 describe-instances --instance-ids $MyInstID --query "Reservations[].Instances[].Tags[?Key=='aws:cloudformation:logical-id'].Value" --output text)

# Retrieve NICE_ROOT path
NICE_ROOT="${Shared_Storage_Linux}/nice"

# Configure access to instance metadata
$NICE_ROOT/scripts/imds-access.sh --allow root,dcvsmagent,dcv

#Start DCV
#systemctl restart dcvserver
systemctl enable dcvserver

#Start DCV session manager
#systemctl restart dcv-session-manager-agent.service
systemctl enable dcv-session-manager-agent.service

instance_family=$(curl -s http://169.254.169.254/latest/meta-data/instance-type | awk -F'.' '{print $1}')

if [ "${instance_family}" == "g4dn" ];then
  nvidia-persistenced
  nvidia-smi -ac 5001,1590
elif [ "${instance_family}" == "p3dn" ];then
  nvidia-persistenced
  nvidia-smi -ac 877,1530
elif [ "${instance_family}" == "p4d" ];then
  nvidia-persistenced
  nvidia-smi -ac 1215,1410
else
  echo "No GPU detected"
fi

# Disable the Login Screen User List 
cat <<'EOF' > /etc/dconf/profile/gdm
user-db:user
system-db:gdm
file-db:/usr/share/gdm/greeter-dconf-defaults
EOF

cat <<'EOF' > /etc/dconf/db/gdm.d/00-login-screen
[org/gnome/login-screen]
# Do not show the user list
disable-user-list=true
EOF

dconf update

# Remove Power Off button
cat <<'EOF' > /etc/polkit-1/rules.d/55-inhibit-shutdown.rules
polkit.addRule(function(action, subject) {
if ((action.id == "org.freedesktop.consolekit.system.stop" || action.id == "org.freedesktop.consolekit.system.poweroff") && subject.isInGroup("admin")) {
return polkit.Result.YES;
}
else {
return polkit.Result.NO;
}
});
EOF

# Configure and mount NVME disks
mkdir /scratch/

# When instance has more than 1 instance store, raid + mount them as /scratch
VOLUME_LIST=()
if [[ ! -z $(ls /dev/nvme[0-9]n1) ]]; then
	echo 'Detected Instance Store: NVME'
	DEVICES=$(ls /dev/nvme[0-9]n1)

elif [[ ! -z $(ls /dev/xvdc[a-z]) ]]; then
	echo 'Detected Instance Store: SSD'
	DEVICES=$(ls /dev/xvdc[a-z])
else
	echo 'No instance store detected on this machine.'
fi

if [[ ! -z $DEVICES ]]; then
	echo "Detected Instance Store with NVME:" $DEVICES
	# Clear Devices which are already mounted (eg: when customer import their own AMI)
	for device in $DEVICES;
	do
		CHECK_IF_PARTITION_EXIST=$(lsblk -b $device | grep part | wc -l)
		if [[ $CHECK_IF_PARTITION_EXIST -eq 0 ]]; then
			echo "$device is free and can be used"
			VOLUME_LIST+=($device)
		fi
	done

	VOLUME_COUNT=${#VOLUME_LIST[@]}
	if [[ $VOLUME_COUNT -eq 1 ]]; then
		# If only 1 instance store, mfks as ext4
		echo "Detected  1 NVMe device available, formatting as ext4 .."
		mkfs -t ext4 $VOLUME_LIST
		echo "$VOLUME_LIST /scratch ext4 defaults,nofail 0 0" >> /etc/fstab
	elif [[ $VOLUME_COUNT -gt 1 ]]; then
		# if more than 1 instance store disks, raid them !
		echo "Detected more than 1 NVMe device available, creating XFS fs ..."
		DEVICE_NAME="md0"
	  for dev in ${VOLUME_LIST[@]} ; do dd if=/dev/zero of=$dev bs=1M count=1 ; done
	  echo yes | mdadm --create -f --verbose --level=0 --raid-devices=$VOLUME_COUNT /dev/$DEVICE_NAME ${VOLUME_LIST[@]}
	  mkfs -t ext4 /dev/$DEVICE_NAME
	  mdadm --detail --scan | tee -a /etc/mdadm.conf
	  echo "/dev/$DEVICE_NAME /scratch ext4 defaults,nofail 0 0" >> /etc/fstab
	else
		echo "All volumes detected already have a partition or mount point and can't be used as scratch devices"
	fi
fi

mount /scratch
chmod 777 /scratch

systemctl isolate graphical.target

#Start DCV
systemctl restart dcvserver
systemctl enable dcvserver

#Send the signal to the Cloudformation Stack
/opt/aws/bin/cfn-signal -e $? --stack ${StackName} --resource $ASGLOGICALID --region ${RegionName}