#!/bin/bash

# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: MIT


#exec 2>"/tmp/debug.log.$$";set -x

#Configure default region for the AWS cli
aws configure set region "${RegionName}"


arn_secret_password=$(aws ssm get-parameter --name "/dcv/linux/Efadmin" --output text --query Parameter.Value)

systemctl stop firewalld
systemctl disable firewalld


#Install some required packages
yum -y install java-1.8.0-openjdk.x86_64 curl wget python2-pip nfs-utils
pip3 install boto3 certifi

mkdir -p "${Shared_Storage_Linux}"

# Mount shared file system
echo "${fsx_dns}:/fsx/ ${Shared_Storage_Linux} nfs defaults 0 0" >> /etc/fstab

mount "${Shared_Storage_Linux}"

first_install="no"

if [ ! -d "${NICE_ROOT}" ]; then

    first_install="yes"

fi


#Crate the EnginFrame administrator user
adduser -u "${efadmin_uid}" efadmin

#Create the EnginFrame service user
efnobody_uid=$(( $efadmin_uid + 1 ))
adduser -u "$efnobody_uid" efnobody


#Retrieve the efadmin password from secret manager
efadmin_password=$(aws secretsmanager get-secret-value --secret-id "${arn_secret_password}" --query "SecretString" --output text)

#Configure the password for the efadmin user
printf "$efadmin_password" | passwd efadmin --stdin



if [ "${first_install}" == "yes" ]; then

	#EnginFrame Download URL
	wget "${ef_installer}"

	ef_jar=$(ls *.jar)

	#Java bin Path
	java_bin=$(readlink /etc/alternatives/java | sed 's/\/bin\/java//')

	#Hostname of the node
	ef_hostname=$(hostname -s)

	# Retrieve Broker ALB address
	broker_alb=$(aws ssm get-parameter --name "/dcv/linux/ClientToBrokerHost" --output text --query Parameter.Value)

	#Create the file used for the EnginFrame unattended installation
	cat <<EOF > efinstall.config

efinstall.config.version = 1.0
ef.accept.eula = true
nice.root.dir.ui = $NICE_ROOT
kernel.java.home = $java_bin
ef.spooler.dir = $NICE_ROOT/enginframe/spoolers
ef.repository.dir = $NICE_ROOT/enginframe/repository
ef.sessions.dir = $NICE_ROOT/enginframe/sessions
ef.data.root.dir = $NICE_ROOT/enginframe/data
ef.logs.root.dir = $NICE_ROOT/enginframe/logs
ef.temp.root.dir = $NICE_ROOT/enginframe/tmp
ef.product = PRO
kernel.agent.on.same.machine = true
kernel.agent.rmi.port = 9999
kernel.agent.rmi.bind.port = 9998
kernel.ef.admin.user = efadmin
kernel.server.tomcat.https = true
kernel.ef.tomcat.user = efnobody
kernel.ef.root.context = enginframe
kernel.tomcat.https.port = 8443
kernel.tomcat.shutdown.port = 8005
kernel.server.tomcat.https.ef.hostname = $ef_hostname
kernel.ef.db = derby
kernel.ef.derby.db.port = 1527
kernel.start_enginframe_at_boot = true
demo.install = true
default.auth.mgr = pam
pam.service = system-auth
pam.user =
ef.delegate.dcvsm = true
dcvsm.oauth2.url = https\://$broker_alb\:8443/oauth2/token
dcvsm.oauth2.id =
dcvsm.broker.url = https\://$broker_alb\:8443/
dcvsm.no.strict.tls = false
dcvsm.no.strict.tls = true
intro-targets = component_enginframe,component_kernel,component_applets,component_parser,component_http,component_pam,component_ldap,component_activedirectory,component_rss,component_lsf,component_pbs,component_torque,component_sge,component_slurm,component_awsbatch,component_dcvsm,component_demo,component_neutro,component_vdi,component_applications,component_service-manager,component_user-group-manager,component_enginframe_finalizer,
progress-targets = cleanuptarget,
EOF

	#Install EnginFrame
	java -jar "$ef_jar" --text --batch
	
	mkdir "$NICE_ROOT"/log

	client_pw="dummy"

	while [ "$client_pw" == "dummy" ]
	do
	  sleep 5
	  client_id=$(aws ssm get-parameter --name "/dcvbroker/ClientId" --output text --query Parameter.Value)
	  client_pw=$(aws ssm get-parameter --name "/dcvbroker/ClientSecret" --output text --query Parameter.Value)
	done



	#Configure the EnginFrame variables required to communicate with DCVSM
	sed -i "s/^DCVSM_CLUSTER_dcvsm_cluster1_AUTH_ID=.*$/DCVSM_CLUSTER_dcvsm_cluster1_AUTH_ID=$client_id/" \
			"$NICE_ROOT"/enginframe/conf/plugins/dcvsm/clusters.props
	sed -i "s/^DCVSM_CLUSTER_dcvsm_cluster1_AUTH_PASSWORD=.*$/DCVSM_CLUSTER_dcvsm_cluster1_AUTH_PASSWORD=$client_pw/" \
			"$NICE_ROOT"/enginframe/conf/plugins/dcvsm/clusters.props
	sed -i "s/^DCVSM_CLUSTER_dcvsm_cluster1_AUTH_ENDPOINT=.*$/DCVSM_CLUSTER_dcvsm_cluster1_AUTH_ENDPOINT=https:\/\/$broker_alb:8443\/oauth2\/token/" \
			"$NICE_ROOT"/enginframe/conf/plugins/dcvsm/clusters.props
	sed -i "s/^DCVSM_CLUSTER_dcvsm_cluster1_SESSION_MANAGER_ENDPOINT=.*$/DCVSM_CLUSTER_dcvsm_cluster1_SESSION_MANAGER_ENDPOINT=https:\/\/$broker_alb:8443/" \
			"$NICE_ROOT"/enginframe/conf/plugins/dcvsm/clusters.props
			
	#Remove lsf from grid.conf
	sed -i "s/lsf/dcvsm/" "$NICE_ROOT"/enginframe/conf/plugins/grid/grid.conf
	

	source "$NICE_ROOT/enginframe/conf/enginframe.conf"


			
	EF_VERSION=$(cat "$NICE_ROOT"/enginframe/current-version | awk -F'=' '{{print $2}}')

	#Create the EnginFrame hook required to add the ALB rules entries for the DCV sessions. 
	aws s3 cp "${starting_hook}" "$NICE_ROOT"/enginframe/"$EF_VERSION"/enginframe/plugins/interactive/bin/alb.session.starting.hook.sh
	sed -i "s/@ALB_DNS_NAME@/${ALB_DNS_NAME}/" "$NICE_ROOT"/enginframe/"$EF_VERSION"/enginframe/plugins/interactive/bin/alb.session.starting.hook.sh
	sed -i "s/@RegionName@/${RegionName}/" "$NICE_ROOT"/enginframe/"$EF_VERSION"/enginframe/plugins/interactive/bin/alb.session.starting.hook.sh


	#Create the EnginFrame hook required to remove the ALB rules entries for the DCV sessions.
	aws s3 cp "${closing_hook}" "$NICE_ROOT"/enginframe/"$EF_VERSION"/enginframe/plugins/interactive/bin/alb.session.closing.hook.sh
	sed -i "s/@ALB_DNS_NAME@/${ALB_DNS_NAME}/" "$NICE_ROOT"/enginframe/"$EF_VERSION"/enginframe/plugins/interactive/bin/alb.session.closing.hook.sh
	sed -i "s/@RegionName@/${RegionName}/" "$NICE_ROOT"/enginframe/"$EF_VERSION"/enginframe/plugins/interactive/bin/alb.session.closing.hook.sh


	chmod +x "$NICE_ROOT"/enginframe/"$EF_VERSION"/enginframe/plugins/interactive/bin/alb.session.closing.hook.sh
	chmod +x "$NICE_ROOT"/enginframe/"$EF_VERSION"/enginframe/plugins/interactive/bin/alb.session.starting.hook.sh


	#Configure the linux service EnginFrame
	sed -i 's/<ef:metadata attribute="VDI_REMOTE">.*$/<ef:metadata attribute="VDI_REMOTE">dcv2sm<\/ef:metadata>\n<ef:metadata attribute="VDI_CLUSTER">dcvsm_cluster1:dcvsm<\/ef:metadata>/' \
			"$NICE_ROOT"/enginframe/data/plugins/applications/services/catalog/interactive_builtin_linux_desktop/WEBAPP/service.xml
	aws s3 cp ${interactive_builtin_linux_desktop}  "$NICE_ROOT"/enginframe/data/plugins/applications/services/published/interactive/interactive_builtin_linux_desktop.xml
	rm -f  "$NICE_ROOT"/enginframe/data/plugins/applications/services/published/batch/*
	sed -i 's|vdi.launch.session.*$|vdi.launch.session --name ${EF_USER}|' "$NICE_ROOT"/enginframe/data/plugins/applications/services/catalog/interactive/interactive_builtin_linux_desktop/bin/action-script.sh
	
	#Configure the windows service EnginFrame
	sed -i 's/<ef:metadata attribute="VDI_REMOTE">.*$/<ef:metadata attribute="VDI_REMOTE">dcv2sm<\/ef:metadata>\n<ef:metadata attribute="VDI_CLUSTER">dcvsm_cluster1:dcvsm<\/ef:metadata>/' \
			"$NICE_ROOT"/enginframe/data/plugins/applications/services/catalog/interactive_builtin_windows_desktop/WEBAPP/service.xml
	aws s3 cp ${interactive_builtin_windows_desktop}  "$NICE_ROOT"/enginframe/data/plugins/applications/services/published/interactive/interactive_builtin_windows_desktop.xml
	rm -f  "$NICE_ROOT"/enginframe/data/plugins/applications/services/published/batch/*
	sed -i 's|vdi.launch.session.*$|vdi.launch.session --name ${EF_USER}|' "$NICE_ROOT"/enginframe/data/plugins/applications/services/catalog/interactive/interactive_builtin_windows_desktop/bin/action-script.sh

	#Configure EnginFrame to use the hooks         
	echo "INTERACTIVE_SESSION_STARTING_HOOK=$NICE_ROOT/enginframe/$EF_VERSION/enginframe/plugins/interactive/bin/alb.session.starting.hook.sh" >> "$NICE_ROOT"/enginframe/conf/plugins/interactive/interactive.efconf
	echo "INTERACTIVE_SESSION_CLOSING_HOOK=$NICE_ROOT/enginframe/$EF_VERSION/enginframe/plugins/interactive/bin/alb.session.closing.hook.sh" >> "$NICE_ROOT"/enginframe/conf/plugins/interactive/interactive.efconf

	# Configure Enginframe to remove the @doman from username
	cat <<'EOF' > $NICE_ROOT/enginframe/$EF_VERSION/enginframe/plugins/pam/bin/ef.user.mapping
#!/bin/bash
echo $1 | awk -F'@' '{print $1}'
EOF
	chmod 755 "$NICE_ROOT"/enginframe/"$EF_VERSION"/enginframe/plugins/pam/bin/ef.user.mapping
	sed -i 's/^EFAUTH_USERMAPPING=.*$/EFAUTH_USERMAPPING="true"/' "$NICE_ROOT"/enginframe/"$EF_VERSION"/enginframe/plugins/pam/conf/ef.auth.conf


	#Set max sessions to 1
	echo "INTERACTIVE_DEFAULT_MAX_SESSIONS=1" >> "$NICE_ROOT"/enginframe/conf/plugins/interactive/interactive.efconf

	#Default page VDI portal
	sed -i "s|demo/index.html|applications/applications.xml|" "$NICE_ROOT"/enginframe/"$EF_VERSION"/enginframe/WEBAPP/index.html
	sed -i 's|<xsl:variable name="nj.welcome.service">.*$|<xsl:variable name="nj.welcome.service">_uri=//com.enginframe.interactive/list.sessions</xsl:variable>|' \
			"$NICE_ROOT"/enginframe/"$EF_VERSION"/enginframe/plugins/applications/lib/xsl/applications.xsl

	#Configure custom hosts list
	rm -f "$NICE_ROOT"/enginframe/"$EF_VERSION"/enginframe/plugins/dcvsm/grid/grid.list.hosts.ui
	aws s3 cp "${grid_list_hosts_ui}" "$NICE_ROOT"/enginframe/"$EF_VERSION"/enginframe/plugins/dcvsm/grid/grid.list.hosts.ui
	chmod +x "$NICE_ROOT"/enginframe/"$EF_VERSION"/enginframe/plugins/dcvsm/grid/grid.list.hosts.ui
	
	# Create scripts folder
	mkdir "$NICE_ROOT"/scripts
	
	# Copy script used to configure iptables and deny access to instance metadata
	aws s3 cp "${imds_access_script}" "$NICE_ROOT"/scripts/imds-access.sh
	chmod 700 "$NICE_ROOT"/scripts/imds-access.sh


  # Add script used to remove the unused ALB rules
  cat <<'EOF' > $NICE_ROOT/scripts/check_alb_rules.sh
#!/bin/bash

source /etc/profile
alb_arn="$1"

listeners=$(aws elbv2 describe-listeners --load-balancer-arn "${alb_arn}" --query 'Listeners[*].ListenerArn' --output text)

for listener in $listeners; do
    RulesArn=$(aws elbv2 describe-rules --listener-arn "${listener}" --query Rules[*].RuleArn --output text)
    for RuleArn in $RulesArn; do
       TargetsGroupArn=$(aws elbv2 describe-rules --rule-arns "${RuleArn}" --query Rules[*].Actions[*].ForwardConfig.TargetGroups[*].TargetGroupArn --output text)
       for TargetGroupArn in $TargetsGroupArn; do
          instances=$(aws elbv2 describe-target-health --target-group-arn "${TargetGroupArn}" --query 'TargetHealthDescriptions[*].Target.Id' --output text)
          if [[ $? -eq 0 && "$instances" == "" ]];then
            echo "Deleting Rule: $RuleArn"
            aws elbv2 delete-rule --rule-arn "${RuleArn}"
            sleep 10
            echo "Deleting TargetGroup: $TargetGroupArn"
            aws elbv2 delete-target-group --target-group-arn "${TargetGroupArn}"
          fi
       done
    done
done
EOF

  chmod +x "$NICE_ROOT"/scripts/check_alb_rules.sh


else

   cat <<EOF > /usr/lib/systemd/system/enginframe.service
[Unit]
Description=NICE EnginFrame (http://www.enginframe.com)
After=local-fs.target network.target remote-fs.target

# Uncomment following requirement in case needed, setting custom mount point
# to be checked
#RequiresMountsFor=<mount point for the EF filesystem>

[Service]
Type=forking
TimeoutStartSec=0
TimeoutStopSec=0
ExecStart=$NICE_ROOT/enginframe/bin/enginframe --conf $NICE_ROOT/enginframe/conf/enginframe.conf start
ExecStop=$NICE_ROOT/enginframe/bin/enginframe --conf $NICE_ROOT/enginframe/conf/enginframe.conf stop
Restart=on-failure
RestartSec=4s

[Install]
WantedBy=multi-user.target
EOF

   systemctl daemon-reload
   systemctl enable enginframe
   

fi


#Configure the VDI autoscaling
mkdir -p /opt/dcv/autoscaling
aws s3 cp "${aws_py}" /opt/dcv/autoscaling/aws.py
chmod +x /opt/dcv/autoscaling/aws.py
aws s3 cp "${swagger_client}" /opt/dcv/autoscaling/swagger_client.zip
unzip /opt/dcv/autoscaling/swagger_client.zip -d /opt/dcv/autoscaling/
rm -f /opt/dcv/autoscaling/swagger_client.zip
aws s3 cp "${dcvasg}" /opt/dcv/autoscaling/dcvasg.py
chmod +x /opt/dcv/autoscaling/dcvasg.py
aws s3 cp "${dcvsm}" /opt/dcv/autoscaling/dcvsm.py
chmod +x /opt/dcv/autoscaling/dcvsm.py

if [ "${first_install}" == "yes" ]; then
	mkdir -p "$NICE_ROOT"/enginframe/"$EF_VERSION"/enginframe/plugins/dcvasg/lib/xml
	aws s3 cp "${dcvasg_triggers}" "$NICE_ROOT"/enginframe/"$EF_VERSION"/enginframe/plugins/dcvasg/lib/xml/dcvasg.triggers.xml
	mkdir -p "$NICE_ROOT"/enginframe/"$EF_VERSION"/enginframe/triggers
	aws s3 cp "${dcvasg_cloudwatch_metrics}" "$NICE_ROOT"/enginframe/"$EF_VERSION"/enginframe/triggers/dcvasg-cloudwatch-metrics.xml
    
	# Disable screenshot to avoid DCV issue
	sed -i "s|return new com.nice.dcvsm.interactive.RetrieveScreenshot(enginframe).run()|//return new com.nice.dcvsm.interactive.RetrieveScreenshot(enginframe).run()|" "$NICE_ROOT"/enginframe/"$EF_VERSION"/enginframe/plugins/dcvsm/interactive/services/interactive.dcvsm.xml


	# Configure download of files
	echo "ef.download.server.url=https://localhost:8443/enginframe/download" >>  "$NICE_ROOT"/enginframe/conf/enginframe/agent.conf
	# Download the DCVSM certificate
	dcvsm_certificate=$(aws ssm get-parameter --name "/dcv/linux/DcvBrokerCACertificate" --output text --query Parameter.Value)
	echo "${dcvsm_certificate}" > "$NICE_ROOT"/dcvsmbroker_ca.pem
	

	
fi

# add dcvsm certificate to Java keystore
openssl x509 -in "$NICE_ROOT"/dcvsmbroker_ca.pem -inform pem \
			-out /tmp/dcvsmbroker_ca.der -outform der
keytool -importcert -alias dcvsm \
				-keystore "$JAVA_HOME/lib/security/cacerts" \
				-storepass changeit \
				-noprompt \
				-file /tmp/dcvsmbroker_ca.der

# Configure access to instance metadata
"$NICE_ROOT"/scripts/imds-access.sh --allow root,efadmin,efnobody


#Start EnginFrame     
systemctl enable enginframe      
systemctl start enginframe

#Add the EnginFrame hostname to parameter store
aws ssm put-parameter --name "/dcv/linux/EnginFrameHost" --value "$(hostname)" --overwrite

#Enginframe ip address
enginframe_ip=$(curl -s http://169.254.169.254/latest/meta-data/local-ipv4)
aws ssm put-parameter --name "/dcv/linux/EnginFrameIp" --value "$enginframe_ip" --overwrite


# Configure check unused alb rules every day at 9am
echo "0 8 * * * $NICE_ROOT/scripts/check_alb_rules.sh ${ALB_ARN} >> $NICE_ROOT/log/check_alb_rules.log 2>&1
" | crontab -


#Retrieve the InstanceID
MyInstID=$(curl -s http://169.254.169.254/latest/meta-data/instance-id)

#Retrieve the logical ID of the resource
ASGLOGICALID=$(aws ec2 describe-instances --instance-ids "$MyInstID" --query "Reservations[].Instances[].Tags[?Key=='aws:cloudformation:logical-id'].Value" --output text)

#Send the signal to the Cloudformation Stack
/opt/aws/bin/cfn-signal -e $? --stack "${StackName}" --resource "$ASGLOGICALID" --region "${RegionName}"
