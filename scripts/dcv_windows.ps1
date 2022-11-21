# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: MIT

# Script parameters
$stackname=$args[0]
$region=$args[1]
$DcvFleet=$args[2]
$InstanceType=$args[3]


#Install SSM
$progressPreference = 'silentlyContinue'
Invoke-WebRequest `
    https://s3.amazonaws.com/ec2-downloads-windows/SSMAgent/latest/windows_amd64/AmazonSSMAgentSetup.exe `
    -OutFile $env:USERPROFILE\Desktop\SSMAgent_latest.exe
Start-Process `
    -FilePath $env:USERPROFILE\Desktop\SSMAgent_latest.exe `
    -ArgumentList "/S"
rm -Force $env:USERPROFILE\Desktop\SSMAgent_latest.exe

#Retrieve the DCV certificate
$dcvsm_certificate = aws ssm get-parameter --name "/dcv/linux/DcvBrokerCACertificate" --output text --query Parameter.Value

#Retrieve the efadmin password
$arn_secret_password = aws ssm get-parameter --name "/dcv/linux/Efadmin" --output text --query Parameter.Value
$efadmin_password = aws secretsmanager get-secret-value --secret-id  $arn_secret_password --query SecretString --output text

#Modify the Administrator password
net user Administrator $efadmin_password

# Retrieve Broker ALB address
$broker_alb = aws ssm get-parameter --name "/dcv/linux/AgentToBrokerHost" --output text --query Parameter.Value

#Configure the DCVSM configuration file
((Get-Content -path "C:\Program Files\NICE\DCVSessionManagerAgent\conf\agent.conf" -Raw) -replace "broker_host = ''","broker_host = '$broker_alb'") | Set-Content -Path "C:\Program Files\NICE\DCVSessionManagerAgent\conf\agent.conf"
((Get-Content -path "C:\Program Files\NICE\DCVSessionManagerAgent\conf\agent.conf" -Raw) -replace "#ca_file = 'ca-cert.pem'","ca_file = 'C:\Program Files\NICE\DCVSessionManagerAgent\conf\broker_cert.pem'") | Set-Content -Path "C:\Program Files\NICE\DCVSessionManagerAgent\conf\agent.conf"

#Retrieve the InstanceID
$MyInstID = Invoke-WebRequest  http://169.254.169.254/latest/meta-data/instance-id -UseBasicParsing
$AsgName = aws ec2 describe-instances --instance-ids $MyInstID --query "Reservations[].Instances[].Tags[?Key=='aws:autoscaling:groupName'].Value" --output text

#Save the DCVSM certificate
echo $dcvsm_certificate | out-file -Encoding ascii 'C:\Program Files\NICE\DCVSessionManagerAgent\conf\broker_cert.pem'

#Load the HKEY_USERS registry
New-PSDrive -PSProvider Registry -Name HKU -Root HKEY_USERS

#Configure the required DCV registry value
New-ItemProperty -Path "HKU:/S-1-5-18/Software/GSettings/com/nicesoftware/dcv/security" -Name "ca-file" -Value "C:\Program Files\NICE\DCVSessionManagerAgent\conf\broker_cert.pem"  -PropertyType "String"

#Retrieve the node AWS hostname
$metadata = Invoke-WebRequest http://169.254.169.254/latest/meta-data/hostname -UseBasicParsing
$hostname = echo $metadata.Content | %{ $_.Split('.')[0]; }


#Configure the DCV we url path
New-ItemProperty -Path "HKU:/S-1-5-18/Software/GSettings/com/nicesoftware/dcv/connectivity" -Name "web-url-path" -Value "/$hostname-dcv"  -PropertyType "String"

#Disable the DCV automatic session creation
Set-ItemProperty -Path "HKU:/S-1-5-18/Software/GSettings/com/nicesoftware/dcv/session-management" -Name "create-session" -Value 0

#Configure the DCV auth-token-verifier
$auth='https://'+$broker_alb+':8445/agent/validate-authentication-token'
New-ItemProperty -Path "HKU:/S-1-5-18/Software/GSettings/com/nicesoftware/dcv/security" -Name "auth-token-verifier" -Value "$auth"  -PropertyType "String"

#Configure Tags
New-Item -Path 'C:\Program Files\NICE\DCVSessionManagerAgent\conf\tags' -ItemType Directory
echo "AutoScalingGroupName=""$AsgName""" | out-file -Encoding ascii 'C:\Program Files\NICE\DCVSessionManagerAgent\conf\tags\agent_tags.toml'
echo "DCVFleet=""$DCVFleet""" | Add-Content -Encoding ascii 'C:\Program Files\NICE\DCVSessionManagerAgent\conf\tags\agent_tags.toml' 
echo "InstanceType=""$InstanceType""" | Add-Content -Encoding ascii 'C:\Program Files\NICE\DCVSessionManagerAgent\conf\tags\agent_tags.toml' 

#Start the required services
Set-Service -Name DcvSessionManagerAgentService -StartupType Automatic
Start-Service -Name DcvSessionManagerAgentService
Stop-Service -Name 'DCV Server'
Start-Service -Name 'DCV Server'

#Install NFS client
#Install-WindowsFeature -Name NFS-Client

#Retrieve from parameter store the shared storage dns
#$fsx_dns = aws ssm get-parameter --name "/dcv/SharedStorageDNS" --output text --query Parameter.Value
#New-PSDrive -Name "Z" -PSProvider "FileSystem" -Root "\\$fsx_dns\fsx\" -Persist

#Retrieve the logical ID of the resource
$ASGLOGICALID = aws ec2 describe-instances --instance-ids $MyInstID.Content --query "Reservations[].Instances[].Tags[?Key=='aws:cloudformation:logical-id'].Value" --output text

#Send the signal to the Cloudformation Stack
cfn-signal -e 0 --stack $stackname --resource $ASGLOGICALID --region $region
