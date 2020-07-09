#!/usr/bin/env bash

set -e

SUBSCRIPTION=$1
RESOURCE_GROUP=$2
RESOURCE_NAME=$3

if [[ -z $SUBSCRIPTION ]]; then
	echo "Subscription must be provided"
	exit 1
fi

if [[ -z $RESOURCE_GROUP ]]; then
	echo "Resource group must be provided"
	exit 1
fi

if [[ -z $RESOURCE_NAME ]]; then
	echo "Resource name must be provided"
	exit 1
fi

echo "Installing sap-hana CLI extension"
az extension add -n sap-hana -y

echo "Fetching information"
SAPMONITOR=$(az sapmonitor show --subscription $SUBSCRIPTION -g $RESOURCE_GROUP -n $RESOURCE_NAME)
SAPMON_ID=$(echo $SAPMONITOR | jq .managedResourceGroupName -r | cut -d'-' -f 3)
DB_NAME=$(echo $SAPMONITOR | jq .hanaDbName -r)

# Note: -k/--insecure cannot be used with curl; security compliance requires we verify certs
LATEST_VERSION=$(curl -s https://api.github.com/repos/Azure/AzureMonitorForSAPSolutions/releases/latest | jq .tag_name -r)
USER_OBJECT_ID=$(az ad signed-in-user show --query objectId -o tsv)

echo "Deleting lock"
az lock delete -g sapmon-rg-$SAPMON_ID -n sapmon-lock-$SAPMON_ID --subscription $SUBSCRIPTION -o none

echo "Checking to see if storage account exists"
set +e
az storage account show --subscription $SUBSCRIPTION -g sapmon-rg-$SAPMON_ID -n sapmonsto$SAPMON_ID -o none
GET_STORAGE_ACCOUNT_EXIT_CODE=$?
set -e

if [ $GET_STORAGE_ACCOUNT_EXIT_CODE -ne 0 ]
then
	echo "No storage account detected, creating storage account"
	az storage account create --subscription $SUBSCRIPTION -g sapmon-rg-$SAPMON_ID -n sapmonsto$SAPMON_ID -o none
	PRINCIPAL_ID=$(az identity show --subscription $SUBSCRIPTION -g "sapmon-rg-$SAPMON_ID" -n "sapmon-msi-$SAPMON_ID" | jq .principalId -r)
	az role assignment create \
		--role "Contributor" \
		--assignee $PRINCIPAL_ID \
		--scope "/subscriptions/$SUBSCRIPTION/resourceGroups/sapmon-rg-$SAPMON_ID/providers/Microsoft.Storage/storageAccounts/sapmonsto$SAPMON_ID" \
		-o none

	echo "Creating logging queue"
	az storage queue create --account-name sapmonsto$SAPMON_ID -n sapmon-que-$SAPMON_ID --subscription $SUBSCRIPTION -o none
fi

echo "Creating customer analytics queue"
az storage queue create --account-name sapmonsto$SAPMON_ID -n sapmon-anl-$SAPMON_ID --subscription $SUBSCRIPTION -o none

echo "Updating Collector VM"
echo '{
	"commandToExecute": "git clone https://github.com/Azure/AzureMonitorForSAPSolutions.git --branch '${LATEST_VERSION}' '${LATEST_VERSION}' && rm -fr /var/opt/microsoft/* && mkdir -p /var/opt/microsoft/'${LATEST_VERSION}' && cp -a '${LATEST_VERSION}'/. /var/opt/microsoft/'${LATEST_VERSION}' && sh /var/opt/microsoft/'${LATEST_VERSION}'/sapmon/setup/configureMonitorVM.sh && head -n -1 /etc/crontab > temp && mv temp /etc/crontab && echo \"* * * * * root python3 /var/opt/microsoft/'${LATEST_VERSION}'/sapmon/payload/sapmon.py monitor\" >> /etc/crontab"
	}' > script.json

az vm extension set \
	--subscription $SUBSCRIPTION \
	--resource-group sapmon-rg-$SAPMON_ID \
	--vm-name sapmon-vm-$SAPMON_ID \
	--publisher Microsoft.Azure.Extensions \
	--name CustomScript \
	--version 2.0 \
	--extension-instance-name sapmon-cse-$SAPMON_ID \
	--protected-settings script.json \
	-o none
rm script.json

echo "Updating keyvault"
az keyvault set-policy \
	--subscription $SUBSCRIPTION \
	--name sapmon-kv-$SAPMON_ID \
	--resource-group sapmon-rg-$SAPMON_ID \
	--object-id $USER_OBJECT_ID \
	--secret-permissions set get \
	-o none
ORIGINAL=$(az keyvault secret show --subscription $SUBSCRIPTION --vault-name sapmon-kv-$SAPMON_ID --name SapHana-$DB_NAME --query value -o tsv)
NEW=$(echo $ORIGINAL | jq '. + {"EnableCustomerAnalytics":true'})
az keyvault secret set --subscription $SUBSCRIPTION --vault-name sapmon-kv-$SAPMON_ID --name SapHana-$DB_NAME --value "$NEW" -o none
az keyvault delete-policy \
	--subscription $SUBSCRIPTION \
	--name sapmon-kv-$SAPMON_ID \
	--resource-group sapmon-rg-$SAPMON_ID \
	--object-id $USER_OBJECT_ID \
	-o none

echo "Recreating lock"
az lock create -g sapmon-rg-$SAPMON_ID -n sapmon-lock-$SAPMON_ID --subscription $SUBSCRIPTION --lock-type CanNotDelete -o none

echo "Upgrade complete, new version: $LATEST_VERSION"
