#!/bin/bash

# Copyright (c) Microsoft Corporation.
# Licensed under the MIT license.

# disable exit on error
set +e

ExecuteCommand() {
    retryCounter=1
    sleepSeconds=1
    while [ $retryCounter -le 5 ]
    do
        echo "Try # $retryCounter: Command: $1"
        #Sleep to allow the servers to recover in case the server was unable to serve the request
        sleep $sleepSeconds
        $1
        if [ $? -eq 0 ]; then
	        return
        fi
        retryCounter=$((retryCounter+1))
        sleepSeconds=$((2*sleepSeconds))
    done
    >&2 echo "Error executing command: $1"
    # Exit if all the retries failed
    exit 1
}

# Update
ExecuteCommand "apt-get -y update"
# Install pip
ExecuteCommand "apt-get install -y python3-pip"
# Upgrade pip
ExecuteCommand "python3 -m pip install -U pip"
# Install hdbcli
ExecuteCommand "pip3 install hdbcli"
# Install azure_storage_logging
ExecuteCommand "pip3 install azure_storage_logging"
# Install azure-mgmt-storage
ExecuteCommand "pip3 install azure-mgmt-storage"
# Install prometheus_client library
ExecuteCommand "pip3 install prometheus_client"
ExecuteCommand "pip3 install azure-keyvault-secrets"
ExecuteCommand "pip3 install azure-identity"

