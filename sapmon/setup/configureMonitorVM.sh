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
        # Sleep to allow the servers to recover in case the server was unable to serve the request
        sleep $sleepSeconds
        ret=$(eval "$1")
        if [ $? == 0 ]; then
                return
        fi
        retryCounter=$((retryCounter+1))
        sleepSeconds=$((2*sleepSeconds))
    done
    >&2 echo "Error executing command: $1"
    # Exit if all the retries failed
    exit 1
}

# Update repos for SQL Server
# Note: -k/--insecure cannot be used with curl; security compliance requires we verify certs
ExecuteCommand "curl https://packages.microsoft.com/keys/microsoft.asc | apt-key add -"
ExecuteCommand "curl https://packages.microsoft.com/config/ubuntu/16.04/prod.list > /etc/apt/sources.list.d/mssql-release.list"
# Update
ExecuteCommand "apt-get -y update"
# Install pip
ExecuteCommand "apt-get install -y python3-pip"
# Install PyODBC dependencies
ExecuteCommand "apt-get install g++ unixodbc-dev"
# Upgrade pip
ExecuteCommand "python3 -m pip install -U pip"
# Install hdbcli
ExecuteCommand "pip3 install hdbcli"
# Install azure-storage pinning version 0.36.0
ExecuteCommand "pip3 install azure-storage==0.36.0"
# Install azure_storage_logging
ExecuteCommand "pip3 install azure_storage_logging"
# Install azure-mgmt-storage
ExecuteCommand "pip3 install azure-mgmt-storage"
# Install azure-identity
ExecuteCommand "pip3 install azure-identity"
# Install azure-keyvault-secrets
ExecuteCommand "pip3 install azure-keyvault-secrets"
# Install prometheus_client
ExecuteCommand "pip3 install prometheus_client"
# Install Python ODBC client
ExecuteCommand "pip3 install pyodbc"
# Install MS SQL Server driver
ExecuteCommand "ACCEPT_EULA=Y apt-get install -y msodbcsql17"
# Install retry
ExecuteCommand "pip3 install retry"