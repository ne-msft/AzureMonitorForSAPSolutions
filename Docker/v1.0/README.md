Dockerfile to create configured images containing the data collector scripts to collect telemetry from customers SAP solutions. The scripts can be found in [Azure Monitor For SAP Solutions](https://github.com/Azure/AzureMonitorForSAPSolutions)

# How to run

## Onboard
```bash
docker run spaziz/amfsspr:%s \
python3 /var/opt/microsoft/sapmon/%s/payload/sapmon.py onboard \
--HanaHostname <HostName/IP address of the Database> \
--HanaDbName <Database name> \
--HanaDbUsername <Username for the selected database> \
--HanaDbSqlPort <Database port> \
--LogAnalyticsWorkspaceId <Id of the workspace created> \
--LogAnalyticsSharedKey <Key of the workaspace> \
--HanaDbPassword <DB password> \
--HanaDbPasswordKeyVault <Keyvault URI containing the DB password if not passed directly>
```

## Monitor
```bash
docker run -t <image:tag> python3 /var/opt/microsoft/sapmon/v1.0/sapmon.py monitor
```