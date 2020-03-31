FROM python:3.7-slim

ARG RELEASE
RUN apt-get update -y
RUN apt-get upgrade -y
RUN apt-get install git -y
RUN apt-get install git gcc libffi-dev -y
RUN pip3 install --upgrade pip
RUN pip3 install hdbcli azure_storage_logging azure-mgmt-storage azure-keyvault-secrets azure-identity prometheus_client
RUN mkdir -p /var/opt/microsoft/sapmon/${RELEASE}
RUN git clone https://github.com/Azure/AzureMonitorForSAPSolutions.git --branch ${RELEASE} ${RELEASE}
RUN cp -a ${RELEASE}/* /var/opt/microsoft/sapmon/${RELEASE}
ADD monitorapp.sh /var/opt/microsoft/sapmon/${RELEASE}/monitorapp.sh
CMD []
