FROM python:3.4-slim

ARG RELEASE
RUN apt-get -y update
RUN apt-get install -y git
RUN pip3 install hdbcli azure_storage_logging azure-mgmt-storage
RUN mkdir -p /var/opt/microsoft/sapmon/${RELEASE}
RUN git clone https://github.com/Azure/AzureMonitorForSAPSolutions.git --branch ${RELEASE} ${RELEASE}
RUN cp -a ${RELEASE}/* /var/opt/microsoft/sapmon/${RELEASE}
ADD monitorapp.sh /var/opt/microsoft/sapmon/${RELEASE}/monitorapp.sh
CMD []
