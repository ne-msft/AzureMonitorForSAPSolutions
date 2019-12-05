#!/bin/sh

Version=$1
infinite=1
while [ $infinite -eq 1 ]
do
  python3 /var/opt/microsoft/sapmon/$Version/payload/sapmon.py monitor
  sleep 60s
done

