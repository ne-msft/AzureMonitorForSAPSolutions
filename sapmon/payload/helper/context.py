#!/usr/bin/env python3
#
#       Azure Monitor for SAP Solutions payload script
#       (deployed on collector VM)
#
#       License:        GNU General Public License (GPL)
#       (c) 2020        Microsoft Corp.
#

# Python modules
import re

# Payload modules
from helper.tracing import *
from provider.saphana import *

# Internal context handler
class Context(object):
   azKv = None
   hanaInstances = []
   sapmonId = None
   vmInstance = None
   vmTage = None
   enableCustomerAnalytics = None
   providerSecrets = []
   analyticsTracer = None
   appTracer = None

   def __init__(self, tracer,
                operation: str):
      self.tracer = tracer
      self.tracer.info("initializing context")

      # Retrieve sapmonId via IMDS
      self.vmInstance = AzureInstanceMetadataService.getComputeInstance(self.appTracer,
                                                                        operation)
      self.vmTags = dict(
         map(lambda s : s.split(':'),
         self.vmInstance["tags"].split(";"))
      )
      self.tracer.debug("vmTags=%s" % self.vmTags)
      self.sapmonId = self.vmTags["SapMonId"]
      self.tracer.debug("sapmonId=%s " % self.sapmonId)

      # Add storage queue log handler to appTracer
      tracing.addQueueLogHandler(self.tracer, self)

      # Initializing appTracer for emitting metrics
      self.analyticsTracer = tracing.initCustomerAnalyticsTracer(self.tracer, self)

      # Get KeyVault
      self.azKv = AzureKeyVault(self.tracer, KEYVAULT_NAMING_CONVENTION % self.sapmonId, self.vmTags.get("SapMonMsiClientId", None))
      if not self.azKv.exists():
         sys.exit(ERROR_KEYVAULT_NOT_FOUND)

      self.tracer.info("successfully initialized context")
