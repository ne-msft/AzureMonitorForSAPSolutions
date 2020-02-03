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
      self.appTracer = tracer
      self.appTracer.info("initializing context")

      # Retrieve sapmonId via IMDS
      self.vmInstance = AzureInstanceMetadataService.getComputeInstance(self.appTracer,
                                                                        operation)
      self.vmTags = dict(
         map(lambda s : s.split(':'),
         self.vmInstance["tags"].split(";"))
      )
      self.appTracer.debug("vmTags=%s" % self.vmTags)
      self.sapmonId = self.vmTags["SapMonId"]
      self.appTracer.debug("sapmonId=%s " % self.sapmonId)

      # Add storage queue log handler to appTracer
      tracing.addQueueLogHandler(self.appTracer, self)

      # Initializing appTracer for emitting metrics
      self.analyticsTracer = tracing.initCustomerAnalyticsTracer(self.appTracer, self)

      # Get KeyVault
      self.azKv = AzureKeyVault(self.appTracer, KEYVAULT_NAMING_CONVENTION % self.sapmonId, self.vmTags.get("SapMonMsiClientId", None))
      if not self.azKv.exists():
         sys.exit(ERROR_KEYVAULT_NOT_FOUND)

      self.appTracer.info("successfully initialized context")

   # Fetch HANA password from a separate KeyVault
   def fetchHanaPasswordFromKeyVault(self,
                                     passwordKeyVault: str,
                                     passwordKeyVaultMsiClientId: str) -> str:

      self.appTracer.info("fetching HANA credentials from KeyVault")

      # Extract KeyVault name from secret URL
      vaultNameSearch = re.search("https://(.*).vault.azure.net", passwordKeyVault)
      self.appTracer.debug("vaultNameSearch=%s" % vaultNameSearch.group(1))

      # Create temporary KeyVault object to get relevant secret
      kv = AzureKeyVault(self.appTracer, vaultNameSearch.group(1), passwordKeyVaultMsiClientId)
      self.appTracer.debug("kv=%s" % kv)

      return kv.getSecret(passwordKeyVault)

   # Read secrets from customer KeyVault and store credentials in context
   # TODO - make this content-specific
   def parseSecrets(self) -> None:

      self.appTracer.info("parsing secrets")

      # Until we have multiple provider instances, just pick the first HANA config
      secrets = self.azKv.getCurrentSecrets()
      hanaSecrets = sliceDict(secrets, HanaSecretName)
      # Just picking the key <HanaSecretName> for now
      hanaJson = hanaSecrets[HanaSecretName]
      hanaDetails = json.loads(hanaJson)
      for hanaDetail in hanaDetails:
         if not hanaDetail["HanaDbPassword"]:
            self.appTracer.info("no HANA password provided; need to fetch password from separate KeyVault")
            try:
               password = self.fetchHanaPasswordFromKeyVault(hanaDetail["HanaDbPasswordKeyVaultUrl"],
                                                             hanaDetail["PasswordKeyVaultMsiClientId"])
               hanaDetail["HanaDbPassword"] = password
               self.appTracer.debug("retrieved HANA password successfully from KeyVault")
            except Exception as e:
               self.appTracer.critical("could not fetch HANA password (instance=%s) from KeyVault (%s)" % (hanaDetails["HanaHostname"], e))
               sys.exit(ERROR_GETTING_HANA_CREDENTIALS)
         # Only the last hanaDetail will take affect, but all the EnableCustomerAnalytics flags should be the same
         # as they are set by HANA RP. TODO: donaliu Refactor out common configs out of hanaDetails
         self.enableCustomerAnalytics = hanaDetail["EnableCustomerAnalytics"]
         self.providerSecrets.append(hanaDetail)

      # Also extract Log Analytics credentials from secrets
      try:
         laSecret = json.loads(secrets["AzureLogAnalytics"])
      except Exception as e:
         self.appTracer.critical("could not fetch Log Analytics credentials (%s)" % e)
         sys.exit(ERROR_GETTING_LOG_CREDENTIALS)
      self.azLa = AzureLogAnalytics(
         self.appTracer,
         laSecret["LogAnalyticsWorkspaceId"],
         laSecret["LogAnalyticsSharedKey"]
         )

      return

   def ingestCustomerAnalytics(self,
                               customLog: str,
                               resultJson: str) -> None:
      self.appTracer.info("sending customer analytics")
      results = json.loads(resultJson)
      for result in results:
         metrics = {
            "Type": customLog,
            "Data": result,
         }
         self.appTracer.debug("metrics=%s" % metrics)
         j = json.dumps(metrics)
         self.analyticsTracer.info(j)

      return
