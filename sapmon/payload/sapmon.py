#!/usr/bin/env python3
# 
#       Azure Monitor for SAP Solutions payload script
#       (deployed on collector VM)
#
#       License:        GNU General Public License (GPL)
#       (c) 2019        Microsoft Corp.
#

# Python modules
from abc import ABC, abstractmethod
import argparse
import json
import os
import re
import sys
import threading

# Payload modules
from const import *
from helper.azure import *
from helper.tools import *
from helper.tracing import *

from provider.saphana import *

###############################################################################

# TODO - refactor the list of content types into provider
sapmonContentTypes = {
   "HANA": "SapHanaCheck"
}

# Internal context handler
class _Context(object):
   azKv = None
   hanaInstances = []
   sapmonId = None
   vmInstance = None
   vmTage = None
   enableCustomerAnalytics = None
   providerSecrets = []

   def __init__(self,
                operation: str):
      global appTracer, analyticsTracer
      appTracer.info("initializing context")

      # Retrieve sapmonId via IMDS
      self.vmInstance = AzureInstanceMetadataService.getComputeInstance(appTracer,
                                                                        operation)
      self.vmTags = dict(
         map(lambda s : s.split(':'),
         self.vmInstance["tags"].split(";"))
      )
      appTracer.debug("vmTags=%s" % self.vmTags)
      self.sapmonId = self.vmTags["SapMonId"]
      appTracer.debug("sapmonId=%s " % self.sapmonId)

      # Add storage queue log handler to appTracer
      tracing.addQueueLogHandler(appTracer, self)

      # Initializing appTracer for emitting metrics
      analyticsTracer = tracing.initCustomerAnalyticsTracer(appTracer, self)

      # Get KeyVault
      self.azKv = AzureKeyVault(appTracer, KEYVAULT_NAMING_CONVENTION % self.sapmonId, self.vmTags.get("SapMonMsiClientId", None))
      if not self.azKv.exists():
         sys.exit(ERROR_KEYVAULT_NOT_FOUND)

      appTracer.info("successfully initialized context")

   # Fetch HANA password from a separate KeyVault
   def fetchHanaPasswordFromKeyVault(self,
                                     passwordKeyVault: str,
                                     passwordKeyVaultMsiClientId: str) -> str:
      global appTracer
      appTracer.info("fetching HANA credentials from KeyVault")

      # Extract KeyVault name from secret URL
      vaultNameSearch = re.search("https://(.*).vault.azure.net", passwordKeyVault)
      appTracer.debug("vaultNameSearch=%s" % vaultNameSearch.group(1))

      # Create temporary KeyVault object to get relevant secret
      kv = AzureKeyVault(appTracer, vaultNameSearch.group(1), passwordKeyVaultMsiClientId)
      appTracer.debug("kv=%s" % kv)

      return kv.getSecret(passwordKeyVault)

   # Read secrets from customer KeyVault and store credentials in context
   # TODO - make this content-specific
   def parseSecrets(self) -> None:
      # From a given dictionary, return only elements whose keys start with a given string
      def sliceDict(d: dict, s: str) -> dict:
         return {k: v for k, v in iter(d.items()) if k.startswith(s)}

      global appTracer
      appTracer.info("parsing secrets")

      # Until we have multiple provider instances, just pick the first HANA config
      secrets = self.azKv.getCurrentSecrets()
      hanaSecrets = sliceDict(secrets, "SapHana")
      hanaJson = list(hanaSecrets.values())[0]
      hanaDetails = json.loads(hanaJson)
      for hanaDetail in hanaDetails:
         if not hanaDetail["HanaDbPassword"]:
            appTracer.info("no HANA password provided; need to fetch password from separate KeyVault")
            try:
               password = self.fetchHanaPasswordFromKeyVault(hanaDetail["HanaDbPasswordKeyVaultUrl"],
                                                             hanaDetail["PasswordKeyVaultMsiClientId"])
               hanaDetail["HanaDbPassword"] = password
               appTracer.debug("retrieved HANA password successfully from KeyVault")
            except Exception as e:
               appTracer.critical("could not fetch HANA password (instance=%s) from KeyVault (%s)" % (hanaDetails["HanaHostname"], e))
               sys.exit(ERROR_GETTING_HANA_CREDENTIALS)
         # Only the last hanaDetail will take affect, but all the EnableCustomerAnalytics flags should be the same
         # as they are set by HANA RP. TODO: donaliu Refactor out common configs out of hanaDetails
         ctx.enableCustomerAnalytics = hanaDetail["EnableCustomerAnalytics"]
         self.providerSecrets.append(hanaDetail)

      # Also extract Log Analytics credentials from secrets
      try:
         laSecret = json.loads(secrets["AzureLogAnalytics"])
      except Exception as e:
         appTracer.critical("could not fetch Log Analytics credentials (%s)" % e)
         sys.exit(ERROR_GETTING_LOG_CREDENTIALS)
      self.azLa = AzureLogAnalytics(
         appTracer,
         laSecret["LogAnalyticsWorkspaceId"],
         laSecret["LogAnalyticsSharedKey"]
         )

      return

   def ingestCustomerAnalytics(self,
                               customLog: str,
                               resultJson: str) -> None:
      appTracer.info("sending customer analytics")
      results = json.loads(resultJson)
      for result in results:
         metrics = {
            "Type": customLog,
            "Data": result,
         }
         appTracer.debug("metrics=%s" % metrics)
         j = json.dumps(metrics)
         analyticsTracer.info(j)

      return

###############################################################################

class providerChecks(threading.Thread):
   def __init__(self, provider):
      threading.Thread.__init__(self)
      self.provider = provider

   def run(self):
      for check in self.provider.checks:
         appTracer.info("starting check %s.%s" % (self.provider.name, check.name))
         # Skip this check if it's not enabled or not due yet
         if (check.isEnabled() == False) or (check.isDue() == False):
            continue

         # Run all actions that are part of this check
         resultJson = check.run()

         # Ingest result into Log Analytics
         ctx.azLa.ingest(check.customLog,
                         resultJson,
                         check.colTimeGenerated)

         # Persist updated internal state to provider state file
         self.provider.writeState()

         # Ingest result into Customer Analytics
         if ctx.enableCustomerAnalytics:
             ctx.ingestCustomerAnalytics(check.customLog, resultJson)

###############################################################################

def onboard(args: str) -> None:
   """
   Store credentials in the customer KeyVault
   (To be executed as custom script upon initial deployment of collector VM)
   """
   appTracer.info("starting onboarding payload")

   if args.HanaDbConfigurationJson is None:
      # Store provided credentials as a KeyVault secret
      hanaSecretValue = json.dumps([{
         "HanaHostname":                args.HanaHostname,
         "HanaDbName":                  args.HanaDbName,
         "HanaDbUsername":              args.HanaDbUsername,
         "HanaDbPassword":              args.HanaDbPassword,
         "HanaDbPasswordKeyVaultUrl":   args.HanaDbPasswordKeyVaultUrl,
         "HanaDbSqlPort":               args.HanaDbSqlPort,
         "PasswordKeyVaultMsiClientId": args.PasswordKeyVaultMsiClientId,
         "EnableCustomerAnalytics":     args.EnableCustomerAnalytics,
         }])
   else:
      # validate it is actual JSON
      jsonObj = json.loads(args.HanaDbConfigurationJson)
      hanaSecretValue = json.dumps(jsonObj)
   appTracer.info("storing HANA credentials as KeyVault secret")
   try:
      ctx.azKv.setSecret("SapHana", hanaSecretValue)
   except Exception as e:
      appTracer.critical("could not store HANA credentials in KeyVault secret (%s)" % e)
      sys.exit(ERROR_SETTING_KEYVAULT_SECRET)

   # Store credentials for new Log Analytics Workspace (created by HanaRP)
   laSecretName = "AzureLogAnalytics"
   appTracer.debug("laSecretName=%s" % laSecretName)
   laSecretValue = json.dumps({
      "LogAnalyticsWorkspaceId": args.LogAnalyticsWorkspaceId,
      "LogAnalyticsSharedKey":   args.LogAnalyticsSharedKey,
      })
   appTracer.info("storing Log Analytics credentials as KeyVault secret")
   try:
      ctx.azKv.setSecret(laSecretName,
                         laSecretValue)
   except Exception as e:
      appTracer.critical("could not store Log Analytics credentials in KeyVault secret (%s)" % e)
      sys.exit(ERROR_SETTING_KEYVAULT_SECRET)

   # Check connectivity to HANA instance
   hanaDetails = json.loads(hanaSecretValue)
   for hanaDetail in hanaDetails:
      if not hanaDetail["HanaDbPassword"]:
         appTracer.info("no HANA password provided; need to fetch password from separate KeyVault")
         hanaDetail["HanaDbPassword"] = ctx.fetchHanaPasswordFromKeyVault(hanaDetail["HanaDbPasswordKeyVaultUrl"],
                                                                          hanaDetail["PasswordKeyVaultMsiClientId"])

      if not SapHanaProvider.validate(appTracer, hanaDetail):
         appTracer.critical("validation of HANA instance failed, aborting")
         sys.exit(ERROR_HANA_CONNECTION)

   appTracer.info("onboarding payload successfully completed")
   return

# Execute the actual monitoring payload
def monitor(args: str) -> None:
   appTracer.info("starting monitor payload")
   ctx.parseSecrets()
   threads = []

   for secrets in ctx.providerSecrets:
      # There is only one type of provider right now, in the future, the provider name will be a part of the secret
      provider = initProvider("SapHana", secrets)
      providerThread = providerChecks(provider)
      providerThread.start()
      threads.append(providerThread)

   for thread in threads:
      thread.join()

   appTracer.info("monitor payload successfully completed")
   return

# Ensures the required directory structure exists
def ensureDirectoryStructure() -> None:
   for path in [PATH_STATE, PATH_TRACE]:
      try:
         if not os.path.exists(path):
            os.makedirs(path)   
      except Exception as e:
         sys.stderr.write("could not create required directory %s; please check permissions (%s)" % (path, e))
         sys.exit(ERROR_FILE_PERMISSION_DENIED)
   return

# Initializes a provider based on it's name
def initProvider(providerName:str, secrets):
   global appTracer
   appTracer.info("initializing provider %s" % providerName)

   contentFullPath = "%s/%s.json" % (PATH_CONTENT, providerName)
   appTracer.debug("providerName=%s, contentFullPath=%s" % (providerName, contentFullPath))

   contentProvider = eval("%sProvider" % providerName)(appTracer, contentFullPath, secrets)

   appTracer.info("successfully loaded content provider %s" % providerName)
   return contentProvider

# Main function with argument parser
def main() -> None:
   global ctx, appTracer

   # Make sure we have all directories in place
   ensureDirectoryStructure()

   # Build the argument parser
   parser = argparse.ArgumentParser(description = "SAP Monitor Payload")
   parser.add_argument("--verbose",
                       action = "store_true",
                       dest = "verbose",
                       help = "run in verbose mode") 
   subParsers = parser.add_subparsers(title = "actions",
                                      help = "Select action to run")
   subParsers.required = True
   subParsers.dest = "command"
   monParser = subParsers.add_parser("monitor",
                                      description = "Monitoring payload",
                                      help = "Execute the monitoring payload")
   monParser.set_defaults(func=monitor)
   onbParser = subParsers.add_parser("onboard",
                                     description = "Onboard payload",
                                     help = "Onboard payload by adding credentials into KeyVault")
   onbParser.set_defaults(func = onboard,
                          command = "onboard")
   onbParser.add_argument("--HanaHostname",
                          required = False,
                          type = str,
                          help = "Hostname of the HDB to be monitored")
   onbParser.add_argument("--HanaDbName",
                          required = False,
                          type = str,
                          help = "Name of the tenant DB (empty if not MDC)")
   onbParser.add_argument("--HanaDbUsername",
                          required = False,
                          type = str,
                          help = "DB username to connect to the HDB tenant")
   onbParser.add_argument("--HanaDbPassword",
                          required = False,
                          type = str,
                          help = "DB user password to connect to the HDB tenant")
   onbParser.add_argument("--HanaDbPasswordKeyVaultUrl",
                          required = False,
                          type = str,
                          help = "URL of KeyVault secret containing HDB password")
   onbParser.add_argument("--HanaDbSqlPort",
                          required = False,
                          type = int,
                          help = "SQL port of the tenant DB")
   onbParser.add_argument("--LogAnalyticsWorkspaceId",
                          required = True,
                          type = str,
                          help = "Workspace ID (customer ID) of the Log Analytics Workspace")
   onbParser.add_argument("--LogAnalyticsSharedKey",
                          required = True,
                          type = str,
                          help = "Shared key (primary) of the Log Analytics Workspace")
   onbParser.add_argument("--PasswordKeyVaultMsiClientId",
                          required = False,
                          type = str,
                          help = "MSI Client ID used to get the access token from IMDS")
   onbParser.add_argument("--EnableCustomerAnalytics",
                          required = False,
                          help = "Setting to enable sending metrics to Microsoft",
                          action="store_true",
                          dest="EnableCustomerAnalytics")
   onbParser.set_defaults(EnableCustomerAnalytics=False)
   onbParser.add_argument("--HanaDbConfigurationJson",
                          required = False,
                          type = str,
                          help = "Configurations to connect multiple HANA DBs in JSON format")
   onbParser.set_defaults(HanaDbConfigurationJson=None)
   args = parser.parse_args()
   appTracer = tracing.initTracer(args)
   ctx = _Context(args.command)
   args.func(args)

   return

appTracer = None
analyticsTracer = None
ctx = None
if __name__ == "__main__":
   main()
