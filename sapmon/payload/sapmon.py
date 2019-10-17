#!/usr/bin/env python3
# 
#       Azure Monitor for SAP Solutions payload script
#       (deployed on collector VM)
#
#       License:        GNU General Public License (GPL)
#       (c) 2019        Microsoft Corp.
#

from abc import ABC, abstractmethod
import argparse
from datetime import date, datetime, timedelta
import json
import os
import re
import sys

from const import *
from helper.azure import *
from helper.tools import *
from helper.tracing import *
from provider.saphana import *

###############################################################################

sapmonContentTypes = {
   "HANA": "SapHanaCheck"
}

###############################################################################

class _Context(object):
   """
   Internal context handler
   """
   hanaInstances   = []
   availableChecks = []

   def __init__(self, operation):
      global tracer
      tracer.info("initializing context")
      self.vmInstance = AzureInstanceMetadataService.getComputeInstance(tracer, operation)
      self.vmTags = dict(map(lambda s : s.split(':'), self.vmInstance["tags"].split(";")))
      tracer.debug("vmTags=%s" % self.vmTags)
      self.sapmonId = self.vmTags["SapMonId"]
      tracer.debug("sapmonId=%s " % self.sapmonId)
      self.azKv = AzureKeyVault(tracer, KEYVAULT_NAMING_CONVENTION % self.sapmonId, self.vmTags.get("SapMonMsiClientId", None))
      if not self.azKv.exists():
         sys.exit(ERROR_KEYVAULT_NOT_FOUND)
      self.initMonitoringContent()
      self.readStateFile()
      tracing.addQueueLogHandler(tracer, self)
      return
 
   def initMonitoringContent(self):
      """
      Initialize all monitoring content (pre-delivered via content/*.json)
      """
      global tracer
      tracer.info("initializing monitoring content")
      for filename in os.listdir(PATH_CONTENT):
         if not filename.endswith(".json"):
            continue
         contentFullPath = "%s/%s" % (PATH_CONTENT, filename)
         tracer.debug("contentFullPath=%s" % contentFullPath)
         try:
            with open(contentFullPath, "r") as file:
               data = file.read()
            jsonData = json.loads(data)
         except Exception as e:
            tracer.error("could not load content file %s (%s)" % (contentFullPath, e))
         contentType = jsonData.get("contentType", None)
         if not contentType:
            tracer.error("content type not specified in content file %s, skipping" % contentFullPath)
            continue
         contentVersion = jsonData.get("contentVersion", None)
         if not contentVersion:
            tracer.error("content version not specified in content file %s, skipping" % contentFullPath)
            continue
         checks = jsonData.get("checks", [])
         if not contentType in sapmonContentTypes:
            tracer.error("unknown content type %s, skipping content file %s" % (contentType, contentFullPath))
            continue
         for checkOptions in checks:
            try:
               tracer.info("instantiate check of type %s" % contentType)
               checkOptions["version"] = contentVersion
               tracer.debug("checkOptions=%s" % checkOptions)
               check = eval(sapmonContentTypes[contentType])(tracer, **checkOptions)
               self.availableChecks.append(check)
            except Exception as e:
               tracer.error("could not instantiate new check of type %s (%s)" % (contentType, e))
      tracer.info("successfully loaded %d monitoring checks" % len(self.availableChecks))
      return

   def readStateFile(self):
      """
      Get most recent state from a local file
      """
      global tracer
      tracer.info("reading state file")
      success  = True
      jsonData = {}
      try:
         tracer.debug("FILENAME_STATEFILE=%s" % FILENAME_STATEFILE)
         with open(FILENAME_STATEFILE, "r") as file:
            data = file.read()
         jsonData = json.loads(data, object_hook=JsonDecoder.datetimeHook)
      except FileNotFoundError as e:
         tracer.warning("state file %s does not exist" % FILENAME_STATEFILE)
      except Exception as e:
         tracer.error("could not read state file %s (%s)" % (FILENAME_STATEFILE, e))
      for c in self.availableChecks:
         sectionKey = "%s_%s" % (c.prefix, c.name)
         if sectionKey in jsonData:
            tracer.debug("parsing section %s" % sectionKey)
            section = jsonData.get(sectionKey, {})
            for k in section.keys():
               c.state[k] = section[k]
         else:
            tracer.warning("section %s not found in state file" % sectionKey)
      tracer.info("successfully parsed state file")
      return success

   def writeStateFile(self):
      """
      Persist current state into a local file
      """
      global tracer
      tracer.info("writing state file")
      success  = False
      jsonData = {}
      try:
         tracer.debug("FILENAME_STATEFILE=%s" % FILENAME_STATEFILE)
         for c in self.availableChecks:
            sectionKey = "%s_%s" % (c.prefix, c.name)
            jsonData[sectionKey] = c.state
         with open(FILENAME_STATEFILE, "w") as file:
            json.dump(jsonData, file, indent=3, cls=JsonEncoder)
         success = True
      except Exception as e:
         tracer.error("could not write state file %s (%s)" % (FILENAME_STATEFILE, e))
      return success

   def fetchHanaPasswordFromKeyVault(self, passwordKeyVault, passwordKeyVaultMsiClientId):
      """
      Fetch HANA password from a separate KeyVault.
      """
      global tracer
      tracer.info("fetching HANA credentials from KeyVault")
      vaultNameSearch = re.search("https://(.*).vault.azure.net", passwordKeyVault)
      tracer.debug("vaultNameSearch=%s" % vaultNameSearch)
      kv = AzureKeyVault(tracer, vaultNameSearch.group(1), passwordKeyVaultMsiClientId)
      tracer.debug("kv=%s" % kv)
      return kv.getSecret(passwordKeyVault)

   def parseSecrets(self):
      """
      Read secrets from customer KeyVault and store credentials in context.
      """
      def sliceDict(d, s):
         return {k: v for k, v in iter(d.items()) if k.startswith(s)}

      def fetchHanaPasswordFromKeyVault(self, passwordKeyVault, passwordKeyVaultMsiClientId):
         global tracer
         vaultNameSearch = re.search('https://(.*).vault.azure.net', passwordKeyVault)
         tracer.debug("vaultNameSearch=%s" % vaultNameSearch)
         kv = AzureKeyVault(tracer, vaultNameSearch.group(1), passwordKeyVaultMsiClientId)
         tracer.debug("kv=%s" % kv)
         return kv.getSecret(passwordKeyVault)

      global tracer
      tracer.info("parsing secrets")
      secrets = self.azKv.getCurrentSecrets()

      # extract HANA instance(s) from secrets
      hanaSecrets = sliceDict(secrets, "SapHana-")
      for h in hanaSecrets.keys():
         hanaDetails = json.loads(hanaSecrets[h])
         if not hanaDetails["HanaDbPassword"]:
            tracer.info("no HANA password provided; need to fetch password from separate KeyVault")
            try:
               password = self.fetchHanaPasswordFromKeyVault(
                  hanaDetails["HanaDbPasswordKeyVaultUrl"],
                  hanaDetails["PasswordKeyVaultMsiClientId"])
               hanaDetails["HanaDbPassword"] = password
               tracer.debug("retrieved HANA password successfully from KeyVault")
            except Exception as e:
               tracer.critical("could not fetch HANA password (instance=%s) from KeyVault (%s)" % (h, e))
               sys.exit(ERROR_GETTING_HANA_CREDENTIALS)
         try:
            hanaInstance = SapHana(tracer, hanaDetails = hanaDetails)
         except Exception as e:
            tracer.error("could not create HANA instance %s) (%s)" % (h, e))
            continue
         self.hanaInstances.append(hanaInstance)

      # extract Log Analytics credentials from secrets
      try:
         laSecret = json.loads(secrets["AzureLogAnalytics"])
      except Exception as e:
         tracer.critical("could not fetch Log Analytics credentials (%s)" % e)
         sys.exit(ERROR_GETTING_LOG_CREDENTIALS)
      self.azLa = AzureLogAnalytics(
         tracer,
         laSecret["LogAnalyticsWorkspaceId"],
         laSecret["LogAnalyticsSharedKey"]
         )
      return

###############################################################################

def onboard(args):
   """
   Store credentials in the customer KeyVault
   (To be executed as custom script upon initial deployment of collector VM)
   """
   tracer.info("starting onboarding payload")

   # Credentials (provided by user) to the existing HANA instance
   hanaSecretName = "SapHana-%s" % args.HanaDbName
   tracer.debug("hanaSecretName=%s" % hanaSecretName)
   hanaSecretValue = json.dumps({
      "HanaHostname":                args.HanaHostname,
      "HanaDbName":                  args.HanaDbName,
      "HanaDbUsername":              args.HanaDbUsername,
      "HanaDbPassword":              args.HanaDbPassword,
      "HanaDbPasswordKeyVaultUrl":   args.HanaDbPasswordKeyVaultUrl,
      "HanaDbSqlPort":               args.HanaDbSqlPort,
      "PasswordKeyVaultMsiClientId": args.PasswordKeyVaultMsiClientId,
      })
   tracer.info("storing HANA credentials as KeyVault secret")
   try:
      ctx.azKv.setSecret(hanaSecretName, hanaSecretValue)
   except Exception as e:
      tracer.critical("could not store HANA credentials in KeyVault secret (%s)" % e)
      sys.exit(ERROR_SETTING_KEYVAULT_SECRET)

   # Credentials (created by HanaRP) to the newly created Log Analytics Workspace
   laSecretName = "AzureLogAnalytics"
   tracer.debug("laSecretName=%s" % laSecretName)
   laSecretValue = json.dumps({
      "LogAnalyticsWorkspaceId": args.LogAnalyticsWorkspaceId,
      "LogAnalyticsSharedKey":   args.LogAnalyticsSharedKey,
      })
   tracer.info("storing Log Analytics credentials as KeyVault secret")
   try:
      ctx.azKv.setSecret(laSecretName, laSecretValue)
   except Exception as e:
      tracer.critical("could not store Log Analytics credentials in KeyVault secret (%s)" % e)
      sys.exit(ERROR_SETTING_KEYVAULT_SECRET)

   hanaDetails = json.loads(hanaSecretValue)
   if not hanaDetails["HanaDbPassword"]:
      tracer.info("no HANA password provided; need to fetch password from separate KeyVault")
      hanaDetails["HanaDbPassword"] = ctx.fetchHanaPasswordFromKeyVault(
         hanaDetails["HanaDbPasswordKeyVaultUrl"],
         hanaDetails["PasswordKeyVaultMsiClientId"])

   # Check connectivity to HANA instance
   tracer.info("connecting to HANA instance to run test query")
   try:
      hana = SapHana(tracer, hanaDetails = hanaDetails)
      hana.connect()
      hana.runQuery("SELECT 0 FROM DUMMY")
      hana.disconnect()
   except Exception as e:
      tracer.critical("could not connect to HANA instance and run test query (%s)" % e)
      sys.exit(ERROR_HANA_CONNECTION)

   tracer.info("onboarding payload successfully completed")
   return

def monitor(args):
   """
   Actual SAP Monitor payload:
   - Obtain credentials from KeyVault secrets
   - For each DB tenant of the monitored HANA instance:
     - Connect to DB tenant via SQL
     - Execute monitoring statements
     - Emit metrics as custom log to Azure Log Analytics
   (To be executed as cronjob after all resources are deployed.)
   """
   tracer.info("starting monitor payload")
   ctx.parseSecrets()
   # TODO(tniek) - proper handling of source connection types
   for h in ctx.hanaInstances:
      try:
         h.connect()
      except Exception as e:
         tracer.critical("could not connect to HANA instance (%s)" % e)
         sys.exit(ERROR_HANA_CONNECTION)

      for c in ctx.availableChecks:
         if not c.state["isEnabled"]:
            tracer.info("check %s_%s has been disabled, skipping" % (c.prefix, c.name))
            continue
         lastRunLocal = c.state["lastRunLocal"]
         tracer.debug("lastRunLocal=%s; frequencySecs=%d; currentLocal=%s" % \
            (lastRunLocal, c.frequencySecs, datetime.utcnow()))
         if lastRunLocal and \
            lastRunLocal + timedelta(seconds=c.frequencySecs) > datetime.utcnow():
            tracer.info("check %s_%s is not due yet, skipping" % (c.prefix, c.name))
            continue
         tracer.info("running check %s_%s" % (c.prefix, c.name))
         resultJson = c.run(h)
         ctx.azLa.ingest(c.customLog, resultJson, c.colTimeGenerated)
      ctx.writeStateFile()

      try:
         h.disconnect()
      except Exception as e:
         tracer.error("could not disconnect from HANA instance (%s)" % e)

   tracer.info("monitor payload successfully completed")
   return

def ensureDirectoryStructure():
   """
   Ensures the required directory structure exists
   """
   for path in [PATH_STATE, PATH_TRACE]:
      try:
         if not os.path.exists(path):
            os.makedirs(path)   
      except Exception as e:
         sys.stderr.write("could not create required directory %s; please check permissions (%s)" % (path, e))
         sys.exit(ERROR_FILE_PERMISSION_DENIED)
   return

def main():
   """
   Main method with arg parser
   """
   global ctx, tracer
   ensureDirectoryStructure()
   parser = argparse.ArgumentParser(description="SAP Monitor Payload")
   parser.add_argument("--verbose", action="store_true", dest="verbose", help="run in verbose mode") 
   subParsers = parser.add_subparsers(title="actions", help="Select action to run")
   subParsers.required = True
   subParsers.dest = "command"
   onbParser = subParsers.add_parser("onboard", description="Onboard payload", help="Onboard payload by adding credentials into KeyVault")
   onbParser.set_defaults(func=onboard, command="onboard")
   onbParser.add_argument("--HanaHostname", required=True, type=str, help="Hostname of the HDB to be monitored")
   onbParser.add_argument("--HanaDbName", required=True, type=str, help="Name of the tenant DB (empty if not MDC)")
   onbParser.add_argument("--HanaDbUsername", required=True, type=str, help="DB username to connect to the HDB tenant")
   onbParser.add_argument("--HanaDbPassword", required=False, type=str, help="DB user password to connect to the HDB tenant")
   onbParser.add_argument("--HanaDbPasswordKeyVaultUrl", required=False, type=str, help="Link to the KeyVault secret containing DB user password to connect to the HDB tenant")
   onbParser.add_argument("--HanaDbSqlPort", required=True, type=int, help="SQL port of the tenant DB")
   onbParser.add_argument("--LogAnalyticsWorkspaceId", required=True, type=str, help="Workspace ID (customer ID) of the Log Analytics Workspace")
   onbParser.add_argument("--LogAnalyticsSharedKey", required=True, type=str, help="Shared key (primary) of the Log Analytics Workspace")
   onbParser.add_argument("--PasswordKeyVaultMsiClientId", required=False, type=str, help="MSI Client ID used to get the access token from IMDS")
   monParser  = subParsers.add_parser("monitor", description="Monitor payload", help="Execute the monitoring payload")
   monParser.set_defaults(func=monitor)
   args = parser.parse_args()
   tracer = tracing.initTracer(args)
   ctx = _Context(args.command)
   args.func(args)

tracer = None
ctx    = None
if __name__ == "__main__":
   main()
