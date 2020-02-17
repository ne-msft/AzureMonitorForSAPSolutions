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
from helper.config import ConfigHandler
from helper.context import *
from helper.tools import *
from helper.tracing import *
from helper.updateprofile import *
from helper.updatefactory import *

from provider.saphana import *

###############################################################################

# TODO(tniek) - Refactor this so each provider gets added automatically
availableProviders["saphana"] = SapHanaProvider

# TODO - refactor the list of content types into provider
sapmonContentTypes = {
   "HANA": "SapHanaCheck"
}

###############################################################################

class providerChecks(threading.Thread):
   def __init__(self, provider):
      threading.Thread.__init__(self)
      self.provider = provider

   def run(self):
      global ctx, appTracer
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






# Store credentials in the customer KeyVault
# (To be executed as custom script upon initial deployment of collector VM)
def onboard(args: str) -> None:
   global ctx, appTracer
   appTracer.info("starting onboarding payload")

   if args.HanaDbConfigurationJson is None:
      # Store provided credentials as a KeyVault secret
      hanaSecretValue = json.dumps([{
         "HanaHostname":                args.hanaHostname,
         "HanaDbName":                  args.hanaDbName,
         "HanaDbUsername":              args.hanaDbUsername,
         "HanaDbPassword":              args.hanaDbPassword,
         "HanaDbPasswordKeyVaultUrl":   args.hanaDbPasswordKeyVaultUrl,
         "HanaDbSqlPort":               args.hanaDbSqlPort,
         "PasswordKeyVaultMsiClientId": args.passwordKeyVaultMsiClientId,
         "EnableCustomerAnalytics":     args.enableCustomerAnalytics,
         }])
   else:
      # validate it is actual JSON
      jsonObj = json.loads(args.HanaDbConfigurationJson)
      hanaSecretValue = json.dumps(jsonObj)
   appTracer.info("storing HANA credentials as KeyVault secret")
   try:
      ctx.azKv.setSecret(HanaSecretName, hanaSecretValue)
   except Exception as e:
      appTracer.critical("could not store HANA credentials in KeyVault secret (%s)" % e)
      sys.exit(ERROR_SETTING_KEYVAULT_SECRET)

   # Store credentials for new Log Analytics Workspace (created by HanaRP)
   laSecretName = "AzureLogAnalytics"
   appTracer.debug("laSecretName=%s" % laSecretName)
   laSecretValue = json.dumps({
      "LogAnalyticsWorkspaceId": args.logAnalyticsWorkspaceId,
      "LogAnalyticsSharedKey":   args.logAnalyticsSharedKey,
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




def addProvider(args: str) -> None:
   print("ADD")
   global ctx, appTracer
   appTracer.info("adding provider %s" % args.name)
   #ConfigHandler.loadConfig(appTracer, ctx)
   instance = {"name": args.name,
               "type": args.type,
               "properties": args.properties}
   if not ConfigHandler.saveInstanceToConfig(appTracer,
                                             ctx,
                                             instance):
      appTracer.critical("adding provider failed")
   else:
      appTracer.info("adding provider successful")
   sys.exit()






# Execute the actual monitoring payload
def monitor(args: str) -> None:
   global ctx, appTracer
   appTracer.info("starting monitor payload")
   ctx.parseSecrets()
   threads = []

   for secrets in ctx.providerSecrets:
      # There is only one type of provider right now, in the future, the provider name will be a part of the secret
      provider = initProvider(HanaSecretName, secrets)
      providerThread = providerChecks(provider)
      providerThread.start()
      threads.append(providerThread)

   for thread in threads:
      thread.join()

   appTracer.info("monitor payload successfully completed")
   return

# prepareUpdate will prepare the resources like keyvault, log analytics etc for the version passed as an argument
# prepareUpdate needs to be run when a version upgrade requires specific update to the content of the resources
def prepareUpdate(args: str) -> None:
    global ctx, appTracer
    appTracer.info("Preparing for %s" % args.toVersion)
    try:
       updateProfileFactoryObj = updateProfileFactory()
       updateprofile = updateProfileFactoryObj.createUpdateProfile(args.toVersion)
       updateprofile.update(ctx, args.fromVersion)
    except Exception as e:
        sys.stderr.write("Could not fulfill the update requirements for %s" % args.toVersion)

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

def deleteProvider(args: str) -> None:
   print("DELETE")
   print(args)
   sys.exit()

# Main function with argument parser
def main() -> None:
   def addVerboseToParser(p: argparse.ArgumentParser) -> None:
      p.add_argument("--verbose",
                     action = "store_true",
                     dest = "verbose",
                     help = "run in verbose mode")
      return

   global ctx, appTracer

   # Make sure we have all directories in place
   ensureDirectoryStructure()

   # Build the argument parser
   parser = argparse.ArgumentParser(description = "SAP Monitor Payload")
   subParsers = parser.add_subparsers(title = "actions",
                                      help = "Select action to run")
   subParsers.required = True
   subParsers.dest = "command"

   # Parsers for "provider" command
   prvParser = subParsers.add_parser("provider",
                                      description = "Configuration of monitoring providers",
                                      help = "Configure monitoring providers and their properties")
   prvSubParsers = prvParser.add_subparsers(title = "action",
                                            help = "Select provider action to run")
   prvSubParsers.required = True
   prvSubParsers.dest = "command"
   prvAddParser = prvSubParsers.add_parser("add",
                                           description = "Add a provider",
                                           help = "Add a new monitoring provider to this SAP Monitor")
   prvAddParser.add_argument("--name",
                             required = True,
                             type = str,
                             help = "Name of the monitoring provider")
   prvAddParser.add_argument("--type",
                             required = True,
                             type = str,
                             help = "Type of the monitoring provider")
   prvAddParser.add_argument("--properties",
                             required = True,
                             type = str,
                             help = "Properties of the monitoring provider")
   addVerboseToParser(prvAddParser)
   prvAddParser.set_defaults(func = addProvider)
   prvDelParser = prvSubParsers.add_parser("delete",
                                           description = "Delete a provider",
                                           help = "Delete an existing monitoring provider from this SAP Monitor")
   prvDelParser.add_argument("--name",
                             required = True,
                             type = str,
                             help = "Name of the monitoring provider")
   addVerboseToParser(prvDelParser)
   prvDelParser.set_defaults(func = deleteProvider)

   # Parsers for "monitor" command
   monParser = subParsers.add_parser("monitor",
                                      description = "Monitoring payload",
                                      help = "Execute the monitoring payload")
   addVerboseToParser(monParser)
   monParser.set_defaults(func = monitor)

   # Parsers for "onboard" command
   onbParser = subParsers.add_parser("onboard",
                                     description = "Onboard payload",
                                     help = "Onboard payload by adding credentials into KeyVault")
   onbParser.set_defaults(func = onboard,
                          command = "onboard")
   onbParser.add_argument("--logAnalyticsWorkspaceId",
                          required = True,
                          type = str,
                          help = "Workspace ID (customer ID) of the Log Analytics Workspace")
   onbParser.add_argument("--logAnalyticsSharedKey",
                          required = True,
                          type = str,
                          help = "Shared key (primary) of the Log Analytics Workspace")
   onbParser.add_argument("--providers",
                          required = True,
                          type = str,
                          help = "JSON-formatted list of all provider properties")
   onbParser.add_argument("--enableCustomerAnalytics",
                          required = False,
                          help = "Setting to enable sending metrics to Microsoft",
                          action="store_true",
                          dest="enableCustomerAnalytics")
   addVerboseToParser(onbParser)
   onbParser.set_defaults(enableCustomerAnalytics=False)

   # Parsers for "update" command
   updParser = subParsers.add_parser("update",
                                     description = "Prepares resources for the given version",
                                     help = "Run this before starting the next version")
   updParser.add_argument("--toVersion",
                           required = True,
                           type = str,
                           help = "Prepare resources for this target version")
   updParser.add_argument("--fromVersion",
                           required = True,
                           type = str,
                           help = "Pass the previous version (i.e. the currently running version)")
   addVerboseToParser(updParser)
   updParser.set_defaults(func = prepareUpdate)

   args = parser.parse_args()
   appTracer = tracing.initTracer(args)
   ctx = Context(appTracer, args.command)
   args.func(args)

   return

ctx = None
appTracer = None
if __name__ == "__main__":
   main()

