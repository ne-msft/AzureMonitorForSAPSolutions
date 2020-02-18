#!/usr/bin/env python3
# 
#       Azure Monitor for SAP Solutions - Payload
#       (to be deployed on collector VM)
#
#       License:        GNU General Public License (GPL)
#       (c) 2020        Microsoft Corp.
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
from helper.context import *
from helper.tools import *
from helper.tracing import *
from helper.updateprofile import *
from helper.updatefactory import *

from provider.saphana import *

###############################################################################

class ProviderInstanceThread(threading.Thread):
   def __init__(self, providerInstance):
      threading.Thread.__init__(self)
      self.providerInstance = providerInstance

   def run(self):
      global ctx, appTracer
      for check in self.provider.checks:
         tracer.info("starting check %s" % (check.fullName))

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
         self.providerInstance.writeState()

         # Ingest result into Customer Analytics
         enableCustomerAnalytics = ctx.globalParams.get("enableCustomerAnalytics", True)
         if enableCustomerAnalytics:
             tracing.ingestCustomerAnalytics(tracer,
                                             ctx,
                                             check.customLog,
                                             resultJson)
      return

###############################################################################

# Load entire config from KeyVault (global parameters and provider instances)
def loadConfig() -> bool:
   global ctx, tracer
   tracer.info("loading config from KeyVault")

   globalParams = {}
   instances = []

   secrets = ctx.azKv.getCurrentSecrets()
   for secretName in secrets.keys():
      tracer.debug("parsing secret %s" % secretName)
      secretValue = secrets[secretName]
      try:
         instanceProperties = json.loads(secretValue)
      except json.decoder.JSONDecodeError as e:
         tracer.error("invalid JSON format for secret %s=%s (%s)" % (secretName, secretValue, e))
         continue
      if secretName == CONFIG_SECTION_GLOBAL:
         globalParams = instanceProperties
      else:
         parts = secretName.split("-")
         if len(parts) != 2:
            tracer.error("invalid secret name (should be: provider-name): %s" % (secretName))
            continue
         providerType, instanceName = parts[0], parts[1]
         providerClass = CLASSNAME_PROVIDER % providerType
         if not providerClass in dir():
            tracer.error("unknown provider type %s" % providerType)
            continue
         provider = ctx.availableProviders[providerType]
         instance = {"type": providerType,
                     "name": instanceName,
                     "properties": instanceProperties}
         instances.append(instance)

   print("globalParams = %s" % globalParams)
   print("instances = %s" % instances)
   ctx.globalParams = globalParams
   ctx.instances = instances
   if globalParams == {} or len(instances) == 0:
      return False
   return True

# Save specific instance properties to customer KeyVault
def saveInstanceToConfig(instance: Dict[str, str]) -> bool:
   global ctx, tracer
   instanceName = instance.get("name", None)
   providerType = instance.get("type", None)
   instanceProperties = instance.get("properties", None)
   if not instanceName or not providerType or not instanceProperties:
      tracer.error("instance to save is missing name, type or properties")
      return False
   tracer.info("saving instance %s to customer KeyVault" % instanceName)
   if not providerType in ctx.availableProviders:
      tracer.error("unknown provider type %s (available types: %s)" % (providerType, list(ctx.availableProviders.keys())))
      return False
   try:
      secretValue = json.dumps(instanceProperties)
   except json.encoder.JSONEncodeError as e:
      tracer.error("cannot JSON encode instance properties (%s)" % e)
      return False   
   secretName = "%s-%s" % (providerType, instanceName)
   return ctx.azKv.setSecret(secretName,
                             secretValue)

# Store credentials in the customer KeyVault
# (To be executed as custom script upon initial deployment of collector VM)
def onboard(args: str) -> None:
   global ctx, tracer
   tracer.info("starting onboarding")
   error = False

   # Update global parameters and save them to KeyVault
   ctx.globalParams = {"LogAnalyticsWorkspaceId": args.logAnalyticsWorkspaceId,
                       "LogAnalyticsSharedKey": args.logAnalyticsSharedKey,
                       "EnableCustomerAnalytics": args.enableCustomerAnalytics}
   if not ctx.azKv.setSecret(CONFIG_SECTION_GLOBAL,
                             json.dumps(ctx.globalParams)):
      tracer.critical("could not save global config to KeyVault")
      sys.exit(ERROR_SETTING_KEYVAULT_SECRET)

   try:
      providerInstances = json.loads(args.providers)
   except json.decoder.JSONDecodeError as e:
      tracer.error("invalid JSON format for provider instance list (%s)" % e)
   for p in providerInstances:
      tracer.debug("trying to add provider instance %s" % p)
      if not addProvider(providerInstance = p):
         error = True

   if error:
      tracer.error("onboarding failed with errors")
      sys.exit(ERROR_ONBOARDING)
   else:
      tracer.info("onboarding successfully completed")
   return

# Used by "onboard" to set each provider instance,
# or by "provider add" to set a single provider instance
def addProvider(args: str = None,
                providerInstance: Dict[str, str] = None) -> bool:
   global ctx, tracer
   # If triggered directly via command-line (sapmon.py provider add)
   if args:
      providerInstance = {"name": args.name,
                          "type": args.type,
                          "properties": args.properties}

   instanceName = providerInstance.get("name", None)
   tracer.info("adding provider %s to KeyVault" % instanceName)
   providerType = providerInstance.get("type", None)
   providerPropertiesJson = providerInstance.get("properties", None)
   if not instanceName or not providerType or not providerProperties:
      tracer.error("provider incomplete; must have name, type and properties")
      return False
   try:
      providerProperties = json.loads(providerPropertiesJson)
   except json.decoder.JSONDecodeError as e:
      tracer.error("invalid JSON format (%s)" % e)
      return False

   # Instantiate provider, so we can run validation check
   try:
      providerClass = CLASSNAME_PROVIDER % p["type"]
      instance = eval(providerClass)(tracer,
                                         p["properties"])
   except Exception as e:
      tracer.critical("could not instantiate %s - wrong provider name? (%s)" % (providerClass,
                                                                                e))
      return False
   if not instance.validate():
      tracer.warning("validation check for provider instance %s failed" % instance.fullName)
      return False
   if not saveInstanceToConfig(p):
      tracer.error("could not save provider instance %s to KeyVault" % instance.fullName)
      return False
   return True

# Delete a single provider instance by name
def deleteProvider(args: str) -> None:
   global ctx, tracer
   tracer.critical("provider delete not yet implemented")
   return

# Execute the actual monitoring payload
def monitor(args: str) -> None:
   global ctx, tracer
   tracer.info("starting monitor payload")

   threads = []
   if not loadConfig():
      tracer.critical("failed to load config from KeyVault")
      sys.exit(ERROR_LOADING_CONFIG)

   logAnalyticsWorkspaceId = ctx.globalParams.get("LogAnalyticsWorkspaceId", None)
   logAnalyticsSharedKey = ctx.globalParams.get("LogAnalyticsSharedKey", None)
   if not logAnalyticsWorkspaceId or not logAnalyticsSharedKey:
      tracer.critical("global config must contain LogAnalyticsWorkspaceId and LogAnalyticsSharedKey")
      sys.exit(ERROR_GETTING_LOG_CREDENTIALS)
   ctx.azLa = AzureLogAnalytics(tracer,
                                logAnalyticsWorkspaceId,
                                logAnalyticsSharedKey)

   for i in ctx.instances:
      instanceName = i.get("name", None)
      providerType = i.get("type", None)
      providerProperties = i.get("properties", None)
      if not instanceName or not providerType or not providerProperties:
         tracer.critical("provider is missing name (%s), type (%s) or properties" % (instanceName,
                                                                                     providerType))
      try:
         providerClass = CLASSNAME_PROVIDER % providerType
         instance = eval(providerClass)(tracer,
                                        providerProperties)
      except Exception as e:
         tracer.critical("could not instantiate %s - wrong provider name? (%s)" % (providerClass,
                                                                                   e))
         continue
      thread = ProviderInstanceThread(instance)
      thread.start()
      threads.append(thread)

   for t in threads:
      t.join()

   tracer.info("monitor payload successfully completed")
   return

# prepareUpdate will prepare the resources like keyvault, log analytics etc for the version passed as an argument
# prepareUpdate needs to be run when a version upgrade requires specific update to the content of the resources
def prepareUpdate(args: str) -> None:
    global ctx, tracer
    tracer.info("Preparing for %s" % args.toVersion)
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
         sys.stderr.write("could not create required directory %s; please check permissions (%s)" % (path,
                                                                                                     e))
         sys.exit(ERROR_FILE_PERMISSION_DENIED)
   return

# Main function with argument parser
def main() -> None:
   def addVerboseToParser(p: argparse.ArgumentParser) -> None:
      p.add_argument("--verbose",
                     action = "store_true",
                     dest = "verbose",
                     help = "run in verbose mode")
      return

   global ctx, tracer

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
                          help = "JSON-formatted list of all provider instances")
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
   tracer = tracing.initTracer(args)
   ctx = Context(tracer, args.command)
   args.func(args)
   return

ctx = None
tracer = None
if __name__ == "__main__":
   main()

