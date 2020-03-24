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
import traceback

# Payload modules
from const import *
from helper.azure import *
from helper.context import Context
from helper.tools import *
from helper.tracing import *
from helper.providerfactory import *
from helper.updateprofile import *
from helper.updatefactory import *

###############################################################################

class ProviderInstanceThread(threading.Thread):
   def __init__(self, providerInstance):
      threading.Thread.__init__(self)
      self.providerInstance = providerInstance

   def run(self):
      global ctx, tracer
      for check in self.providerInstance.checks:
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
         if enableCustomerAnalytics and check.includeInCustomerAnalytics:
             tracing.ingestCustomerAnalytics(tracer,
                                             ctx,
                                             check.customLog,
                                             resultJson)
         tracer.info("finished check %s" % (check.fullName))
      return

###############################################################################

# Load entire config from KeyVault (global parameters and provider instances)
def loadConfig() -> bool:
   global ctx, tracer
   tracer.info("loading config from KeyVault")

   secrets = ctx.azKv.getCurrentSecrets()
   for secretName in secrets.keys():
      tracer.debug("parsing KeyVault secret %s" % secretName)
      secretValue = secrets[secretName]
      try:
         providerProperties = json.loads(secretValue)
      except json.decoder.JSONDecodeError as e:
         tracer.error("invalid JSON format for secret %s (%s)" % (secretName,
                                                                  e))
         continue
      if secretName == CONFIG_SECTION_GLOBAL:
         ctx.globalParams = providerProperties
      else:
         parts = secretName.split("-")
         if len(parts) < 2:
            tracer.error("invalid secret name (should be: provider-name): %s" % (secretName))
            continue
         providerType, instanceName = parts[0], parts[1]
         instanceProperties = {"type": providerType,
                               "name": instanceName,
                               "properties": providerProperties}
         try:
            providerInstance = ProviderFactory.makeProviderInstance(providerType,
                                                                    tracer,
                                                                    instanceProperties,
                                                                    skipContent = False)
         except Exception as e:
            tracer.error("could not validate provider instance %s (%s)" % (instanceName,
                                                                           e))
            continue
         ctx.instances.append(providerInstance)
   if ctx.globalParams == {} or len(ctx.instances) == 0:
      return False
   return True

# Save specific instance properties to customer KeyVault
def saveInstanceToConfig(instance: Dict[str, str]) -> bool:
   global ctx, tracer
   instanceName = instance.get("name", None)
   providerType = instance.get("type", None)
   providerProperties = instance.get("properties", None)
   if not instanceName or not providerType or not providerProperties:
      tracer.error("instance to save is missing name, type or properties")
      return False
   tracer.info("saving instance %s to customer KeyVault" % instanceName)
   try:
      secretValue = json.dumps(providerProperties)
   except json.encoder.JSONEncodeError as e:
      tracer.error("cannot JSON encode instance properties (%s)" % e)
      return False   
   secretName = KV_SECRET_FORMAT % (providerType, instanceName)
   result = ctx.azKv.setSecret(secretName, secretValue)
   return result

# Store credentials in the customer KeyVault
# (To be executed as custom script upon initial deployment of collector VM)
def onboard(args: str) -> None:
   global ctx, tracer
   tracer.info("starting onboarding")

   # Update global parameters and save them to KeyVault
   ctx.globalParams = {"logAnalyticsWorkspaceId": args.logAnalyticsWorkspaceId,
                       "logAnalyticsSharedKey": args.logAnalyticsSharedKey,
                       "enableCustomerAnalytics": args.enableCustomerAnalytics}
   if not ctx.azKv.setSecret(CONFIG_SECTION_GLOBAL,
                             json.dumps(ctx.globalParams)):
      tracer.critical("could not save global config to KeyVault")
      sys.exit(ERROR_SETTING_KEYVAULT_SECRET)

   tracer.info("onboarding successfully completed")
   return

# Used by "onboard" to set each provider instance,
# or by "provider add" to set a single provider instance
def addProvider(args: str = None,
                instanceProperties: Dict[str, str] = None) -> None:
   global ctx, tracer
   # If triggered directly via command-line (sapmon.py provider add)
   if args:
      instanceProperties = {"name": args.name,
                            "type": args.type}
      try:
         instanceProperties["properties"] = json.loads(args.properties)
      except json.decoder.JSONDecodeError as e:
         tracer.error("invalid JSON format (%s)" % e)
         return False

   instanceName = instanceProperties.get("name", None)
   providerType = instanceProperties.get("type", None)
   providerProperties = instanceProperties.get("properties", None)
   tracer.info("trying to add new provider instance (name=%s, type=%s)" % (instanceName,
                                                                           providerType))
   if not instanceName or not providerType or not providerProperties:
      tracer.error("provider incomplete; must have name, type and properties")
      sys.exit(ERROR_ADDING_PROVIDER)

   # Instantiate provider, so we can run validation check
   try:
      newProviderInstance = ProviderFactory.makeProviderInstance(providerType,
                                                                 tracer,
                                                                 instanceProperties,
                                                                 skipContent = True)
   except Exception as e:
      tracer.critical("could not instantiate %s (%s)" % (providerType,
                                                         e))
      sys.exit(ERROR_ADDING_PROVIDER)

   if not newProviderInstance.validate():
      tracer.critical("validation check for provider instance %s failed" % newProviderInstance.fullName)
      sys.exit(ERROR_ADDING_PROVIDER)
   if not saveInstanceToConfig(instanceProperties):
      tracer.error("could not save provider instance %s to KeyVault" % newProviderInstance.fullName)
      sys.exit(ERROR_ADDING_PROVIDER)
   tracer.info("successfully added provider instance %s to KeyVault" % newProviderInstance.fullName)
   return

# Delete a single provider instance by name
def deleteProvider(args: str) -> None:
   global ctx, tracer
   tracer.info("retrieving provider list from KeyVault")

   providerToDelete = args.name.lower()
   secrets = ctx.azKv.getCurrentSecrets()
   # Get a dictionary with provider instance names and their corresponding secret names
   providerSecrets = {k.split("-")[1].lower(): k for k in iter(secrets.keys()) if k.find("-") > 0}

   if providerToDelete not in providerSecrets:
      tracer.error("provider instance %s not found in KeyVault" % providerToDelete)
      sys.exit(ERROR_DELETING_PROVIDER)
   secretToDelete = providerSecrets[providerToDelete]

   if not ctx.azKv.kv_client.deleteSecret(secretToDelete):
      tracer.error("error deleting KeyVault secret %s" % secretToDelete)
      sys.exit(ERROR_DELETING_PROVIDER)

   tracer.info("provider %s successfully deleted from KeyVault" % providerToDelete)
   return

# Execute the actual monitoring payload
def monitor(args: str) -> None:
   global ctx, tracer
   tracer.info("starting monitor payload")

   threads = []
   if not loadConfig():
      tracer.critical("failed to load config from KeyVault")
      sys.exit(ERROR_LOADING_CONFIG)
   logAnalyticsWorkspaceId = ctx.globalParams.get("logAnalyticsWorkspaceId", None)
   logAnalyticsSharedKey = ctx.globalParams.get("logAnalyticsSharedKey", None)
   if not logAnalyticsWorkspaceId or not logAnalyticsSharedKey:
      tracer.critical("global config must contain logAnalyticsWorkspaceId and logAnalyticsSharedKey")
      sys.exit(ERROR_GETTING_LOG_CREDENTIALS)
   ctx.azLa = AzureLogAnalytics(tracer,
                                logAnalyticsWorkspaceId,
                                logAnalyticsSharedKey)
   for i in ctx.instances:
      thread = ProviderInstanceThread(i)
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
   onbParser.add_argument("--enableCustomerAnalytics",
                          required = False,
                          help = "Setting to enable sending metrics to Microsoft",
                          action = "store_true",
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

