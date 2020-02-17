# Azure modules


# Python modules
import json
import logging
import sys

# Payload modules
from const import *
from helper.azure import AzureKeyVault
from helper.tools import *
from helper.context import Context
from typing import Callable, Dict, List

###############################################################################

# Provide access to configuration (stored in customer KeyVault)
class ConfigHandler:
   sectionGlobal = "global"

   # Load configuration (global and providers) from customer KeyVault
   @staticmethod
   def loadConfig(tracer: logging.Logger,
                  ctx: Context) -> (Dict[str, str], List[Dict[str, str]]):
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
         if secretName == ConfigHandler.sectionGlobal:
            globalParams = instanceProperties
         else:
            parts = secretName.split("-")
            if len(parts) != 2:
               tracer.error("invalid secret name (should be provider-name): %s" % (secretName))
               continue
            providerType, instanceName = parts[0], parts[1]
            if not providerType in ctx.availableProviders:
               tracer.error("unknown provider type %s (available types: %s)" % (providerType, list(ctx.availableProviders.keys())))
               continue
            provider = ctx.availableProviders[providerType]
            instance = {"type": providerType,
                        "name": instanceName,
                        "properties": instanceProperties}
            instances.append(instance)
            
      print("globalParams = %s" % globalParams)
      print("instances = %s" % instances)
      return (globalParams, instances)

   # Save global parameters to customer KeyVault
   @staticmethod
   def saveGlobalConfig(tracer: logging.Logger,
                        ctx: Context) -> bool:
      tracer.info("saving global parameters to customer KeyVault")
      return ctx.azKv.setSecret(ConfigHandler.sectionGlobal,
                                ctx.globalParams)

   # Save specific instance properties to customer KeyVault
   @staticmethod
   def saveInstanceToConfig(tracer: logging.Logger,
                            ctx: Context,
                            instance: Dict) -> bool:
      if ("name" not in instance) or \
         ("type" not in instance) or \
         ("properties" not in instance):
         tracer.error("instance to save is missing name, type or properties")
         return False
      instanceName = instance["name"]
      tracer.info("saving instance %s to customer KeyVault" % instanceName)
      providerType = instance["type"]
      if not providerType in ctx.availableProviders:
         tracer.error("unknown provider type %s (available types: %s)" % (providerType, list(ctx.availableProviders.keys())))
         return False
      instanceProperties = instance["properties"]
      try:
         secretValue = json.dumps(instanceProperties)
      except json.decoder.JSONEncodeError as e:
         tracer.error("cannot JSON encode instance properties (%s)" % e)
         return False   
      secretName = "%s-%s" % (providerType, instanceName)
      return ctx.azKv.setSecret(secretName,
                                secretValue)

   # Load configuration (global and providers) from customer KeyVault
   @staticmethod
   def loadConfigX(tracer: logging.Logger,
                  ctx: Context) -> (Dict[str, str], List[Dict[str, str]]):      
      return
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
