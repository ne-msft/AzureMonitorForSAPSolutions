# Azure modules


# Python modules
import json
import logging

# Payload modules
from const import *
from helper.Azure import AzureKeyVault
from helper.tools import *
from helper.context import Context

###############################################################################

# Provide access to configuration (stored in customer KeyVault)
class ConfigHandler:
   globalPrefix = "Global"

   # Load configuration (global and providers) from customer KeyVault
	@staticmethod
	def loadConfig(tracer: logging.Logger,
		            ctx: Context)
      self.tracer.info("loading config from KeyVault")

      secrets = ctx.azKv.getCurrentSecrets()
      self.tracer.error("secrets = " % secrets)
      sys.exit()

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
