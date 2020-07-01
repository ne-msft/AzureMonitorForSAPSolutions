# Python modules
from abc import ABC, abstractmethod
from datetime import date, datetime, timedelta
import json
import logging
from retry.api import retry_call
from typing import Callable, Dict, List, Optional

# Payload modules
from const import *
from helper.context import *
from helper.tools import *

###############################################################################

# Abstract base class for an instance of a monitoring provider
class ProviderInstance(ABC):
   tracer = None
   ctx = None
   name = None
   fullName = None
   providerType = None
   providerProperties = {}
   metadata = {}
   checks = []
   state = {}
   retrySettings = {}
   
   def __init__(self,
                tracer: logging.Logger,
                ctx: Context,
                providerInstance: Dict[str, str],
                retrySettings: Dict[str, int],
                skipContent: bool = False):
      # This constructor gets called after the child class
      self.tracer = tracer
      self.ctx = ctx
      self.providerProperties = providerInstance["properties"]
      self.metadata = providerInstance["metadata"]
      self.name = providerInstance["name"]
      self.providerType = providerInstance["type"]
      self.fullName = "%s/%s" % (self.providerType, self.name)
      self.state = {}
      self.retrySettings = retrySettings
      if not self.parseProperties():
         raise ValueError("failed to parse properties of the provider instance")
      if not skipContent and not self.initContent():
         raise Exception("failed to initialize content")
      self.readState()

   # Read provider content file
   def initContent(self) -> bool:
      from helper.providerfactory import ProviderFactory

      self.tracer.info("[%s] initializing content for provider instance" % self.fullName)
      try:
         filename = os.path.join(PATH_CONTENT, "%s.json" % self.providerType)
         self.tracer.debug("filename=%s" % filename)
         with open(filename, "r") as file:
            data = file.read()
         jsonData = json.loads(data, object_hook=JsonDecoder.datetimeHook)
      except FileNotFoundError as e:
         self.tracer.warning("[%s] content file %s does not exist" % (self.fullName,
                                                                      filename))
         return False
      except Exception as e:
         self.tracer.error("[%s] could not read content file %s (%s)" % (self.fullName,
                                                                         filename,
                                                                         e))
         return False

      # Parse and instantiate the individual checks of the provider
      checks = jsonData.get("checks", [])
      self.checks = []
      for checkOptions in checks:
         try:
            self.tracer.info("[%s] instantiating check for provider type %s" % (self.fullName,
                                                                                self.providerType))
            self.tracer.debug("[%s] checkOptions=%s" % (self.fullName,
                                                        checkOptions))
            newCheck = ProviderFactory.makeProviderCheck(self.providerType,
                                                         self,
                                                         **checkOptions)
            self.checks.append(newCheck)
         except Exception as e:
            self.tracer.error("[%s] could not instantiate check for provider type %s (%s)" % (self.fullName,
                                                                                              self.providerType,
                                                                                              e))
      return True

   # Read most recent, provider-specific state from state file
   def readState(self) -> bool:
      self.tracer.info("[%s] reading state file for provider instance" % self.fullName)
      jsonData = {}

      # Parse JSON for all check states of this provider
      try:
         filename = os.path.join(PATH_STATE, "%s.state" % self.name)
         self.tracer.debug("[%s] filename=%s" % (self.fullName,
                                                 filename))
         with open(filename, "r") as file:
            data = file.read()
         jsonData = json.loads(data, object_hook=JsonDecoder.datetimeHook)
      except FileNotFoundError as e:
         self.tracer.warning("[%s] state file %s does not exist" % (self.fullName,
                                                                    filename))
         return False
      except Exception as e:
         self.tracer.error("[%s] could not read state file %s (%s)" % (self.fullName,
                                                                       filename,
                                                                       e))
         return False

      # Update global state for this provider
      self.state = jsonData.get("global", {})
      self.tracer.debug("[%s] global state=%s" % (self.fullName, str(self.state)))

      # Update state for each individual check of this provider
      checkStates = jsonData.get("checks", {})
      saveIsEnabled = None
      for check in self.checks:
         if "isEnabled" in check.state:
            saveIsEnabled = check.state["isEnabled"]
         check.state = checkStates.get(check.name, {})
         if saveIsEnabled is not None:
            check.state["isEnabled"] = saveIsEnabled
         self.tracer.debug("[%s] check state=%s" % (check.fullName, str(check.state)))
      self.tracer.info("[%s] successfully read state file for provider instance" % self.fullName)
      return True

   # Write current state for this provider and its checks into state file
   def writeState(self) -> bool:
      self.tracer.info("[%s] writing state file for provider instance" % self.fullName)

      # Initialize JSON object with global state
      jsonData = {
         "global": self.state
      }

      # Build dictionary with states for all checks of this provider and insert it into JSON object
      checkStates = {}
      for check in self.checks:
         checkStates[check.name] = check.state
      jsonData["checks"] = checkStates

      # Write JSON object into state file
      try:
         filename = os.path.join(PATH_STATE, "%s.state" % self.name)
         self.tracer.debug("[%s] filename=%s" % (self.fullName,
                                                 filename))
         with open(filename, "w") as file:
            json.dump(jsonData, file, indent=3, cls=JsonEncoder)
      except Exception as e:
         self.tracer.error("[%s] could not write state file %s (%s)" % (self.fullName,
                                                                        filename,
                                                                        e))
         return False

      self.tracer.info("[%s] successfully wrote state file for provider instance" % self.fullName)
      return True

   # Provider-specific validation logic (e.g. establish HANA connection)
   @abstractmethod
   def validate(self) -> bool:
      pass

   # Provider-specific additional parsing logic (e.g. extract password from KeyVault)
   @abstractmethod
   def parseProperties(self) -> bool:
      pass

###############################################################################

# Base class for a check as part of a monitoring provider
class ProviderCheck(ABC):
   providerInstance = None
   name = None
   description = None
   customLog = None
   frequencySecs = None
   includeInCustomerAnalytics = False
   actions = []
   state = {}
   fullName = None
   tracer = None
   colTimeGenerated = None

   def __init__(self,
                providerInstance: ProviderInstance,
                name: str,
                description: str,
                customLog: str,
                frequencySecs: int,
                actions: List[str],
                includeInCustomerAnalytics: bool = False,
                enabled: bool = True):
      self.providerInstance = providerInstance
      self.name = name
      self.description = description
      self.customLog = customLog
      self.frequencySecs = frequencySecs
      self.includeInCustomerAnalytics = includeInCustomerAnalytics
      self.actions = actions
      self.state = {
         "isEnabled": enabled,
         "lastRunLocal": None
      }
      self.fullName = "%s.%s" % (self.providerInstance.fullName, self.name)
      self.tracer = providerInstance.tracer

   # Return if this check is enabled or not
   def isEnabled(self) -> bool:
      self.tracer.debug("[%s] verifying if check is enabled" % self.fullName)
      if not self.state["isEnabled"]:
         self.tracer.info("[%s] check is currently not enabled, skipping" % self.fullName)
         return False
      return True

   # Determine if this check is due to be executed
   def isDue(self) -> bool:
      # lastRunLocal = last execution time on collector VM
      # lastRunServer (used in provider) = last execution time on (HANA) server
      self.tracer.debug("[%s] verifying if check is due to be run" % self.fullName)
      lastRunLocal = self.state.get("lastRunLocal", None)
      self.tracer.debug("[%s] lastRunLocal=%s; frequencySecs=%d; currentLocal=%s" % (self.fullName,
                                                                                     lastRunLocal,
                                                                                     self.frequencySecs,
                                                                                     datetime.utcnow()))
      if lastRunLocal and \
         lastRunLocal + timedelta(seconds = self.frequencySecs) > datetime.utcnow():
         self.tracer.info("[%s] check is not due yet, skipping" % self.fullName)
         return False
      return True

   # Method that gets called when this check is executed
   # Returns a JSON-formatted string that can be ingested into Log Analytics
   def run(self) -> str:
      self.tracer.info("[%s] executing all actions of check" % self.fullName)
      self.tracer.debug("[%s] actions=%s" % (self.fullName,
                                             self.actions))
      for action in self.actions:
         methodName = METHODNAME_ACTION % action["type"]
         parameters = action.get("parameters", {})
         self.tracer.debug("[%s] calling action %s" % (self.fullName,
                                                       methodName))
         method = getattr(self, methodName)
         tries = action.get("retries", self.providerInstance.retrySettings["retries"])
         delay = action.get("delayInSeconds", self.providerInstance.retrySettings["delayInSeconds"])
         backoff = action.get("backoffMultiplier", self.providerInstance.retrySettings["backoffMultiplier"])

         try :
            retry_call(method, fkwargs=parameters, tries=tries, delay=delay, backoff=backoff, logger=self.tracer)
         except Exception as e:
            self.tracer.error("[%s] error executing action %s, Exception %s, skipping remaining actions" % (self.fullName,
                                                                                                            methodName,
                                                                                                            e))
            break
      return self.generateJsonString()

   # Method to generate a JSON object that can be ingested into Log Analytics
   @abstractmethod
   def generateJsonString(self) -> str:
      return

   # Method that gets called when the internal state is updated
   @abstractmethod
   def updateState(self):
      pass
