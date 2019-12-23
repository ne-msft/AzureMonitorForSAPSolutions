# Python modules
from abc import ABC, abstractmethod
from datetime import date, datetime, timedelta
import json
import logging
from typing import Callable, Dict, List, Optional

# Payload modules
from const import *
from helper.tools import *

###############################################################################

# Base class for all SAP Monitor content providers
class SapmonContentProvider:
   tracer = None
   name = None
   version = None
   checks = []
   state = {}
   secrets = {}

   def __init__(self,
                tracer: logging.Logger,
                contentFullPath: str):
      self.readState()

   # Read most recent, provider-specific state from state file
   def readState(self) -> bool:
      self.tracer.info("reading state file for content provider %s" % self.name)
      jsonData = {}

      # Parse JSON for all check states of this provider
      try:
         filename = os.path.join(PATH_STATE, "%s.state" % self.name)
         self.tracer.debug("filename=%s" % filename)
         with open(filename, "r") as file:
            data = file.read()
         jsonData = json.loads(data, object_hook=JsonDecoder.datetimeHook)
      except FileNotFoundError as e:
         self.tracer.warning("state file %s does not exist" % filename)
         return False
      except Exception as e:
         self.tracer.error("could not read state file %s (%s)" % (filename, e))
         return False

      # Update global state for this provider
      self.state = jsonData.get("global", {})
      self.tracer.debug("global state for content provider %s=%s" % (self.name, str(self.state)))

      # Update state for each individual check of this provider
      checkStates = jsonData.get("checks", {})
      saveIsEnabled = None
      for check in self.checks:
         if "isEnabled" in check.state:
            saveIsEnabled = check.state["isEnabled"]
         check.state = checkStates.get(check.name, {})
         if saveIsEnabled is not None:
            check.state["isEnabled"] = saveIsEnabled
         self.tracer.debug("state for check %s=%s" % (check.name, str(check.state)))
      self.tracer.info("successfully read state file for content provider %s" % self.name)
      return True
      
   # Write current state for this provider and its checks into state file
   def writeState(self) -> bool:
      self.tracer.info("writing state file for content provider %s" % self.name)

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
         self.tracer.debug("filename=%s" % filename)
         with open(filename, "w") as file:
            json.dump(jsonData, file, indent=3, cls=JsonEncoder)
      except Exception as e:
         self.tracer.error("could not write state file %s (%s)" % (FILENAME_STATEFILE, e))
         return False

      self.tracer.info("successfully wrote state file for content provider %s" % self.name)
      return True

###############################################################################

# Base class for all SAP Monitor checks
class SapmonCheck(ABC):
   provider = None
   name = None
   description = None
   customLog = None
   frequencySecs = None
   actions = []
   state = {}

   def __init__(self,
                provider: SapmonContentProvider,
                name: str,
                description: str,
                customLog: str,
                frequencySecs: int,
                actions: List[str],
                enabled: bool = True):
      self.provider = provider
      self.tracer = provider.tracer
      self.name = name
      self.description = description
      self.customLog = customLog
      self.frequencySecs = frequencySecs
      self.actions = actions
      self.state = {
         "isEnabled": enabled,
         "lastRunLocal": None
      }

   # Return if this check is enabled or not
   def isEnabled(self) -> bool:
      self.tracer.info("verifying if check %s.%s is enabled" % (self.provider.name, self.name))
      if not self.state["isEnabled"]:
         self.tracer.info("check %s.%s is currently not enabled, skipping" % (self.provider.name, self.name))
         return False
      return True

   # Determine if this check is due to be executed
   def isDue(self) -> bool:
      # lastRunLocal = last execution time on collector VM
      # lastRunServer (used in provider) = last execution time on (HANA) server
      self.tracer.info("verifying if check %s.%s is due to be run" % (self.provider.name, self.name))
      lastRunLocal = self.state["lastRunLocal"]
      self.tracer.debug("lastRunLocal=%s; frequencySecs=%d; currentLocal=%s" % \
         (lastRunLocal, self.frequencySecs, datetime.utcnow()))
      if lastRunLocal and \
         lastRunLocal + timedelta(seconds = self.frequencySecs) > datetime.utcnow():
         self.tracer.info("check %s.%s is not due yet, skipping" % (self.provider.name, self.name))
         return False
      return True

   # Method that gets called when this check is executed
   # Returns a JSON-formatted string that can be ingested into Log Analytics
   def run(self) -> str:
      self.tracer.info("executing all actions of check %s.%s" % (self.provider.name, self.name))
      self.tracer.debug("actions=%s" % self.actions)
      for action in self.actions:
         methodName = action["type"]
         parameters = action.get("parameters", {})
         self.tracer.debug("calling action %s" % methodName)
         method = getattr(self, methodName)
         if method(**parameters) == False:
            self.tracer.info("error while executing check %s.%s (action %s), skipping remaining actions" % (self.provider.name, self.name, methodName))
      return self._generateJsonString()

   # Method that gets called when the internal state is updated
   @abstractmethod
   def _updateState(self):
      pass

   # Method to generate a JSON-encoded string containing the result
   # (This string will be ingested into Log Analytics and Customer Analytics)
   @abstractmethod
   def _generateJsonString(self) -> str:
      pass
