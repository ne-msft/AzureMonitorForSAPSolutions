# Python modules
from abc import ABC, abstractmethod
import logging

# Payload modules
from const import *

###############################################################################

class SapmonContentProvider:
   tracer = None
   name = None
   version = None
   checks = []
   def __init__(self,
                tracer: logging.Logger,
                filename: str):
      self.tracer = tracer
      if not self.initContent(filename):
         return None
      self.readState()

   # Read content from provider definition
   def initContent(filename: str) -> bool:
      try:
         with open(filename, "r") as file:
            data = file.read()
         jsonData = json.loads(data)
      except Exception as e:
         self.tracer.error("could not load content file %s (%s)" % (filename, e))
         return False

      self.name = jsonData.get("providerName", None)
      if not self.name:
         self.tracer.error("provider name not specified in content file %s" % filename)
         return False
      self.version = jsonData.get("contentVersion", None)
      if not self.version:
         self.tracer.error("content version not specified in content file %s" % filename)
         return False
      self.checkType = jsonData.get("checkType", None)
      if not self.checkType:
         self.tracer.error("check type not specified in content file %s" % filename)
         return False

      checks = jsonData.get("checks", [])
      for checkOptions in checks:
         try:
            self.tracer.info("instantiate check of type %s" % self.checkType)
            self.tracer.debug("checkOptions=%s" % checkOptions)
            checkOptions["provider"] = self
            check = eval(self.checkType)(**checkOptions)
            self.checks.append(check)
         except Exception as e:
            self.tracer.error("could not instantiate new check of type %s (%s)" % (self.checkType, e))

   # Read most recent, provider-specific state from state file
   def readState(self) -> bool:
      self.tracer.info("reading state file for content provider %s" % self.name)
      jsonData = {}

      # Parse JSON for all check states for this provider
      try:
         filename = os.path.join(PATH_STATE, "%s.state" % self.name)
         self.tracer.debug("filename=%s" % filename)
         with open(FILENAME_STATEFILE, "r") as file:
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
      for check in self.checks:
         check.state = checkStates.get(check.name, {})
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
      self.name = name
      self.description = description
      self.customLog = customLog
      self.frequencySecs = frequencySecs
      self.actions = actions
      self.state = {
         "isEnabled":    enabled,
         "lastRunLocal": None
      }

   # Method that gets called when this check is executed
   def run(self):
      self.provider.tracer.info("executing check %s" % self.name)
      self.provider.tracer.debug("actions=%s" % self.actions)
      for a in self.actions:
         action = getattr(self, a)
         action()

   # Method that gets called when the internal state is updated
   @abstractmethod
   def updateState(self):
      pass
