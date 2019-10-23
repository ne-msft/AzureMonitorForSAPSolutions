# Python modules
from abc import ABC, abstractmethod
import logging

###############################################################################

# Base class for all SAP Monitor checks
class SapmonCheck(ABC):
   description = None
   customLog = None
   frequencySecs = None
   name = None
   state = {}
   tracer = None
   version = None

   def __init__(self,
                tracer: logging.Logger,
                version: str,
                name: str,
                description: str,
                customLog: str,
                frequencySecs: int,
                enabled: bool = True):
      self.tracer = tracer
      self.version = version
      self.name = name
      self.description = description
      self.customLog = customLog
      self.frequencySecs = frequencySecs
      self.state = {
         "isEnabled":    enabled,
         "lastRunLocal": None
      }

   # Method that gets called when this check is executed
   @abstractmethod
   def run(self):
      pass

   # Method that gets called when the internal state is updated
   @abstractmethod
   def updateState(self):
      pass
