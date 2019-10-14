from abc import ABC, abstractmethod

###############################################################################

class SapmonCheck(ABC):
   """
   Implements a monitoring check inside SAP Monitor
   """
   version       = ""
   name          = ""
   description   = ""
   customLog     = ""
   frequencySecs = 0
   state         = {}
   logger        = None
   def __init__(self, logger, version, name, description, customLog, frequencySecs, enabled=True):
      self.logger        = logger
      self.version       = version
      self.name          = name
      self.description   = description
      self.customLog     = customLog
      self.frequencySecs = frequencySecs
      self.state         = {
         "isEnabled":    enabled,
         "lastRunLocal": None,
      }

   @abstractmethod
   def run(self):
      pass

   @abstractmethod
   def updateState(self):
      pass
