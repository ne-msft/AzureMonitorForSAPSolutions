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
   tracer        = None
   def __init__(self, tracer, version, name, description, customLog, frequencySecs, enabled=True):
      self.tracer        = tracer
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
