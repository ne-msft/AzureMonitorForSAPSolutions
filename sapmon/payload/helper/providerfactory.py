import logging
import sys

from provider.saphana import *

availableProviders = {
                        "saphana": (saphanaProviderInstance, saphanaProviderCheck)
                     }

class ProviderFactory(object):
   @staticmethod
   def makeProviderInstance(providerType: str,
                            tracer: logging.Logger,
                            instanceProperties: Dict[str, str],
                            **kwargs) -> ProviderInstance:
      if providerType in availableProviders:
         providerClass = availableProviders[providerType][0]
         return providerClass(tracer,
                              instanceProperties,
                              **kwargs)
      raise ValueError("unknown provider type %s" % providerType)

   @staticmethod
   def makeProviderCheck(providerType: str,
                         providerInstance: ProviderInstance,
                         **kwargs) -> ProviderCheck:
      if providerType in availableProviders:
         checkClass = availableProviders[providerType][1]
         return checkClass(providerInstance,
                           **kwargs)
      raise ValueError("unknown provider type %s" % providerType)
