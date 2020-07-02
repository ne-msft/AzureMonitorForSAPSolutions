import logging
import sys

from helper.context import *
from provider.saphana import *
from provider.prometheus import *
from provider.sqlserver import *

availableProviders = {
                        "SapHana": (saphanaProviderInstance, saphanaProviderCheck),
                        "MsSqlServer": (MSSQLProviderInstance, MSSQLProviderCheck),
                        "PrometheusGeneric": (prometheusProviderInstance, prometheusProviderCheck),
                        "PrometheusHaCluster": (prometheusProviderInstance, prometheusProviderCheck),
                        "PrometheusNode": (prometheusProviderInstance, prometheusProviderCheck)
                     }

class ProviderFactory(object):
   @staticmethod
   def makeProviderInstance(providerType: str,
                            tracer: logging.Logger,
                            ctx: Context,
                            instanceProperties: Dict[str, str],
                            **kwargs) -> ProviderInstance:
      if providerType in availableProviders:
         providerClass = availableProviders[providerType][0]
         return providerClass(tracer,
                              ctx,
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
