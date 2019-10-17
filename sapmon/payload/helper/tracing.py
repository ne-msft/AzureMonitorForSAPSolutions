# Azure modules
from azure.mgmt.storage import StorageManagementClient
from azure_storage_logging.handlers import QueueStorageHandler

# Python modules
import argparse
import logging
import logging.config
from typing import Callable, Dict, Optional

# Payload modules
from const import *
from helper.azure import *

# Helper class to enable all kinds of tracing
class tracing:
   config = {
       "version": 1,
       "disable_existing_loggers": True,
       "formatters": {
           "detailed": {
               "format": "[%(process)d] %(asctime)s %(levelname).1s %(filename)s:%(lineno)d %(message)s"
           },
           "simple": {
               "format": "%(levelname)-8s %(message)s"
           }
       },
       "handlers": {
           "console": {
               "class": "logging.StreamHandler",
               "formatter": "simple",
               "level": DEFAULT_CONSOLE_TRACE_LEVEL
           },
           "file": {
               "class": "logging.handlers.RotatingFileHandler",
               "formatter": "detailed",
               "level": DEFAULT_FILE_TRACE_LEVEL,
               "filename": FILENAME_TRACE,
               "maxBytes": 10000000,
               "backupCount": 10
           },
       },
       "root": {
           "level": logging.DEBUG,
           "handlers": ["console", "file"]
       }
   }

   # Initialize the tracer object
   @staticmethod
   def initTracer(args: argparse.Namespace) -> logging.Logger:
      if args.verbose:
         tracing.config["handlers"]["console"]["formatter"] = "detailed"
         tracing.config["handlers"]["console"]["level"] = logging.DEBUG
      logging.config.dictConfig(tracing.config)
      return logging.getLogger(__name__)

   # Add a storage queue log handler to an existing tracer
   @staticmethod
   def addQueueLogHandler(tracer: logging.Logger,
                          ctx) -> None:
      tracer.info("adding storage queue log handler")
      try:
         storageQueue = AzureStorageQueue(tracer,
                                          sapmonId = ctx.sapmonId,
                                          msiClientID = ctx.vmTags.get("SapMonMsiClientId", None),
                                          subscriptionId = ctx.vmInstance["subscriptionId"],
                                          resourceGroup = ctx.vmInstance["resourceGroupName"])
         storageKey = storageQueue.getAccessKey()
         queueStorageLogHandler = QueueStorageHandler(account_name=storageQueue.accountName,
                                                      account_key = storageKey,
                                                      protocol = "https",
                                                      queue = storageQueue.name)
         queueStorageLogHandler.level = DEFAULT_QUEUE_TRACE_LEVEL
         formatter = logging.Formatter(tracing.config["formatters"]["detailed"]["format"])
         queueStorageLogHandler.setFormatter(formatter)
      except Exception as e:
         tracer.error("could not add handler for the storage queue logging (%s) " % e)
         return

      tracer.addHandler(queueStorageLogHandler)
      return
