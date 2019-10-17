from azure.mgmt.storage import StorageManagementClient
from azure_storage_logging.handlers import QueueStorageHandler
from helper.azure import *
from const import *
import logging
import logging.config

class tracing:
   config = {
       "version": 1,
       "disable_existing_loggers": True,
       "formatters": {
           "detailed": {
               "format": "[%(process)d] %(asctime)s %(levelname).1s %(filename)s:%(lineno)d %(message)s",
           },
           "simple": {
               "format": "%(levelname)-8s %(message)s",
           }
       },
       "handlers": {
           "console": {
               "class": "logging.StreamHandler",
               "formatter": "simple",
               "level": DEFAULT_CONSOLE_TRACE_LEVEL,
           },
           "file": {
               "class": "logging.handlers.RotatingFileHandler",
               "formatter": "detailed",
               "level": DEFAULT_FILE_TRACE_LEVEL,
               "filename": FILENAME_TRACE,
               "maxBytes": 10000000,
               "backupCount": 10,
           },
       },
       "root": {
           "level": logging.DEBUG,
           "handlers": ["console", "file"],
       }
   }

   @staticmethod
   def initTracer(args):
      """
      Initialize the tracer object
      """
      if args.verbose:
         tracing.config["handlers"]["console"]["formatter"] = "detailed"
         tracing.config["handlers"]["console"]["level"] = logging.DEBUG
      logging.config.dictConfig(tracing.config)
      return logging.getLogger(__name__)

   @staticmethod
   def addQueueLogHandler(tracer, ctx):
      try:
         storageQueue = AzureStorageQueue(
            tracer,
            sapmonId = ctx.sapmonId,
            msiClientID = ctx.vmTags.get("SapMonMsiClientId", None),
            subscriptionId = ctx.vmInstance["subscriptionId"],
            resourceGroup = ctx.vmInstance["resourceGroupName"]
            )
         storageKey = storageQueue.getAccessKey()
         queueStorageLogHandler = QueueStorageHandler(
         	account_name=storageQueue.accountName,
            account_key = storageKey,
            protocol = "https",
            queue = storageQueue.name
            )
         queueStorageLogHandler.level = DEFAULT_QUEUE_TRACE_LEVEL
         formatter = logging.Formatter(tracing.config["formatters"]["detailed"]["format"])
         queueStorageLogHandler.setFormatter(formatter)
      except Exception as e:
         tracer.error("could not add handler for the storage queue logging (%s) " % e)
         return
      tracer.addHandler(queueStorageLogHandler)
      return

