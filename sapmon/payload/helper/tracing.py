# Azure modules
from azure.mgmt.storage import StorageManagementClient
from azure_storage_logging.handlers import QueueStorageHandler

# Python modules
import argparse
from collections import OrderedDict
import json
import logging
import logging.config
from typing import Callable, Dict, Optional

# Payload modules
from const import *
from helper.azure import *

# Formats a log/trace payload as JSON-formatted string
class JsonFormatter(logging.Formatter):
   def __init__(self,
                fieldMapping: Dict[str, str] = {},
                datefmt: Optional[str] = None,
                customJson: Optional[json.JSONEncoder] = None):
      logging.Formatter.__init__(self, None, datefmt)
      self.fieldMapping = fieldMapping
      self.customJson = customJson

   # Overridden from the parent class to look for the asctime attribute in the fields attribute
   def usesTime(self) -> bool:
      return "asctime" in self.fieldMapping.values()

   # Formats time using a specific date format
   def _formatTime(self,
                   record: logging.LogRecord) -> None:
      if self.usesTime():
         record.asctime = self.formatTime(record, self.datefmt)

   # Combines any supplied fields with the log record msg field into an object to convert to JSON
   def _getJsonData(self,
                    record: logging.LogRecord) -> OrderedDict():
      if len(self.fieldMapping.keys()) > 0:
         # Build a temporary list of tuples with the actual content for each field
         jsonContent = []
         for f in sorted(self.fieldMapping.keys()):
            jsonContent.append((f, getattr(record, self.fieldMapping[f])))
         jsonContent.append(("msg", record.msg))

         # An OrderedDict is used to ensure that the converted data appears in the same order for every record
         return OrderedDict(jsonContent)
      else:
         return record.msg

   # Overridden from the parent class to take a log record and output a JSON-formatted string
   def format(self,
              record: logging.LogRecord) -> str:
      self._formatTime(record)
      jsonData = self._getJsonData(record)
      formattedJson = json.dumps(jsonData, cls=self.customJson)
      return formattedJson

# Helper class to enable all kinds of tracing
class tracing:
   config = {
       "version": 1,
       "disable_existing_loggers": True,
       "formatters": {
           "json": {
               "class": "helper.tracing.JsonFormatter",
               "fieldMapping": {
                   "pid": "process",
                   "timestamp": "asctime",
                   "traceLevel": "levelname",
                   "module": "filename",
                   "lineNum": "lineno",
                   "function": "funcName",
                   # Custom (payload-specific) fields below
                   "payloadVersion": "payloadversion",
                   "sapmonId": "sapmonid"
               }
           },
           "detailed": {
               "format": "[%(process)d] %(asctime)s %(levelname).1s %(filename)s:%(lineno)d %(message)s"
           },
           "simple": {
               "format": "%(levelname)-8s %(message)s"
           }
       },
       "handlers": {
           "consolex": {
               "class": "logging.StreamHandler",
               "formatter": "simple",
               "level": DEFAULT_CONSOLE_TRACE_LEVEL
           },
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
   def addQueueLogHandler(
           tracer: logging.Logger,
           ctx) -> None:

      # Provide access to custom (payload-specific) fields
      oldFactory = logging.getLogRecordFactory()
      def recordFactory(*args, **kwargs):
         record = oldFactory(*args, **kwargs)
         record.sapmonid = ctx.sapmonId
         record.payloadversion = PAYLOAD_VERSION
         return record
      tracer.info("adding storage queue log handler")
      try:
         storageQueue = AzureStorageQueue(tracer,
                                          sapmonId = ctx.sapmonId,
                                          msiClientID = ctx.vmTags.get("SapMonMsiClientId", None),
                                          subscriptionId = ctx.vmInstance["subscriptionId"],
                                          resourceGroup = ctx.vmInstance["resourceGroupName"],
                                          queueName = STORAGE_QUEUE_NAMING_CONVENTION % ctx.sapmonId)
         storageKey = storageQueue.getAccessKey()
         queueStorageLogHandler = QueueStorageHandler(account_name=storageQueue.accountName,
                                                      account_key = storageKey,
                                                      protocol = "https",
                                                      queue = storageQueue.name)
         queueStorageLogHandler.level = DEFAULT_QUEUE_TRACE_LEVEL
         jsonFormatter = JsonFormatter(tracing.config["formatters"]["json"]["fieldMapping"])
         queueStorageLogHandler.setFormatter(jsonFormatter)
         logging.setLogRecordFactory(recordFactory)

      except Exception as e:
         tracer.error("could not add handler for the storage queue logging (%s) " % e)
         return

      queueStorageLogHandler.level = DEFAULT_QUEUE_TRACE_LEVEL
      tracer.addHandler(queueStorageLogHandler)
      return

   # Initialize customer metrics tracer object
   @staticmethod
   def initCustomerMetricsTracer(
           tracer: logging.Logger,
           ctx) -> logging.Logger:
       tracer.info("creating customer metrics tracer object")
       try:
           storageQueue = AzureStorageQueue(tracer,
                                            sapmonId = ctx.sapmonId,
                                            msiClientID = ctx.vmTags.get("SapMonMsiClientId", None),
                                            subscriptionId = ctx.vmInstance["subscriptionId"],
                                            resourceGroup = ctx.vmInstance["resourceGroupName"],
                                            queueName = CUSTOMER_METRICS_QUEUE_NAMING_CONVENTION % ctx.sapmonId)
           storageKey = storageQueue.getAccessKey()
           customerMetricsLogHandler = QueueStorageHandler(account_name=storageQueue.accountName,
                                                           account_key = storageKey,
                                                           protocol = "https",
                                                           queue = storageQueue.name)
       except Exception as e:
           tracer.error("could not add handler for the storage queue logging (%s) " % e)
           return

       logger = logging.getLogger("customerMetricsLogger")
       logger.addHandler(customerMetricsLogHandler)
       return logger

