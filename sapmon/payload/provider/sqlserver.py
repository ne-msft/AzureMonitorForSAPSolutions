# Python modules
import hashlib
import json
import logging
import re
import time
import pyodbc

# Payload modules
from const import *
from helper.azure import *
from helper.context import *
from helper.tools import *
from provider.base import ProviderInstance, ProviderCheck
from typing import Dict, List

###############################################################################

TIMEOUT_SQL_SECS = 3

# Default retry settings
RETRY_RETRIES = 3
RETRY_DELAY_SECS   = 1
RETRY_BACKOFF_MULTIPLIER = 2

###############################################################################

class MSSQLProviderInstance(ProviderInstance):
   sqlHostname = None
   sqlUsername = None
   sqlPassword = None

   def __init__(self,
                tracer: logging.Logger,
                ctx: Context,
                providerInstance: Dict[str, str],
                skipContent: bool = False,
                **kwargs):

      retrySettings = {
         "retries": RETRY_RETRIES,
         "delayInSeconds": RETRY_DELAY_SECS,
         "backoffMultiplier": RETRY_BACKOFF_MULTIPLIER
      }

      super().__init__(tracer,
                       ctx,
                       providerInstance,
                       retrySettings,
                       skipContent,
                       **kwargs)

   # Parse provider properties and fetch DB password from KeyVault, if necessary
   def parseProperties(self):
      self.sqlHostname = self.providerProperties.get("sqlHostname", None)
      if not self.sqlHostname:
         self.tracer.error("[%s] sqlHostname cannot be empty" % self.fullName)
         return False
      self.sqlPort = self.providerProperties.get("sqlPort", None)
      self.sqlUsername = self.providerProperties.get("sqlUsername", None)
      if not self.sqlUsername:
         self.tracer.error("[%s] sqlUsername cannot be empty" % self.fullName)
         return False
      self.sqlPassword = self.providerProperties.get("sqlPassword", None)
      if not self.sqlPassword:
         self.tracer.error("[%s] sqlPassword cannot be empty" % self.fullName)
         return False
      return True

   # Validate that we can establish a sql connection and run queries
   def validate(self) -> bool:
      self.tracer.info("connecting to sql instance (%s) to run test query" % self.sqlHostname)

      # Try to establish a sql connection using the details provided by the user
      try:
         connection = self._establishSqlConnectionToHost()
         cursor = connection.cursor()
      except Exception as e:
         self.tracer.error("[%s] could not establish sql connection %s (%s)" % (self.fullName, self.sqlHostname, e))
         return False

      # Try to run a query 
      try:
         cursor.execute("SELECT db_name();")
         connection.close()
      except Exception as e:
         self.tracer.error("[%s] could run validation query (%s)" % (self.fullName, e))
         return False
      return True

   def _establishSqlConnectionToHost(self,
                                     sqlHostname: str = None,
                                     sqlPort:int = None,
                                     sqlUsername: str = None,
                                     sqlPassword: str = None) -> pyodbc.Connection:
      if not sqlHostname:
         sqlHostname = self.sqlHostname
      if not sqlPort:
         sqlPort = self.sqlPort
      if not sqlUsername:
         sqlUsername = self.sqlUsername
      if not sqlPassword:
         sqlPassword = self.sqlPassword

      # if SQL port is given, append it to the hostname
      if sqlPort:
         sqlHostname += ",%d" % sqlPort

      self.tracer.debug("trying to connect DRIVER={ODBC Driver 17 for SQL Server};SERVER=%s;UID=%s" % (sqlHostname, sqlUsername))
      conn = pyodbc.connect("DRIVER={ODBC Driver 17 for SQL Server};SERVER=%s;UID=%s;PWD=%s" % (sqlHostname, sqlUsername, sqlPassword),
                            timeout=TIMEOUT_SQL_SECS)
      return conn

###############################################################################

# Implements a SAP sql-specific monitoring check
class MSSQLProviderCheck(ProviderCheck):
   lastResult = None
   colTimeGenerated = None

   def __init__(self,
                provider: ProviderInstance,
                **kwargs):
      return super().__init__(provider, **kwargs)

   # Obtain one working sql connection
   def _getSqlConnection(self):
      self.tracer.info("[%s] establishing connection with sql instance" % self.fullName)

      try:
        connection = self.providerInstance._establishSqlConnectionToHost()
        cursor = connection.cursor()
      except Exception as e:
         self.tracer.warning("[%s] could not connect to sql (%s) " % (self.fullName,e))
         return (None)
      return (connection)

   # Calculate the MD5 hash of a result set
   def _calculateResultHash(self,
                            resultRows: List[List[str]]) -> str:
      self.tracer.info("[%s] calculating hash of SQL query result" % self.fullName)
      if len(resultRows) == 0:
         self.tracer.debug("[%s] result set is empty" % self.fullName)
         return None
      resultHash = None
      try:
         resultHash = hashlib.md5(str(resultRows).encode("utf-8")).hexdigest()
         self.tracer.debug("resultHash=%s" % resultHash)
      except Exception as e:
         self.tracer.error("[%s] could not calculate result hash (%s)" % (self.fullName,e))
      return resultHash

   # Generate a JSON-encoded string with the last query result
   # This string will be ingested into Log Analytics and Customer Analytics
   def generateJsonString(self) -> str:
      self.tracer.info("[%s] converting SQL query result set into JSON format" % self.fullName)
      logData = []

      # Only loop through the result if there is one
      if self.lastResult:
         (colIndex, resultRows) = self.lastResult
         
         # Iterate through all rows of the last query result
         for r in resultRows:
            logItem = {
               "SAPMON_VERSION": PAYLOAD_VERSION,
               "PROVIDER_INSTANCE": self.providerInstance.name,
               "METADATA": self.providerInstance.metadata
            }
            for c in colIndex.keys():
               # Unless it's the column mapped to TimeGenerated, remove internal fields
               if c != self.colTimeGenerated and (c.startswith("_") or c == "DUMMY"):
                  continue
               logItem[c] = r[colIndex[c]]
            logData.append(logItem)

      # Convert temporary dictionary into JSON string
      try:
         resultJsonString = json.dumps(logData, sort_keys=True, indent=4, cls=JsonEncoder)
         self.tracer.debug("[%s] resultJson=%s" % (self.fullName,
                                                   str(resultJsonString)))
      except Exception as e:
         self.tracer.error("[%s] could not format logItem=%s into JSON (%s)" % (self.fullName,
                                                                                logItem,
                                                                                e))
      return resultJsonString

   # Connect to sql and run the check-specific SQL statement
   def _actionExecuteSql(self, sql: str) -> None:
      def handle_sql_variant_as_string(value):
         return value.decode('utf-16le')
      self.tracer.info("[%s] connecting to sql and executing SQL" % self.fullName)

      # Find and connect to sql server
      connection = self._getSqlConnection()
      if not connection:
         raise Exception("Unable to get SQL connection")

      cursor = connection.cursor()
      connection.add_output_converter(-150, handle_sql_variant_as_string)

      # Execute SQL statement
      try:
         self.tracer.debug("[%s] executing SQL statement %s" % (self.fullName, sql))
         cursor.execute(sql)

         colIndex = {col[0] : idx for idx, col in enumerate(cursor.description)}
         resultRows = cursor.fetchall()

      except Exception as e:
         raise Exception("[%s] could not execute SQL (%s)" % (self.fullName,e))

      self.lastResult = (colIndex, resultRows)
      self.tracer.debug("[%s] lastResult.colIndex=%s" % (self.fullName,colIndex))
      self.tracer.debug("[%s] lastResult.resultRows=%s " % (self.fullName,resultRows))

      # Update internal state
      if not self.updateState():
         raise Exception("Failed to update state")

      # Disconnect from sql server to avoid memory leaks
      try:
         self.tracer.debug("[%s] closing sql connection" % self.fullName)
         connection.close()
      except Exception as e:
         raise Exception("[%s] could not close connection to sql instance (%s)" % (self.fullName,e))

      self.tracer.info("[%s] successfully ran SQL for check" % self.fullName)

# Update the internal state of this check (including last run times)
   def updateState(self) -> bool:
      self.tracer.info("[%s] updating internal state" % self.fullName)

      # Always store lastRunLocal; 
      lastRunLocal = datetime.utcnow()
      self.state["lastRunLocal"] = lastRunLocal
      self.tracer.info("[%s] internal state successfully updated" % self.fullName)
      return True
