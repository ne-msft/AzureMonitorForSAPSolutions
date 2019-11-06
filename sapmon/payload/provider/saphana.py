# Python modules
import hashlib
import json
import logging

# Payload modules
from const import *
from helper.tools import *
from provider.base import *
from typing import Dict, List

# SAP HANA modules
from hdbcli import dbapi

###############################################################################

# Provide access to a HANA Database (HDB) instance
class SapHana:
   TIMEOUT_HANA_SECS = 5

   connection = None
   cursor = None
   tracer = None

   def __init__(self,
                tracer: logging.Logger,
                host: str = None,
                port: int = None,
                user: str = None,
                password: str = None,
                hanaDetails: Dict[str, str] = None):
      self.tracer = tracer
      self.tracer.info("initializing HANA instance")
      if hanaDetails:
         self.host = hanaDetails["HanaHostname"]
         self.port = hanaDetails["HanaDbSqlPort"]
         self.user = hanaDetails["HanaDbUsername"]
         self.password = hanaDetails["HanaDbPassword"]
      else:
         self.host = host
         self.port = port
         self.user = user
         self.password = password

   # Connect to a HDB instance
   def connect(self) -> None:
      self.connection = dbapi.connect(address = self.host,
                                      port = self.port,
                                      user = self.user,
                                      password = self.password,
                                      timeout = self.TIMEOUT_HANA_SECS)
      self.cursor = self.connection.cursor()

   # Close an open HDB connection
   def disconnect(self) -> None:
      self.connection.close()

   # Execute a SQL query
   def runQuery(self,
                sql: str) -> (Dict[str, str], List[str]):
      self.cursor.execute(sql)
      colIndex = {col[0] : idx for idx, col in enumerate(self.cursor.description)}
      return colIndex, self.cursor.fetchall()

###############################################################################

# Implements a SAP HANA-specific monitoring check
class SapHanaCheck(SapmonCheck):
   COL_SERVER_UTC = "_SERVER_UTC"
   COL_TIMESERIES_UTC = "_TIMESERIES_UTC"
   COL_CONTENT_VERSION = "CONTENT_VERSION"
   COL_SAPMON_VERSION = "SAPMON_VERSION"

   prefix = "HANA"
   isTimeSeries = False
   colIndex = {}
   lastResult = []

   def __init__(self,
                tracer: logging.Logger,
                hanaOptions: Dict[str, str],
                **kwargs):
      super().__init__(tracer, **kwargs)
      self.query = hanaOptions["query"]
      self.isTimeSeries = hanaOptions.get("isTimeSeries", False)
      self.colTimeGenerated = self.COL_TIMESERIES_UTC if self.isTimeSeries else self.COL_SERVER_UTC
      self.initialTimespanSecs = hanaOptions.get("initialTimespanSecs", 0)
      self.state["lastRunServer"] = None

   # Prepare the SQL statement based on the check-specific query
   def prepareSql(self) -> str:
      self.tracer.info("preparing SQL statement")

      # insert logic to get server UTC time (_SERVER_UTC)
      sqlTimestamp = ", '%s' AS %s, '%s' AS %s, CURRENT_UTCTIMESTAMP AS %s FROM DUMMY," % \
         (self.version, self.COL_CONTENT_VERSION, PAYLOAD_VERSION, self.COL_SAPMON_VERSION, self.COL_SERVER_UTC)
      self.tracer.debug("sqlTimestamp=%s" % sqlTimestamp)
      sql = self.query.replace(" FROM", sqlTimestamp, 1)

      # if time series, insert time condition
      if self.isTimeSeries:
         lastRunServer = self.state.get("lastRunServer", None)
         # TODO(tniek) - make WHERE conditions for time series queries more flexible
         if not lastRunServer:
            self.tracer.info("time series query for check %s_%s has never been run, applying initalTimespanSecs=%d" % \
               (self.prefix, self.name, self.initialTimespanSecs))
            lastRunServerUtc = "ADD_SECONDS(NOW(), i.VALUE*(-1) - %d)" % self.initialTimespanSecs
         else:
            if not isinstance(lastRunServer, datetime):
               self.tracer.error("lastRunServer=%s has not been de-serialized into a valid datetime object" % str(lastRunServer))
               return None
            try:
               lastRunServerUtc = "'%s'" % lastRunServer.strftime(TIME_FORMAT_HANA)
            except:
               self.tracer.error("could not format lastRunServer=%s into HANA format" % str(lastRunServer))
               return None
            self.tracer.info("time series query for check %s_%s has been run at %s, filter out only new records since then" % \
               (self.prefix, self.name, lastRunServerUtc))
         self.tracer.debug("lastRunServerUtc = %s" % lastRunServerUtc)
         sql = sql.replace("{lastRunServerUtc}", lastRunServerUtc, 1)
         self.tracer.debug("sql=%s" % sql)

      return sql

   # Run this SAP HANA-specific check
   def run(self,
           hana: SapHana) -> str:
      self.tracer.info("running HANA SQL query")
      sql = self.prepareSql()

      # Only run this and update state if the prepared SQL is non-empty
      if sql:
         self.colIndex, self.lastResult = hana.runQuery(sql)
         self.updateState(hana)

      # But still always convert into a JSON string
      resultJson = self.convertResultIntoJson()
      return resultJson

   # Calculate the MD5 hash of a result set
   def calculateResultHash(self) -> str:
      self.tracer.info("calculating SQL result hash")
      resultHash = None
      if len(self.lastResult) == 0:
         self.tracer.debug("SQL result is empty")
      else:
         try:
            resultHash = hashlib.md5(str(self.lastResult).encode("utf-8")).hexdigest()
            self.tracer.debug("resultHash=%s" % resultHash)
         except Exception as e:
            self.tracer.error("could not calculate result hash (%s)" % e)
      return resultHash

   # Convert last result into a JSON string (as required by Log Analytics Data Collector API)
   def convertResultIntoJson(self):
      self.tracer.info("converting result set into JSON")
      logData = []
      # In case we cannot convert, the JSON string would just be "{}"
      jsonData = "{}"

      # Iterate through all rows of the last result
      for r in self.lastResult:
         logItem = {}
         for c in self.colIndex.keys():
            if c != self.colTimeGenerated and (c.startswith("_") or c == "DUMMY"): # remove internal fields
               continue
            logItem[c] = r[self.colIndex[c]]
         logData.append(logItem)
      try:
         resultJson = json.dumps(logData, sort_keys=True, indent=4, cls=JsonEncoder)
         self.tracer.debug("resultJson=%s" % str(resultJson))
      except Exception as e:
         self.tracer.error("could not encode logItem=%s into JSON (%s)" % (logItem, e))

      return resultJson

   # Update the internal state of this check (including last run times)
   def updateState(self,
                   hana: SapHana) -> bool:
      self.tracer.info("updating internal state of check %s_%s" % (self.prefix, self.name))
      self.state["lastRunLocal"] = datetime.utcnow()
      if len(self.lastResult) == 0:
         self.tracer.info("SQL result is empty")
         return False
      self.state["lastRunServer"] = self.lastResult[0][self.colIndex[self.COL_SERVER_UTC]]
      self.state["lastResultHash"] = self.calculateResultHash()
      self.tracer.info("internal state successfully updated")
      return True

