# Python modules
import hashlib
import json
import logging
import time

# Payload modules
from const import *
from helper.tools import *
from provider.base import *
from typing import Dict, List

# SAP HANA modules
from hdbcli import dbapi

###############################################################################

# Stores configuration specific to a SAP HANA database instance
class SapHanaConfig(metaclass=Singleton):
   host = None
   port = None
   user = None
   password = None
   timeout = TIMEOUT_HANA_MS

   @classmethod
   def update(cls, hanaDetails):
      cls.host = hanaDetails.get("HanaHostname", None)
      cls.port = hanaDetails.get("HanaDbSqlPort", None)
      cls.user = hanaDetails.get("HanaDbUsername", None)
      cls.password = hanaDetails.get("HanaDbPassword", None)
#         {"PasswordKeyVaultMsiClientId": null, "HanaHostname": "10.7.1.4", "HanaDbUsername": "SYSTEM", "HanaDbPassword": "Manager1", "HanaDbName": "SYSTEMDB", "HanaDbSqlPort": 30015, "HanaDbPasswordKeyVaultUrl": null}

###############################################################################

# Stores configuration specific to a SAP HANA database instance
class SapHanaProvider(SapmonContentProvider):
   def __init__(self,
                tracer,
                contentFullPath,
                **kwargs):
      self.tracer = tracer
      if not self.initContent(contentFullPath):
         return None
      super().__init__(tracer, contentFullPath, **kwargs)

   # Read content from provider definition
   def initContent(self, filename: str) -> bool:
      try:
         with open(filename, "r") as file:
            data = file.read()
         jsonData = json.loads(data)
      except Exception as e:
         self.tracer.error("could not load content file %s (%s)" % (filename, e))
         return False

      self.name = jsonData.get("providerName", None)
      if not self.name:
         self.tracer.error("provider name not specified in content file %s" % filename)
         return False
      self.version = jsonData.get("contentVersion", None)
      if not self.version:
         self.tracer.error("content version not specified in content file %s" % filename)
         return False
      self.checkType = jsonData.get("checkType", None)
      if not self.checkType:
         self.tracer.error("check type not specified in content file %s" % filename)
         return False

      checks = jsonData.get("checks", [])
      for checkOptions in checks:
         try:
            self.tracer.info("instantiate check of type %s" % self.checkType)
            self.tracer.debug("checkOptions=%s" % checkOptions)
            checkOptions["provider"] = self
            check = eval(self.checkType)(**checkOptions)
            self.checks.append(check)
         except Exception as e:
            self.tracer.error("could not instantiate new check of type %s (%s)" % (self.checkType, e))
      return True

   @staticmethod
   def validate(tracer) -> bool:
      tracer.info("connecting to HANA instance to run test query")
      hanaConfig = SapHanaConfig()

      try:
         connection = dbapi.connect(address = hanaConfig.host,
                                    port = hanaConfig.port,
                                    user = hanaConfig.user,
                                    password = hanaConfig.password,
                                    CONNECTTIMEOUT = hanaConfig.timeout)
         cursor = connection.cursor()
         if not connection.isconnected():
            tracer.error("unable to validate connection status")
            return False
      except Exception as e:
         tracer.error("could not connect to HANA node %s:%d (%s)" % (hanaConfig.host,
                                                                     hanaConfig.port,
                                                                     e))
         return False

      try:
         cursor.execute("SELECT * FROM M_SERVICES")
         connection.close()
      except Exception as e:
         tracer.critical("could run test query (%s)" % e)
         return False

      return True

###############################################################################

# Implements a SAP HANA-specific monitoring check
class SapHanaCheck(SapmonCheck):
   lastResult = None
   colTimeGenerated = None
   hanaConfig = SapHanaConfig()
   
   def __init__(self,
                provider: SapmonContentProvider,
                **kwargs):
      super().__init__(provider, **kwargs)

   # Obtain one working HANA connection (client-side failover logic)
   def _getHanaConnection(self):
      self.tracer.info("establishing connection with HANA instance")
      # Check if HANA host config has been retrieved from DB yet
      if "hostConfig" not in self.provider.state:
         # Host config has not been retrieved yet; our only candidate is the one provided by user
         self.tracer.debug("no host config has been persisted to provider yet, using user-provided host")
         hostsToTry = [self.hanaConfig.host]
      else:
         # Host config has already been retrieved; rank the hosts to compile a list of hosts to try
         self.tracer.debug("host config has been persisted to provider, deriving prioritized host list")
         hostConfig = self.provider.state["hostConfig"]
         hostsToTry = [h["host"] for h in hostConfig]

      cursor = None
      self.tracer.debug("hostsToTry=%s" % hostsToTry)
      for host in hostsToTry:
         try:
            connection = dbapi.connect(address = host,
                                       port = self.hanaConfig.port,
                                       user = self.hanaConfig.user,
                                       password = self.hanaConfig.password,
                                       CONNECTTIMEOUT = self.hanaConfig.timeout)
            if connection.isconnected():
               cursor = connection.cursor()
               break
         except Exception as e:
            self.tracer.warning("could not connect to HANA node %s:%d (%s)" % (host,
                                                                               self.hanaConfig.port,
                                                                               e))
      if not cursor:
         self.tracer.error("unable to connect to any HANA node (hostsToTry=%s)" % hostsToTry)
         return (None, None, None)
      return (connection, cursor, host)

   # Prepare the SQL statement based on the check-specific query
   def _prepareSql(self,
                   sql: str,
                   isTimeSeries: bool,
                   initialTimespanSecs: int) -> str:
      self.tracer.info("preparing SQL statement")

      # Insert logic to get server UTC time (_SERVER_UTC)
      sqlTimestamp = ", CURRENT_UTCTIMESTAMP AS %s FROM DUMMY," % COL_SERVER_UTC
      self.tracer.debug("sqlTimestamp=%s" % sqlTimestamp)
      preparedSql = sql.replace(" FROM", sqlTimestamp, 1)
      
      # If time series, insert time condition
      if isTimeSeries:
         lastRunServer = self.state.get("lastRunServer", None)
         # TODO(tniek) - make WHERE conditions for time series queries more flexible
         if not lastRunServer:
            self.tracer.info("time series query for HANA check %s has never been run, applying initalTimespanSecs=%d" % \
               (self.name, initialTimespanSecs))
            lastRunServerUtc = "ADD_SECONDS(NOW(), i.VALUE*(-1) - %d)" % initialTimespanSecs
         else:
            if not isinstance(lastRunServer, datetime):
               self.tracer.error("lastRunServer=%s has not been de-serialized into a valid datetime object" % str(lastRunServer))
               return None
            try:
               lastRunServerUtc = "'%s'" % lastRunServer.strftime(TIME_FORMAT_HANA)
            except Exception as e:
               self.tracer.error("could not format lastRunServer=%s into HANA format (%s)" % (str(lastRunServer), e))
               return None
            self.tracer.info("time series query for check %s.%s has been run at %s, filter out only new records since then" % \
               (self.provider.name, self.name, lastRunServerUtc))
         self.tracer.debug("lastRunServerUtc=%s" % lastRunServerUtc)
         preparedSql = sql.replace("{lastRunServerUtc}", lastRunServerUtc, 1)
         self.tracer.debug("preparedSql=%s" % preparedSql)

      # Return the finished SQL statement
      return preparedSql

   # Calculate the MD5 hash of a result set
   def _calculateResultHash(self,
                            resultRows: List[List[str]]) -> str:
      self.tracer.info("calculating hash of SQL query result")
      resultHash = None
      try:
         resultHash = hashlib.md5(str(resultRows).encode("utf-8")).hexdigest()
         self.tracer.debug("resultHash=%s" % resultHash)
      except Exception as e:
         self.tracer.error("could not calculate result hash (%s)" % e)
      return resultHash

   # Generate a JSON-encoded string with the last query result
   def _generateJsonString(self) -> str:
      # TODO(tniek): Consider SapmonCheck._generateJsonString() for all check types 
      self.tracer.info("converting SQL query result set into JSON")
      logData = []
      
      # Only loop through the result if there is one
      if self.lastResult:
         (colIndex, resultRows) = self.lastResult
         # Iterate through all rows of the last query result
         for r in resultRows:
            logItem = {
               "CONTENT_VERSION": self.provider.version,
               "SAPMON_VERSION": PAYLOAD_VERSION
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
         self.tracer.debug("resultJson=%s" % str(resultJsonString))
      except Exception as e:
         self.tracer.error("could not encode logItem=%s into JSON (%s)" % (logItem, e))
      return resultJsonString

   # Update the internal state of this check (including last run times)
   def _updateState(self) -> bool:
      self.tracer.info("updating internal state of check %s.%s" % (self.provider.name, self.name))
      (colIndex, resultRows) = self.lastResult

      # Always store lastRunLocal; if the check result doesn't have it, use current time
      if COL_LOCAL_UTC in colIndex:
         lastRunLocal = resultRows[0][colIndex[COL_LOCAL_UTC]]
      else:
         lastRunLocal = datetime.utcnow()
      self.state["lastRunLocal"] = lastRunLocal

      # Only store lastRunServer if we have it in the check result; consider time-series queries
      if len(resultRows) > 0:
         if COL_TIMESERIES_UTC in colIndex:
            self.state["lastRunServer"] = resultRows[-1][colIndex[COL_TIMESERIES_UTC]]
         elif COL_SERVER_UTC in colIndex:
            self.state["lastRunServer"] = resultRows[0][colIndex[COL_SERVER_UTC]]

      self.state["lastResultHash"] = self._calculateResultHash(resultRows)
      self.tracer.info("internal state successfully updated")
      return True

   # Connect to HANA and run the defined SQL statement
   def executeSql(self,
                  sql: str,
                  isTimeSeries: bool = False,
                  initialTimespanSecs: int = 60) -> bool:
      self.tracer.info("connecting to HANA and executing SQL for check %s" % self.name)

      # Marking which column will be used for TimeGenerated
      self.colTimeGenerated = COL_TIMESERIES_UTC if isTimeSeries else COL_SERVER_UTC

      # Find and connect to HANA server
      (connection, cursor, host) = self._getHanaConnection()
      if not connection:
         return False

      # Prepare SQL statement
      preparedSql = self._prepareSql(sql,
                                     isTimeSeries,
                                     initialTimespanSecs)
      #sys.exit()
      if not preparedSql:
         return False

      # Execute SQL statement
      try:
         cursor.execute(preparedSql)
         colIndex = {col[0] : idx for idx, col in enumerate(cursor.description)}
         resultRows = cursor.fetchall()
      except Exception as e:
         self.tracer.error("could not execute SQL %s (%s)" % (query, e))
         return False

      # Cancel if result is empty
      #if len(resultRows) == 0:
      #   self.tracer.error("SQL query returned empty results, cancelling check execution")
      #   return False
      self.lastResult = (colIndex, resultRows)
      self.tracer.debug("lastResult.colIndex=%s" % colIndex)
      self.tracer.debug("lastResult.resultRows=%s " % resultRows)

      # Update internal state
      if not self._updateState():
         return False

      # Disconnect from HANA server
      try:
         connection.close()
      except Exception as e:
         self.tracer.error("could not disconnect from HANA instance (%s)" % e)
         return False

      self.tracer.info("successfully ran SQL for check %s" % self.name)
      return True

   # Parse result of the query against M_LANDSCAPE_HOST_CONFIGURATION and store it internally
   def parseHostConfig(self):
      # description
      # (('HOST', 9, 64, 64, 64, 0, True), ('HOST_ACTIVE', 9, 128, 128, 128, 0, True), ('HOST_STATUS', 9, 128, 128, 128, 0, True), ('FAILOVER_STATUS', 9, 128, 128, 128, 0, True), ('FAILOVER_GROUP', 9, 256, 256, 256, 0, True), ('FAILOVER_CONFIG_GROUP', 9, 256, 256, 256, 0, True), ('FAILOVER_ACTUAL_GROUP', 9, 256, 256, 256, 0, True), ('NAMESERVER_CONFIG_ROLE', 9, 16, 16, 16, 0, True), ('NAMESERVER_ACTUAL_ROLE', 9, 16, 16, 16, 0, True), ('INDEXSERVER_CONFIG_ROLE', 9, 16, 16, 16, 0, True), ('INDEXSERVER_ACTUAL_ROLE', 9, 16, 16, 16, 0, True), ('HOST_CONFIG_ROLES', 9, 64, 64, 64, 0, True), ('HOST_ACTUAL_ROLES', 9, 64, 64, 64, 0, True), ('STORAGE_PARTITION', 3, 10, 10, 10, 0, True), ('STORAGE_CONFIG_PARTITION', 3, 10, 10, 10, 0, True), ('STORAGE_ACTUAL_PARTITION', 3, 10, 10, 10, 0, True), ('WORKER_CONFIG_GROUPS', 9, 256, 256, 256, 0, True), ('WORKER_ACTUAL_GROUPS', 9, 256, 256, 256, 0, True), ('REMOVE_STATUS', 9, 16, 16, 16, 0, True))

      # hdb01, 02, 03 up
      # [('hdb01', 'YES', 'OK', '', 'default', 'default', 'default', 'MASTER 1', 'MASTER', 'WORKER', 'MASTER', 'WORKER', 'WORKER', 1, 1, 1, 'default', 'default', ''), ('hdb02', 'YES', 'OK', '', 'default', 'default', 'default', 'MASTER 2', 'SLAVE', 'WORKER', 'SLAVE', 'WORKER', 'WORKER', 2, 2, 2, 'default', 'default', ''), ('hdb03', 'YES', 'IGNORE', '', 'default', 'default', 'default', 'MASTER 3', 'SLAVE', 'STANDBY', 'STANDBY', 'STANDBY', 'STANDBY', 0, 0, 0, 'default', '-', '')]

      # stop hdb01
      # [('hdb01', 'NO', 'INFO', '', 'default', 'default', 'default', 'MASTER 1', 'SLAVE', 'WORKER', 'STANDBY', 'WORKER', 'STANDBY', 0, 1, 0, 'default', '-', ''), ('hdb02', 'YES', 'OK', '', 'default', 'default', 'default', 'MASTER 2', 'SLAVE', 'WORKER', 'SLAVE', 'WORKER', 'WORKER', 2, 2, 2, 'default', 'default', ''), ('hdb03', 'YES', 'INFO', '', 'default', 'default', 'default', 'MASTER 3', 'MASTER', 'STANDBY', 'MASTER', 'STANDBY', 'WORKER', 1, 0, 1, 'default', 'default', '')]

      self.tracer.info("parsing HANA host configuration and storing it in provider state")
      hosts = []
      (colIndex, resultRows) = self.lastResult
      for r in resultRows:
         host = {
            "host": r["HOST"],
            "active": True if r["HOST_ACTIVE"] == "YES" else False,
            "role": r["INDEXSERVER_ACTUAL_ROLE"]
            }
         hosts.append(host)
      self.provider.state["hostConfig"] = hosts
      self.tracer.debug("hosts=%s" % hosts)
      return True

   # Probe SQL Connection to all nodes in HANA landscape
   def probeSqlConnection(self):
      self.tracer.info("probing SQL connection to all HANA nodes")

      # For this check, the column storing the local UTC will be used for TimeGenerated
      self.colTimeGenerated = COL_LOCAL_UTC

      # This check requires the HANA host configuration to be run first
      if "hostConfig" not in self.provider.state:
         self.tracer.error("HANA host configuration check has not been executed and/or persisted in provider state yet")
         return False

      hostConfig = self.provider.state["hostConfig"]
      hostsToProbe = [h["host"] for h in hostConfig]
      probeResults = []
      for host in sorted(hostsToProbe):
         latency = None
         success = False

         # Probe SQL connection to a particular HANA node
         startTime = time.time()
         try:
            connection = dbapi.connect(address = host,
                                       port = self.hanaConfig.port,
                                       user = self.hanaConfig.user,
                                       password = self.hanaConfig.password,
                                       CONNECTTIMEOUT = self.hanaConfig.timeout)

            # If connection is successful, measure latency
            if connection.isconnected():
               latency = (time.time() - startTime) * 1000
               success = True
         except Exception as e:
            self.tracer.error("could not connect to HANA instance %s:%d (%s)" % (host,
                                                                                 self.hanaConfig.port,
                                                                                 e))
         finally:
            connection.close()

         # Build probing result tuple with current local time
         probeResults.append(
               [
                  datetime.utcnow(),
                  host,
                  success,
                  latency
               ]
            )

      # Store complete probing result internally and update state
      self.tracer.debug("probeResults=%s" % probeResults)
      self.lastResult = (
            {
               COL_LOCAL_UTC: 0,
               "HOST": 1,
               "SUCCESS": 2,
               "LATENCY_MS": 3,
            },
            probeResults
         )

      # Update internal state
      if not self._updateState():
         return False
      return True

