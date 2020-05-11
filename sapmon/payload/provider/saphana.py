# Python modules
import hashlib
import json
import logging
import re
import time

# Payload modules
from const import *
from helper.azure import *
from helper.tools import *
from provider.base import ProviderInstance, ProviderCheck
from typing import Dict, List

# SAP HANA modules
from hdbcli import dbapi
import pyhdbcli

###############################################################################

# HANA-specific constants
REGEX_EXTERNAL_KEYVAULT_URL = "https://([A-Za-z0-9\-]+).vault.azure.net/secrets/([A-Za-z0-9\-]+)(\/)?([A-Za-z0-9\-]+)?"
TIMEOUT_HANA_SECS           = 5
COL_LOCAL_UTC               = "_LOCAL_UTC"
COL_SERVER_UTC              = "_SERVER_UTC"
COL_TIMESERIES_UTC          = "_TIMESERIES_UTC"

###############################################################################

class saphanaProviderInstance(ProviderInstance):
   hanaHostname = None
   hanaDbSqlPort = None
   hanaDbUsername = None
   hanaDbPassword = None

   def __init__(self,
                tracer: logging.Logger,
                providerInstance: Dict[str, str],
                skipContent: bool = False,
                **kwargs):
      super().__init__(tracer,
                       providerInstance,
                       skipContent,
                       **kwargs)

   # Parse provider properties and fetch DB password from KeyVault, if necessary
   def parseProperties(self):
      self.hanaHostname = self.providerProperties.get("hanaHostname", None)
      if not self.hanaHostname:
         self.tracer.error("[%s] hanaHostname cannot be empty" % self.fullName)
         return False
      self.hanaDbSqlPort = self.providerProperties.get("hanaDbSqlPort", None)
      if not self.hanaDbSqlPort:
         self.tracer.error("[%s] hanaDbSqlPort cannot be empty" % self.fullName)
         return False
      self.hanaDbUsername = self.providerProperties.get("hanaDbUsername", None)
      if not self.hanaDbUsername:
         self.tracer.error("[%s] hanaDbUsername cannot be empty" % self.fullName)
         return False
      self.hanaDbPassword = self.providerProperties.get("hanaDbPassword", None)
      if not self.hanaDbPassword:
         hanaDbPasswordKeyVaultUrl = self.providerProperties.get("hanaDbPasswordKeyVaultUrl", None)
         passwordKeyVaultMsiClientId = self.providerProperties.get("keyVaultCredentialsMsiClientID", None)
         if not hanaDbPasswordKeyVaultUrl or not passwordKeyVaultMsiClientId:
            self.tracer.error("[%s] if no password, hanaDbPasswordKeyVaultUrl and keyVaultCredentialsMsiClientID must be given" % self.fullName)
            return False

         # Determine URL of separate KeyVault
         self.tracer.info("[%s] fetching HANA credentials from separate KeyVault" % self.fullName)
         try:
            passwordSearch = re.match(REGEX_EXTERNAL_KEYVAULT_URL,
                                      hanaDbPasswordKeyVaultUrl,
                                      re.IGNORECASE)
            kvName = passwordSearch.group(1)
            passwordName = passwordSearch.group(2)
            passwordVersion = passwordSearch.group(4)
         except Exception as e:
            self.tracer.error("[%s] invalid URL format (%s)" % (self.fullName, e))
            return False

         # Create temporary KeyVault object to fetch relevant secret
         try:
            kv = AzureKeyVault(self.tracer,
                               kvName,
                               passwordKeyVaultMsiClientId)
         except Exception as e:
            self.tracer.error("[%s] error accessing the separate KeyVault (%s)" % (self.fullName,
                                                                                   e))
            return False

         # Access the actual secret from the external KeyVault
         # TODO: proper (provider-independent) handling of external KeyVaults
         try:
            self.hanaDbPassword = kv.getSecret(passwordName, None).value
         except Exception as e:
            self.tracer.error("[%s] error accessing the secret inside the separate KeyVault (%s)" % (self.fullName,
                                                                                                     e))
            return False        
      return True

   # Validate that we can establish a HANA connection and run queries
   def validate(self) -> bool:
      self.tracer.info("connecting to HANA instance (%s:%d) to run test query" % (self.hanaHostname,
                                                                                  self.hanaDbSqlPort))

      # Try to establish a HANA connection using the details provided by the user
      try:
         connection = self._establishHanaConnectionToHost()
         cursor = connection.cursor()
         if not connection.isconnected():
            self.tracer.error("[%s] unable to validate connection status" % self.fullName)
            return False
      except Exception as e:
         self.tracer.error("[%s] could not establish HANA connection %s:%d (%s)" % (self.fullName,
                                                                                    self.hanaHostname,
                                                                                    self.hanaDbSqlPort,
                                                                                    e))
         return False

      # Try to run a query against the services view
      # This query will (rightfully) fail if the HANA license is expired
      try:
         cursor.execute("SELECT * FROM M_SERVICES")
         connection.close()
      except Exception as e:
         self.tracer.error("[%s] could run validation query (%s)" % (self.fullName, e))
         return False
      return True

   def _establishHanaConnectionToHost(self,
                                      hostname: str = None,
                                      port: int = None,
                                      timeout: int = TIMEOUT_HANA_SECS) -> pyhdbcli.Connection:
      if not hostname:
         hostname = self.hanaHostname
      if not port:
         port = self.hanaDbSqlPort
      return dbapi.connect(address = hostname,
                           port = port,
                           user = self.hanaDbUsername,
                           password = self.hanaDbPassword,
                           timeout = timeout,
                           CONNECTTIMEOUT = timeout * 1000)

###############################################################################

# Implements a SAP HANA-specific monitoring check
class saphanaProviderCheck(ProviderCheck):
   lastResult = None
   colTimeGenerated = None
   
   def __init__(self,
                provider: ProviderInstance,
                **kwargs):
      return super().__init__(provider, **kwargs)

   # Obtain one working HANA connection (client-side failover logic)
   def _getHanaConnection(self):
      self.tracer.info("[%s] establishing connection with HANA instance" % self.fullName)

      # Check if HANA host config has been retrieved from DB yet
      if "hostConfig" not in self.providerInstance.state:
         # Host config has not been retrieved yet; our only candidate is the one provided by user
         self.tracer.debug("[%s] no host config has been persisted yet, using user-provided host" % self.fullName)
         hostsToTry = [self.providerInstance.hanaHostname]
      else:
         # Host config has already been retrieved; rank the hosts to compile a list of hosts to try
         self.tracer.debug("[%s] host config has been persisted to provider, deriving prioritized host list" % self.fullName)
         hostConfig = self.providerInstance.state["hostConfig"]
         hostsToTry = [h["host"] for h in hostConfig]

      # Iterate through the prioritized list of hosts to try
      cursor = None
      self.tracer.debug("hostsToTry=%s" % hostsToTry)
      for host in hostsToTry:
         try:
            connection = self.providerInstance._establishHanaConnectionToHost(hostname = host)
            # Validate that we're indeed connected
            if connection.isconnected():
               cursor = connection.cursor()
               break
         except Exception as e:
            self.tracer.warning("[%s] could not connect to HANA node %s:%d (%s)" % (self.fullName,
                                                                                    host,
                                                                                    self.providerInstance.hanaDbSqlPort,
                                                                                    e))
      if not cursor:
         self.tracer.error("[%s] unable to connect to any HANA node (hosts to try=%s)" % (self.fullName,
                                                                                          hostsToTry))
         return (None, None, None)
      return (connection, cursor, host)

   # Prepare the SQL statement based on the check-specific query
   def _prepareSql(self,
                   sql: str,
                   isTimeSeries: bool,
                   initialTimespanSecs: int) -> str:
      self.tracer.info("[%s] preparing SQL statement" % self.fullName)

      # Insert logic to get server UTC time (_SERVER_UTC)
      sqlTimestamp = ", CURRENT_UTCTIMESTAMP AS %s FROM DUMMY," % COL_SERVER_UTC
      self.tracer.debug("[%s] sqlTimestamp=%s" % (self.fullName,
                                                  sqlTimestamp))
      preparedSql = sql.replace(" FROM", sqlTimestamp, 1)
      
      # If time series, insert time condition
      if isTimeSeries:
         lastRunServer = self.state.get("lastRunServer", None)

         # TODO(tniek) - make WHERE conditions for time series queries more flexible
         if not lastRunServer:
            self.tracer.info("[%s] time series query has never been run, applying initalTimespanSecs=%d" % \
               (self.fullName, initialTimespanSecs))
            lastRunServerUtc = "ADD_SECONDS(NOW(), i.VALUE*(-1) - %d)" % initialTimespanSecs
         else:
            if not isinstance(lastRunServer, datetime):
               self.tracer.error("[%s] lastRunServer=%s could not been de-serialized into datetime object" % (self.fullName,
                                                                                                              str(lastRunServer)))
               return None
            try:
               lastRunServerUtc = "'%s'" % lastRunServer.strftime(TIME_FORMAT_HANA)
            except Exception as e:
               self.tracer.error("[%s] could not format lastRunServer=%s into HANA format (%s)" % (self.fullName,
                                                                                                   str(lastRunServer),
                                                                                                   e))
               return None
            self.tracer.info("[%s] time series query has been run at %s, filter out only new records since then" % \
               (self.fullName, lastRunServerUtc))
         self.tracer.debug("[%s] lastRunServerUtc=%s" % (self.fullName,
                                                         lastRunServerUtc))
         preparedSql = sql.replace("{lastRunServerUtc}", lastRunServerUtc, 1)
         self.tracer.debug("[%s] preparedSql=%s" % (self.fullName,
                                                    preparedSql))

      # Return the finished SQL statement
      return preparedSql

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
         self.tracer.error("[%s] could not calculate result hash (%s)" % (self.fullName,
                                                                          e))
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
               "CONTENT_VERSION": self.providerInstance.contentVersion,
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

   # Update the internal state of this check (including last run times)
   def updateState(self) -> bool:
      self.tracer.info("[%s] updating internal state" % self.fullName)
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
      self.tracer.info("[%s] internal state successfully updated" % self.fullName)
      return True

   # Connect to HANA and run the check-specific SQL statement
   def _actionExecuteSql(self,
                    sql: str,
                    isTimeSeries: bool = False,
                    initialTimespanSecs: int = 60) -> None:
      self.tracer.info("[%s] connecting to HANA and executing SQL" % self.fullName)

      # Marking which column will be used for TimeGenerated
      self.colTimeGenerated = COL_TIMESERIES_UTC if isTimeSeries else COL_SERVER_UTC

      # Find and connect to HANA server
      (connection, cursor, host) = self._getHanaConnection()
      if not connection:
         raise Exception("Unable to get HANA connection")

      # Prepare SQL statement
      preparedSql = self._prepareSql(sql,
                                     isTimeSeries,
                                     initialTimespanSecs)
      if not preparedSql:
         raise Exception("Unable to prepare SQL statement")

      # Execute SQL statement
      self.tracer.debug("[%s] executing SQL statement %s" % (self.fullName,
                                                             preparedSql))
      cursor.execute(preparedSql)
      colIndex = {col[0] : idx for idx, col in enumerate(cursor.description)}
      resultRows = cursor.fetchall()

      self.lastResult = (colIndex, resultRows)
      self.tracer.debug("[%s] lastResult.colIndex=%s" % (self.fullName,
                                                         colIndex))
      self.tracer.debug("[%s] lastResult.resultRows=%s " % (self.fullName,
                                                            resultRows))

      # Update internal state
      if not self.updateState():
         raise Exception("Failed to update state")

      # Disconnect from HANA server to avoid memory leaks
      self.tracer.debug("[%s] closing HANA connection" % self.fullName)
      connection.close()

      self.tracer.info("[%s] successfully ran SQL for check" % self.fullName)

   # Parse result of the query against M_LANDSCAPE_HOST_CONFIGURATION and store it internally
   def _actionParseHostConfig(self) -> None:
      self.tracer.info("[%s] parsing HANA host configuration and storing it in provider state" % self.fullName)

      # Iterate through the results and store a mini version in the global provider state
      hosts = []
      (colIndex, resultRows) = self.lastResult
      for r in resultRows:
         host = {
            "host": r["HOST"],
            "active": True if r["HOST_ACTIVE"] == "YES" else False,
            "role": r["INDEXSERVER_ACTUAL_ROLE"]
            }
         hosts.append(host)
      self.providerInstance.state["hostConfig"] = hosts
      self.tracer.debug("hosts=%s" % hosts)

   # Probe SQL Connection to all nodes in HANA landscape
   def _actionProbeSqlConnection(self,
                            probeTimeout: int = None) -> None:
      self.tracer.info("[%s] probing SQL connection to all HANA nodes" % self.fullName)

      # If no probeTimeout parameter is defined for this action, use the default
      if probeTimeout is None:
         probeTimeout = TIMEOUT_HANA_MS

      # For this check, the column storing the local UTC will be used for TimeGenerated
      self.colTimeGenerated = COL_LOCAL_UTC

      # This check requires the HANA host configuration to be run first
      if "hostConfig" not in self.providerInstance.state:
         raise Exception("HANA host config check has not been executed yet")

      # Iterate through all hosts (alphabetical order) from the host config
      hostConfig = self.providerInstance.state["hostConfig"]
      hostsToProbe = [h["host"] for h in hostConfig]
      probeResults = []
      for host in sorted(hostsToProbe):
         latency = None
         success = False

         # Given the SQL port (3xxyy), calculate hdbnameserver port (3xx01)
         portSQL = self.providerInstance.hanaDbSqlPort
         portNameserver = int(str(portSQL)[:-2] + "01")

         for port in (portSQL, portNameserver):
            # Probe connection to Indexserver (SQL) and Nameserver of a particular node
            # This Nameserver workaround is required, since in a n+m scale-out scenario (with m>0),
            # stand-by nodes will have no hdbindexserver running, hence SQL connection will fail.
            startTime = time.time()
            try:
               self.tracer.debug("[%s] probing HANA connection at %s:%d" % (self.fullName,
                                                                            host,
                                                                            port))
               connection = self.providerInstance._establishHanaConnectionToHost(hostname = host,
                                                                                 port = port,
                                                                                 timeout = probeTimeout)
               if connection.isconnected():
                  self.tracer.debug("[%s] HANA connection successfully established" % self.fullName)
                  success = True
                  connection.close()
            except Exception as e:
               # We know that SQL connections to hdbnameserver will fail
               # Let's determine if the HANA landscape is up, based on the error code
               # (Note: this applies to scale-out landscapes with n+m nodes only)
               msg = e.errortext.lower()
               if "89008" in msg or "socket closed" in msg:
                  success = True
                  self.tracer.debug("[%s] received expected error probing HANA nameserver %s:%d (%s" % (self.fullName,
                                                                                                        host,
                                                                                                        portNameserver,
                                                                                                        e))
               elif "89001" in msg or "cannot resolve host name" in msg \
               or "89006" in msg or "connection refused" in msg \
               or "timeout expired" in msg:
                 self.tracer.error("[%s] HANA nameserver %s:%d is not responding to probe (%s)" % (self.fullName,
                                                                                                   host,
                                                                                                   portNameserver,
                                                                                                   e))
               else:
                 self.tracer.error("[%s] unexpected error when probing HANA nameserver %s:%d (%s)" % (self.fullName,
                                                                                                      host,
                                                                                                      portNameserver,
                                                                                                      e))
            if success:
               latency = (time.time() - startTime) * 1000
               break

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
      self.tracer.debug("[%s] probeResults=%s" % (self.fullName,
                                                  probeResults))
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
      if not self.updateState():
         raise Exception("Failed to update state")
