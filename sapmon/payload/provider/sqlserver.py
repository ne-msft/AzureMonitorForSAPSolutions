# Python modules
import hashlib
import json
import logging
import re
import time
import pyodbc


# Payload modules

###############################################################################


###############################################################################

class sapsqlProviderInstance(ProviderInstance):
   sqlHostname = None
   sqlDbUsername = None
   sqlDbPassword = None

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
      self.sqlHostname = self.providerProperties.get("sqlHostname", None)
      if not self.sqlHostname:
         self.tracer.error("[%s] sqlHostname cannot be empty" % self.fullName)
         return False
      self.sqlDbSqlPort = self.providerProperties.get("sqlDbSqlPort", None)
      if not self.sqlDbSqlPort:
         self.tracer.error("[%s] sqlDbSqlPort cannot be empty" % self.fullName)
         return False
      self.sqlDbUsername = self.providerProperties.get("sqlDbUsername", None)
      if not self.sqlDbUsername:
         self.tracer.error("[%s] sqlDbUsername cannot be empty" % self.fullName)
         return False
      self.sqlDbPassword = self.providerProperties.get("sqlDbPassword", None)
      if not self.sqlDbPassword:
         sqlDbPasswordKeyVaultUrl = self.providerProperties.get("sqlDbPasswordKeyVaultUrl", None)
         passwordKeyVaultMsiClientId = self.providerProperties.get("keyVaultCredentialsMsiClientID", None)
         if not sqlDbPasswordKeyVaultUrl or not passwordKeyVaultMsiClientId:
            self.tracer.error("[%s] if no password, sqlDbPasswordKeyVaultUrl and keyVaultCredentialsMsiClientID must be given" % self.fullName)
            return False

         # Determine URL of separate KeyVault
         self.tracer.info("[%s] fetching sql credentials from separate KeyVault" % self.fullName)
         try:
            passwordSearch = re.match(REGEX_EXTERNAL_KEYVAULT_URL,
                                      sqlDbPasswordKeyVaultUrl,
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
            self.sqlDbPassword = kv.getSecret(passwordName, None).value
         except Exception as e:
            self.tracer.error("[%s] error accessing the secret inside the separate KeyVault (%s)" % (self.fullName,
                                                                                                     e))
            return False        
      return True

   # Validate that we can establish a sql connection and run queries
   def validate(self) -> bool:
      self.tracer.info("connecting to sql instance (%s:%d) to run test query" % (self.sqlHostname,
                                                                                  self.sqlDbSqlPort))

      # Try to establish a sql connection using the details provided by the user
      try:
         connection = self._establishsqlConnectionToHost()
         cursor = connection.cursor()
         if not connection.isconnected():
            self.tracer.error("[%s] unable to validate connection status" % self.fullName)
            return False
      except Exception as e:
         self.tracer.error("[%s] could not establish sql connection %s:%d (%s)" % (self.fullName,
                                                                                    self.sqlHostname,
                                                                                    self.sqlDbSqlPort,
                                                                                    e))
         return False

      # Try to run a query against the services view
      # This query will (rightfully) fail if the sql license is expired
      try:
         cursor.execute("SELECT * FROM M_SERVICES")
         connection.close()
      except Exception as e:
         self.tracer.error("[%s] could run validation query (%s)" % (self.fullName, e))
         return False
      return True

   def _establishsqlConnectionToHost(self,
                                     SQLHostname: str = None,
                                     SQLUser: str = None,
                                     SQLPasswd: str = None) -> pyodbc.Connection:
      if not SQLHostname:
         SQLHostname = self.sqlHostname
      if not SQLUser:
         SQLUser = self.SQLUser
      if not SQLPasswd:
         SQLUser = self.SQLPasswd
         
      conn = pyodbc.connect("DRIVER={ODBC Driver 17 for SQL Server};SERVER=[%s];UID=[%s];PWD=[%s]" % (SQLHostname, SQLUser, SQLPasswd))         
         
                         

###############################################################################

# Implements a SAP sql-specific monitoring check
class sapsqlProviderCheck(ProviderCheck):
   lastResult = None
   colTimeGenerated = None
   
   def __init__(self,
                provider: ProviderInstance,
                **kwargs):
      return super().__init__(provider, **kwargs)

   # Obtain one working sql connection (client-side failover logic)
   def _getsqlConnection(self):
      self.tracer.info("[%s] establishing connection with sql instance" % self.fullName)

      # Check if sql host config has been retrieved from DB yet
      if "hostConfig" not in self.providerInstance.state:
         # Host config has not been retrieved yet; our only candidate is the one provided by user
         self.tracer.debug("[%s] no host config has been persisted yet, using user-provided host" % self.fullName)
         hostsToTry = [self.providerInstance.sqlHostname]
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
            connection = self.providerInstance._establishsqlConnectionToHost(hostname = host)
            # Validate that we're indeed connected
            if connection.isconnected():
               cursor = connection.cursor()
               break
         except Exception as e:
            self.tracer.warning("[%s] could not connect to sql node %s:%d (%s)" % (self.fullName,
                                                                                    host,
                                                                                    self.providerInstance.sqlDbSqlPort,
                                                                                    e))
      if not cursor:
         self.tracer.error("[%s] unable to connect to any sql node (hosts to try=%s)" % (self.fullName,
                                                                                          hostsToTry))
         return (None, None, None)
      return (connection, cursor, host)



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
   def _actionExecuteSql(self,
                    sql: str,
                    isTimeSeries: bool = False,
                    initialTimespanSecs: int = 60) -> bool:
      self.tracer.info("[%s] connecting to sql and executing SQL" % self.fullName)

      # Marking which column will be used for TimeGenerated
      self.colTimeGenerated = COL_TIMESERIES_UTC if isTimeSeries else COL_SERVER_UTC

      # Find and connect to sql server
      (connection, cursor, host) = self._getsqlConnection()
      if not connection:
         return False

      # Prepare SQL statement
      preparedSql = self._prepareSql(sql,
                                     isTimeSeries,
                                     initialTimespanSecs)
      if not preparedSql:
         return False

      # Execute SQL statement
      try:
         self.tracer.debug("[%s] executing SQL statement %s" % (self.fullName,
                                                                preparedSql))
         cursor.execute(preparedSql)
         colIndex = {col[0] : idx for idx, col in enumerate(cursor.description)}
         resultRows = cursor.fetchall()
      except Exception as e:
         self.tracer.error("[%s] could not execute SQL %s (%s)" % (self.fullName,
                                                                   preparedSql,
                                                                   e))
         return False

      self.lastResult = (colIndex, resultRows)
      self.tracer.debug("[%s] lastResult.colIndex=%s" % (self.fullName,
                                                         colIndex))
      self.tracer.debug("[%s] lastResult.resultRows=%s " % (self.fullName,
                                                            resultRows))

      # Update internal state
      if not self.updateState():
         return False

      # Disconnect from sql server to avoid memory leaks
      try:
         self.tracer.debug("[%s] closing sql connection" % self.fullName)
         connection.close()
      except Exception as e:
         self.tracer.error("[%s] could not close connection to sql instance (%s)" % (self.fullName,
                                                                                      e))
         return False

      self.tracer.info("[%s] successfully ran SQL for check" % self.fullName)
      return True



 
