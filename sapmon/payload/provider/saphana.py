import hashlib
import json
import pyhdb

###############################################################################

class SapHanaCheck(SapmonCheck):
   """
   Implements a SAP HANA-specific monitoring check
   """
   COL_SERVER_UTC      = "_SERVER_UTC"
   COL_TIMESERIES_UTC  = "_TIMESERIES_UTC"
   COL_CONTENT_VERSION = "CONTENT_VERSION"
   COL_SAPMON_VERSION  = "SAPMON_VERSION"
   TIME_FORMAT_HANA    = "%Y-%m-%d %H:%M:%S.%f"

   prefix             = "HANA"
   isTimeSeries       = False
   colIndex           = {}
   lastResult         = []
   def __init__(self, hanaOptions, **kwargs):
      super().__init__(**kwargs)
      self.query                  = hanaOptions["query"]
      self.isTimeSeries           = hanaOptions.get("isTimeSeries", False)
      self.colTimeGenerated       = self.COL_TIMESERIES_UTC if self.isTimeSeries else self.COL_SERVER_UTC
      self.initialTimespanSecs    = hanaOptions.get("initialTimespanSecs", 0)
      self.state["lastRunServer"] = None

   def prepareSql(self):
      """
      Prepare the SQL statement based on the check-specific query
      """
      logger.info("preparing SQL statement")
      # insert logic to get server UTC time (_SERVER_UTC)
      sqlTimestamp = ", '%s' AS %s, '%s' AS %s, CURRENT_UTCTIMESTAMP AS %s FROM DUMMY," % \
         (self.version, self.COL_CONTENT_VERSION, PAYLOAD_VERSION, self.COL_SAPMON_VERSION, self.COL_SERVER_UTC)
      logger.debug("sqlTimestamp=%s" % sqlTimestamp)
      sql = self.query.replace(" FROM", sqlTimestamp, 1)
      # if time series, insert time condition
      if self.isTimeSeries:
         lastRunServer = self.state.get("lastRunServer", None)
         # TODO(tniek) - make WHERE conditions for time series queries more flexible
         if not lastRunServer:
            logger.info("time series query for check %s_%s has never been run, applying initalTimespanSecs=%d" % \
               (self.prefix, self.name, self.initialTimespanSecs))
            lastRunServerUtc = "ADD_SECONDS(NOW(), i.VALUE*(-1) - %d)" % self.initialTimespanSecs
         else:
            if not isinstance(lastRunServer, datetime):
               logger.error("lastRunServer=%s has not been de-serialized into a valid datetime object" % str(lastRunServer))
               return None
            try:
               lastRunServerUtc = "'%s'" % lastRunServer.strftime(self.TIME_FORMAT_HANA)
            except:
               logger.error("could not format lastRunServer=%s into HANA format" % str(lastRunServer))
               return None
            logger.info("time series query for check %s_%s has been run at %s, filter out only new records since then" % \
               (self.prefix, self.name, lastRunServerUtc))
         logger.debug("lastRunServerUtc = %s" % lastRunServerUtc)
         sql = sql.replace("{lastRunServerUtc}", lastRunServerUtc, 1)
         logger.debug("sql=%s" % sql)
         # sys.exit()
      return sql

   def run(self, hana):
      """
      Run this SAP HANA-specific check
      """
      logger.info("running HANA SQL query")
      sql = self.prepareSql()
      if sql:
         self.colIndex, self.lastResult = hana.runQuery(sql)
         self.updateState(hana)
      resultJson = self.convertResultIntoJson()
      return resultJson

   def calculateResultHash(self):
      """
      Calculate the MD5 hash of a result set
      """
      logger.info("calculating SQL result hash")
      resultHash = None
      if len(self.lastResult) == 0:
         logger.debug("SQL result is empty")
      else:
         try:
            resultHash = hashlib.md5(str(self.lastResult).encode("utf-8")).hexdigest()
            logger.debug("resultHash=%s" % resultHash)
         except Exception as e:
            logger.error("could not calculate result hash (%s)" % e)
      return resultHash

   def convertResultIntoJson(self):
      """
      Convert the last query result into a JSON-formatted string (as required by Log Analytics)
      """
      logger.info("converting result set into JSON")
      logData  = []
      jsonData = "{}"
      for r in self.lastResult:
         logItem = {}
         for c in self.colIndex.keys():
            if c != self.colTimeGenerated and (c.startswith("_") or c == "DUMMY"): # remove internal fields
               continue
            logItem[c] = r[self.colIndex[c]]
         logData.append(logItem)
      try:
         resultJson = json.dumps(logData, sort_keys=True, indent=4, cls=_JsonEncoder)
         logger.debug("resultJson=%s" % str(resultJson))
      except Exception as e:
         logger.error("could not encode logItem=%s into JSON (%s)" % (logItem, e))
      return resultJson

   def updateState(self, hana):
      """
      Update the internal state of this check (including last run times)
      """
      logger.info("updating internal state of check %s_%s" % (self.prefix, self.name))
      self.state["lastRunLocal"] = datetime.utcnow()
      if len(self.lastResult) == 0:
         logger.info("SQL result is empty")
         return False
      self.state["lastRunServer"] = self.lastResult[0][self.colIndex[self.COL_SERVER_UTC]]
      self.state["lastResultHash"] = self.calculateResultHash()
      logger.info("internal state successfully updated")
      return True

###############################################################################

class SapHana:
   """
   Provide access to a HANA Database (HDB) instance
   """
   TIMEOUT_HANA_SECS = 5

   connection = None
   cursor     = None
   def __init__(self, host = None, port = None, user = None, password = None, hanaDetails = None):
      logger.info("initializing HANA instance")
      if hanaDetails:
         self.host     = hanaDetails["HanaHostname"]
         self.port     = hanaDetails["HanaDbSqlPort"]
         self.user     = hanaDetails["HanaDbUsername"]
         self.password = hanaDetails["HanaDbPassword"]
      else:
         self.host     = host
         self.port     = port
         self.user     = user
         self.password = password

   def connect(self):
      """
      Connect to a HDB instance
      """
      self.connection = pyhdb.Connection(
         host = self.host,
         port = self.port,
         user = self.user,
         password = self.password,
         timeout = self.TIMEOUT_HANA_SECS,
         )
      self.connection.connect()
      self.cursor = self.connection.cursor()

   def disconnect(self):
      """
      Close an open HDB connection
      """
      self.connection.close()

   def runQuery(self, sql):
      """
      Execute a SQL query
      """
      self.cursor.execute(sql)
      colIndex = {col[0] : idx for idx, col in enumerate(self.cursor.description)}
      return colIndex, self.cursor.fetchall()
