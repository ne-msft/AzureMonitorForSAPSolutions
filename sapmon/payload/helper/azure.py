from azure.common.credentials import BasicTokenAuthentication
import base64
import hmac
import json

###############################################################################

class AzureInstanceMetadataService:
   """
   Provide access to the Azure Instance Metadata Service (IMS) inside the VM
   """
   uri     = "http://169.254.169.254/metadata"
   params  = {"api-version": "2018-02-01"}
   headers = {"Metadata": "true"}

   @staticmethod
   def _sendRequest(endpoint, params = {}, headers = {}):
      params.update(AzureInstanceMetadataService.params)
      headers.update(AzureInstanceMetadataService.headers)
      return REST.sendRequest(
         "%s/%s" % (AzureInstanceMetadataService.uri, endpoint),
         params  = params,
         headers = headers,
         )

   @staticmethod
   def getComputeInstance(operation):
      """
      Get the compute instance for the current VM via IMS
      """
      logger.info("getting compute instance")      
      computeInstance = None
      try:
         computeInstance = AzureInstanceMetadataService._sendRequest(
            "instance",
            headers = {"User-Agent": "SAP Monitor/%s (%s)" % (PAYLOAD_VERSION, operation)}
            )["compute"]
         logger.debug("computeInstance=%s" % computeInstance)
      except Exception as e:
         logger.error("could not obtain instance metadata (%s)" % e)
      return computeInstance

   @staticmethod
   def getAuthToken(resource, msiClientId = None):
      """
      Get an authentication token via IMDS
      """
      logger.info("getting auth token for resource=%s%s" % (resource, ", msiClientId=%s" % msiClientId if msiClientId else ""))
      authToken = None
      try:
         authToken = AzureInstanceMetadataService._sendRequest(
            "identity/oauth2/token",
            params = {"resource": resource, "client_id": msiClientId}
            )["access_token"]
      except Exception as e:
         logger.critical("could not get auth token (%s)" % e)
         sys.exit(ERROR_GETTING_AUTH_TOKEN)
      return authToken

###############################################################################

class AzureKeyVault:
   """
   Provide access to an Azure KeyVault instance
   """
   params  = {"api-version": "7.0"}

   def __init__(self, kvName, msiClientId = None):
      logger.info("initializing KeyVault %s" % kvName)
      self.kvName  = kvName
      self.uri     = "https://%s.vault.azure.net" % kvName
      self.token   = AzureInstanceMetadataService.getAuthToken("https://vault.azure.net", msiClientId)
      self.headers = {
         "Authorization": "Bearer %s" % self.token,
         "Content-Type":  "application/json"
         }

   def _sendRequest(self, endpoint, method = requests.get, data = None):
      """
      Easy access to KeyVault REST endpoints
      """
      response = REST.sendRequest(
         endpoint,
         method  = method,
         params  = self.params,
         headers = self.headers,
         data    = data,
         )
      if response and "value" in response:
         return (True, response["value"])
      return (False, None)

   def setSecret(self, secretName, secretValue):
      """
      Set a secret in the KeyVault
      """
      logger.info("setting KeyVault secret for secretName=%s" % secretName)
      success = False
      try:
         (success, response) = self._sendRequest(
            "%s/secrets/%s" % (self.uri, secretName),
            method = requests.put,
            data   = json.dumps({"value": secretValue})
            )
      except Exception as e:
         logger.critical("could not set KeyVault secret (%s)" % e)
         sys.exit(ERROR_SETTING_KEYVAULT_SECRET)
      return success

   def getSecret(self, secretId):
      """
      Get the current version of a specific secret in the KeyVault
      """
      logger.info("getting KeyVault secret for secretId=%s" % secretId)
      secret = None
      try:
         (success, secret) = self._sendRequest(secretId)
      except Exception as e:
         logger.error("could not get KeyVault secret for secretId=%s (%s)" % (secretId, e))
      return secret

   def getCurrentSecrets(self):
      """
      Get the current versions of all secrets inside the customer KeyVault
      """
      logger.info("getting current KeyVault secrets")
      secrets = {}
      try:
         (success, kvSecrets) = self._sendRequest("%s/secrets" % self.uri)
         logger.debug("kvSecrets=%s" % kvSecrets)
         for k in kvSecrets:
            id = k["id"].split("/")[-1]
            secrets[id] = self.getSecret(k["id"])
      except Exception as e:
         logger.error("could not get current KeyVault secrets (%s)" % e)
      return secrets

   def exists(self):
      """
      Check if a KeyVault with a specified name exists
      """
      logger.info("checking if KeyVault %s exists" % self.kvName)
      try:
         (success, response) = self._sendRequest("%s/secrets" % self.uri)
      except Exception as e:
         logger.error("could not determine is KeyVault %s exists (%s)" % (kvName, e))
      if success:
         logger.info("KeyVault %s exists" % self.kvName)
      else:
         logger.info("KeyVault %s does not exist" % self.kvName)
      return success

###############################################################################

class AzureLogAnalytics:
   """
   Provide access to an Azure Log Analytics WOrkspace
   """
   def __init__(self, workspaceId, sharedKey):
      logger.info("initializing Log Analytics instance")
      self.workspaceId = workspaceId
      self.sharedKey   = sharedKey
      self.uri         = "https://%s.ods.opinsights.azure.com/api/logs?api-version=2016-04-01" % workspaceId
      return

   def ingest(self, logType, jsonData, colTimeGenerated):
      """
      Ingest JSON payload as custom log to Log Analytics
      """
      def buildSig(content, timestamp):
         stringHash  = """POST
%d
application/json
x-ms-date:%s
/api/logs""" % (len(content), timestamp)
         bytesHash   = bytes(stringHash, encoding="utf-8")
         decodedKey  = base64.b64decode(self.sharedKey)
         encodedHash = base64.b64encode(hmac.new(
            decodedKey,
            bytesHash,
            digestmod=hashlib.sha256).digest()
         )
         stringHash = encodedHash.decode("utf-8")
         return "SharedKey %s:%s" % (self.workspaceId, stringHash)

      logger.info("ingesting telemetry into Log Analytics")
      timestamp = datetime.utcnow().strftime(TIME_FORMAT_LOG_ANALYTICS)
      headers = {
         "content-type":  "application/json",
         "Authorization": buildSig(jsonData, timestamp),
         "Log-Type":      logType,
         "x-ms-date":     timestamp,
         "time-generated-field": colTimeGenerated,
      }
      logger.debug("data=%s" % jsonData)
      response = None
      try:
         response = REST.sendRequest(
            self.uri,
            method  = requests.post,
            headers = headers,
            data    = jsonData,
            )
      except Exception as e:
         logger.error("could not ingest telemetry into Log Analytics (%s)" % e)
      return response

###############################################################################

class AzureStorageQueue():
    accountName = None
    name = None
    token = {}
    subscriptionId = None
    resourceGroup = None
    def __init__(self, sapmonId, msiClientID, subscriptionId, resourceGroup):
        """
        Retrieve the name of the storage account and storage queue
        """
        self.accountName = STORAGE_ACCOUNT_NAMING_CONVENTION % sapmonId
        self.name = STORAGE_QUEUE_NAMING_CONVENTION % sapmonId
        tokenResponse = AzureInstanceMetadataService.getAuthToken(resource="https://management.azure.com/", msiClientId=msiClientID)
        self.token["access_token"] = tokenResponse
        self.subscriptionId = subscriptionId
        self.resourceGroup = resourceGroup

    def getAccessKey(self):
        """
        Get the access key to the storage queue
        """
        storageclient = StorageManagementClient(credentials=BasicTokenAuthentication(self.token), subscription_id=self.subscriptionId)
        storageKeys = storageclient.storage_accounts.list_keys(resource_group_name=self.resourceGroup, account_name=self.accountName)
        if storageKeys is None or len(storageKeys.keys) <= 0 :
           print("Could not retrive storage keys of the storage account{0}".format(self.accountName))
           return None
        return storageKeys.keys[0].value