from datetime import date, datetime, timedelta
import decimal
import http.client as http_client
import json
import logging
import requests

###############################################################################

class REST:
   """
   Provide access to a REST endpoint
   """
   @staticmethod
   # TODO(tniek) - improve error handling (include HTTP status together with response)
   def sendRequest(endpoint, method = requests.get, params = {}, headers = {}, timeout = 5, data = None, debug = False):
      if debug:
         http_client.HTTPConnection.debuglevel = 1
         logging.basicConfig()
         logging.getLogger().setLevel(logging.DEBUG)
         requests_log = logging.getLogger("requests.packages.urllib3")
         requests_log.setLevel(logging.DEBUG)
         requests_log.propagate = True
      try:
         response = method(
            endpoint,
            params  = params,
            headers = headers,
            timeout = timeout,
            data    = data,
            )
         if response.status_code == requests.codes.ok:
            contentType = response.headers.get("content-type")
            if contentType and contentType.find("json") >= 0:
               return json.loads(response.content.decode("utf-8"))
            else:
               return response.content
         else:
            print(response.content) # poor man's logging
            response.raise_for_status()
      except Exception as e:
         logger.error("could not send HTTP request (%s)" % e)
         return None

###############################################################################

class _JsonEncoder(json.JSONEncoder):
   """
   Helper class to serialize datetime and Decimal objects into JSON
   """
   def default(self, o):
      if isinstance(o, decimal.Decimal):
         return float(o)
      elif isinstance(o, (datetime, date)):
         return datetime.strftime(o, TIME_FORMAT_JSON)
      return super(_JsonEncoder, self).default(o)

class _JsonDecoder(json.JSONDecoder):
   """
   Helper class to de-serialize JSON into datetime and Decimal objects
   """
   def datetimeHook(jsonData):
      for (k, v) in jsonData.items():
         try:
            jsonData[k] = datetime.strptime(v, TIME_FORMAT_JSON)
         except Exception as e:
            pass
      return jsonData
