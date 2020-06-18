# Python modules
from datetime import date, datetime, timedelta
import decimal
import http.client as http_client
import json
import logging
import requests
from typing import Callable, Dict, Optional
from binascii import hexlify

# Payload modules
from const import *

###############################################################################

# Provide access to a REST endpoint
class REST:
   @staticmethod
   # TODO - improve error handling (include HTTP status together with response)
   def sendRequest(tracer: logging.Logger,
                   endpoint: str,
                   method: Callable = requests.get,
                   params: Optional[Dict[str, str]] = None,
                   headers: Optional[Dict[str, str]] = None,
                   timeout: int = 5,
                   data: bytes = None,
                   debug: bool = False) -> str:
      if debug:
         # TODO - improve tracing
         http_client.HTTPConnection.debuglevel = 1
         logging.basicConfig()
         logging.gettracer().setLevel(logging.DEBUG)
         requests_log = logging.gettracer("requests.packages.urllib3")
         requests_log.setLevel(logging.DEBUG)
         requests_log.propagate = True
      try:
         response = method(endpoint,
                           params = params if params else {},
                           headers = headers if headers else {},
                           timeout = timeout,
                           data = data)
         # Only accept 200 OK
         if response.status_code == requests.codes.ok:
            contentType = response.headers.get("content-type")
            if contentType and contentType.find("json") >= 0:
               return json.loads(response.content.decode("utf-8"))
            else:
               return response.content
         else:
            tracer.debug(response.content) # poor man's logging
            response.raise_for_status()
      except Exception as e:
         tracer.error("could not send HTTP request (%s)" % e)
         return None

###############################################################################

# Helper class to serialize datetime and Decimal objects into JSON
class JsonEncoder(json.JSONEncoder):
   # Overwrite encoder for Decimal and datetime objects
   def default(self,
               o: object) -> object:
      if isinstance(o, decimal.Decimal):
         return float(o)
      elif isinstance(o, (datetime, date)):
         return datetime.strftime(o, TIME_FORMAT_JSON)
      elif isinstance(o, bytes):
         s = hexlify(o).decode("ascii")
         return "0x%s" % s.upper()
      return super(_JsonEncoder, self).default(o)      

# Helper class to de-serialize JSON into datetime and Decimal objects
class JsonDecoder(json.JSONDecoder):
   def datetimeHook(jsonData: Dict[str, str]) -> Dict[str, str]:
      for (k, v) in jsonData.items():
         try:
            jsonData[k] = datetime.strptime(v, TIME_FORMAT_JSON)
         except Exception as e:
            pass
      return jsonData

###############################################################################

# Helper class to implement singleton
class Singleton(type):
   _instances = {}
   def __call__(cls, *args, **kwargs):
      if cls not in cls._instances:
         cls._instances[cls] = super(Singleton, cls).__call__(*args, **kwargs)
      return cls._instances[cls]
