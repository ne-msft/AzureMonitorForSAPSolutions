# Python modules
import hashlib
import json
import logging
import time
from datetime import datetime,timezone
import uuid
import re
from prometheus_client.parser import text_string_to_metric_families
import requests
from requests.exceptions import Timeout
# Payload modules
from const import *
from helper.tools import *
from provider.base import *
from typing import Dict, List

###############################################################################

class HttpConnection(SapmonConnection):
    HTTP_TIMEOUT = (2, 5) # timeouts: 2s connect, 5s read

    def __init__(self,
                tracer:logging.Logger,
                connectionDetails = Dict[str,str]):
        self.tracer = tracer
        self.url=connectionDetails["PrometheusUrl"]
        self.enabledChecks = set(connectionDetails["enabledChecks"] or [])
        self.tracer.info("Created connection for %s and enabled %s" % (self.url, self.enabledChecks))

    def isCheckEnabled(self, check):
        self.tracer.info("Checking %s in set %s" % (check.fullname, self.enabledChecks))
        return check.fullname in self.enabledChecks

    def connect(self):
        return True

    def disconnect(self):
        return True

    def fetch(self):
        try:
            resp = requests.get(self.url, timeout = (2,5))
            resp.raise_for_status()
            return resp.text
        except Exception as err:
            self.tracer.info("Failed to fetch %s (%s)" % (self.url, err))
            return None

# Implements a generic prometheus collector
class PrometheusCheck(SapmonCheck):
    COL_TIME_GENERATED = "TIME_GENERATED"
    COL_SERVER_UTC = "_SERVER_UTC"
    COL_TIMESERIES_UTC = "_TIMESERIES_UTC"
    COL_CONTENT_VERSION = "CONTENT_VERSION"
    COL_SAPMON_VERSION = "SAPMON_VERSION"
    isTimeSeries = False

    def __init__(self,
            tracer: logging.Logger,
            prometheusOptions: Dict[str, str],
            **kwargs):
        super().__init__(tracer, prefix = "Prometheus", **kwargs)
        # The default will ignore go_, promhttp_ and process_ fields, which are only relevant for
        # direct application monitoring. Everything else is included
        includePrefixes = prometheusOptions.get("includePrefixes", None)
        self.includePrefixesRegexp = re.compile(includePrefixes) if includePrefixes else None
        excludePrefixes = prometheusOptions.get("excludePrefixes", r"^(?:go|promhttp|process)_" )
        self.excludePrefixesRegexp = re.compile(excludePrefixes) if excludePrefixes else None

        self.colTimeGenerated = self.COL_TIME_GENERATED
        self.initialTimespanSecs = prometheusOptions.get("initialTimespanSecs", 0)
        self.state["lastRunServer"] = None

    def run(self,
            promUrl: HttpConnection) -> str:
        if not isinstance(promUrl, HttpConnection):
            return None
        self.tracer.info("Fetching prometheus data - Start")
        data = promUrl.fetch()
        self.tracer.info("Fetching prometheus data - Done")
        # But still always convert into a JSON string
        return self.convertResultIntoJson(data)

    # Convert last result into a JSON string (as required by Log Analytics Data Collector API)
    def convertResultIntoJson(self, promData):
        correlation_id = str(uuid.uuid4())
        isotime_fallback = time.time()
        
        # There should only be a small number of possible timestamps
        # Instead of converting all of them we'll use a cache
        timecache = dict()
        def convert_timestamp_cached(timestamp):
            if timestamp not in timecache:
                timecache[timestamp] = datetime.fromtimestamp(timestamp, tz=timezone.utc).isoformat()+"Z"
            return timecache[timestamp]

        def prometheusSample2Dict(sample):
            """
            Convert a prometheus metric sample to Python dictionary for serialization
            FIXME: It might be cleaner to have this as part of a custom encoder
            """
            self.tracer.debug("Converting %s" % str(sample))
            sample_dict = {
                "name" : sample.name,
                "labels" : json.dumps(sample.labels),
                "value" : sample.value,
                # Prefer the usage of metric provided timestamp, fall back to using our own
                "timestamp_unix": sample.timestamp if sample.timestamp is not None else isotime_fallback,
                self.COL_TIME_GENERATED: convert_timestamp_cached(sample.timestamp if sample.timestamp is not None else isotime_fallback),
                # Needs to be defined
                "hostname": "pacemakertest",
                "correlation_id": correlation_id}
            self.tracer.debug("Converted to %s" % str(sample_dict))
            return sample_dict

        def filter_prometheus_metric(metric):
            """
            Filter out names based on our exclude and include lists
            """
            if self.includePrefixesRegexp:
                if self.includePrefixesRegexp.match(metric.name):
                    return True
                return False
            if self.excludePrefixesRegexp:
                if self.excludePrefixesRegexp.match(metric.name):
                    return False
            return True

        resultSet = list()
        self.tracer.info("converting result set into JSON")
        for family in filter(filter_prometheus_metric, text_string_to_metric_families(promData)):
            resultSet.extend(map(prometheusSample2Dict, family.samples))
        # FixMe: What is the impact of using the custom JsonEncoder?
        return json.dumps(resultSet) 

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


    # Update the internal state of this check (including last run times)
    def updateState(self,
            hana: HttpConnection) -> bool:
        self.tracer.info("updating internal state of check %s_%s" % (self.prefix, self.name))
        self.state["lastRunLocal"] = datetime.utcnow()
        if len(self.lastResult) == 0:
            self.tracer.info("SQL result is empty")
            return False
        self.state["lastRunServer"] = self.lastResult[0][self.colIndex[self.COL_SERVER_UTC]]
        self.state["lastResultHash"] = self.calculateResultHash()
        self.tracer.info("internal state successfully updated")
        return True
