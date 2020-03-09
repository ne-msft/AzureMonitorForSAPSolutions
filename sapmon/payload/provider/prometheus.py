# Python modules
import json
import logging

# Payload modules
from const import PAYLOAD_VERSION
from helper.tools import JsonEncoder
from provider.base import ProviderInstance, ProviderCheck
from typing import Dict, List

# provider specific modules
from prometheus_client.samples import Sample
from prometheus_client.parser import text_string_to_metric_families
import uuid
import re
import requests
from requests.exceptions import Timeout
import urllib
from datetime import datetime,timezone
###############################################################################

class prometheusProviderInstance(ProviderInstance):
    metricsUrl = None
    HTTP_TIMEOUT = (2, 5) # timeouts: 2s connect, 5s read

    def __init__(self,
               tracer: logging.Logger,
               providerInstance: Dict[str, str],
               skipContent: bool = False,
               **kwargs):
        super().__init__(tracer,
                         providerInstance,
                         skipContent,
                         **kwargs)

    def parseProperties(self):
        ### Fixme: Should this validate the url format?
        self.metricsUrl = self.providerProperties.get("prometheusUrl", None)
        if not self.metricsUrl:
            self.tracer.error("[%s] PrometheusUrl cannot be empty" % self.fullName)
            return False
        self.instance_name = urllib.parse.urlparse(self.metricsUrl).netloc
        return True

    def validate(self) -> bool:
        self.tracer.info("fetching data from %s to validate connection" % self.metricsUrl)
        return bool(self.fetch_metrics())

    def fetch_metrics(self) -> str:
        try:
            resp = requests.get(self.metricsUrl, timeout = self.HTTP_TIMEOUT)
            resp.raise_for_status()
            return resp.text
        except Exception as err:
            self.tracer.info("Failed to fetch %s (%s)" % (self.metricsUrl, err))
            return None

    @property
    def instance(self):
        return self.instance_name

# Implements a generic prometheus collector
class prometheusProviderCheck(ProviderCheck):
    colTimeGenerated = None
    excludeRegex = re.compile(r"^(?:go|promhttp|process)_")
    lastResult = ([], None)

    def __init__(self,
                 provider: ProviderInstance,
                 **kwargs):
        return super().__init__(provider, **kwargs)

    def _actionFetchMetrics(self,
                            includePrefixes: str) -> bool:
        self.tracer.info("[%s] Fetching metrics" % self.fullName)
        metricsData = self.providerInstance.fetch_metrics()
        self.lastResult=(metricsData, includePrefixes)
        if metricsData == None:
            self.tracer.info("[%s] Unable to fetch metrics" % self.fullName)
            return False
        return self.updateState()

    # Convert last result into a JSON string (as required by Log Analytics Data Collector API)
    def generateJsonString(self) -> str:
        # The correlation_id can be used to group fields from the same metrics call
        correlation_id = str(uuid.uuid4())
        fallback_datetime=datetime.now(timezone.utc)

        def prometheusSample2Dict(sample):
            """
            Convert a prometheus metric sample to Python dictionary for serialization
            """
            TimeGenerated = fallback_datetime
            if sample.timestamp:
                TimeGenerated = datetime.fromtimestamp(sample.timestamp, tz=timezone.utc)
            sample.labels["instance"] = self.providerInstance.instance
            sample_dict = {
                "name" : sample.name,
                "labels" : json.dumps(sample.labels, separators=(',',':'), sort_keys=True),
                "value" : sample.value,
                "TimeGenerated": TimeGenerated,
                "instance": self.providerInstance.instance,
                "correlation_id": correlation_id
            }
            # FIXME: Implement custom fields
            #for (k, v) in promUrl.customFields:
            #    sample_dict["custom_%s" % k] = v
            return sample_dict

        def filter_prometheus_metric(metric):
            """
            Filter out names based on our exclude and include lists
            """
            if includePrefixesRegex:
                return bool(includePrefixesRegex.match(metric.name))
            return not bool(self.excludeRegex.match(metric.name))

        prometheusMetricsText = self.lastResult[0]
        includePrefixes = self.lastResult[1]
        # If a prefix was given it has to compile to a valid regular expression
        if includePrefixes:
            try:
                includePrefixesRegex = re.compile(includePrefixes)
            except re.error:
                self.tracer.error("[%s] includePrefixes must be a valid regular expression: %s" %
                                  (self.fullName, includePrefixes))
                return False
        resultSet = list()
        self.tracer.info("converting result set into JSON")
        try:
            if not prometheusMetricsText:
                raise ValueError("Empty result from prometheus instance %s", self.providerInstance.instance)
            for family in filter(filter_prometheus_metric,
                                 text_string_to_metric_families(prometheusMetricsText)):
                resultSet.extend(map(prometheusSample2Dict, family.samples))
        except ValueError as e:
            self.tracer.error("Could not parse prometheus metrics (%s): %s" % (e, prometheusMetricsText))
            resultSet.append(prometheusSample2Dict(Sample("up", dict(), 0)))
        else:
            # The up-metric is used to determine whatever valid data could be read from
            # the prometheus endpoint and is used by prometheus in a similar way
            resultSet.append(prometheusSample2Dict(Sample("up", dict(), 1)))
        resultSet.append(prometheusSample2Dict(
            Sample("sapmon",
                   {
                       "content_version": self.providerInstance.contentVersion,
                       "sapmon_version": PAYLOAD_VERSION,
                       "provider_instance": self.providerInstance.name
                   }, 1)))
        # Convert temporary dictionary into JSON string
        try:
            # Use a very compact json representation to limit amount of data parsed by LA
            resultJsonString = json.dumps(resultSet, sort_keys=True,
                                          separators=(',',':'),
                                          cls=JsonEncoder)
            self.tracer.debug("[%s] resultJson=%s" % (self.fullName, str(resultJsonString)[:1000]))
        except Exception as e:
            self.tracer.error("[%s] could not format logItem=%s into JSON (%s)" % (self.fullName,
                                                                                   resultSet[:50],
                                                                                   e))
        return resultJsonString

    # Update the internal state of this check (including last run times)
    def updateState(self) -> bool:
        self.tracer.info("[%s] updating internal state" % self.fullName)
        self.state["lastRunLocal"] = datetime.utcnow()
        self.tracer.info("[%s] internal state successfully updated" % self.fullName)
        return True

