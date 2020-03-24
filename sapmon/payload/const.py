# Python modules
import logging
import os

# Version of the payload script
PAYLOAD_VERSION = "0.14.0"

# Default file/directory locations
PATH_PAYLOAD       = os.path.dirname(os.path.realpath(__file__))
PATH_ROOT          = os.path.abspath(os.path.join(PATH_PAYLOAD, ".."))
PATH_CONTENT       = os.path.join(PATH_ROOT, "content")
PATH_TRACE         = os.path.join(PATH_ROOT, "trace")
PATH_STATE         = os.path.join(PATH_ROOT, "state")
FILENAME_TRACE     = os.path.join(PATH_TRACE, "sapmon.trc")

# Time formats
TIME_FORMAT_LOG_ANALYTICS = "%a, %d %b %Y %H:%M:%S GMT"
TIME_FORMAT_JSON          = "%Y-%m-%dT%H:%M:%S.%fZ"
TIME_FORMAT_HANA          = "%Y-%m-%d %H:%M:%S.%f"

# Trace levels
DEFAULT_CONSOLE_TRACE_LEVEL = logging.DEBUG
DEFAULT_FILE_TRACE_LEVEL    = logging.INFO
DEFAULT_QUEUE_TRACE_LEVEL   = logging.DEBUG

# Config parameters
CONFIG_SECTION_GLOBAL = "global"
METHODNAME_ACTION     = "_action%s"
KV_SECRET_FORMAT      = "%s-%s"

# Naming conventions for generated resources
KEYVAULT_NAMING_CONVENTION               = "sapmon-kv-%s"
STORAGE_ACCOUNT_NAMING_CONVENTION        = "sapmonsto%s"
STORAGE_QUEUE_NAMING_CONVENTION          = "sapmon-que-%s"
CUSTOMER_METRICS_QUEUE_NAMING_CONVENTION = "sapmon-anl-%s"

# Error codes
ERROR_GETTING_AUTH_TOKEN       = 10
ERROR_SETTING_KEYVAULT_SECRET  = 20
ERROR_KEYVAULT_NOT_FOUND       = 21
ERROR_GETTING_LOG_CREDENTIALS  = 22
ERROR_GETTING_HANA_CREDENTIALS = 23
ERROR_HANA_CONNECTION          = 30
ERROR_FILE_PERMISSION_DENIED   = 40
ERROR_ONBOARDING               = 50
ERROR_LOADING_CONFIG           = 60
ERROR_ADDING_PROVIDER          = 70
ERROR_DELETING_PROVIDER        = 80
