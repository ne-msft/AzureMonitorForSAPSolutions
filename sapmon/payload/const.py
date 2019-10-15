import logging
import os

PAYLOAD_VERSION                   = "0.7.0"

PATH_PAYLOAD                      = os.path.dirname(os.path.realpath(__file__))
PATH_ROOT                         = os.path.abspath(os.path.join(PATH_PAYLOAD, ".."))
PATH_CONTENT                      = os.path.join(PATH_ROOT, "content")
PATH_TRACE                        = os.path.join(PATH_ROOT, "trace")
PATH_STATE                        = os.path.join(PATH_ROOT, "state")
FILENAME_STATEFILE                = os.path.join(PATH_STATE, "sapmon.state")
FILENAME_TRACE                    = os.path.join(PATH_TRACE, "sapmon.trc")

TIME_FORMAT_LOG_ANALYTICS         = "%a, %d %b %Y %H:%M:%S GMT"
TIME_FORMAT_JSON                  = "%Y-%m-%dT%H:%M:%S.%fZ"

DEFAULT_CONSOLE_TRACE_LEVEL       = logging.INFO
DEFAULT_FILE_TRACE_LEVEL          = logging.INFO
DEFAULT_QUEUE_TRACE_LEVEL         = logging.DEBUG

KEYVAULT_NAMING_CONVENTION        = "sapmon-kv-%s"
STORAGE_ACCOUNT_NAMING_CONVENTION = "sapmonsto%s"
STORAGE_QUEUE_NAMING_CONVENTION   = "sapmon-que-%s"

ERROR_GETTING_AUTH_TOKEN          = 10
ERROR_SETTING_KEYVAULT_SECRET     = 20
ERROR_KEYVAULT_NOT_FOUND          = 21
ERROR_GETTING_LOG_CREDENTIALS     = 22
ERROR_GETTING_HANA_CREDENTIALS    = 23
ERROR_HANA_CONNECTION             = 30
ERROR_FILE_PERMISSION_DENIED      = 40

