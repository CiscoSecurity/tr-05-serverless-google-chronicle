import json
from uuid import NAMESPACE_X500


class Config(object):
    settings = json.load(open('container_settings.json', 'r'))
    VERSION = settings['VERSION']

    API_URL = 'https://backstory.googleapis.com/v1'

    AUTH_SCOPES = ['https://www.googleapis.com/auth/chronicle-backstory']

    CTR_ENTITIES_DEFAULT_LIMIT = 100

    DEFAULT_NUMBER_OF_DAYS_FOR_CHRONICLE_TIME_FILTER = 90

    USER_AGENT = ('SecureX Threat Response Integrations '
                  '<tr-integrations-support@cisco.com>')

    NAMESPACE_BASE = NAMESPACE_X500
