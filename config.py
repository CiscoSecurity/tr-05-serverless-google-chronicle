import os


class Config(object):
    API_URL = 'https://backstory.googleapis.com/v1'

    AUTH_SCOPES = ['https://www.googleapis.com/auth/chronicle-backstory']

    SECRET_KEY = os.environ.get('SECRET_KEY', '')

    CTR_ENTITIES_DEFAULT_LIMIT = 100
    CTR_ENTITIES_LIMIT = CTR_ENTITIES_DEFAULT_LIMIT

    try:
        custom_limit = int(os.environ['CTR_ENTITIES_LIMIT'])
        if custom_limit > 0:
            CTR_ENTITIES_LIMIT = custom_limit
    except Exception:
        pass

    DEFAULT_NUMBER_OF_DAYS_FOR_CHRONICLE_TIME_FILTER = 90

    USER_AGENT = ('Cisco Threat Response Integrations '
                  '<tr-integrations-support@cisco.com>')
