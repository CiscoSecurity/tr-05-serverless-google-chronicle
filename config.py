import os


class Config(object):
    API_URL = 'https://backstory.googleapis.com/v1'

    AUTH_SCOPES = ['https://www.googleapis.com/auth/chronicle-backstory']

    SECRET_KEY = os.environ.get('SECRET_KEY', '')
