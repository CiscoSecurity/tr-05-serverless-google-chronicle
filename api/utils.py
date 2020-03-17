from datetime import datetime, timedelta

from authlib.jose import jwt
from authlib.jose.errors import JoseError
from flask import request, current_app, jsonify
from google.oauth2 import service_account
from googleapiclient import _auth

from api.errors import (
    InvalidJWTError,
    InvalidChronicleCredentialsError,
    TRFormattedError,
    InvalidArgumentError
)


def get_jwt():
    """
    Parse the incoming request's Authorization Bearer JWT for some credentials.
    Validate its signature against the application's secret key.

    """

    try:
        scheme, token = request.headers['Authorization'].split()
        assert scheme.lower() == 'bearer'
        return jwt.decode(token, current_app.config['SECRET_KEY'])
    except (KeyError, ValueError, AssertionError, JoseError):
        raise InvalidJWTError()


def get_chronicle_http_client(account_info):
    """
    Returns an http client that is authorized with the given credentials
    using oauth2client or google-auth.

    """
    try:
        credentials = service_account.Credentials.from_service_account_info(
            account_info, scopes=current_app.config['AUTH_SCOPES']
        )
    except ValueError as e:
        raise InvalidChronicleCredentialsError(str(e))

    return _auth.authorized_http(credentials)


def get_json(schema):
    """
    Parse the incoming request's data as JSON.
    Validate it against the specified schema.

    """

    data = request.get_json(force=True, silent=True, cache=False)

    message = schema.validate(data)

    if message:
        raise InvalidArgumentError(message)

    return data


def jsonify_data(data):
    return jsonify({'data': data})


def jsonify_errors(error):
    if issubclass(type(error), TRFormattedError):
        error = error.json

    return jsonify({'errors': [error.json]})


def join_url(base, *parts):
    return '/'.join(
        [base.rstrip('/')] +
        [part.strip('/') for part in parts]
    )


class TimeFilter:
    def __init__(self):
        self.end = datetime.utcnow()
        delta = timedelta(
            days=current_app.config[
                'DEFAULT_NUMBER_OF_DAYS_FOR_CHRONICLE_TIME_FILTER'
            ]
        )
        self.start = self.end - delta

    @staticmethod
    def format_time_to_arg(input_datetime):
        """
           Converts datetime to yyyy-MM-dd'T'HH:mm:ss'Z' format
           acceptable by Chronicle Backstory API

        """
        return f'{input_datetime.isoformat(timespec="seconds")}Z'

    def __str__(self):
        return (f'&start_time={self.format_time_to_arg(self.start)}'
                f'&end_time={self.format_time_to_arg(self.end)}')
