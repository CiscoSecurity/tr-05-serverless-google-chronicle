from authlib.jose import jwt
from authlib.jose.errors import JoseError
from flask import request, current_app, jsonify
from google.oauth2 import service_account
from googleapiclient import _auth
from werkzeug.exceptions import Forbidden, BadRequest


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
        raise Forbidden('Invalid Authorization Bearer JWT.')


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
        raise Forbidden(f'Chronicle Backstory Authorization failed: {str(e)}.')

    return _auth.authorized_http(credentials)


def get_json(schema):
    """
    Parse the incoming request's data as JSON.
    Validate it against the specified schema.

    """

    data = request.get_json(force=True, silent=True, cache=False)

    message = schema.validate(data)

    if message:
        raise BadRequest(message)

    return data


def jsonify_data(data):
    return jsonify({'data': data})


def jsonify_errors(error):
    # Make the actual error payload compatible with the expected TR error
    # payload in order to fix the following types of possible UI alerts, e.g.:
    # :code (not (instance? java.lang.String 40x)),
    # :details disallowed-key,
    # :status disallowed-key,
    # etc.
    error['code'] = error.pop('status', '').lower()
    error.pop('details', None)

    # According to the official documentation, an error here means that the
    # corresponding TR module is in an incorrect state and needs to be
    # reconfigured:
    # https://visibility.amp.cisco.com/help/alerts-errors-warnings.
    error['type'] = 'fatal'

    return jsonify({'errors': [error]})


def join_url(base, *parts):
    return '/'.join(
        [base.rstrip('/')] +
        [part.strip('/') for part in parts]
    )


def format_time_to_arg(input_datetime):
    """
       Converts datetime to yyyy-MM-dd'T'HH:mm:ss'Z' format
       acceptable by Chronicle Backstory API

    """
    return f'{input_datetime.isoformat(timespec="seconds")}Z'
