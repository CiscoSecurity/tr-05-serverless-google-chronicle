from authlib.jose import jwt
from authlib.jose.errors import JoseError, BadSignatureError, DecodeError
from flask import request, current_app, jsonify, g
from google.oauth2 import service_account
from googleapiclient import _auth

from api.errors import (
    AuthorizationError,
    InvalidChronicleCredentialsError,
    InvalidArgumentError
)


def get_auth_token() -> [str, Exception]:
    """Parse the incoming request's Authorization header and Validate it."""
    expected_errors = {
        KeyError: 'Authorization header is missing',
        AssertionError: 'Wrong authorization type'
    }
    try:
        scheme, token = request.headers['Authorization'].split()
        assert scheme.lower() == 'bearer'
        return token
    except tuple(expected_errors) as error:
        raise AuthorizationError(expected_errors[error.__class__])


def get_jwt() -> [str, Exception]:
    """
    Get Authorization token and validate its signature
    according the application's secret key .
    """
    expected_errors = {
        # KeyError: 'Wrong JWT payload structure',
        TypeError: '<SECRET_KEY> is missing',
        BadSignatureError: 'Failed to decode JWT with provided key',
        DecodeError: 'Wrong JWT structure'
    }
    token = get_auth_token()
    try:
        payload = jwt.decode(token, current_app.config['SECRET_KEY'])
        return payload
    except tuple(expected_errors) as error:
        message = expected_errors[error.__class__]
        raise AuthorizationError(message)


def get_chronicle_http_client(account_info):
    """
    Return an http client that is authorized with the given credentials
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


def format_docs(docs):
    return {'count': len(docs), 'docs': docs}


def jsonify_data(data):
    return jsonify({'data': data})


def jsonify_errors(error):
    return jsonify({'errors': [error]})


def jsonify_result():
    result = {'data': {}}

    if g.get('sightings'):
        result['data']['sightings'] = format_docs(g.sightings)

    if g.get('indicators'):
        result['data']['indicators'] = format_docs(g.indicators)

    if g.get('relationships'):
        result['data']['relationships'] = format_docs(g.relationships)

    if g.get('errors'):
        result['errors'] = g.errors

    return jsonify(result)


def join_url(base, *parts):
    return '/'.join(
        [base.rstrip('/')] +
        [part.strip('/') for part in parts]
    )


def all_subclasses(cls):
    """
    Retrieve set of class subclasses recursively.
    """
    subclasses = set(cls.__subclasses__())
    return subclasses.union(s for c in subclasses for s in all_subclasses(c))
