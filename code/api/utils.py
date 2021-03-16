import json

import jwt
import requests
from flask import request, current_app, jsonify, g
from google.oauth2 import service_account
from googleapiclient import _auth
from jwt import InvalidSignatureError, DecodeError, InvalidAudienceError
from requests.exceptions import ConnectionError, InvalidURL

from api.errors import (
    AuthorizationError,
    InvalidArgumentError
)

NO_AUTH_HEADER = 'Authorization header is missing'
WRONG_AUTH_TYPE = 'Wrong authorization type'
WRONG_PAYLOAD_STRUCTURE = 'Wrong JWT payload structure'
WRONG_JWT_STRUCTURE = 'Wrong JWT structure'
WRONG_AUDIENCE = 'Wrong configuration-token-audience'
KID_NOT_FOUND = 'kid from JWT header not found in API response'
WRONG_KEY = ('Failed to decode JWT with provided key. '
             'Make sure domain in custom_jwks_host '
             'corresponds to your SecureX instance region.')
JWKS_HOST_MISSING = ('jwks_host is missing in JWT payload. Make sure '
                     'custom_jwks_host field is present in module_type')
WRONG_JWKS_HOST = ('Wrong jwks_host in JWT payload. Make sure domain follows '
                   'the visibility.<region>.cisco.com structure')


def set_ctr_entities_limit(payload):
    try:
        ctr_entities_limit = int(payload['CTR_ENTITIES_LIMIT'])
        assert ctr_entities_limit > 0
    except (KeyError, ValueError, AssertionError):
        ctr_entities_limit = current_app.config['CTR_ENTITIES_DEFAULT_LIMIT']
    current_app.config['CTR_ENTITIES_LIMIT'] = ctr_entities_limit


def get_public_key(jwks_host, token):
    expected_errors = {
        ConnectionError: WRONG_JWKS_HOST,
        InvalidURL: WRONG_JWKS_HOST,
    }

    try:
        response = requests.get(f"https://{jwks_host}/.well-known/jwks")
        jwks = response.json()

        public_keys = {}
        for jwk in jwks['keys']:
            kid = jwk['kid']
            public_keys[kid] = jwt.algorithms.RSAAlgorithm.from_jwk(
                json.dumps(jwk)
            )
        kid = jwt.get_unverified_header(token)['kid']
        return public_keys.get(kid)
    except tuple(expected_errors) as error:
        message = expected_errors[error.__class__]
        raise AuthorizationError(message)


def get_auth_token() -> [str, Exception]:
    """
    Parse and validate incoming request Authorization header.
    """
    expected_errors = {
        KeyError: NO_AUTH_HEADER,
        AssertionError: WRONG_AUTH_TYPE
    }
    try:
        scheme, token = request.headers['Authorization'].split()
        assert scheme.lower() == 'bearer'
        return token
    except tuple(expected_errors) as error:
        raise AuthorizationError(expected_errors[error.__class__])


def get_jwt() -> [dict, Exception]:
    """
    Get authorization token and validate its signature against the public key
    from /.well-known/jwks endpoint
    """
    jwt_payload_keys = {
        'private_key',
        'client_email',
        'token_uri'
    }
    expected_errors = {
        AssertionError: WRONG_PAYLOAD_STRUCTURE,
        KeyError: JWKS_HOST_MISSING,
        InvalidSignatureError: WRONG_KEY,
        DecodeError: WRONG_JWT_STRUCTURE,
        InvalidAudienceError: WRONG_AUDIENCE,
        TypeError: KID_NOT_FOUND
    }
    token = get_auth_token()
    try:
        jwks_host = jwt.decode(
            token, options={'verify_signature': False}
        )['jwks_host']
        key = get_public_key(jwks_host, token)
        aud = request.url_root
        payload = jwt.decode(
            token, key=key, algorithms=['RS256'], audience=[aud.rstrip('/')]
        )

        assert payload.keys() >= jwt_payload_keys
        payload['private_key'] = payload['private_key'].replace('\\n', '\n')
        set_ctr_entities_limit(payload)
        return payload
    except tuple(expected_errors) as error:
        raise AuthorizationError(expected_errors[error.__class__])


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
        raise AuthorizationError(str(e))

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

        if not result.get('data'):
            result.pop('data', None)

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
