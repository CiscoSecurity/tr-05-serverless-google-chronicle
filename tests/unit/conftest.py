import json
from datetime import datetime
from http import HTTPStatus
from unittest.mock import MagicMock

from authlib.jose import jwt
from pytest import fixture

from api.errors import (
    PERMISSION_DENIED,
    INVALID_ARGUMENT,
    TOO_MANY_REQUESTS,
    UNKNOWN,
    AUTH_ERROR
)
from app import app


@fixture(scope='session')
def secret_key():
    # Generate some string based on the current datetime.
    return datetime.utcnow().isoformat()


@fixture(scope='session')
def client(secret_key):
    app.secret_key = secret_key

    app.testing = True

    with app.test_client() as client:
        yield client


class ResponseMock:
    def __init__(self, status_code, reason=None):
        self.status = status_code
        self.reason = reason


class ClientMock(MagicMock):
    def __init__(self, return_value=None, side_effect=None, *args, **kwargs):
        super().__init__(*args, **kwargs)
        if return_value:
            self.request.return_value = return_value
        elif side_effect:
            self.request.side_effect = side_effect


@fixture(scope='session')
def chronicle_response_unauthorized_creds(secret_key):
    return (
        ResponseMock(HTTPStatus.FORBIDDEN),
        json.dumps({"error": {"code": HTTPStatus.FORBIDDEN,
                              "message": "Wrong creds!",
                              "status": PERMISSION_DENIED}}))


@fixture(scope='session')
def chronicle_response_internal_error():
    return (
        ResponseMock(HTTPStatus.INTERNAL_SERVER_ERROR,
                     reason='Internal Server Error'),
        json.dumps(
            {
                'error':
                    {
                        'code': HTTPStatus.INTERNAL_SERVER_ERROR,
                        'message': 'generic::internal: internal error, '
                                   'please try again later',
                        'status': 'INTERNAL'}}),

    )


@fixture(scope='session')
def chronicle_response_too_many_requests():
    return (
        ResponseMock(HTTPStatus.TOO_MANY_REQUESTS),
        json.dumps(
            {
                'error':
                    {
                        'code': TOO_MANY_REQUESTS,
                        'message': 'generic::resource_exhausted: insufficient '
                                   'ListArtifactAssets quota for '
                                   '000000demo-dev',
                        'status': 'RESOURCE_EXHAUSTED'},
                'data': {}
            }
        )
    )


@fixture(scope='session')
def chronicle_response_bad_request():
    return (
        ResponseMock(HTTPStatus.BAD_REQUEST, reason='BAD REQUEST'),
        "HTTP bla bla bla"
    )


@fixture(scope='session')
def chronicle_response_ok(secret_key):
    payload_success = {
        "assets": [
            {
                "asset": {"hostname": "ronald-malone-pc"},
                "firstSeenArtifactInfo": {
                    "artifactIndicator": {"domainName": "www.google.com"},
                    "seenTime": "2018-11-16T08:42:20Z",
                },
                "lastSeenArtifactInfo": {
                    "artifactIndicator": {"domainName": "www.google.com"},
                    "seenTime": "2019-10-15T14:53:57Z",
                },
            },
        ],
        "uri": ["uri1"],
    }

    return ResponseMock(HTTPStatus.OK), json.dumps(payload_success)


@fixture(scope='session')
def valid_jwt(secret_key):
    header = {'alg': 'HS256'}

    payload = {'username': 'gdavoian', 'superuser': False}

    return jwt.encode(header, payload, secret_key).decode('ascii')


@fixture(scope='session')
def invalid_jwt(valid_jwt, secret_key):
    header, payload, signature = valid_jwt.split('.')

    def jwt_decode(s: str) -> dict:
        from authlib.common.encoding import urlsafe_b64decode, json_loads
        return json_loads(urlsafe_b64decode(s.encode('ascii')))

    def jwt_encode(d: dict) -> str:
        from authlib.common.encoding import json_dumps, urlsafe_b64encode
        return urlsafe_b64encode(json_dumps(d).encode('ascii')).decode(
            'ascii')

    payload = jwt_decode(payload)

    # Corrupt the valid JWT by tampering with its payload.
    payload['superuser'] = True

    payload = jwt_encode(payload)

    return '.'.join([header, payload, signature])


def expected_payload(r, body):
    if r.endswith('/deliberate/observables'):
        return {'data': {}}

    if r.endswith('/refer/observables'):
        return {'data': []}

    return body


@fixture(scope='module')
def invalid_jwt_expected_payload(route):
    return expected_payload(
        route,
        {
            'errors': [
                {'code': AUTH_ERROR,
                 'message': 'Authorization failed: Failed to decode JWT '
                            'with provided key',
                 'type': 'fatal'}
            ],
            'data': {}
        }
    )


@fixture(scope='module')
def authorization_is_missing_expected_payload(route):
    return expected_payload(
        route,
        {
            'errors': [
                {'code': AUTH_ERROR,
                 'message': 'Authorization failed: '
                            'Authorization header is missing',
                 'type': 'fatal'}
            ],
            'data': {}
        }
    )


@fixture(scope='module')
def unauthorized_creds_body():
    return {
        'errors': [
            {'code': PERMISSION_DENIED,
             'message': ("Unexpected response from Google Chronicle: "
                         "Wrong creds!"),
             'type': 'fatal'}
        ],
        'data': {}
    }


@fixture(scope='module')
def unauthorized_creds_expected_payload(route, unauthorized_creds_body):
    return expected_payload(route, unauthorized_creds_body)


@fixture(scope='module')
def invalid_creds_expected_payload(route):
    return expected_payload(
        route,
        {
            'errors': [
                {'code': PERMISSION_DENIED,
                 'message': ('Google Chronicle Authorization failed:'
                             ' Wrong structure.'),
                 'type': 'fatal'}
            ],
            'data': {}
        }
    )


@fixture(scope='module')
def invalid_json_expected_payload(route):
    return expected_payload(
        route,
        {
            'errors': [
                {'code': INVALID_ARGUMENT,
                 'message': ("{0: {'value': "
                             "['Missing data for required field.']}}"),
                 'type': 'fatal'}
            ],
            'data': {}
        }
    )


@fixture(scope='module')
def too_many_requests_expected_payload(route):
    return expected_payload(
        route,
        {
            'errors': [
                {'code': TOO_MANY_REQUESTS,
                 'message': 'Too many requests to Google Chronicle'
                            ' have been made. Please, try again later.',
                 'type': 'fatal'}
            ],
            'data': {}
        }
    )


@fixture(scope='module')
def internal_server_error_expected_payload(route):
    return expected_payload(
        route,
        {
            'errors': [
                {'code': UNKNOWN,
                 'message': 'Unexpected response from Google Chronicle:'
                            ' Internal Server Error',
                 'type': 'fatal'}
            ],
            'data': {}
        }
    )


@fixture(scope='module')
def bad_request_expected_payload(route):
    return expected_payload(route, {'data': {}})


@fixture(scope='module')
def success_enrich_body():
    return {
        'data': {
            'sightings': {
                'count': 2,
                'docs': [
                    {
                        'confidence': 'High',
                        'count': 1,
                        'internal': True,
                        'observables': [
                            {
                                'type': 'domain',
                                'value': 'www.google.com'
                            }
                        ],
                        'observed_time': {
                            'start_time': '2019-10-15T14:53:57Z',
                            'end_time': '2019-10-15T14:53:57Z'
                        },
                        'relations': [
                            {
                                'origin': 'Chronicle Enrichment Module',
                                'related': {
                                    'type': 'domain',
                                    'value': 'www.google.com'
                                },
                                'relation': 'Supra-domain_Of',
                                'source': {
                                    'type': 'domain',
                                    'value': 'google.com'
                                }
                            }
                        ],
                        'schema_version': '1.0.17',
                        'source': 'Chronicle',
                        'source_uri': 'uri1',
                        'targets': [
                            {
                                'observables': [
                                    {
                                        'type': 'hostname',
                                        'value': 'ronald-malone-pc'
                                    }
                                ],
                                'observed_time': {
                                    'start_time': '2019-10-15T14:53:57Z',
                                    'end_time': '2019-10-15T14:53:57Z'
                                },
                                'type': 'endpoint'
                            }
                        ],
                        'title': 'Found in Chronicle',
                        'type': 'sighting'
                    },
                    {
                        'confidence': 'High',
                        'count': 1,
                        'internal': True,
                        'observables': [
                            {
                                'type': 'domain',
                                'value': 'www.google.com'
                            }
                        ],
                        'observed_time': {
                            'start_time': '2018-11-16T08:42:20Z',
                            'end_time': '2018-11-16T08:42:20Z'
                        },
                        'relations': [
                            {
                                'origin': 'Chronicle Enrichment Module',
                                'related': {
                                    'type': 'domain',
                                    'value': 'www.google.com'
                                },
                                'relation': 'Supra-domain_Of',
                                'source': {
                                    'type': 'domain',
                                    'value': 'google.com'
                                }
                            }
                        ],
                        'schema_version': '1.0.17',
                        'source': 'Chronicle',
                        'source_uri': 'uri1',
                        'targets': [
                            {
                                'observables': [
                                    {
                                        'type': 'hostname',
                                        'value': 'ronald-malone-pc'
                                    }
                                ],
                                'observed_time': {
                                    'start_time': '2018-11-16T08:42:20Z',
                                    'end_time': '2018-11-16T08:42:20Z'
                                },
                                'type': 'endpoint'
                            }
                        ],
                        'title': 'Found in Chronicle',
                        'type': 'sighting'
                    }
                ]
            }
        }}


@fixture(scope='module')
def success_enrich_expected_payload(route, success_enrich_body):
    return expected_payload(route, success_enrich_body)
