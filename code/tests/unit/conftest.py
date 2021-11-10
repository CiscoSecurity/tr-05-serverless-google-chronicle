import json
from http import HTTPStatus
from unittest.mock import MagicMock

import jwt
from api.errors import (
    PERMISSION_DENIED,
    INVALID_ARGUMENT,
    TOO_MANY_REQUESTS,
    UNKNOWN,
    AUTH_ERROR
)
from app import app
from pytest import fixture
from tests.unit.mock_for_tests import (
    EXPECTED_RESPONSE_OF_JWKS_ENDPOINT,
    PRIVATE_KEY,
    RESPONSE_OF_JWKS_ENDPOINT_WITH_WRONG_KEY
)


@fixture(scope='session')
def valid_jwt(client):
    def _make_jwt(
            jwks_host='visibility.amp.cisco.com',
            aud='http://localhost',
            kid='02B1174234C29F8EFB69911438F597FF3FFEE6B7',
            wrong_structure=False,
            missing_jwks_host=False
    ):
        payload = {
            'type': '<CREDENTIALS_TYPE>',
            'project_id': '<PROJECT_ID>',
            'private_key_id': '<PRIVATE_KEY_ID>',
            'private_key': '<PRIVATE_KEY>',
            'client_email': '<CLIENT_EMAIL>',
            'client_id': '<CLIENT_ID>',
            'auth_uri': '<AUTH_URI>',
            'token_uri': '<TOKEN_URI>',
            'auth_provider_x509_cert_url': '<AUTH_PROVIDER_X509_CERT_URL>',
            'client_x509_cert_url': '<CLIENT_CERT_URL>',
            'jwks_host': jwks_host,
            'aud': aud,
        }

        if wrong_structure:
            payload.pop('token_uri')
        if missing_jwks_host:
            payload.pop('jwks_host')

        return jwt.encode(
            payload, client.application.rsa_private_key, algorithm='RS256',
            headers={
                'kid': kid
            }
        )

    return _make_jwt


@fixture(scope='session')
def client():
    app.rsa_private_key = PRIVATE_KEY

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
def chronicle_response_unauthorized_creds():
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
                        'status': 'RESOURCE_EXHAUSTED'}
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
def chronicle_response_ok():
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


@fixture(scope='module')
def wrong_jwt_structure():
    return 'jwt_with_wrong_structure'


@fixture(scope='module')
def authorization_errors_expected_payload():
    def _make_payload_message(message):
        return {
            "errors": [
                {
                    "code": AUTH_ERROR,
                    "message": f'Authorization failed: '
                               f'{message}',
                    "type": "fatal"
                }
            ]
        }
    return _make_payload_message


@fixture(scope='module')
def unauthorized_creds_body():
    return {
        'errors': [
            {'code': PERMISSION_DENIED,
             'message': ("Unexpected response from Google Chronicle: "
                         "Wrong creds!"),
             'type': 'fatal'}
        ]
    }


@fixture(scope='module')
def unauthorized_creds_expected_payload(unauthorized_creds_body):
    return unauthorized_creds_body


@fixture(scope='module')
def invalid_json_expected_payload():
    return {
        'errors': [
            {'code': INVALID_ARGUMENT,
             'message': ("{0: {'value': "
                         "['Missing data for required field.']}}"),
             'type': 'fatal'}
        ]
    }


@fixture(scope='module')
def too_many_requests_expected_payload():
    return {
        'errors': [
            {'code': TOO_MANY_REQUESTS,
             'message': 'Too many requests to Google Chronicle'
                        ' have been made. Please, try again later.',
             'type': 'fatal'}
        ]
    }


@fixture(scope='module')
def internal_server_error_expected_payload():
    return {
        'errors': [
            {'code': UNKNOWN,
             'message': 'Unexpected response from Google Chronicle:'
                        ' Internal Server Error',
             'type': 'fatal'}
        ]
    }


@fixture(scope='module')
def bad_request_expected_payload():
    return {'data': {}}


@fixture(scope='module')
def ssl_error_expected_payload():
    return {
        'errors': [
            {
                'code': UNKNOWN,
                'message': 'Unable to verify SSL certificate:'
                           ' Self signed certificate',
                'type': 'fatal'
            }
        ]
    }


@fixture(scope='module')
def success_enrich_expected_payload():
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


@fixture(scope='session')
def get_public_key():
    mock_response = MagicMock()
    payload = EXPECTED_RESPONSE_OF_JWKS_ENDPOINT

    mock_response.json = lambda: payload
    return mock_response


@fixture(scope='session')
def get_wrong_public_key():
    mock_response = MagicMock()
    payload = RESPONSE_OF_JWKS_ENDPOINT_WITH_WRONG_KEY
    mock_response.json = lambda: payload
    return mock_response
