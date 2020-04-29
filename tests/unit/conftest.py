import json
from datetime import datetime
from http import HTTPStatus
from unittest.mock import MagicMock

from authlib.jose import jwt
from pytest import fixture

from api.errors import (
    PERMISSION_DENIED, INVALID_ARGUMENT, TOO_MANY_REQUESTS, UNKNOWN
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


class ChronicleClientMock:
    def __init__(self, status_code, response_body, reason=None):
        self.__response_mock = MagicMock()
        self.__response_mock.status = status_code
        if reason:
            self.__response_mock.reason = reason
        self.__response_body = response_body

    def request(self, *args, **kwargs):
        return self.__response_mock, self.__response_body


@fixture(scope='session')
def chronicle_client_unauthorized_creds(secret_key):
    return ChronicleClientMock(
        HTTPStatus.FORBIDDEN,
        json.dumps({"error": {"code": HTTPStatus.FORBIDDEN,
                              "message": "Wrong creds!",
                              "status": PERMISSION_DENIED}})
    )


@fixture(scope='session')
def chronicle_client_internal_error():
    return ChronicleClientMock(
        HTTPStatus.INTERNAL_SERVER_ERROR,
        json.dumps(
            {'error':
                {'code': HTTPStatus.INTERNAL_SERVER_ERROR,
                 'message': 'generic::internal: internal error, '
                            'please try again later',
                 'status': 'INTERNAL'}}),
        reason='Internal Server Error'
    )


@fixture(scope='session')
def chronicle_client_too_many_requests():
    return ChronicleClientMock(
        HTTPStatus.TOO_MANY_REQUESTS,
        json.dumps(
            {'error':
                {'code': TOO_MANY_REQUESTS,
                 'message': 'generic::resource_exhausted: insufficient '
                            'ListArtifactAssets quota for 000000demo-dev',
                 'status': 'RESOURCE_EXHAUSTED'}
             }
        )
    )


@fixture(scope='session')
def chronicle_client_bad_request():
    return ChronicleClientMock(
        HTTPStatus.BAD_REQUEST,
        "HTTP bla bla bla",
        reason='BAD REQUEST'
    )


@fixture(scope='session')
def chronicle_client_ok(secret_key):
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
        "uri": [
            "https://demodev.backstory.chronicle.security/domainResults?\
                domain=www.google.com&selectedList=DomainViewDistinctAssets&\
                whoIsTimestamp=2020-03-19T10%3A33%3A26.529103917Z"
        ],
    }

    return ChronicleClientMock(
        HTTPStatus.OK, json.dumps(payload_success))


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
        return urlsafe_b64encode(json_dumps(d).encode('ascii')).decode('ascii')

    payload = jwt_decode(payload)

    # Corrupt the valid JWT by tampering with its payload.
    payload['superuser'] = True

    payload = jwt_encode(payload)

    return '.'.join([header, payload, signature])


@fixture(scope='module')
def invalid_jwt_expected_payload(route):
    if route in ('/observe/observables', '/health'):
        return {
            'errors': [
                {'code': PERMISSION_DENIED,
                 'message': 'Invalid Authorization Bearer JWT.',
                 'type': 'fatal'}
            ]
        }

    if route.endswith('/deliberate/observables'):
        return {'data': {}}

    if route.endswith('/refer/observables'):
        return {'data': []}


@fixture(scope='module')
def unauthorized_creds_expected_payload(route):
    if route in ('/observe/observables', '/health'):
        return {
            'errors': [
                {'code': PERMISSION_DENIED,
                 'message': ("Unexpected response from Chronicle Backstory: "
                             "Wrong creds!"),
                 'type': 'fatal'}
            ]
        }

    if route.endswith('/deliberate/observables'):
        return {'data': {}}

    if route.endswith('/refer/observables'):
        return {'data': []}


@fixture(scope='module')
def invalid_creds_expected_payload(route):
    if route in ('/observe/observables', '/health'):
        return {
            'errors': [
                {'code': PERMISSION_DENIED,
                 'message': ('Chronicle Backstory Authorization failed:'
                             ' Wrong structure.'),
                 'type': 'fatal'}
            ]
        }

    if route.endswith('/deliberate/observables'):
        return {'data': {}}

    if route.endswith('/refer/observables'):
        return {'data': []}


@fixture(scope='module')
def invalid_json_expected_payload(route, client):
    if route.endswith('/observe/observables'):
        return {'errors': [
            {'code': INVALID_ARGUMENT,
             'message': "{0: {'value': ['Missing data for required field.']}}",
             'type': 'fatal'}
        ]}

    if route.endswith('/deliberate/observables'):
        return {'data': {}}

    return {'data': []}


@fixture(scope='module')
def too_many_requests_expected_payload(route, client):
    if route.endswith('/observe/observables'):
        return {'errors': [
            {'code': TOO_MANY_REQUESTS,
             'message': 'To many requests to Chronicle Backstory'
                        ' have been made. Please, try again later.',
             'type': 'fatal'}
        ]}

    if route.endswith('/deliberate/observables'):
        return {'data': {}}

    return {'data': []}


@fixture(scope='module')
def internal_server_error_expected_payload(route, client):
    if route.endswith('/observe/observables'):
        return {'errors': [
            {'code': UNKNOWN,
             'message': 'Unexpected response from Chronicle Backstory:'
                        ' Internal Server Error',
             'type': 'fatal'}
        ]}

    if route.endswith('/deliberate/observables'):
        return {'data': {}}

    return {'data': []}


@fixture(scope='module')
def bad_request_expected_payload(route, client):
    if route.endswith('/observe/observables'):
        return {'errors': [
            {'code': INVALID_ARGUMENT,
             'message': 'Unexpected response from Chronicle Backstory:'
                        ' BAD REQUEST',
             'type': 'fatal'}
        ]}

    if route.endswith('/deliberate/observables'):
        return {'data': {}}

    return {'data': []}
