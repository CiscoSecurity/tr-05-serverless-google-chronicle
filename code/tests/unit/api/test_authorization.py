from http import HTTPStatus
from unittest.mock import patch

from api.errors import AUTH_ERROR
from api.utils import (
    NO_AUTH_HEADER,
    WRONG_AUTH_TYPE,
    WRONG_JWKS_HOST,
    WRONG_PAYLOAD_STRUCTURE,
    JWKS_HOST_MISSING,
    WRONG_KEY,
    WRONG_JWT_STRUCTURE,
    WRONG_AUDIENCE,
    KID_NOT_FOUND
)
from pytest import fixture
from requests.exceptions import InvalidURL, ConnectionError

from .utils import headers
from ..conftest import ClientMock


def routes():
    yield '/health'
    yield '/observe/observables'


@fixture(scope='module', params=routes(), ids=lambda route: f'POST {route}')
def route(request):
    return request.param


@fixture(scope='module')
def valid_json():
    return [{'type': 'domain', 'value': 'ibm.com'}]


def authorization_error(message, prefix='Authorization failed: '):
    return {
        'errors': [
            {
                'code': AUTH_ERROR,
                'message': f'{prefix}{message}',
                'type': 'fatal'
            }
        ]
    }


def test_call_with_authorization_header_missing(
        route, client, valid_json
):
    response = client.post(route, json=valid_json)

    assert response.status_code == HTTPStatus.OK
    assert response.json == authorization_error(
        NO_AUTH_HEADER
    )


def test_call_with_authorization_type_error(route, client, valid_json):
    response = client.post(
        route, json=valid_json, headers={'Authorization': 'Basic blabla'}
    )

    assert response.status_code == HTTPStatus.OK
    assert response.json == authorization_error(WRONG_AUTH_TYPE)


def test_call_with_jwt_structure_error(route, client, valid_json):
    response = client.post(
        route, json=valid_json, headers={'Authorization': 'Bearer blabla'}
    )

    assert response.status_code == HTTPStatus.OK
    assert response.json == authorization_error(WRONG_JWT_STRUCTURE)


@patch('requests.get')
def test_call_with_jwt_payload_structure_error(
        request_mock, route, client, valid_json, get_public_key, valid_jwt
):
    request_mock.return_value = get_public_key
    response = client.post(
        route, json=valid_json,
        headers=headers(valid_jwt(wrong_structure=True))
    )

    assert response.status_code == HTTPStatus.OK
    assert response.json == authorization_error(WRONG_PAYLOAD_STRUCTURE)


@patch('requests.get')
def test_call_with_wrong_public_key_error(
        request_mock, route, client, valid_json,
        valid_jwt, get_wrong_public_key
):
    request_mock.return_value = get_wrong_public_key

    response = client.post(
        route, json=valid_json, headers=headers(valid_jwt())
    )

    assert response.status_code == HTTPStatus.OK
    assert response.json == authorization_error(
       WRONG_KEY
    )


@patch('requests.get')
def test_call_without_jwks_host(
        request_mock, route, client, valid_json, valid_jwt,
        authorization_errors_expected_payload,
        get_public_key
):

    request_mock.return_value = get_public_key

    response = client.post(
        route, json=valid_json,
        headers=headers(valid_jwt(missing_jwks_host=True))
    )
    assert response.status_code == HTTPStatus.OK
    assert response.json == authorization_errors_expected_payload(
        JWKS_HOST_MISSING)


@patch('requests.get')
def test_call_with_wrong_audience(
        request_mock, route, client, valid_json, valid_jwt, get_public_key,
        authorization_errors_expected_payload,
):
    request_mock.return_value = get_public_key

    response = client.post(
            route, json=valid_json,
            headers=headers(valid_jwt(aud='wrong_aud'))
        )
    assert response.status_code == HTTPStatus.OK
    assert response.json == authorization_errors_expected_payload(
        WRONG_AUDIENCE
    )


@patch('requests.get')
def test_call_with_wrong_kid(
        request_mock, route, client, valid_json,
        authorization_errors_expected_payload,
        get_public_key, valid_jwt
):

    request_mock.return_value = get_public_key
    response = client.post(
        route, headers=headers(valid_jwt(kid='wrong_kid')), json=valid_json
    )

    assert response.status_code == HTTPStatus.OK
    assert response.json == authorization_errors_expected_payload(
       KID_NOT_FOUND
    )


@patch('requests.get')
def test_call_with_wrong_jwks_host(
    request_mock, route, client, valid_json, valid_jwt,
    authorization_errors_expected_payload
):
    for error in (ConnectionError, InvalidURL):
        request_mock.side_effect = error()

        response = client.post(
            route, json=valid_json, headers=headers(valid_jwt())
        )

        assert response.status_code == HTTPStatus.OK
        assert response.json == authorization_errors_expected_payload(
            WRONG_JWKS_HOST
        )


@patch('requests.get')
def test_call_with_invalid_creds_failure(
        request_mock, route, client, valid_jwt,
        authorization_errors_expected_payload,
        get_public_key
):
    request_mock.return_value = get_public_key
    with patch('api.utils.service_account.'
               'Credentials.from_service_account_info',
               side_effect=ValueError("Wrong credentials")):
        response = client.post(route, headers=headers(valid_jwt()))

        assert response.status_code == HTTPStatus.OK
        assert response.json == authorization_errors_expected_payload(
            'Wrong credentials'
        )


@patch('requests.get')
def test_call_with_unauthorized_creds_failure(
        request_mock, route, client, valid_jwt, valid_json,
        chronicle_response_unauthorized_creds,
        unauthorized_creds_expected_payload,
        get_public_key
):
    request_mock.return_value = get_public_key
    with patch('api.utils._auth.authorized_http') as authorized_http_mock, \
        patch('api.utils.service_account.'
              'Credentials.from_service_account_info'):
        authorized_http_mock.return_value = ClientMock(
            chronicle_response_unauthorized_creds
        )
        response = client.post(route, headers=headers(valid_jwt()),
                               json=valid_json)

        assert response.json == unauthorized_creds_expected_payload
