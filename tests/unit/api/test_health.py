from http import HTTPStatus
from unittest.mock import patch

from pytest import fixture

from .utils import headers
from ..conftest import ClientMock


def routes():
    yield '/health'


@fixture(scope='module', params=routes(), ids=lambda route: f'POST {route}')
def route(request):
    return request.param


def test_health_call_with_authorization_header_failure(
        route, client,
        authorization_errors_expected_payload
):
    response = client.post(route)

    assert response.status_code == HTTPStatus.OK
    assert response.json == authorization_errors_expected_payload(
        'Authorization header is missing'
    )


def test_health_call_with_wrong_authorization_type(
        route, client, valid_jwt,
        authorization_errors_expected_payload
):
    response = client.post(
        route, headers=headers(valid_jwt, auth_type='wrong_type')
    )

    assert response.status_code == HTTPStatus.OK
    assert response.json == authorization_errors_expected_payload(
        'Wrong authorization type'
    )


def test_health_call_with_wrong_jwt_structure(
        route, client, wrong_jwt_structure,
        authorization_errors_expected_payload
):
    response = client.post(route, headers=headers(wrong_jwt_structure))

    assert response.status_code == HTTPStatus.OK
    assert response.json == authorization_errors_expected_payload(
        'Wrong JWT structure'
    )


def test_health_call_with_jwt_encoded_by_wrong_key(
        route, client, invalid_jwt,
        authorization_errors_expected_payload
):
    response = client.post(route, headers=headers(invalid_jwt))

    assert response.status_code == HTTPStatus.OK
    assert response.json == authorization_errors_expected_payload(
        'Failed to decode JWT with provided key'
    )


def test_health_call_with_wrong_jwt_payload_structure(
        route, client, wrong_payload_structure_jwt,
        authorization_errors_expected_payload
):
    response = client.post(route,
                           headers=headers(wrong_payload_structure_jwt))

    assert response.status_code == HTTPStatus.OK
    assert response.json == authorization_errors_expected_payload(
        'Wrong JWT payload structure'
    )


def test_health_call_with_missed_secret_key(
        route, client, valid_jwt,
        authorization_errors_expected_payload
):
    right_secret_key = client.application.secret_key
    client.application.secret_key = None
    response = client.post(route, headers=headers(valid_jwt))
    client.application.secret_key = right_secret_key

    assert response.status_code == HTTPStatus.OK
    assert response.json == authorization_errors_expected_payload(
        '<SECRET_KEY> is missing'
    )


def test_health_call_with_invalid_creds_failure(
        route, client, valid_jwt,
        authorization_errors_expected_payload
):
    with patch('api.utils.service_account.'
               'Credentials.from_service_account_info',
               side_effect=ValueError("Wrong credentials")):
        response = client.post(route, headers=headers(valid_jwt))

        assert response.status_code == HTTPStatus.OK
        assert response.json == authorization_errors_expected_payload(
            'Wrong credentials'
        )


def test_health_call_with_unauthorized_creds_failure(
        route, client, valid_jwt,
        chronicle_response_unauthorized_creds,
        unauthorized_creds_expected_payload,
):
    with patch('api.utils._auth.authorized_http') as authorized_http_mock, \
            patch('api.utils.service_account.'
                  'Credentials.from_service_account_info'):
        authorized_http_mock.return_value = ClientMock(
            chronicle_response_unauthorized_creds
        )

        response = client.post(route, headers=headers(valid_jwt))

        assert response.json == unauthorized_creds_expected_payload


def test_health_call_success(route, client, valid_jwt, chronicle_response_ok):
    with patch('api.utils._auth.authorized_http') as authorized_http_mock, \
            patch('api.utils.service_account.'
                  'Credentials.from_service_account_info'):
        authorized_http_mock.return_value = ClientMock(chronicle_response_ok)

        response = client.post(route, headers=headers(valid_jwt))

        assert response.status_code == HTTPStatus.OK
        assert response.json == {'data': {'status': 'ok'}}
