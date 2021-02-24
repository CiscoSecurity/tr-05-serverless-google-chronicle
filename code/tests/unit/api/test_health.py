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


@patch('requests.get')
def test_health_call_with_unauthorized_creds_failure(
        request_mock, route, client, valid_jwt,
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

        response = client.post(route, headers=headers(valid_jwt()))

        assert response.json == unauthorized_creds_expected_payload


@patch('requests.get')
def test_health_call_success(
        request_mock, route, client, valid_jwt, chronicle_response_ok,
        get_public_key
):
    request_mock.return_value = get_public_key
    with patch('api.utils._auth.authorized_http') as authorized_http_mock, \
            patch('api.utils.service_account.'
                  'Credentials.from_service_account_info'):
        authorized_http_mock.return_value = ClientMock(chronicle_response_ok)

        response = client.post(route, headers=headers(valid_jwt()))

        assert response.status_code == HTTPStatus.OK
        assert response.json == {'data': {'status': 'ok'}}
