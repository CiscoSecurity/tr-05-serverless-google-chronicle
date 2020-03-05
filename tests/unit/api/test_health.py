from http import HTTPStatus
from unittest.mock import MagicMock, patch

from pytest import fixture

from .utils import headers


def routes():
    yield '/health'


@fixture(scope='module', params=routes(), ids=lambda route: f'POST {route}')
def route(request):
    return request.param


class ChronicleClientMock:
    def __init__(self, status_code, response_body):
        self.__response_mock = MagicMock()
        self.__response_mock.status = status_code
        self.__response_body = response_body

    def request(self, *args, **kwargs):
        return self.__response_mock, self.__response_body


def test_health_call_without_jwt_failure(route, client):
    response = client.post(route)
    assert response.status_code == HTTPStatus.FORBIDDEN
    assert response.json['message'] == 'Invalid Authorization Bearer JWT.'


def test_health_call_with_invalid_jwt_failure(route, client, invalid_jwt):
    response = client.post(route, headers=headers(invalid_jwt))
    assert response.status_code == HTTPStatus.FORBIDDEN
    assert response.json['message'] == 'Invalid Authorization Bearer JWT.'


def test_health_call_with_unauthorized_creds_failure(route, client, valid_jwt):
    chronicle_client_mock = ChronicleClientMock(HTTPStatus.FORBIDDEN,
                                                '{"error":{"status":"403"}}')
    with patch('api.utils._auth.authorized_http',
               return_value=chronicle_client_mock), \
        patch('api.utils.service_account.'
              'Credentials.from_service_account_info'):
        response = client.post(route, headers=headers(valid_jwt))
        assert response.status_code == HTTPStatus.OK
        assert response.json == {'errors': [{'code': '403', 'type': 'fatal'}]}


def test_health_call_with_invalid_creds_failure(route, client, valid_jwt):
    with patch('api.utils.service_account.'
               'Credentials.from_service_account_info',
               side_effect=ValueError("Wrong structure")):
        response = client.post(route, headers=headers(valid_jwt))
        assert response.status_code == HTTPStatus.FORBIDDEN
        assert (response.json['message'] ==
                "Chronicle Backstory Authorization failed: Wrong structure.")


def test_health_call_success(route, client, valid_jwt):
    with patch('api.utils._auth.authorized_http',
               return_value=ChronicleClientMock(HTTPStatus.OK, '{}')), \
         patch('api.utils.service_account.'
               'Credentials.from_service_account_info'):
        response = client.post(route, headers=headers(valid_jwt))
        assert response.status_code == HTTPStatus.OK
