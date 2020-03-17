import json
from http import HTTPStatus
from unittest.mock import patch

from pytest import fixture

from . import invalid_jwt_error, ChronicleClientMock
from .utils import headers


def routes():
    yield '/health'


@fixture(scope='module', params=routes(), ids=lambda route: f'POST {route}')
def route(request):
    return request.param


def test_health_call_without_jwt_failure(route, client):
    response = client.post(route)
    assert response.status_code == HTTPStatus.OK
    assert response.json['errors'] == [invalid_jwt_error]


def test_health_call_with_invalid_jwt_failure(route, client, invalid_jwt):
    response = client.post(route, headers=headers(invalid_jwt))
    assert response.status_code == HTTPStatus.OK
    assert response.json['errors'] == [invalid_jwt_error]


def test_health_call_with_unauthorized_creds_failure(route, client, valid_jwt):
    chronicle_client_mock = ChronicleClientMock(
        HTTPStatus.FORBIDDEN,
        json.dumps({"error": {"code": HTTPStatus.FORBIDDEN,
                              "message": "Wrong creds!",
                              "status": "PERMISSION_DENIED"}})
    )

    with patch('api.utils._auth.authorized_http',
               return_value=chronicle_client_mock), \
        patch('api.utils.service_account.'
              'Credentials.from_service_account_info'):
        response = client.post(route, headers=headers(valid_jwt))
        assert response.status_code == HTTPStatus.OK
        assert response.json['errors'] == [
            {'code': 'permission_denied',
             'message': 'Wrong creds!',
             'type': 'fatal'}
        ]


def test_health_call_with_invalid_creds_failure(route, client, valid_jwt):
    with patch('api.utils.service_account.'
               'Credentials.from_service_account_info',
               side_effect=ValueError("Wrong structure")):
        response = client.post(route, headers=headers(valid_jwt))
        assert response.status_code == HTTPStatus.OK
        assert response.json['errors'] == [
            {'code': 'permission_denied',
             'message': ('Chronicle Backstory Authorization failed:'
                         ' Wrong structure.'),
             'type': 'fatal'}
        ]


def test_health_call_success(route, client, valid_jwt):
    with patch('api.utils._auth.authorized_http',
               return_value=ChronicleClientMock(HTTPStatus.OK, '{}')), \
         patch('api.utils.service_account.'
               'Credentials.from_service_account_info'):
        response = client.post(route, headers=headers(valid_jwt))
        assert response.status_code == HTTPStatus.OK
