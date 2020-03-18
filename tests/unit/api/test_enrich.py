from http import HTTPStatus

from mock import patch
from pytest import fixture

from tests.unit.api import ChronicleClientMock
from .utils import headers


def routes():
    yield '/deliberate/observables'
    yield '/observe/observables'
    yield '/refer/observables'


@fixture(scope='module', params=routes(), ids=lambda route: f'POST {route}')
def route(request):
    return request.param


@fixture(scope='module')
def invalid_json():
    return [{'type': 'domain'}]


@fixture(scope='module')
def invalid_json_expected_payload(route, client):
    if route.endswith('/observe/observables'):
        return {'errors': [
            {'code': 'invalid_argument',
             'message': "{0: {'value': ['Missing data for required field.']}}",
             'type': 'fatal'}
        ]}

    if route.endswith('/deliberate/observables'):
        return {'data': {}}

    return {'data': []}


def test_enrich_call_without_jwt_failure(route, client,
                                         invalid_jwt_expected_payload):
    response = client.post(route)
    assert response.status_code == HTTPStatus.OK
    assert response.json == invalid_jwt_expected_payload


def test_enrich_call_with_invalid_jwt_failure(
        route, client, invalid_jwt, invalid_jwt_expected_payload
):
    response = client.post(route, headers=headers(invalid_jwt))
    assert response.status_code == HTTPStatus.OK
    assert response.json == invalid_jwt_expected_payload


def test_enrich_call_with_valid_jwt_but_invalid_json_failure(
        route, client, valid_jwt, invalid_json, invalid_json_expected_payload
):
    with patch('api.utils._auth.authorized_http',
               return_value=ChronicleClientMock(HTTPStatus.OK, '{}')), \
         patch('api.utils.service_account.'
               'Credentials.from_service_account_info'):
        response = client.post(route,
                               headers=headers(valid_jwt),
                               json=invalid_json)
        assert response.status_code == HTTPStatus.OK
        assert response.json == invalid_json_expected_payload


@fixture(scope='module')
def valid_json():
    return [{'type': 'domain', 'value': 'cisco.com'}]


def test_enrich_call_success(route, client, valid_jwt, valid_json):
    response = client.post(route, headers=headers(valid_jwt), json=valid_json)
    assert response.status_code == HTTPStatus.OK
