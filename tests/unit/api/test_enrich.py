from http import HTTPStatus
from unittest.mock import patch, MagicMock

from pytest import fixture

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


def test_enrich_call_without_jwt_failure(
        route, client, invalid_jwt_expected_payload
):
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
        route, client, valid_jwt, invalid_json,
        chronicle_response_ok, invalid_json_expected_payload,
):
    with patch('api.utils._auth.authorized_http') as chronicle_client_mock, \
         patch('api.utils.service_account.'
               'Credentials.from_service_account_info'):

        chronicle_client_mock.request.return_value = chronicle_response_ok
        response = client.post(route,
                               headers=headers(valid_jwt),
                               json=invalid_json)

        assert response.status_code == HTTPStatus.OK
        assert response.json == invalid_json_expected_payload


@fixture(scope='module')
def valid_json():
    return [{'type': 'domain', 'value': 'google.com'}]


def test_enrich_call_with_unauthorized_creds_failure(
        route, client, valid_jwt, valid_json,
        chronicle_response_unauthorized_creds,
        unauthorized_creds_expected_payload
):

    with patch('api.utils._auth.authorized_http') as authorized_http_mock, \
         patch('api.utils.service_account.'
               'Credentials.from_service_account_info'):

        client_mock = MagicMock()
        client_mock.request.return_value = chronicle_response_unauthorized_creds
        authorized_http_mock.return_value = client_mock

        response = client.post(route, headers=headers(valid_jwt),
                               json=valid_json)

        assert response.json == unauthorized_creds_expected_payload


def test_enrich_call_with_too_many_requests_failure(
        route, client, valid_jwt, valid_json,
        chronicle_response_too_many_requests,
        too_many_requests_expected_payload
):
    with patch('api.utils._auth.authorized_http') as authorized_http_mock, \
            patch('api.utils.service_account.'
                  'Credentials.from_service_account_info'):
        client_mock = MagicMock()
        client_mock.request.return_value = chronicle_response_too_many_requests
        authorized_http_mock.return_value = client_mock

        response = client.post(route, headers=headers(valid_jwt),
                               json=valid_json)

        assert response.json == too_many_requests_expected_payload


def test_enrich_call_with_internal_error_failure(
        route, client, valid_jwt, valid_json,
        chronicle_response_internal_error,
        internal_server_error_expected_payload
):
    with patch('api.utils._auth.authorized_http') as authorized_http_mock, \
            patch('api.utils.service_account.'
                  'Credentials.from_service_account_info'):
        client_mock = MagicMock()
        client_mock.request.return_value = chronicle_response_internal_error
        authorized_http_mock.return_value = client_mock

        response = client.post(route, headers=headers(valid_jwt),
                               json=valid_json)

        assert response.json == internal_server_error_expected_payload


def test_enrich_call_with_bad_request_success(
        route, client, valid_jwt, valid_json,
        chronicle_response_bad_request,
        bad_request_expected_payload
):
    with patch('api.utils._auth.authorized_http') as authorized_http_mock, \
            patch('api.utils.service_account.'
                  'Credentials.from_service_account_info'):
        client_mock = MagicMock()
        client_mock.request.return_value = chronicle_response_bad_request
        authorized_http_mock.return_value = client_mock

        response = client.post(route, headers=headers(valid_jwt),
                               json=valid_json)

        assert response.json == bad_request_expected_payload


def test_enrich_call_success(
        route, client, valid_jwt, valid_json,
        chronicle_response_ok, success_enrich_expected_payload
):
    with patch('api.utils._auth.authorized_http') as authorized_http_mock, \
            patch('api.utils.service_account.'
                  'Credentials.from_service_account_info'):
        client_mock = MagicMock()
        client_mock.request.return_value = chronicle_response_ok
        authorized_http_mock.return_value = client_mock

        response = client.post(route, headers=headers(valid_jwt),
                               json=valid_json)

        assert response.status_code == HTTPStatus.OK
        assert response.json.get('errors') is None

        response = response.get_json()

        if response.get('data') and response['data'].get('sightings'):
            for doc in response['data']['sightings']['docs']:
                assert doc.pop('id')

        assert response == success_enrich_expected_payload


@fixture(scope='module')
def valid_json_multiple():
    return [{'type': 'domain', 'value': 'google.com'},
            {'type': 'domain', 'value': '1.1.1.1'},
            {'type': 'domain', 'value': 'cisco.com'}]


def test_enrich_call_success_with_extended_error_handling(
        client, valid_jwt, valid_json_multiple, chronicle_response_ok,
        chronicle_response_unauthorized_creds, chronicle_response_bad_request,
        success_enrich_body, unauthorized_creds_body
):
    with patch('api.utils._auth.authorized_http') as authorized_http_mock, \
         patch('api.utils.service_account.'
               'Credentials.from_service_account_info'):

        client_mock = MagicMock()
        client_mock.request.side_effect = [
            chronicle_response_ok,
            chronicle_response_ok,
            chronicle_response_bad_request,
            chronicle_response_bad_request,
            chronicle_response_unauthorized_creds,
            chronicle_response_unauthorized_creds,
        ]
        authorized_http_mock.return_value = client_mock

        response = client.post('observe/observables',
                               headers=headers(valid_jwt),
                               json=valid_json_multiple)

        assert response.status_code == HTTPStatus.OK

        response = response.get_json()

        for doc in response['data']['sightings']['docs']:
            assert doc.pop('id')

        assert response['data'] == success_enrich_body['data']
        assert response['errors'] == unauthorized_creds_body['errors']
