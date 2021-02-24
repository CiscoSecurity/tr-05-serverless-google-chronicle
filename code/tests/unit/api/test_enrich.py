from http import HTTPStatus
from ssl import SSLCertVerificationError
from unittest.mock import patch, MagicMock

from pytest import fixture

from .utils import headers
from ..conftest import ClientMock


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


@patch('requests.get')
def test_enrich_call_with_valid_jwt_but_invalid_json_failure(
        request_mock, route, client, valid_jwt, invalid_json,
        invalid_json_expected_payload, get_public_key
):
    request_mock.return_value = get_public_key
    with patch('api.utils._auth.authorized_http'), \
         patch('api.utils.service_account.'
               'Credentials.from_service_account_info'):
        response = client.post(route,
                               headers=headers(valid_jwt()),
                               json=invalid_json)

        assert response.status_code == HTTPStatus.OK
        assert response.json == invalid_json_expected_payload


@fixture(scope='module')
def valid_json():
    return [{'type': 'domain', 'value': 'google.com'}]


@patch('requests.get')
def test_enrich_call_with_too_many_requests_failure(
        request_mock, route, client, valid_jwt, valid_json,
        chronicle_response_too_many_requests,
        too_many_requests_expected_payload,
        get_public_key
):
    request_mock.return_value = get_public_key
    with patch('api.utils._auth.authorized_http') as authorized_http_mock, \
            patch('api.utils.service_account.'
                  'Credentials.from_service_account_info'):
        authorized_http_mock.return_value = ClientMock(
            chronicle_response_too_many_requests
        )

        response = client.post(route, headers=headers(valid_jwt()),
                               json=valid_json)

        assert response.json == too_many_requests_expected_payload


@patch('requests.get')
def test_enrich_call_with_internal_error_failure(
        request_mock, route, client, valid_jwt, valid_json,
        chronicle_response_internal_error,
        internal_server_error_expected_payload,
        get_public_key
):
    request_mock.return_value = get_public_key
    with patch('api.utils._auth.authorized_http') as authorized_http_mock, \
            patch('api.utils.service_account.'
                  'Credentials.from_service_account_info'):
        authorized_http_mock.return_value = ClientMock(
            chronicle_response_internal_error
        )

        response = client.post(route, headers=headers(valid_jwt()),
                               json=valid_json)

        assert response.json == internal_server_error_expected_payload


@patch('requests.get')
def test_enrich_call_with_bad_request_success(
        request_mock, route, client, valid_jwt, valid_json,
        chronicle_response_bad_request,
        bad_request_expected_payload, get_public_key
):
    request_mock.return_value = get_public_key
    with patch('api.utils._auth.authorized_http') as authorized_http_mock, \
        patch('api.utils.service_account.'
              'Credentials.from_service_account_info'):
        authorized_http_mock.return_value = ClientMock(
            chronicle_response_bad_request
        )

        response = client.post(route, headers=headers(valid_jwt()),
                               json=valid_json)

        assert response.json == bad_request_expected_payload


@patch('requests.get')
def test_enrich_call_success(
        request_mock, route, client, valid_jwt, valid_json,
        chronicle_response_ok, success_enrich_expected_payload,
        get_public_key
):
    request_mock.return_value = get_public_key
    with patch('api.utils._auth.authorized_http') as authorized_http_mock, \
            patch('api.utils.service_account.'
                  'Credentials.from_service_account_info'):
        authorized_http_mock.return_value = ClientMock(
            chronicle_response_ok
        )

        response = client.post(route, headers=headers(valid_jwt()),
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


@patch('requests.get')
def test_enrich_call_success_with_extended_error_handling(
        request_mock, client, valid_jwt, valid_json_multiple,
        chronicle_response_ok, chronicle_response_unauthorized_creds,
        chronicle_response_bad_request, success_enrich_body,
        unauthorized_creds_body, get_public_key
):
    request_mock.side_effect = [get_public_key]*3
    with patch('api.utils._auth.authorized_http') as authorized_http_mock, \
        patch('api.utils.service_account.'
              'Credentials.from_service_account_info'):
        authorized_http_mock.return_value = ClientMock(
            side_effect=[
                chronicle_response_ok,
                chronicle_response_ok,
                chronicle_response_bad_request,
                chronicle_response_unauthorized_creds,
            ]
        )

        response = client.post('observe/observables',
                               headers=headers(valid_jwt()),
                               json=valid_json_multiple)

        assert response.status_code == HTTPStatus.OK

        response = response.get_json()

        for doc in response['data']['sightings']['docs']:
            assert doc.pop('id')

        assert response['data'] == success_enrich_body['data']
        assert response['errors'] == unauthorized_creds_body['errors']


@patch('requests.get')
def test_enrich_call_with_ssl_error(
        request_mock, route, client, valid_jwt, valid_json,
        ssl_error_expected_payload, get_public_key
):
    request_mock.return_value = get_public_key
    with patch('api.utils._auth.authorized_http') as authorized_http_mock, \
            patch('api.utils.service_account.'
                  'Credentials.from_service_account_info'):
        mock_exception = MagicMock()
        mock_exception.reason.args.__getitem__().verify_message \
            = 'self signed certificate'
        authorized_http_mock.return_value = ClientMock(
            side_effect=SSLCertVerificationError(mock_exception,
                                                 'self signed certificate')
        )

        response = client.post(
            route, headers=headers(valid_jwt()), json=valid_json
        )

        assert response.status_code == HTTPStatus.OK
        assert response.json == ssl_error_expected_payload
