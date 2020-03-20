from http import HTTPStatus

from unittest.mock import patch
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
        chronicle_client_ok, invalid_json_expected_payload,
):
    with patch('api.utils._auth.authorized_http',
               return_value=chronicle_client_ok), \
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


def test_enrich_call_with_unauthorized_creds_failure(
        route, client, valid_jwt, valid_json,
        chronicle_client_unauthorized_creds,
        unauthorized_creds_expected_payload
):
    with patch('api.utils._auth.authorized_http',
               return_value=chronicle_client_unauthorized_creds), \
        patch('api.utils.service_account.'
              'Credentials.from_service_account_info'):
        response = client.post(route, headers=headers(valid_jwt),
                               json=valid_json)

        assert response.json == unauthorized_creds_expected_payload


def test_enrich_call_success(
        route, client, valid_jwt, valid_json, chronicle_client_ok
):
    with patch('api.utils._auth.authorized_http',
               return_value=chronicle_client_ok), \
         patch('api.utils.service_account.'
               'Credentials.from_service_account_info'):
        response = client.post(route, headers=headers(valid_jwt),
                               json=valid_json)

        data = response.get_json()
        if type(data["data"]) == dict and data["data"].get("sightings"):
            assert data["data"]["sightings"]["docs"][0].pop("confidence")
            assert data["data"]["sightings"]["docs"][0].pop("id")
            assert data["data"]["sightings"]["docs"][0].pop("count")
            assert data["data"]["sightings"]["docs"][0].pop("observed_time")
            assert data["data"]["sightings"]["docs"][0].pop("schema_version")
            assert data["data"]["sightings"]["docs"][0].pop("type")

        assert response.status_code == HTTPStatus.OK
        assert response.json.get('errors') is None
