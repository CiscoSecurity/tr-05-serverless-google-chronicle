import os
import pytest


def test_relay_auth_positive(relay_api):
    """Perform testing for relay health endpoint to check
    status auth for Google Chronicle

    ID: CCTRI-769-0cc7805e-297d-4700-872b-dbf82f267326

    Steps:
        1. Send request to relay endpoint with right token

    Expectedresults:
        1. Check that response has status 200

    Importance: Critical
    """
    response = relay_api.health('')
    assert response.status_code == 200
    assert response.json()['data'] == {'status': 'ok'}


@pytest.mark.parametrize(
    'wrong_token,message',
    (
        # ('', 'Invalid Authorization Bearer JWT.'),
        ('123', 'Invalid Authorization Bearer JWT.'),
        (os.environ['ANOTHER_KEY'],
         'Unexpected response from Google Chronicle: '
         'Backstory API has not been used in project ')
     )
)
def test_relay_auth_negative(relay_api_without_token, wrong_token, message):
    """Perform testing for relay health endpoint to check
    status auth for Google Chronicle with wrong token

    ID: CCTRI-769-86f8a6c7-4356-4fe8-b504-8403c2be7e41

    Steps:
        1. Send request to relay endpoint with wrong tokens

    Expectedresults:
        1. Check that response has status 200, and error message

    Importance: Critical
    """
    response = relay_api_without_token.health(
        '',
        **{'headers': {'Authorization': 'Bearer {}'.format(wrong_token)}}
    )
    assert response.status_code == 200
    error = response.json()["errors"][0]

    assert error['type'] == 'fatal'
    assert error['code'] == 'permission denied'
    assert error['message'].startswith(message)
