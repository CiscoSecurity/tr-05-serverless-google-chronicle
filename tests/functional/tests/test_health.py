from ctrlibrary.core.utils import get_observables
from ctrlibrary.threatresponse.enrich import enrich_post_health


def test_positive_smoke_enrich_health(module_headers):
    """Perform testing for enrich health endpoint to check
    status of Chronicle Backstory

    ID: CCTRI-769-34e92acf-45e2-4ef6-b5f4-c7e7f4e10f11

    Steps:
        1. Send request to enrich health endpoint

    Expectedresults:
        1. Check that data in response body contains status Ok
            from Chronicle Backstory module

    Importance: Critical
    """
    response = enrich_post_health(
        **{'headers': module_headers}
    )['data']
    health = get_observables(response, 'Chronicle Backstory')
    assert health['data'] == {'status': 'ok'}
