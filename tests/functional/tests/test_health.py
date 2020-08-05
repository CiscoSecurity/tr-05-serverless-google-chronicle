from ctrlibrary.core.utils import get_observables
from ctrlibrary.threatresponse.enrich import enrich_post_health
from tests.functional.tests.constants import MODULE_NAME


def test_positive_smoke_enrich_health(module_headers):
    """Perform testing for enrich health endpoint to check
    status of Google Chronicle

    ID: CCTRI-769-34e92acf-45e2-4ef6-b5f4-c7e7f4e10f11

    Steps:
        1. Send request to enrich health endpoint

    Expectedresults:
        1. Check that data in response body contains status Ok
            from Google Chronicle module

    Importance: Critical
    """
    response_from_all_modules = enrich_post_health(
        **{'headers': module_headers}
    )['data']
    response_from_chronicle_module = get_observables(response_from_all_modules,
                                                     MODULE_NAME)
    assert response_from_chronicle_module['data'] == {'status': 'ok'}
