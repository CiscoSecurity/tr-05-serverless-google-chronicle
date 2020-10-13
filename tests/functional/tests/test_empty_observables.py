import pytest
from ctrlibrary.core.utils import get_observables
from ctrlibrary.threatresponse.enrich import enrich_observe_observables
from tests.functional.tests.constants import MODULE_NAME


@pytest.mark.skip('switched off till find valid data')
# @pytest.mark.parametrize(
#     'observable_type, observable',
#     (
#      ('ip', '4.3.1.4'),
#      ('domain', 'wp.org'),
#      ('md5', 'd41d8cd98f00b204e9800998ecf8427e'),
#      ('ipv6', '2600:387:a:904::18'),
#      ('sha1', 'A94A8FE5CCB19BA61C4C0873D391E987982FBBD3'),
#      ('sha256',
#       '824916EE370035D2FCED9D4D216D6EA45E5F3866590130C1FA5FDA652F952529')
#      )
# )
def test_positive_smoke_empty_observables(
        module_headers, observable, observable_type):
    """Perform testing for enrich observe observables endpoint to check that
     observable, on which Google Chronicle doesn't have information, will
     return empty data

    ID: CCTRI-1707-1a53cc5b-80c7-4859-bdd2-dc6f301ffac9

    Steps:
        1. Send request to enrich observe observables endpoint

    Expectedresults:
        1. Response body contains empty data dict from Google Chronicle module

    Importance: Critical
    """
    observables = [{'type': observable_type, 'value': observable}]
    response_from_all_modules = enrich_observe_observables(
        payload=observables,
        **{'headers': module_headers}
    )
    google_chronicle_data = response_from_all_modules['data']

    response_from_chronicle_module = get_observables(
        google_chronicle_data, MODULE_NAME)

    assert response_from_chronicle_module['module'] == MODULE_NAME
    assert response_from_chronicle_module['module_instance_id']
    assert response_from_chronicle_module['module_type_id']

    assert response_from_chronicle_module['data'] == {}
