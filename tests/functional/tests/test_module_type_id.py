from ctrlibrary.core.utils import get_observables
from ctrlibrary.threatresponse.enrich import enrich_observe_observables


def test_positive_module_type_id(module_headers):
    """Perform testing for enrich observe observables endpoint to get
    module type id from Chronicle Backstory

    ID: CCTRI-1086-292f9b82-8a93-433e-8932-e2cc89121b74

    Steps:
        1. Send request to enrich observe observable endpoint

    Expectedresults:
        1. Response body contains correct module type id from Chronicle
        Backstory module

    Importance: Critical
    """
    observable = {'type': 'domain', 'value': 'google.com'}
    response_from_all_modules = enrich_observe_observables(
        payload=[observable],
        **{'headers': module_headers}
    )
    module_type_id = get_observables(
        response_from_all_modules['data'], 'Chronicle Backstory'
    )['module_type_id']
    assert module_type_id == 'a14ae422-01b6-5013-9876-695ff1b0ebe0'
