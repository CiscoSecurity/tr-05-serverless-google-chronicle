from ctrlibrary.core.utils import get_observables
from ctrlibrary.threatresponse.enrich import enrich_observe_observables


def test_positive_indicators_domain(module_headers):
    """Perform testing for enrich observe observables endpoint to get
    indicators for observable with domain from Chronicle Backstory

    ID: CCTRI-859-56c35f55-a7f7-4857-8ba1-39ef7f644932

    Steps:
        1. Send request to enrich observe observable endpoint

    Expectedresults:
        1. Check that data in response body contains expected indicators for
            observable from Chronicle Backstory

    Importance: Critical
    """
    observable = {'type': 'domain', 'value': 'wp.com'}
    response = enrich_observe_observables(
        payload=[observable],
        **{'headers': module_headers}
    )['data']
    indicators = get_observables(
        response, 'Chronicle Backstory')['data']['indicators']
    assert indicators['count'] == 1
    # check some generic properties
    assert indicators['docs'][0]['type'] == 'indicator'
    assert indicators['docs'][0]['producer'] == 'Chronicle'
    assert indicators['docs'][0]['schema_version']
    assert (
        indicators['docs'][0]['short_description']
        == 'Malware Command and Control Server'
    )
    assert indicators['docs'][0]['id']
    assert indicators['docs'][0]['severity'] == 'High'
    assert indicators['docs'][0]['confidence'] == 'Low'
    assert indicators[
        'docs'][0]['external_references'][0]['source_name'] == 'Chronicle IOC'
    assert indicators['docs'][0]['external_references'][0]['url']
