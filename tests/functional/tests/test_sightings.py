from ctrlibrary.core.utils import get_observables
from ctrlibrary.threatresponse.enrich import enrich_observe_observables


def test_positive_sighting_ip(module_headers):
    """Perform testing for enrich observe observables endpoint to get
    sightings for observable with ip from Chronicle Backstory

    ID: CCTRI-883-666472f6-db34-4240-8eaf-8fc5347253a5

    Steps:
        1. Send request to enrich deliberate observable endpoint

    Expectedresults:
        1. Check that data in response body contains expected sightings for
            observable from Chronicle Backstory

    Importance: Critical
    """
    observable = {'type': 'ip', 'value': '1.1.1.1'}
    response = enrich_observe_observables(
        payload=[observable],
        **{'headers': module_headers}
    )['data']
    sightings = get_observables(
        response, 'Chronicle Backstory')['data']['sightings']
    assert sightings['count'] == 0
    assert sightings['docs'] == []


def test_positive_sighting_domain(module_headers):
    """Perform testing for enrich observe observables endpoint to get
    sightings for observable with domain from Chronicle Backstory

    ID: CCTRI-883-13cda7fd-1357-4621-98f6-a0dd3789c3cf

    Steps:
        1. Send request to enrich deliberate observable endpoint

    Expectedresults:
        1. Check that data in response body contains expected sightings for
            observable from Chronicle Backstory

    Importance: Critical
    """
    observable = {'type': 'domain', 'value': 'google.com'}
    response = enrich_observe_observables(
        payload=[observable],
        **{'headers': module_headers}
    )
    sightings = get_observables(
        response['data'], 'Chronicle Backstory')['data']['sightings']
    assert sightings['count'] == 100

    for sighting in sightings['docs']:
        assert sighting['confidence'] == 'High'
        assert sighting['count']
        assert sighting['id']
        assert 'start_time' in sighting['observed_time']
        assert 'schema_version' in sighting
        assert sighting['type'] == 'sighting'
        assert sighting['source'] == 'Chronicle'
        assert sighting['title'] == 'Found in Chronicle'
        assert len(sighting['observables']) == 1
        assert sighting['observables'][0]['value'].endswith('google.com')
        assert sighting['observables'][0]['type'] == 'domain'

        for target in sighting['targets']:
            assert target['type'] == 'endpoint'
            assert target['observables'][0]['type'] == 'hostname'
            assert 'start_time' in target['observed_time']
