import random

from ctrlibrary.core.utils import get_observables
from ctrlibrary.threatresponse.enrich import enrich_observe_observables


def test_positive_relationship_domain(module_headers):
    """Perform testing for enrich observe observables endpoint to get
    relationship for observable from Chronicle Backstory module

    ID: CCTRI-859-923556f5-f678-4ed3-a2ed-f2c37bd4b5e5

    Steps:
        1. Send request to enrich observe observable endpoint

    Expectedresults:
        1. Check that data in response body contains expected relationship for
            observable from Chronicle Backstory module and it connects expected
            entities

    Importance: Critical
    """
    observable = {'type': 'domain', 'value': 'sipapals.servehalflife.com'}
    response = enrich_observe_observables(
        payload=[observable],
        **{'headers': module_headers}
    )['data']
    module_response = get_observables(response, 'Chronicle Backstory')['data']
    # Get one indicator to check for relation
    assert module_response['indicators']['count'] == 1
    indicator = module_response['indicators']['docs'][0]
    # Get any random sighting as we have only one indicator to be connected to
    assert module_response['sightings']['count'] == 2
    sighting = random.choice(module_response['sightings']['docs'])
    # Check that we have (sightings*indicators) number of relationships
    assert module_response['relationships']['count'] == 2
    # Validate that entities are connected
    relationship = [
        d for d
        in module_response['relationships']['docs']
        if d.get('source_ref') == sighting['id']
    ]
    assert relationship, 'There is no relationship for provided sighting'
    assert relationship[0]['type'] == 'relationship'
    assert relationship[0]['relationship_type'] == 'sighting-of'
    assert relationship[0]['target_ref'] == indicator['id']
