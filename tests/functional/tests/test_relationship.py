import pytest
from ctrlibrary.core.utils import get_observables
from ctrlibrary.threatresponse.enrich import enrich_observe_observables
from tests.functional.tests.constants import (
    MODULE_NAME,
    CTR_ENTITIES_LIMIT
)


@pytest.mark.parametrize(
    'observable_type, observable',
    (
     #('ip', '1.1.1.1'),
     ('domain', 'securecorp.club')
     )
)
def test_positive_relationship(module_headers, observable_type, observable):
    """Perform testing for enrich observe observables endpoint to get
    relationship for observable from Google Chronicle module

    ID: CCTRI-859-923556f5-f678-4ed3-a2ed-f2c37bd4b5e5

    Steps:
        1. Send request to enrich observe observable endpoint

    Expectedresults:
        1. Check that data in response body contains expected relationship for
            observable from Google Chronicle module and it connects expected
            entities

    Importance: Critical
    """
    observables = [{'type': observable_type, 'value': observable}]
    response_from_all_modules = enrich_observe_observables(
        payload=observables,
        **{'headers': module_headers}
    )['data']

    response_from_chronicle_module = get_observables(response_from_all_modules,
                                                     MODULE_NAME)

    assert response_from_chronicle_module['module'] == MODULE_NAME
    assert response_from_chronicle_module['module_instance_id']
    assert response_from_chronicle_module['module_type_id']

    indicators_ids = {
        indicator['id']
        for indicator in (
            response_from_chronicle_module['data']['indicators']['docs']
        )
    }
    sightings_ids = {
        sighting['id']
        for sighting in (
            response_from_chronicle_module['data']['sightings']['docs']
        )
    }
    relationships = (
        response_from_chronicle_module['data']['relationships']
    )

    assert len(relationships['docs']) > 0

    for relationship in relationships['docs']:
        assert relationship['schema_version']
        assert relationship['type'] == 'relationship'
        assert relationship['relationship_type'] == 'sighting-of'
        assert relationship['target_ref'] in indicators_ids
        assert relationship['source_ref'] in sightings_ids

    assert relationships['count'] == (
        len(relationships['docs'])) <= (
        CTR_ENTITIES_LIMIT
    )
