import pytest
from ctrlibrary.core.utils import get_observables
from ctrlibrary.threatresponse.enrich import enrich_observe_observables
from tests.functional.tests.constants import (
    MODULE_NAME,
    CONFIDENCE,
    PRODUCER,
    CTR_ENTITIES_LIMIT,
    CHRONICLE_LINK,
    URL_CATEGORY,
    RELATION_TYPE,
    TARGETS_OBSERVABLES_VALUE,
    TARGETS_OBSERVABLES_TYPES
)


@pytest.mark.skip('switched off till find valid data')
# @pytest.mark.parametrize(
#     'observable_type, observable',
#     (
#      ('ip', '1.1.1.1'),
#      ('domain', 'wp.com'),
#      ('md5', '34d5ea586a61b0aba512c0cb1d3d8b15')
#      )
# )
def test_positive_sighting(module_headers, observable, observable_type):
    """Perform testing for enrich observe observables endpoint to get
    sightings for observable from Google Chronicle

    ID: CCTRI-768-07b71138-a7e9-417d-a0f3-866dcde1536c

    Steps:
        1. Send request to enrich observe observable endpoint

    Expectedresults:
        1. Check that data in response body contains expected sightings for
            observable from Google Chronicle

    Importance: Critical
    """
    observables = [{'type': observable_type, 'value': observable}]
    response_from_all_modules = enrich_observe_observables(
        payload=observables,
        **{'headers': module_headers}
    )

    response_from_chronicle_module = get_observables(response_from_all_modules,
                                                     MODULE_NAME)

    assert response_from_chronicle_module['module'] == MODULE_NAME
    assert response_from_chronicle_module['module_instance_id']
    assert response_from_chronicle_module['module_type_id']

    sightings = response_from_chronicle_module['data']['sightings']
    assert len(sightings['docs']) > 0

    for sighting in sightings['docs']:
        assert sighting['schema_version']
        assert sighting['type'] == 'sighting'
        assert sighting['source'] == PRODUCER
        assert sighting['confidence'] in CONFIDENCE
        assert 0 < sighting['count'] <= CTR_ENTITIES_LIMIT
        assert sighting['observed_time']['start_time'] == (
            sighting['observed_time']['end_time'])
        assert sighting['id'].startswith('transient:sighting-')
        assert sighting['title'] == f'Found in {PRODUCER}'
        assert sighting['internal'] is True
        assert sighting['source_uri'].startswith(
            f'{CHRONICLE_LINK}'
            f'{URL_CATEGORY[observable_type]}?{observable_type}={observable}')
        if observable_type == 'domain':
            assert sighting['observables'][0]['type'] == observable_type
            assert sighting['observables'][0]['value'].endswith(observable)
        else:
            assert sighting['observables'] == observables

        if 'relations' in sighting:
            for relation in sighting['relations']:
                assert relation['origin'] == f'{PRODUCER} Enrichment Module'
                assert relation['relation'] == RELATION_TYPE[observable_type]
                assert relation['source']['value']
                assert relation['source']['type']
                if observable_type == 'domain':
                    assert relation['related']['value'].split('.', 1)[1] == (
                        observable)
                if observable_type == 'ip':
                    assert relation['related']['value'] == observable
                assert relation['related']['type'] == observable_type

        for target in sighting['targets']:
            assert target['type'] == 'endpoint'
            for target_observable in target['observables']:
                assert target_observable['type'] in TARGETS_OBSERVABLES_TYPES
                if target_observable['type'] == 'hostname':
                    assert target_observable['value'].endswith(
                        TARGETS_OBSERVABLES_VALUE)
            assert target['observed_time']['start_time'] == (
                target['observed_time']['end_time'])

    assert sightings['count'] == len(sightings['docs']) <= CTR_ENTITIES_LIMIT
