import pytest
from ctrlibrary.core.utils import get_observables
from ctrlibrary.threatresponse.enrich import enrich_observe_observables
from tests.functional.tests.constants import (
    MODULE_NAME,
    PRODUCER,
    SOURCE_NAME,
    CONFIDENCE,
    SEVERITY,
    CTR_ENTITIES_LIMIT
)


@pytest.mark.parametrize(
    'observable_type, observable',
    (
     ('ip', '1.1.1.1'),
     ('domain', 'wp.com')
     )
)
def test_positive_indicators(module_headers, observable, observable_type):
    """Perform testing for enrich observe observables endpoint to get
    indicators from Google Chronicle

    ID: CCTRI-859-56c35f55-a7f7-4857-8ba1-39ef7f644932

    Steps:
        1. Send request to enrich observe observable endpoint

    Expectedresults:
        1. Check that data in response body contains expected indicators for
            observable from Google Chronicle

    Importance: Critical
    """
    observables = [{'type': observable_type, 'value': observable}]
    response_from_all_modules = enrich_observe_observables(
        payload=observables,
        **{'headers': module_headers}
    )

    response_from_chronicle_module = get_observables(
        response_from_all_modules, MODULE_NAME)

    assert response_from_chronicle_module['module'] == MODULE_NAME
    assert response_from_chronicle_module['module_instance_id']
    assert response_from_chronicle_module['module_type_id']

    indicators = response_from_chronicle_module['data']['indicators']
    assert len(indicators['docs']) > 0
    # check some generic properties
    for indicator in indicators['docs']:
        assert 'valid_time' in indicator
        assert indicator['type'] == 'indicator'
        assert indicator['producer'] == PRODUCER
        assert indicator['schema_version']
        assert indicator['short_description']
        assert indicator['id'].startswith('transient:indicator-')
        assert indicator['severity'] in SEVERITY
        assert indicator['confidence'] in CONFIDENCE
        if 'external_references' in indicator:
            for external_references in indicator['external_references']:
                assert external_references['source_name'] == SOURCE_NAME
                assert external_references['url'].startswith('http')

    assert indicators['count'] == (
        len(indicators['docs'])) <= (
        CTR_ENTITIES_LIMIT
    )
