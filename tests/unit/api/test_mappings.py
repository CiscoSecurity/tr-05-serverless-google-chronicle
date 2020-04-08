import json

from pytest import fixture

from api.mappings import (
    Domain, Mapping, SHA256,
    IP, IPV6, MD5, SHA1
)

from collections import namedtuple


def input_sets():
    TestData = namedtuple('TestData', 'file mapping')
    yield TestData('domain.json',
                   Domain({'type': 'domain', 'value': 'cisco.com'}))
    yield TestData('ip.json', IP({'type': 'ip', 'value': '127.0.0.1'}))
    yield TestData('ipv6.json',
                   IPV6({'type': 'ipv6',
                         'value': '2001:0db8:85a3:0000:0000:8a2e:0370:7334'}))
    yield TestData('md5.json',
                   MD5({'type': 'md5',
                        'value': 'feeeb7d9b65e7c0624aee185c969a723'}))
    yield TestData('sha1.json',
                   SHA1({'type': 'sha1',
                         'value': 'ad90dfe35a50ec9b6b93f720f036b1a6f6b32c4c'}))
    yield TestData('sha256.json',
                   SHA256({'type': 'sha256',
                           'value': ('66489577986bc78cf66cbb2333350b8872faf31'
                                     'da241d23735ace67e12510143')}))


@fixture(scope='module', params=input_sets(), ids=lambda d: d.file)
def input_data(request):
    return request.param


def methods():
    yield 'extract_sightings'
    yield 'extract_indicators'


@fixture(scope='module', params=methods())
def method(request):
    return request.param


def test_map(input_data, method):
    with open('tests/unit/data/' + input_data.file) as file:
        data = json.load(file)

        results = getattr(input_data.mapping, method)(data[method]['input'])

        for record in results:
            assert record.pop('id').startswith('transient:')
        assert results == data[method]['output']


def test_mapping_for_():
    assert isinstance(Mapping.for_({'type': 'domain'}), Domain)
    assert isinstance(Mapping.for_({'type': 'sha256'}), SHA256)
    assert isinstance(Mapping.for_({'type': 'sha1'}), SHA1)
    assert isinstance(Mapping.for_({'type': 'ip'}), IP)
    assert isinstance(Mapping.for_({'type': 'ipv6'}), IPV6)
    assert isinstance(Mapping.for_({'type': 'md5'}), MD5)
    assert Mapping.for_({'type': 'whatever'}) is None


def test_create_relationships():
    sightings = [{'id': 's1'}, {'id': 's2'}, {'id': 's3'}]
    indicators = []
    relationships = Mapping.create_relationships(sightings, indicators)
    for relationship in relationships:
        assert relationship.pop('id').startswith('transient:')
    assert relationships == []

    sightings = []
    indicators = [{'id': 'i1'}, {'id': 'i2'}]
    relationships = Mapping.create_relationships(sightings, indicators)
    for relationship in relationships:
        assert relationship.pop('id').startswith('transient:')
    assert relationships == []

    sightings = [{'id': 's1'}, {'id': 's2'}, {'id': 's3'}]
    indicators = [{'id': 'i1'}, {'id': 'i2'}]
    relationships = Mapping.create_relationships(sightings, indicators)
    for relationship in relationships:
        assert relationship.pop('id').startswith('transient:')

    assert relationships == [
        {'schema_version': '1.0.16',
         'type': 'relationship', 'relationship_type': 'sighting-of',
         'source_ref': 's1', 'target_ref': 'i1'},
        {'schema_version': '1.0.16',
         'type': 'relationship', 'relationship_type': 'sighting-of',
         'source_ref': 's2', 'target_ref': 'i1'},
        {'schema_version': '1.0.16',
         'type': 'relationship', 'relationship_type': 'sighting-of',
         'source_ref': 's3', 'target_ref': 'i1'},
        {'schema_version': '1.0.16',
         'type': 'relationship', 'relationship_type': 'sighting-of',
         'source_ref': 's1', 'target_ref': 'i2'},
        {'schema_version': '1.0.16',
         'type': 'relationship', 'relationship_type': 'sighting-of',
         'source_ref': 's2', 'target_ref': 'i2'},
        {'schema_version': '1.0.16',
         'type': 'relationship', 'relationship_type': 'sighting-of',
         'source_ref': 's3', 'target_ref': 'i2'}
    ]
