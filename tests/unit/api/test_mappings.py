import json

from pytest import fixture

from api.mappings import (
    Domain, Mapping, SHA256,
    IP, IPV6, MD5, SHA1
)

from collections import namedtuple
File_Mapping = namedtuple('File_Mapping', 'file mapping')


def data_data():

    yield File_Mapping('domain.json', Domain({"type": "domain", "value": "cisco.com"}))
    yield File_Mapping('ip.json', IP({"type": "ip", "value": "127.0.0.1"}))
    yield File_Mapping('ipv6.json',
           IPV6({"type": "ipv6",
                 "value": "2001:0db8:85a3:0000:0000:8a2e:0370:7334"}))
    yield File_Mapping('md5.json', MD5({"type": "domain", "value": "cisco.com"}))
    yield File_Mapping('sha1.json', SHA1({"type": "domain", "value": "cisco.com"}))
    yield File_Mapping('sha256.json', SHA256({"type": "domain", "value": "cisco.com"}))


@fixture(scope='module', params=data_data(), ids=lambda d: str(d))
def test_data(request):
    return request.param


def tests():
    yield 'extract_sightings'
    yield 'extract_indicators'


@fixture(scope='module', params=tests(), ids=lambda d: str(d))
def test_test(request):
    return request.param


def test_map(test_data, test_test):
    with open('tests/unit/data/' + test_data.file) as file:
        data = json.load(file)
        sightings = getattr(test_data.mapping, test_test)(data[test_test]['input'])
        for sighting in sightings:
            assert sighting.pop('id').startswith('transient:')
        assert sightings == data[test_test]['output']


def test_mapping_of():
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
