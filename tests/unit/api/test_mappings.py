import json

from api.mappings import (
    Domain, Mapping, SHA256,
    IP, IPV6, MD5, SHA1
)


def test_mapping_of():
    assert isinstance(Mapping.for_({'type': 'domain'}), Domain)
    assert isinstance(Mapping.for_({'type': 'sha256'}), SHA256)
    assert isinstance(Mapping.for_({'type': 'sha1'}), SHA1)
    assert isinstance(Mapping.for_({'type': 'ip'}), IP)
    assert isinstance(Mapping.for_({'type': 'ipv6'}), IPV6)
    assert isinstance(Mapping.for_({'type': 'md5'}), MD5)
    assert Mapping.for_({'type': 'whatever'}) is None


def test_domain_map():
    m = Domain({"type":  "domain", "value": "cisco.com"})
    assert_maps_correctly_sightings(m, 'domain.json')
    assert_maps_correctly_indicators(m, 'domain.json')


def test_md5_map():
    # ToDo: Add more data to file md5.json.
    m = MD5({})
    assert_maps_correctly_sightings(m, 'md5.json')
    assert_maps_correctly_indicators(m, 'md5.json')


def test_sha256_map():
    # ToDo: Add more data to file sha256.json.
    m = SHA256({})
    assert_maps_correctly_sightings(m, 'sha256.json')
    assert_maps_correctly_indicators(m, 'sha256.json')


def test_sha1_map():
    # ToDo: Add more data to file sha1.json.
    m = SHA1({})
    assert_maps_correctly_sightings(m, 'sha1.json')
    assert_maps_correctly_indicators(m, 'sha1.json')


def test_ip_map():
    m = IP({"type": "ip", "value": "127.0.0.1"})
    assert_maps_correctly_sightings(m, 'ip.json')
    assert_maps_correctly_indicators(m, 'ip.json')


def test_ipv6_map():
    m = IPV6({"type": "ipv6",
              "value": "2001:0db8:85a3:0000:0000:8a2e:0370:7334"})
    assert_maps_correctly_sightings(m,'ipv6.json')
    assert_maps_correctly_indicators(m,'ipv6.json')


def assert_maps_correctly_sightings(mapping, path):
    with open('tests/unit/data/' + path) as file:
        data = json.load(file)
        sightings = mapping.extract_sightings(data['extract_sightings']['input'])
        for sighting in sightings:
            assert sighting.pop('id').startswith('transient:')
        assert sightings == data['extract_sightings']['output']


def assert_maps_correctly_indicators(mapping, path):
    with open('tests/unit/data/' + path) as file:
        data = json.load(file)
        indicators = mapping.extract_indicators(data['extract_indicators']['input'])
        for indicator in indicators:
            assert indicator.pop('id').startswith('transient:')
        assert indicators == data['extract_indicators']['output']


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




