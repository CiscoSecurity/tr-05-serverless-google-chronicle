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
    assert_maps_correctly(Domain({"type":  "domain", "value": "cisco.com"}),
                          'domain.json')


def test_md5_map():
    # ToDo: Add more data to file md5.json.
    assert_maps_correctly(MD5({}), 'md5.json')


def test_sha256_map():
    # ToDo: Add more data to file sha256.json.
    assert_maps_correctly(SHA256({}), 'sha256.json')


def test_sha1_map():
    # ToDo: Add more data to file sha1.json.
    assert_maps_correctly(SHA1({}), 'sha1.json')


def test_ip_map():
    assert_maps_correctly(IP({"type": "ip", "value": "127.0.0.1"}), 'ip.json')


def test_ipv6_map():
    assert_maps_correctly(
        IPV6({"type": "ipv6",
              "value": "2001:0db8:85a3:0000:0000:8a2e:0370:7334"}),
        'ipv6.json'
    )


def assert_maps_correctly(mapping, path):
    with open('tests/unit/data/' + path) as file:
        data = json.load(file)
        sightings = mapping.extract_sightings(data['input'])
        for sighting in sightings:
            assert sighting.pop('id').startswith('transient:')
        assert sightings == data['output']  # ToDo
