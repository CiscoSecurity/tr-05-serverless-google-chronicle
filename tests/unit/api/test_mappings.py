import json

from api.mappings import (
    Domain, Mapping, SHA256,
    IP, MD5, SHA1
)


def test_mapping_of(client):
    base_url = client.application.config['API_URL']
    assert isinstance(Mapping.of('domain', base_url, client), Domain)
    assert isinstance(Mapping.of('sha256', base_url, client), SHA256)
    assert isinstance(Mapping.of('sha1', base_url, client), SHA1)
    assert isinstance(Mapping.of('ip', base_url, client), IP)
    assert isinstance(Mapping.of('md5', base_url, client), MD5)
    assert Mapping.of('whatever', base_url, client) is None


def test_domain_filter(client):
    base_url = client.application.config['API_URL']
    mapping = Domain(base_url, client)
    url = mapping.filter('https://www.cisco.com/')

    assert url == 'artifact.domain_name=https://www.cisco.com/'


def test_domain_map(client):
    base_url = client.application.config['API_URL']
    assert_maps_correctly(Domain(base_url, client), 'domain.json')


def test_md5_filter(client):
    base_url = client.application.config['API_URL']
    mapping = MD5(base_url, client)
    url = mapping.filter('3a7068e0c9930f')

    assert url == 'artifact.hash_md5=3a7068e0c9930f'


def test_md5_map(client):
    base_url = client.application.config['API_URL']
    # ToDo: Add more data to file md5.json.
    assert_maps_correctly(MD5(base_url, client), 'md5.json')


def test_sha256_filter(client):
    base_url = client.application.config['API_URL']
    mapping = SHA256(base_url, client)
    url = mapping.filter('deadbeef')

    assert url == 'artifact.hash_sha256=deadbeef'


def test_sha256_map(client):
    base_url = client.application.config['API_URL']
    # ToDo: Add more data to file sha256.json.
    assert_maps_correctly(SHA256(base_url, client), 'sha256.json')


def test_sha1_filter(client):
    base_url = client.application.config['API_URL']
    mapping = SHA1(base_url, client)
    url = mapping.filter('cf23df2207')

    assert url == 'artifact.hash_sha1=cf23df2207'


def test_sha1_map(client):
    base_url = client.application.config['API_URL']
    # ToDo: Add more data to file sha1.json.
    assert_maps_correctly(SHA1(base_url, client), 'sha1.json')


def test_ip_filter(client):
    base_url = client.application.config['API_URL']
    mapping = IP(base_url, client)
    url = mapping.filter('127.0.0.1')

    assert url == 'artifact.destination_ip_address=127.0.0.1'


def test_ip_map(client):
    base_url = client.application.config['API_URL']
    assert_maps_correctly(IP(base_url, client), 'ip.json')


# def test_ipv6_filter(client):
#     base_url = client.application.config['API_URL']
#     mapping = IPV6(base_url, client)
#     url = mapping.filter('2001:0db8:85a3:0000:0000:8a2e:0370:7334')
#
#     assert url == (
#         'artifact.destination_ip_address='
#         '2001:0db8:85a3:0000:0000:8a2e:0370:7334'
#     )
#
#
# def test_ipv6_map(client):
#     base_url = client.application.config['API_URL']
#     # ToDo: Add more data to file ipv6.json.
#     assert_maps_correctly(IPV6(base_url, client), 'ipv6.json')


def assert_maps_correctly(mapping, path):
    with open('tests/unit/data/' + path) as file:
        data = json.load(file)
        output = mapping.map(data['observable'], data['input'])
        for sighting in output:
            assert sighting.pop('id').startswith('transient:')
        assert output == data['output']
