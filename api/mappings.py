import json
from abc import ABCMeta, abstractmethod
from http import HTTPStatus
from uuid import uuid4

from api.errors import (
    UnexpectedChronicleResponseError,
    UnknownObservableTypeError
)
from api.utils import join_url, TimeFilter


class Mapping(metaclass=ABCMeta):

    def __init__(self, base_url, client):
        self.client = client
        self.base_url = base_url

    @classmethod
    def of(cls, type_, base_url, client):
        """Returns an instance of `Mapping` for the specified type."""

        for subcls in Mapping.__subclasses__():
            if subcls.type() == type_:
                return subcls(base_url, client)

        return None

    def _request_chronicle(self, path, observable, time_filter=None):
        url = join_url(
            self.base_url,
            f'{path}?{self.filter(observable)}{str(time_filter or "")}'
        )

        response, body = self.client.request(
            url, 'GET', headers={'Content-Type': 'application/json',
                                 'Accept': 'application/json'}
        )

        if response.status != HTTPStatus.OK:
            raise UnexpectedChronicleResponseError(body)

        return json.loads(body)

    def _list_assets(self, observable):
        return self._request_chronicle('/artifact/listassets',
                                       observable, TimeFilter())

    def _list_ioc_details(self, observable):
        return self._request_chronicle('artifact/listiocdetails', observable)

    def get(self, observable):
        """Retrieves and maps Chronicle Assets and IoC details to CTIM."""
        assets = self._list_assets(observable)
        # ToDO: ioc_details = self._list_ioc_details(observable)

        return self.map(observable, assets)

    @classmethod
    @abstractmethod
    def type(cls):
        """Returns the observable type that the mapping is able to process."""

    @abstractmethod
    def filter(self, observable):
        """Returns an artifact filter to query Chronicle."""

    def map(self, observable, data):
        """Maps a Chronicle response to CTIM."""

        def sighting(asset, artifact):

            initial_artifact_observables = self._get_observables(artifact['artifactIndicator'])
            artifact_observables = []
            for ob in initial_artifact_observables:
                if self.type() in ('ip', 'ipv6') and ob != observable:
                    resolved_domains.add(ob['value'])
                else:
                    artifact_observables.append(ob)

            if not artifact_observables:
                return

            return {
                'id': f'transient:{uuid4()}',
                'type': 'sighting',
                'schema_version': '1.0.16',
                'confidence': 'High',
                'count': len(assets),
                'source': 'Chronicle',
                'source_uri': data['uri'][0],
                'internal': True,
                'title': 'Found in Chronicle',
                'observables': artifact_observables,
                'observed_time': {
                    'start_time':
                        artifact['seenTime']
                },
                'targets': [
                    {
                        'type': 'endpoint',
                        'observables': self._get_observables(asset),
                        'observed_time': {'start_time': artifact['seenTime']}
                    }
                ]

            }

        def resolved_to(domain, ip):
            return {
                "origin": "Chronicle Enrichment Module",
                "relation": "Resolved_To",
                "source": {
                    "value": domain,
                    "type": "domain"
                },
                "related": {
                    "value": ip,
                    "type": "ip"
                }
            }

        assets = data.get('assets', [])
        sightings = []
        resolved_domains = set()

        for asset in assets:
            s1 = sighting(asset['asset'],
                          asset['firstSeenArtifactInfo'])
            s2 = sighting(asset['asset'],
                          asset['lastSeenArtifactInfo'])

            if s1:
                sightings.append(s1)
            if s2:
                sightings.append(s2)


        a = 10

        domain_relationships = [
            resolved_to(domain, observable)
            for domain in resolved_domains
        ]

        if domain_relationships:
            for s in sightings:
                s['relations'] = domain_relationships

        return sightings

    @staticmethod
    def _get_observables(info):
        """Retrieves CTR observables list
        from Chronicle Asset or Artifact Indicator."""

        def ctr_type(chronicle_type):
            # ToDo: confirm assetMacAddress, destinationIpAddress,
            #  hashMd5, hashSha1 hashSha256
            type_map = {
                # assets types
                'hostname': 'hostname',
                'assetIpAddress': 'ip',
                'assetMacAddress': 'mac_address',
                # artifacts types
                'domainName': 'domain',
                'destinationIpAddress': 'ip',
                'hashMd5': 'md5',
                'hashSha1': 'sha1',
                'hashSha256': 'sha256',
            }

            ctr_type_ = type_map.get(chronicle_type)

            if ctr_type_ is None:
                raise UnknownObservableTypeError(chronicle_type)

            if ctr_type_ == 'ip' and len(ctr_type_) > 15:
                return 'ipv6'

            return ctr_type_

        return [{"value": value,
                 "type": ctr_type(type_)} for type_, value in info.items()]


class Domain(Mapping):

    @classmethod
    def type(cls):
        return 'domain'

    def filter(self, observable):
        return f'artifact.domain_name={observable}'


class IP(Mapping):

    @classmethod
    def type(cls):
        return 'ip'

    def filter(self, observable):
        return f'artifact.destination_ip_address={observable}'


class IPV6(IP):

    @classmethod
    def type(cls):
        return 'ipv6'

    def filter(self, observable):
        return f'artifact.destination_ip_address={observable}'


class MD5(Mapping):

    @classmethod
    def type(cls):
        return 'md5'

    def filter(self, observable):
        return f'artifact.hash_md5={observable}'


class SHA1(Mapping):

    @classmethod
    def type(cls):
        return 'sha1'

    def filter(self, observable):
        return f'artifact.hash_sha1={observable}'


class SHA256(Mapping):

    @classmethod
    def type(cls):
        return 'sha256'

    def filter(self, observable):
        return f'artifact.hash_sha256={observable}'
