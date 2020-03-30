import json
from abc import ABCMeta, abstractmethod
from http import HTTPStatus
from uuid import uuid4

from api.errors import UnexpectedChronicleResponseError
from api.utils import join_url, TimeFilter, all_subclasses

NONE = 'None'
INFO = 'Info'
LOW = 'Low'
MEDIUM = 'Medium'
HIGH = 'High'
UNKNOWN = 'Unknown'
INDICATOR_SCORES = (INFO, LOW, MEDIUM, HIGH, NONE, UNKNOWN)


class Mapping(metaclass=ABCMeta):

    def __init__(self, base_url, client):
        self.client = client
        self.base_url = base_url
        self.observable = None

    @classmethod
    def of(cls, type_, base_url, client):
        """Returns an instance of `Mapping` for the specified type."""

        for subcls in all_subclasses(Mapping):
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
        self.observable = observable
        assets = self._list_assets(observable)
        ioc_details = self._list_ioc_details(observable)

        return self.map(assets, ioc_details)

    @classmethod
    @abstractmethod
    def type(cls):
        """Returns the observable type that the mapping is able to process."""

    @abstractmethod
    def filter(self, observable):
        """Returns an artifact filter to query Chronicle."""

    def map(self, assets_data, ioc_details):
        """Maps a Chronicle response to CTIM."""

        assets = assets_data.get('assets', [])

        def sighting(asset, artifact):
            artifact_observables = self.artifact_observables(artifact)
            if artifact_observables:
                result = {
                    'id': f'transient:{uuid4()}',
                    'type': 'sighting',
                    'schema_version': '1.0.16',
                    'confidence': 'High',
                    'count': len(assets),
                    'source': 'Chronicle',
                    'source_uri': assets_data['uri'][0],
                    'internal': True,
                    'title': 'Found in Chronicle',
                    'observables': artifact_observables,
                    'observed_time': {'start_time': artifact['seenTime']},
                }
            else:
                return None

            asset_observables = self.get_observables(asset)
            if asset_observables:
                result['targets'] = [
                    {
                        'type': 'endpoint',
                        'observables': asset_observables,
                        'observed_time': {'start_time': artifact['seenTime']}
                    }
                ]

            return result

        def indicator(source):
            r = {
                'id': f'transient:{uuid4()}',
                'type': 'indicator',
                'schema_version': '1.0.16',
                'producer': 'Chronicle',
                'valid_time': [],
                'confidence': self.confidence(
                    source.get('confidenceScore', {}).get(
                        'strRawConfidenceScore')),
                'severity': self.severity(source.get('rawSeverity')),
                'short_description': source['category'],
            }

            source_url = source.get('sourceUrl')
            if source_url:
                r['external_references'] = [
                    {"source_name": "Chronicle IOC",
                     "url": source_url}
                ]

            return r

        def relationship(indicator, sighting):
            return {'type': 'relationship',
                    'relationship_type': 'sighting-of',
                    'schema_version': '1.0.16',
                    'id': f'transient:{uuid4()}',
                    'source_ref': sighting['id'],
                    'target_ref': indicator['id']}

        sources = ioc_details.get('sources', [])

        sightings = []
        relationships = []
        indicators = []
        for asset in assets:
            sightings.append(sighting(asset['asset'],
                                      asset['firstSeenArtifactInfo']))
            sightings.append(sighting(asset['asset'],
                                      asset['lastSeenArtifactInfo']))

        sightings = [s for s in sightings if s is not None]

        for source in sources:
            i = indicator(source)
            indicators.append(i)

            for s in sightings:
                relationships.append(relationship(i, s))

        return sightings, indicators, relationships

    @staticmethod
    def confidence(raw_confidence_score):
        # ToDo: This field may be a string "High", "Low", etc
        #  or it may be a number as a string between 0 and 127 "71", "124".
        #  Will need some logic to map those values to the required
        #  High, Medium, Low for now just split them evenly

        if raw_confidence_score is None:
            return NONE

        if raw_confidence_score in INDICATOR_SCORES:
            return raw_confidence_score

        try:
            segments = [
                (43, LOW),
                (86, MEDIUM),
                (127, HIGH)
            ]

            for bound, result in segments:
                if int(raw_confidence_score) <= bound:
                    return result
        except ValueError:
            pass

        return UNKNOWN

    @staticmethod
    def severity(raw_severity):
        # ToDo: Finding out what the possible values are have only seen "High".
        #  The value is not always present in the response
        #  Got "Info"
        if raw_severity is None:
            return NONE

        if raw_severity in INDICATOR_SCORES:
            return raw_severity

        return UNKNOWN

    @staticmethod
    def get_observables(info):
        """Retrieves CTR observables list
        from Chronicle {'type': 'value'} structures."""

        def ctr_type(chronicle_type, value):
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

            mapped_type = type_map.get(chronicle_type)

            if mapped_type and mapped_type == 'ip' and len(value) > 15:
                return 'ipv6'

            return mapped_type

        observables = []
        for type_, value in info.items():
            type_ = ctr_type(type_, value)
            if type_:
                observables.append({"value": value, "type": type_})

        return observables

    def artifact_observables(self, artifact):
        """Retrieves CTR observables list from Chronicle Artifact."""
        return self.get_observables(artifact['artifactIndicator'])


class Domain(Mapping):

    @classmethod
    def type(cls):
        return 'domain'

    def filter(self, observable):
        return f'artifact.domain_name={observable}'


class IP(Mapping):

    def __init__(self, base_url, client):
        super().__init__(base_url, client)
        self.resolved_domains = set()

    @classmethod
    def type(cls):
        return 'ip'

    def filter(self, observable):
        return f'artifact.destination_ip_address={observable}'

    def artifact_observables(self, artifact):
        """ Chronicle returns assets for resolved domains in
            response for ips, so we need to separate it. """
        ips = []
        initial_observables = super().artifact_observables(artifact)

        for ob in initial_observables:
            if ob['type'] == self.type():
                ips.append(ob)
            elif ob['type'] == 'domain':
                self.resolved_domains.add(ob['value'])

        return ips

    def resolved_domains_relationships(self):
        self.resolved_domains = sorted(self.resolved_domains)

        def resolved_to(domain, ip_observable):
            return {
                "origin": "Chronicle Enrichment Module",
                "relation": "Resolved_To",
                "source": {
                    "value": domain,
                    "type": "domain"
                },
                "related": {
                    "value": ip_observable['value'],
                    "type": ip_observable['type']
                }
            }

        return [
            resolved_to(domain, self.observable)
            for domain in self.resolved_domains
        ]

    def map(self, assets_data, ioc_details):
        sightings, indicators, relationships = super().map(assets_data, ioc_details)
        relationships = self.resolved_domains_relationships()

        if sightings and relationships:
            for sighting in sightings:
                sighting['relations'] = relationships

        return sightings, indicators, relationships


class IPV6(IP):

    @classmethod
    def type(cls):
        return 'ipv6'


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
