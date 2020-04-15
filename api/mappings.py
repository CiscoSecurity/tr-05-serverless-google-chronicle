from abc import ABCMeta, abstractmethod
from collections import namedtuple
from uuid import uuid4

from api.utils import all_subclasses

NONE = 'None'
INFO = 'Info'
LOW = 'Low'
MEDIUM = 'Medium'
HIGH = 'High'
UNKNOWN = 'Unknown'
INDICATOR_SCORES = (INFO, LOW, MEDIUM, HIGH, NONE, UNKNOWN)

CTIM_DEFAULTS = {
    'schema_version': '1.0.16',
}


class Mapping(metaclass=ABCMeta):

    def __init__(self, observable):
        self.observable = observable

    @classmethod
    def for_(cls, observable):
        """Returns an instance of `Mapping` for the specified type."""

        for subcls in all_subclasses(Mapping):
            if subcls.type() == observable['type']:
                return subcls(observable)

        return None

    @classmethod
    @abstractmethod
    def type(cls):
        """Returns the observable type that the mapping is able to process."""

    FlattenAssertRecord = namedtuple(
        'FlattenAssertRecord',
        'asset_observables artifact_observables seen_time'
    )

    def prepare_asset_records(self, records):
        """
        Filters nonmappable Chronicle assets and
        converts original Chronicle asset record:
        {
          "asset": {
            "<asset_type>": "<asset_value>"
          },
          "firstSeenArtifactInfo": {
            "artifactIndicator": {
              "<artifact_type>": "<artifact_value>""
            },
            "seenTime": "<artifact_seen_time"
          },
          "lastSeenArtifactInfo": {
            "artifactIndicator": {
              "<artifact_type>": "<artifact_value>""
            },
            "seenTime": "<artifact_seen_time"
          }
        }

        to FlattenAssertRecord.
        """
        results = []

        for record in records:
            first_artifact = record['firstSeenArtifactInfo']
            last_artifact = record.get('lastSeenArtifactInfo')

            to_add = (first_artifact,)
            if last_artifact and last_artifact != first_artifact:
                to_add = (first_artifact, last_artifact)

            asset_observables = self.get_observables(record['asset'])
            for artifact in to_add:
                artifact_observables = self.artifact_observables(artifact)
                if artifact_observables:
                    results.append(
                        self.FlattenAssertRecord(asset_observables,
                                                 artifact_observables,
                                                 artifact['seenTime'])
                    )

        return results

    def extract_sightings(self, assets_data, limit):
        def sighting(record):
            result = {
                **CTIM_DEFAULTS,
                'id': f'transient:{uuid4()}',
                'type': 'sighting',
                'source': 'Chronicle',
                'title': 'Found in Chronicle',
                'confidence': HIGH,
                'internal': True,
                'count': asset_records_count,
                'observables': record.artifact_observables,
                'observed_time': {'start_time': record.seen_time},
            }

            if uri:
                result['source_uri'] = uri

            if record.asset_observables:
                result['targets'] = [
                    {
                        'type': 'endpoint',
                        'observables': record.asset_observables,
                        'observed_time': {'start_time': record.seen_time}
                    }
                ]

            return result

        uri_list = assets_data.get('uri')
        uri = uri_list[0] if uri_list else None

        asset_records = assets_data.get('assets', [])
        asset_records_count = len(asset_records)

        asset_records = self.prepare_asset_records(asset_records)
        asset_records.sort(key=lambda r: r.seen_time, reverse=True)
        asset_records = asset_records[:limit]

        return [sighting(r) for r in asset_records]

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

    def extract_indicators(self, ioc_details, limit):
        def indicator(source):
            r = {
                **CTIM_DEFAULTS,
                'id': f'transient:{uuid4()}',
                'type': 'indicator',
                'producer': 'Chronicle',
                'valid_time': {},
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

        sources = ioc_details.get('sources', [])[:limit]
        return [indicator(source) for source in sources]

    @staticmethod
    def create_relationships(sightings, indicators):
        def sighting_of(sighting, indicator):
            return {
                **CTIM_DEFAULTS,
                'id': f'transient:{uuid4()}',
                'type': 'relationship',
                'relationship_type': 'sighting-of',
                'source_ref': sighting['id'],
                'target_ref': indicator['id']}

        return [sighting_of(s, i) for i in indicators for s in sightings]

    @staticmethod
    def confidence(raw_confidence_score):
        # raw_confidence_score possible values: 'Low', 'Medium', 'High', ''
        # or a number as a string between 0 and 127

        if raw_confidence_score in (None, ''):
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
        # raw_severity possible values: 'n/a', 'Low', 'Medium', 'High', 'Info'
        if raw_severity in (None, 'n/a'):
            return NONE

        if raw_severity in INDICATOR_SCORES:
            return raw_severity

        return UNKNOWN


class Domain(Mapping):

    @classmethod
    def type(cls):
        return 'domain'


class IP(Mapping):

    def __init__(self, observable):
        super().__init__(observable)
        self.resolved_domains = set()

    @classmethod
    def type(cls):
        return 'ip'

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

        resolved_domains = sorted(self.resolved_domains)
        return [
            resolved_to(domain, self.observable)
            for domain in resolved_domains
        ]

    def extract_sightings(self, assets_data, limit):
        sightings = super().extract_sightings(assets_data, limit)
        relationships = self.resolved_domains_relationships()

        if sightings and relationships:
            for sighting in sightings:
                sighting['relations'] = relationships

        return sightings


class IPV6(IP):

    @classmethod
    def type(cls):
        return 'ipv6'


class MD5(Mapping):

    @classmethod
    def type(cls):
        return 'md5'


class SHA1(Mapping):

    @classmethod
    def type(cls):
        return 'sha1'


class SHA256(Mapping):

    @classmethod
    def type(cls):
        return 'sha256'
