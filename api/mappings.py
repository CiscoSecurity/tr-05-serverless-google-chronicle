import json
from abc import ABCMeta, abstractmethod
from http import HTTPStatus
from uuid import uuid4

from api.errors import UnexpectedChronicleResponseError
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
        sightings = []

        def sighting(asset, artifact):
            return {
                'id': f'transient:{uuid4()}',
                'type': 'sighting',
                'schema_version': '1.0.16',
                'confidence': 'High',
                'count': len(assets),
                'source': 'Chronicle',
                'source_uri': assets_data['uri'][0],
                'internal': True,
                'title': 'Found in Chronicle',
                'observables': [
                    self.artifact_to_observable(
                        artifact['artifactIndicator'])
                ],
                'observed_time': {
                    'start_time':
                        artifact['seenTime']
                },

                'targets': [
                    {
                        'type': 'endpoint',
                        'observables': self.asset_to_observables(asset),
                        'observed_time': {'start_time': artifact['seenTime']}
                    }
                ]

            }

        def indicator(source):
            r = {
                'type': 'indicator',
                'schema_version': '1.0.16',
                'producer': 'Chronicle',
                'valid_time': [],
                'confidence': self.confidence(source.get('confidenceScore', {}).get('strRawConfidenceScore')),
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

        for asset in assets:
            sightings.append(sighting(asset['asset'],
                                      asset['firstSeenArtifactInfo']))
            sightings.append(sighting(asset['asset'],
                                      asset['lastSeenArtifactInfo']))

        sources = ioc_details.get('sources', [])
        indicators = [indicator(source) for source in sources]

        return sightings, indicators

    @staticmethod
    def confidence(raw_confidence_score):
        # ToDo: This field may be a string "High", "Low", etc
        #  or it may be a number as a string between 0 and 127 "71", "124".
        #  Will need some logic to map those values to the required
        #  High, Medium, Low for now just split them evenly

        if raw_confidence_score is None:
            return 'None'

        segments = [
            (43, 'Low'),
            (86, 'Medium'),
            (127, 'High')
        ]

        if raw_confidence_score in ('Low', 'Medium', 'High'):
            return raw_confidence_score

        try:
            for bound, result in segments:
                if int(raw_confidence_score) <= bound:
                    return result
        except ValueError:
            pass

        return 'Unknown'

    @staticmethod
    def severity(raw_severity):
        # ToDo: Finding out what the possible values are have only seen "High".
        #  The value is not always present in the response
        #  Got "Info"
        return raw_severity

    @staticmethod
    def asset_to_observables(asset):
        type_map = {
            'hostname': 'hostname',
            'assetIpAddress': 'ip'
            # ToDO: "???": 'mac_address',
        }

        # ToDo: differ ip and ipv6
        return [{"value": v,
                 "type": type_map.get(k, k)} for k, v in asset.items()]

    def artifact_to_observable(self, artifact_indicator):
        # ToDo: find better solution???
        values = list(artifact_indicator.values())
        return {'type': self.type(),
                'value': values[0]}


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
