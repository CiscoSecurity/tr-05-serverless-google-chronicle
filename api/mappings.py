import json
from abc import ABCMeta, abstractmethod
from uuid import uuid4

from datetime import datetime, timedelta

from api.errors import UnexpectedChronicleResponseError
from api.utils import (
    join_url,
    format_time_to_arg
)


class TimeFilter:
    def __init__(self, start_time=None, end_time=None):
        self.end = end_time or datetime.utcnow()
        self.start = start_time or self.end - timedelta(days=90)

    @staticmethod
    def format_time_to_arg(input_datetime):
        """
           Converts datetime to yyyy-MM-dd'T'HH:mm:ss'Z' format
           acceptable by Chronicle Backstory API

        """
        return f'{input_datetime.isoformat(timespec="seconds")}Z'

    def __str__(self):
        return (f'&start_time={format_time_to_arg(self.start)}'
                f'&end_time={format_time_to_arg(self.end)}')


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

        if response.status != 200:
            raise UnexpectedChronicleResponseError(body)

        return json.loads(body)

    def _list_assets(self, observable):
        return self._request_chronicle('/artifact/listassets',
                                       observable, TimeFilter())

    def _list_ioc_details(self, observable):
        return self._request_chronicle('artifact/listiocdetails', observable)

    def get(self, observable):
        """Retries and maps Chronicle Assets and IoC details to CTIM."""
        assets = self._list_assets(observable)
        ioc_details = self._list_ioc_details(observable)

        return self.map(observable, assets)

    @classmethod
    @abstractmethod
    def type(cls):
        """Returns the observable type that the mapping is able to process."""

    @abstractmethod
    def filter(self, observable):
        """Returns a relative URL to Graph Security to query alerts."""

    def map(self, observable, data):
        """Maps a Graph Security response to CTIM."""
        # ToDo:
        return {
            'id': f'transient:{uuid4()}',
            'count': 1,
            'source': 'Chronicle Backstory',
            'type': 'sighting'
        }


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
