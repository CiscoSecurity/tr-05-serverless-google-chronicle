import json
from datetime import datetime, timedelta
from http import HTTPStatus

from flask import current_app

from api.errors import (
    UnexpectedChronicleResponseError,
    UnsupportedArtifactTypeError
)
from api.utils import join_url


class ChronicleClient:
    def __init__(self, base_url, client):
        self.client = client
        self.base_url = base_url

    def _artifact_filter(self, observable):
        type_mapping = {
            'ip': 'destination_ip_address',
            'ipv6': 'destination_ip_address',
            'domain': 'domain_name',
            'md5': 'hash_md5',
            'sha1': 'hash_sha1',
            'sha256': 'hash_sha256',
        }

        artifact_type = type_mapping.get(observable["type"])
        if artifact_type is None:
            raise UnsupportedArtifactTypeError(observable["type"])

        return f'artifact.{artifact_type}={observable["value"]}'

    def _request_chronicle(self, path, observable,
                           time_filter=None, page_size=None):

        page_size_filter = ("&page_size=" + str(page_size)
                            if page_size is not None else '')

        url = join_url(
            self.base_url,
            f'{path}?{self._artifact_filter(observable)}'
            f'{str(time_filter or "")}'
            f'{page_size_filter or ""}'
        )

        response, body = self.client.request(
            url, 'GET',
            headers={'Content-Type': 'application/json',
                     'Accept': 'application/json',
                     'User-Agent': current_app.config['USER_AGENT']}
        )

        if response.status != HTTPStatus.OK:
            raise UnexpectedChronicleResponseError(response, body)

        return json.loads(body)

    def list_assets(self, observable, page_size=None):
        return self._request_chronicle(
            '/artifact/listassets', observable, TimeFilter(), page_size
        )

    def list_ioc_details(self, observable):
        allowed_types = ('domain', 'ip', 'ipv6')
        if observable['type'] not in allowed_types:
            return {}
        return self._request_chronicle('artifact/listiocdetails', observable)


class TimeFilter:
    def __init__(self):
        self.end = datetime.utcnow()
        delta = timedelta(
            days=current_app.config[
                'DEFAULT_NUMBER_OF_DAYS_FOR_CHRONICLE_TIME_FILTER'
            ]
        )
        self.start = self.end - delta

    @staticmethod
    def format_time_to_arg(input_datetime):
        """
           Converts datetime to yyyy-MM-dd'T'HH:mm:ss'Z' format
           acceptable by Chronicle Backstory API

        """
        return f'{input_datetime.isoformat(timespec="seconds")}Z'

    def __str__(self):
        return (f'&start_time={self.format_time_to_arg(self.start)}'
                f'&end_time={self.format_time_to_arg(self.end)}')
