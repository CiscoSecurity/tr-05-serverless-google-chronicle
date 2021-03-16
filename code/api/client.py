import json
from datetime import datetime, timedelta
from http import HTTPStatus
from ssl import SSLCertVerificationError
from google.auth.exceptions import RefreshError
from json.decoder import JSONDecodeError
from urllib.parse import urlencode

from flask import current_app

from api.errors import (
    UnexpectedChronicleResponseError,
    UnsupportedArtifactTypeError,
    ChronicleSSLError,
    AuthorizationError
)
from api.utils import join_url

NOT_CRITICAL_ERRORS = (HTTPStatus.BAD_REQUEST, HTTPStatus.NOT_FOUND)
EXPECTED_AUTH_ERRORS = {
    RefreshError: 'Invalid Client Email',
    JSONDecodeError: 'Invalid Token URI'
}


class ChronicleClient:
    def __init__(self, base_url, client):
        self.client = client
        self.base_url = base_url

    @staticmethod
    def _artifact_filter(observable):
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

        args = {f'artifact.{artifact_type}': observable["value"]}
        return urlencode(args)

    @staticmethod
    def _time_filter(number_of_days_to_filter):
        def format_time_to_arg(input_datetime):
            return f'{input_datetime.isoformat(timespec="seconds")}Z'

        end = datetime.utcnow()
        delta = timedelta(number_of_days_to_filter)
        start = end - delta

        return (f'&start_time={format_time_to_arg(start)}'
                f'&end_time={format_time_to_arg(end)}')

    def _request_chronicle(self, path, observable,
                           number_of_days_to_filter=None, page_size=None):

        time_filter = (self._time_filter(number_of_days_to_filter)
                       if number_of_days_to_filter is not None else '')

        page_size_filter = ("&page_size=" + str(page_size)
                            if page_size is not None else '')

        url = join_url(
            self.base_url,
            f'{path}?{self._artifact_filter(observable)}'
            f'{time_filter}'
            f'{page_size_filter}'
        )
        try:
            response, body = self.client.request(
                url, 'GET',
                headers={'Content-Type': 'application/json',
                         'Accept': 'application/json',
                         'User-Agent': current_app.config['USER_AGENT']}
            )
        except SSLCertVerificationError as error:
            raise ChronicleSSLError(error)
        except tuple(EXPECTED_AUTH_ERRORS) as error:
            raise AuthorizationError(EXPECTED_AUTH_ERRORS[error.__class__])

        if response.status == HTTPStatus.OK:
            return json.loads(body)

        if response.status in NOT_CRITICAL_ERRORS:
            return {}

        raise UnexpectedChronicleResponseError(response, body)

    def list_assets(self, observable, number_of_days_to_filter,
                    page_size=None):
        return self._request_chronicle('/artifact/listassets', observable,
                                       number_of_days_to_filter, page_size)

    def list_ioc_details(self, observable):
        allowed_types = ('domain', 'ip', 'ipv6')
        if observable['type'] not in allowed_types:
            return {}
        return self._request_chronicle('artifact/listiocdetails', observable)
