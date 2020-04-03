from http import HTTPStatus

from flask import Blueprint, current_app

from api.client import TimeFilter
from api.errors import UnexpectedChronicleResponseError
from api.utils import (
    jsonify_data,
    get_chronicle_http_client,
    get_jwt,
    join_url
)

health_api = Blueprint('health', __name__)


@health_api.route('/health', methods=['POST'])
def health():
    url = join_url(
        current_app.config['API_URL'],
        '/artifact/listassets'
        '?artifact.domain_name=www.google.com&page_size=1'
        f'{str(TimeFilter())}'
    )

    http_client = get_chronicle_http_client(get_jwt())

    response, body = http_client.request(
        url, 'GET', headers={'Content-Type': 'application/json',
                             'Accept': 'application/json',
                             'User-Agent': current_app.config['USER_AGENT']}
    )

    if response.status != HTTPStatus.OK:
        raise UnexpectedChronicleResponseError(body)
    else:
        return jsonify_data({'status': 'ok'})
