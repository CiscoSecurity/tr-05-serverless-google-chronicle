from flask import Blueprint, current_app

from api.client import TimeFilter, ChronicleClient
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
    chronicle_client = ChronicleClient(current_app.config['API_URL'],
                                       http_client)

    _ = chronicle_client.list_assets({'type': 'domain',
                                      'value': 'www.google.com'})

    return jsonify_data({'status': 'ok'})
