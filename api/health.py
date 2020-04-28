from flask import Blueprint, current_app

from api.client import ChronicleClient
from api.utils import (
    jsonify_data,
    get_chronicle_http_client,
    get_jwt
)

health_api = Blueprint('health', __name__)


@health_api.route('/health', methods=['POST'])
def health():
    http_client = get_chronicle_http_client(get_jwt())
    chronicle_client = ChronicleClient(current_app.config['API_URL'],
                                       http_client)

    time_delta = current_app.config[
        'DEFAULT_NUMBER_OF_DAYS_FOR_CHRONICLE_TIME_FILTER'
    ]

    _ = chronicle_client.list_assets(
        {'type': 'domain', 'value': 'www.google.com'}, time_delta
    )

    return jsonify_data({'status': 'ok'})
