import json
from datetime import datetime, timedelta

from flask import Blueprint, current_app

from api.utils import (
    jsonify_data,
    get_chronicle_http_client,
    get_jwt,
    join_url,
    jsonify_errors,
    format_time_to_arg
)

health_api = Blueprint('health', __name__)


@health_api.route('/health', methods=['POST'])
def health():
    now = datetime.utcnow()
    ninety_days_ago = now - timedelta(days=90)

    url = join_url(
        current_app.config['API_URL'],
        '/artifact/listassets'
        f'?start_time={format_time_to_arg(ninety_days_ago)}'
        f'&end_time={format_time_to_arg(now)}'
        '&artifact.domain_name=www.google.com&page_size=1'
    )

    http_client = get_chronicle_http_client(get_jwt())

    response, body = http_client.request(
        url, 'GET', headers={'Content-Type': 'application/json',
                             'Accept': 'application/json'}
    )

    if response.status == 200:
        return jsonify_data({'status': 'ok'})
    else:
        return jsonify_errors(json.loads(body).get('error'))
