import json
from datetime import datetime

from flask import Blueprint, current_app

from api.utils import jsonify_data, get_http_client, join_url, jsonify_errors

health_api = Blueprint('health', __name__)


@health_api.route('/health', methods=['POST'])
def health():
    now = datetime.utcnow().replace(microsecond=0).isoformat()
    url = join_url(
        current_app.config['API_URL'],
        '/alert/listalerts'
        f'?start_time={now}&end_time={now}Z'
    )

    http_client = get_http_client()

    response, body = http_client.request(
        url, 'GET', headers={'Content-Type': 'application/json',
                             'Accept': 'application/json'}
    )

    if response.status == 200:
        return jsonify_data({'status': 'ok'})
    else:
        return jsonify_errors(json.loads(body).get('error'))
