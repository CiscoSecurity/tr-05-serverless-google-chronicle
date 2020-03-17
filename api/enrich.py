from functools import partial
from itertools import chain

from flask import Blueprint, current_app

from api.mappings import Mapping
from api.schemas import ObservableSchema
from api.utils import (
    jsonify_data,
    get_chronicle_http_client,
    get_jwt,
    get_json,
)

enrich_api = Blueprint('enrich', __name__)

get_observables = partial(get_json, schema=ObservableSchema(many=True))


@enrich_api.route('/deliberate/observables', methods=['POST'])
def deliberate_observables():
    return jsonify_data({})


@enrich_api.route('/observe/observables', methods=['POST'])
def observe_observables():
    http_client = get_chronicle_http_client(get_jwt())
    observables = get_observables()

    def _observe(observable):
        type_ = observable['type']
        value = observable['value']

        mapping = Mapping.of(type_, current_app.config['API_URL'],
                             http_client)

        return mapping.get(value) if mapping is not None else []

    data = (_observe(x) for x in observables)
    data = chain.from_iterable(data)
    data = list(data)

    return jsonify_data({
        'sightings': {
            'count': len(data),
            'docs': data
        }
    })


@enrich_api.route('/refer/observables', methods=['POST'])
def refer_observables():
    return jsonify_data([])
