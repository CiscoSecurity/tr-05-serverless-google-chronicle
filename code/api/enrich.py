from functools import partial

from flask import Blueprint, current_app, g

from api.client import ChronicleClient
from api.mappings import Mapping
from api.schemas import ObservableSchema
from api.utils import (
    get_chronicle_http_client,
    get_jwt,
    get_json,
    jsonify_result
)

enrich_api = Blueprint('enrich', __name__)

get_observables = partial(get_json, schema=ObservableSchema(many=True))


@enrich_api.route('/observe/observables', methods=['POST'])
def observe_observables():
    http_client = get_chronicle_http_client(get_jwt())
    chronicle_client = ChronicleClient(current_app.config['API_URL'],
                                       http_client)

    observables = get_observables()
    limit = current_app.config['CTR_ENTITIES_LIMIT']
    time_delta = current_app.config[
        'DEFAULT_NUMBER_OF_DAYS_FOR_CHRONICLE_TIME_FILTER'
    ]

    g.sightings = []
    g.indicators = []
    g.relationships = []

    for x in observables:

        mapping = Mapping.for_(x)

        if mapping:
            assets_data = chronicle_client.list_assets(x, time_delta, limit)
            ioc_details = chronicle_client.list_ioc_details(x)

            x_sightings = mapping.extract_sightings(assets_data, limit)
            x_indicators = mapping.extract_indicators(ioc_details, limit)

            g.sightings.extend(x_sightings)
            g.indicators.extend(x_indicators)

            g.relationships.extend(
                mapping.create_relationships(x_sightings, x_indicators)
            )

    return jsonify_result()
