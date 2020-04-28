from functools import partial

from flask import Blueprint, current_app

from api.client import ChronicleClient
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
    chronicle_client = ChronicleClient(current_app.config['API_URL'],
                                       http_client)

    observables = get_observables()
    limit = current_app.config['CTR_ENTITIES_LIMIT']
    time_delta = current_app.config[
        'DEFAULT_NUMBER_OF_DAYS_FOR_CHRONICLE_TIME_FILTER'
    ]

    sightings = []
    indicators = []
    relationships = []

    for x in observables:

        mapping = Mapping.for_(x)

        if mapping:
            assets_data = chronicle_client.list_assets(x, time_delta, limit)
            ioc_details = chronicle_client.list_ioc_details(x)

            x_sightings = mapping.extract_sightings(assets_data, limit)
            x_indicators = mapping.extract_indicators(ioc_details, limit)

            sightings.extend(x_sightings)
            indicators.extend(x_indicators)

            relationships.extend(
                mapping.create_relationships(x_sightings, x_indicators)
            )

    data = {}

    def format_docs(docs):
        return {'count': len(docs), 'docs': docs}

    if indicators:
        data['indicators'] = format_docs(indicators)

    if sightings:
        data['sightings'] = format_docs(sightings)

    if relationships:
        data['relationships'] = format_docs(relationships)

    return jsonify_data(data)


@enrich_api.route('/refer/observables', methods=['POST'])
def refer_observables():
    return jsonify_data([])
