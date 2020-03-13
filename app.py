from flask import Flask, jsonify

from api.enrich import enrich_api
from api.errors import TRFormattedException
from api.health import health_api
from api.respond import respond_api
from api.utils import jsonify_errors

app = Flask(__name__)

app.url_map.strict_slashes = False
app.config.from_object('config.Config')

app.register_blueprint(health_api)
app.register_blueprint(enrich_api)
app.register_blueprint(respond_api)


@app.errorhandler(Exception)
def handle_error(exception):
    code = getattr(exception, 'code', 500)
    message = getattr(exception, 'description', 'Something went wrong.')
    reason = '.'.join([
        exception.__class__.__module__,
        exception.__class__.__name__,
    ])

    response = jsonify(code=code, message=message, reason=reason)
    return response, code


@app.errorhandler(TRFormattedException)
def handle_tr_formatted_error(exception):
    return jsonify_errors(exception)


if __name__ == '__main__':
    app.run()
