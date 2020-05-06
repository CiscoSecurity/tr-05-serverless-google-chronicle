import json
from http import HTTPStatus
from json import JSONDecodeError

INVALID_ARGUMENT = 'invalid argument'
PERMISSION_DENIED = 'permission denied'
UNKNOWN = 'unknown'
TOO_MANY_REQUESTS = 'too many requests'


class TRFormattedError(Exception):
    def __init__(self, code, message, type_='fatal'):
        super().__init__()
        self.code = code or UNKNOWN
        self.message = message or 'Something went wrong.'
        self.type_ = type_

    @property
    def json(self):
        return {'type': self.type_,
                'code': self.code,
                'message': self.message}


class UnexpectedChronicleResponseError(TRFormattedError):
    def __init__(self, response, payload):
        title = f"Unexpected response from Chronicle Backstory"

        if response.status == HTTPStatus.INTERNAL_SERVER_ERROR:
            super().__init__(UNKNOWN, f"{title}: {response.reason}")

        elif response.status == HTTPStatus.TOO_MANY_REQUESTS:
            super().__init__(
                TOO_MANY_REQUESTS,
                "Too many requests to Chronicle Backstory have been made. "
                "Please, try again later."
            )

        else:

            status_mapping = {
                HTTPStatus.BAD_REQUEST: INVALID_ARGUMENT,
                HTTPStatus.FORBIDDEN: PERMISSION_DENIED
            }

            error_payload = {}
            try:
                error_payload = json.loads(payload).get('error', {})
            except JSONDecodeError:
                pass

            status = (status_mapping.get(response.status)
                      or error_payload.get('status',
                                           '').lower().replace('_', ' '))

            message = (error_payload.get('message', None)
                       or error_payload.get('details', None)
                       or response.reason)

            super().__init__(status, f"{title}: {message}")


class InvalidJWTError(TRFormattedError):
    def __init__(self):
        super().__init__(
            PERMISSION_DENIED,
            'Invalid Authorization Bearer JWT.'
        )


class InvalidChronicleCredentialsError(TRFormattedError):
    def __init__(self, error):
        super().__init__(
            PERMISSION_DENIED,
            f'Chronicle Backstory Authorization failed: {str(error)}.'
        )


class InvalidArgumentError(TRFormattedError):
    def __init__(self, error):
        super().__init__(
            INVALID_ARGUMENT,
            str(error)
        )


class UnsupportedArtifactTypeError(InvalidArgumentError):
    def __init__(self, type_):
        super().__init__(
            f"Unsupported artifact type error: {type_}"
        )
