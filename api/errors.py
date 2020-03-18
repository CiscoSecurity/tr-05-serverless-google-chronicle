import json

INVALID_ARGUMENT = 'invalid argument'
PERMISSION_DENIED = 'permission denied'
UNKNOWN = 'unknown'


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
    def __init__(self, payload):
        error_payload = json.loads(payload).get('error', {})

        super().__init__(
            error_payload.get('status', '').lower().replace('_', ' '),
            error_payload.get('message', None)
            or error_payload.get('details', None)
        )


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
