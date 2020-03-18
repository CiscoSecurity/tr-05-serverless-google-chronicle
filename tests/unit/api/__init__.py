from unittest.mock import MagicMock


class ChronicleClientMock:
    def __init__(self, status_code, response_body):
        self.__response_mock = MagicMock()
        self.__response_mock.status = status_code
        self.__response_body = response_body

    def request(self, *args, **kwargs):
        return self.__response_mock, self.__response_body
