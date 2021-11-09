import socket
import json

_GRAYLOG_INPUT_ADDRESS = ('127.0.01', 12201)


class GraylogInputs:

    def __init__(self):
        self._socket = socket.create_connection(_GRAYLOG_INPUT_ADDRESS)

    def send(self, args):
        data = dict({'version': '1.1', 'host': 'test.org', 'short_message': 'test message'}, **args)
        message = '{}\0'.format(json.dumps(data))
        self._socket.send(message.encode())

    def close(self):
        self._socket.close()
