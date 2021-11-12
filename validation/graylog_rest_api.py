import requests
import time
from urllib import parse
from requests.exceptions import ConnectionError
from graylog_inputs import GraylogInputs

STREAM_ALL_MESSAGES = "000000000000000000000001"
_AUTH = ('admin', 'admin')
_HEADERS = {"X-Requested-By": "test-program"}


class GraylogRestApi:

    def _build_url(self, path):
        return parse.urljoin('http://127.0.0.1:9000/api/', path)

    def get(self, path):
        url = self._build_url(path)
        print('GET {}'.format(url))
        return requests.get(url, auth=_AUTH, headers=_HEADERS)

    def put(self, path, payload):
        url = self._build_url(path)
        print('PUT {} {}'.format(url, payload))
        requests.put(url, json=payload, auth=_AUTH, headers=_HEADERS)

    def post(self, path, payload):
        url = self._build_url(path)
        print('POST {} {}'.format(url, payload))
        return requests.post(url, json=payload, auth=_AUTH, headers=_HEADERS)

    def _input_is_running(self, identifier):
        response = self.get('system/inputstates/')
        body = response.json()
        for state in body['states']:
            if state['id'] != identifier:
                continue
            return state['state'] == 'RUNNING'
        return False

    def create_gelf_input(self):
        payload = {
            'configuration': {
                'bind_address': '0.0.0.0',
                'decompress_size_limit': 8388608,
                'max_message_size': 2097152,
                'number_worker_threads': 8,
                'override_source': None,
                'port': 12201,
                'recv_buffer_size': 1048576,
                'tcp_keepalive': False,
                'tls_cert_file': '',
                'tls_client_auth': 'disabled',
                'tls_client_auth_cert_file': '',
                'tls_enable': False,
                'tls_key_file': 'admin',
                'tls_key_password': 'admin',
                'use_null_delimiter': True
            },
            'global': True,
            'title': 'Inputs',
            'type': 'org.graylog2.inputs.gelf.tcp.GELFTCPInput'
        }
        response = self.post('system/inputs', payload)
        identifier = response.json()['id']
        while not self._input_is_running(identifier):
            time.sleep(.1)
        return GraylogInputs()

    def create_aggregation_count(self, threshold, group_by_fields=None, distinct_fields=None, period=5):
        """
        :param title:
        :param threshold:
        :param distinct_fields:
        :param period: in seconds
        :return:
        """
        if group_by_fields is None:
            group_by_fields = []
        if distinct_fields is None:
            distinct_fields = []
        event_definition = {
            'alert': False,
            'config': {
                'comment': '',
                'distinction_fields': distinct_fields,
                'execute_every_ms': period*1000,
                'grouping_fields': group_by_fields,
                'search_query': '*',
                'search_within_ms': period*1000,
                'stream': STREAM_ALL_MESSAGES,
                'threshold': threshold[1],
                'threshold_type': threshold[0],
                'type': 'aggregation-count'
            },
            'description': '',
            'field_spec': {},
            'key_spec': [],
            'notification_settings': {
                'backlog_size': None,
                'grace_period_ms': 0
            },
            'notifications': [],
            'priority': 2,
            'title': 'AAA'
        }
        self.post('events/definitions', event_definition)

    def wait_until_graylog_is_started(self):
        """
        We wait until the default deflector is up, as it seems to be the last operation done on startup
        This might have to change in the future, if graylog changes its ways...
        :return:
        """
        print('Waiting for graylog to start...')

        # TODO move as a method in _graylog_rest_api
        #only for 60s maximum
        while True:
            try:
                response = self.get('system/deflector')
                body = response.json()
                if body['is_up']:
                    break
            except ConnectionError:
                pass
            time.sleep(1)
