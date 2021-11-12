# to execute these tests:
# * activate venv
#   source ./venv/bin/activate
# * execute tests
#   python -m unittest

from unittest import TestCase
import time
from graylog_server import GraylogServer
from graylog_rest_api import GraylogRestApi

_PERIOD = 5


class Test(TestCase):

    def setUp(self) -> None:
        # TODO maybe merge _graylog and _graylog_rest_api
        self._graylog = GraylogServer('../runtime')
        self._graylog.start()
        self._graylog_rest_api = GraylogRestApi()
        self._graylog_rest_api.wait_until_graylog_is_started()

    def tearDown(self) -> None:
        self._graylog.stop()

    def test_send_alert_should_not_raise_exception_when_there_is_a_distinct_field(self):
        with self._graylog_rest_api.create_gelf_input() as gelf_inputs:
            self._graylog_rest_api.create_aggregation_count('AAA', ('MORE', 2), ['port'], period=_PERIOD)
            gelf_inputs.send({'_port': 80})

            logs = self._graylog.extract_logs(2*_PERIOD)
            self.assertNotIn('java.lang.IllegalStateException', logs)

    def test_send_alerts_should_trigger_alert_when_there_are_distinct_ports(self):
        with self._graylog_rest_api.create_gelf_input() as gelf_inputs:
            self._graylog_rest_api.create_aggregation_count('AAA', ('MORE', 1), ['port'], period=_PERIOD)
            gelf_inputs.send({'_port': 80})
            gelf_inputs.send({'_port': 81})
            time.sleep(_PERIOD)

            gelf_inputs.send({'short_message': 'pop'})
            time.sleep(2*_PERIOD)
            response = self._graylog_rest_api.post('events/search', {})
            body = response.json()

            self.assertEqual(1, body['total_events'])
