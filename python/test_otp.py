import re
from datetime import datetime, timedelta, timezone
from unittest import TestCase

from otp import code, dt2unix, secret

# Base32 pattern https://en.wikipedia.org/wiki/Base32
RG_BASE = re.compile(r'^[A-Z2-7=]+$')


class TestOTP(TestCase):

    def setUp(self) -> None:
        self.dt = datetime(2020, 1, 2, 3, tzinfo=timezone.utc)
        self.value = 'PLH5US7K4JYU3DAP7KBXNFLQ66PSRNNH'

    def test_secret(self) -> None:
        value = secret(1024)
        self.assertTrue(RG_BASE.match(value))

    def test_zero(self) -> None:
        self.assertEqual('038572', code(self.value, 0))

    def test_some_time(self) -> None:
        self.assertEqual('300755', code(self.value, dt2unix(self.dt)))

    def test_plus_10_seconds(self) -> None:
        dt = self.dt + timedelta(seconds=10)
        self.assertEqual('300755', code(self.value, dt2unix(dt)))

    def test_plus_40_seconds(self) -> None:
        dt = self.dt + timedelta(seconds=40)
        self.assertEqual('602895', code(self.value, dt2unix(dt)))

    def test_another_secret(self) -> None:
        value = 'AJIS553K23JWRJ4J3GDL7B6PBRWKL4AP'
        self.assertEqual('239244', code(value, dt2unix(self.dt)))
