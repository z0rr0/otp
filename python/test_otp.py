from datetime import datetime, timedelta, timezone
from unittest import TestCase

from otp import code, dt2unix


class TestOTP(TestCase):

    def setUp(self) -> None:
        self.dt = datetime(2020, 1, 2, 3, tzinfo=timezone.utc)
        self.value = 'PLH5US7K4JYU3DAP7KBXNFLQ66PSRNNH'

    def test_zero(self) -> None:
        self.assertEqual('038572', code(self.value, 0))

    def test_some_time(self) -> None:
        self.assertEqual('300755', code(self.value, dt2unix(self.dt) // 30))

    def test_plus_10_seconds(self) -> None:
        dt = self.dt + timedelta(seconds=10)
        self.assertEqual('300755', code(self.value, dt2unix(dt) // 30))

    def test_plus_40_seconds(self) -> None:
        dt = self.dt + timedelta(seconds=40)
        self.assertEqual('602895', code(self.value, dt2unix(dt) // 30))

    def test_another_secret(self) -> None:
        value = 'AJIS553K23JWRJ4J3GDL7B6PBRWKL4AP'
        dt = self.dt + timedelta(seconds=40)
        self.assertEqual('507727', code(value, dt2unix(dt) // 30))
