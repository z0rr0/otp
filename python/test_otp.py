import re
import time
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


class TestBenchmarkOTP(TestCase):

    def test_code(self) -> None:
        """Measure the minimal time to generate a code."""
        values = [
            "PLH5US7K4JYU3DAP7KBXNFLQ66PSRNNH",
            "NL5VXOSCGA4FKG7FXWJLKQ3OUH6XLQI6",
            "QT4LBO53X3Y3U5QWDJBSUD6TZIIYUQ3V",
        ]
        expected = ["038572", "501675", "213936"]
        n = len(values)

        min_time = 0
        for i in range(100_000):
            j = i % n

            start = time.process_time_ns()
            c = code(values[j], j)
            duration = time.process_time_ns() - start

            self.assertEqual(expected[j], c)
            if duration < min_time or not min_time:
                min_time = duration

        print(f'benchmark: min {min_time} ns per call')
