import hmac
from base64 import b32decode, b32encode
from datetime import datetime, timezone
from hashlib import sha1
from os import urandom
from typing import Optional

KEY_SIZE = 64


def dt2unix(dt: datetime, divider: int = 30) -> int:
    """Convert dt datetime to unix timestamp and divide it by a given divider."""
    return int((dt - datetime(1970, 1, 1, tzinfo=timezone.utc)).total_seconds()) // divider


def secret(size: int = 0) -> str:
    """Generate a random secret key."""
    rnd_bytes = urandom(size or KEY_SIZE)
    return b32encode(rnd_bytes).decode()


def code(value: str, counter: Optional[int] = None) -> str:
    """Generate OTP code for a given value and counter."""
    if counter is None:
        counter = dt2unix(datetime.utcnow()) // 30

    key = b32decode(value.upper().encode())
    counter_bytes = counter.to_bytes(8, byteorder='big')

    m = hmac.new(key, digestmod=sha1)
    m.update(counter_bytes)
    digest = m.digest()

    offset = digest[-1] & 0xf
    truncated = int.from_bytes(digest[offset:offset + 4], byteorder='big') & 0x7fffffff

    # add left padding zeros and take right 6 digits
    return f'{truncated:06d}'[-6:]
