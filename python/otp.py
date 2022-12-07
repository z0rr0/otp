import hmac
from base64 import b32decode, b32encode
from datetime import datetime, timezone
from hashlib import sha1
from os import urandom

KEY_SIZE = 64


def dt2unix(dt: datetime) -> int:
    """Convert a datetime to unix timestamp."""
    return int((dt - datetime(1970, 1, 1, tzinfo=timezone.utc)).total_seconds())


def secret(size: int = 0) -> str:
    """Generate a random secret key."""
    rnd_bytes = urandom(size or KEY_SIZE)
    return b32encode(rnd_bytes).decode().upper()


def code(value: str, counter: int) -> str:
    """Generate OTP code for a given value and counter."""
    if counter < 0:
        counter = dt2unix(datetime.utcnow()) // 30

    key = b32decode(value.upper().encode())
    counter_bytes = counter.to_bytes(8, byteorder='big')

    m = hmac.new(key, digestmod=sha1)
    m.update(counter_bytes)
    digest = m.digest()

    offset = digest[-1] & 0xf
    truncated = int.from_bytes(digest[offset:offset + 4], byteorder='big') & 0x7fffffff

    return str(truncated % 1_000_000).zfill(6)
