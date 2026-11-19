import hashlib
import hmac
import threading
import time


_HEX_DIGITS = frozenset("0123456789abcdef")


class CallbackSeal:
    def __init__(self, secret, tolerance=300):
        if not isinstance(secret, (bytes, bytearray, memoryview)):
            raise ValueError("secret must be bytes")
        secret = bytes(secret)
        if not secret:
            raise ValueError("secret must not be empty")
        if not isinstance(tolerance, int) or isinstance(tolerance, bool):
            raise ValueError("tolerance must be an integer")
        if tolerance < 0:
            raise ValueError("tolerance must not be negative")

        self.secret = secret
        self.tolerance = tolerance
        self.seen = set()
        self._lock = threading.Lock()

    @staticmethod
    def _body_bytes(body):
        if not isinstance(body, (bytes, bytearray, memoryview)):
            raise ValueError("body must be bytes")
        return bytes(body)

    @staticmethod
    def _validate_timestamp(timestamp):
        if not isinstance(timestamp, int) or isinstance(timestamp, bool):
            raise ValueError("timestamp must be an integer")
        if timestamp < 0:
            raise ValueError("timestamp must not be negative")

    @staticmethod
    def _validate_now(now):
        if not isinstance(now, int) or isinstance(now, bool):
            raise ValueError("now must be an integer")

    def _digest(self, body, timestamp):
        message = str(timestamp).encode("ascii") + b"." + body
        return hmac.new(self.secret, message, hashlib.sha256).hexdigest()

    def sign(self, body, timestamp):
        body = self._body_bytes(body)
        self._validate_timestamp(timestamp)
        return self._digest(body, timestamp)

    def verify(self, body, timestamp, signature, now=None):
        body = self._body_bytes(body)
        self._validate_timestamp(timestamp)
        if not isinstance(signature, str):
            raise ValueError("signature must be a hexadecimal string")
        if now is None:
            now = int(time.time())
        else:
            self._validate_now(now)

        normalized = signature.strip().lower()
        if len(normalized) != 64 or any(c not in _HEX_DIGITS for c in normalized):
            return False

        supplied_digest = bytes.fromhex(normalized)

        with self._lock:
            if abs(now - timestamp) > self.tolerance:
                return False
            expected_digest = bytes.fromhex(self._digest(body, timestamp))
            if not hmac.compare_digest(expected_digest, supplied_digest):
                return False
            if normalized in self.seen:
                return False
            self.seen.add(normalized)
            return True
