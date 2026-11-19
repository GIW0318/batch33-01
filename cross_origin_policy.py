import re
from collections.abc import Iterable
from urllib.parse import urlsplit

ALLOWED_METHODS = ("GET", "POST", "OPTIONS")
ALLOWED_HEADERS = ("Authorization", "Content-Type")
WILDCARD_ORIGIN = "*"
NULL_ORIGIN = "null"
PREFLIGHT_MAX_AGE = "0"

_ORIGIN_RE = re.compile(
    r"^[A-Za-z][A-Za-z0-9+.\-]*://[^\s/?#@]+(?::\d+)?$"
)


def _is_valid_origin(origin):
    if not isinstance(origin, str) or origin in (WILDCARD_ORIGIN, NULL_ORIGIN):
        return False
    if not _ORIGIN_RE.match(origin):
        return False
    try:
        parsed = urlsplit(origin)
        parsed.port
    except ValueError:
        return False
    return bool(
        parsed.scheme
        and parsed.hostname
        and not parsed.path
        and not parsed.query
        and not parsed.fragment
        and parsed.username is None
    )


class CrossOriginPolicy:
    def __init__(self, allowed_origins, allow_credentials=False):
        if isinstance(allowed_origins, str) or not isinstance(
            allowed_origins, Iterable
        ):
            raise ValueError(
                "allowed_origins must be a non-string iterable of origin strings"
            )

        normalized = set()
        for origin in allowed_origins:
            if not isinstance(origin, str) or not origin:
                raise ValueError("allowed origins must be non-empty strings")
            if origin == NULL_ORIGIN:
                raise ValueError("the opaque 'null' origin cannot be allow-listed")
            if origin == WILDCARD_ORIGIN:
                if allow_credentials:
                    raise ValueError(
                        "wildcard origin cannot be combined with allow_credentials"
                    )
                normalized.add(origin)
                continue
            if not _is_valid_origin(origin):
                raise ValueError(f"invalid allowed origin: {origin!r}")
            normalized.add(origin)

        self.allowed_origins = frozenset(normalized)
        self.allow_credentials = bool(allow_credentials)

    def headers(self, origin, method, request_headers=None):
        headers = {"Vary": "Origin"}

        if not origin or origin in (WILDCARD_ORIGIN, NULL_ORIGIN):
            return headers

        if not _is_valid_origin(origin):
            raise ValueError(f"invalid origin: {origin!r}")

        if not isinstance(method, str) or method not in ALLOWED_METHODS:
            raise ValueError(f"unsupported method: {method!r}")

        if WILDCARD_ORIGIN not in self.allowed_origins and (
            origin not in self.allowed_origins
        ):
            return headers

        headers["Access-Control-Allow-Origin"] = (
            WILDCARD_ORIGIN
            if WILDCARD_ORIGIN in self.allowed_origins
            else origin
        )
        if self.allow_credentials:
            headers["Access-Control-Allow-Credentials"] = "true"

        if method == "OPTIONS":
            headers["Access-Control-Allow-Methods"] = ", ".join(ALLOWED_METHODS)
            headers["Access-Control-Allow-Headers"] = ", ".join(ALLOWED_HEADERS)
            headers["Access-Control-Max-Age"] = PREFLIGHT_MAX_AGE

        return headers
