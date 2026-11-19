import unicodedata
from urllib.parse import unquote, urljoin, urlsplit, urlunsplit


_DEFAULT_PORTS = {"http": 80, "https": 443}
_MAX_DECODE_ROUNDS = 16
_WEB_SCHEMES = frozenset(_DEFAULT_PORTS)
_PATH_BASE = "https://return-path.invalid/"


class ReturnPathGuard:
    def __init__(self, allowlist):
        self.allowlist = allowlist
        if allowlist is None:
            raise ValueError("an allowlist is required")
        if isinstance(allowlist, str):
            allowlist = (allowlist,)
        try:
            allowlist = tuple(allowlist)
        except TypeError as exc:
            raise ValueError("allowlist must be an iterable of sites") from exc
        self._allowed_origins = frozenset(
            self._allowed_origin(site) for site in allowlist
        )

    def settle(self, target):
        target = self._decoded_and_checked(target)

        if target.startswith("//"):
            raise ValueError("protocol-relative targets are not allowed")
        if target.startswith("/"):
            self._check_resolved_path(urlsplit(target).path)
            return target

        scheme, host, port, parsed = self._split_absolute(target)
        if (scheme, host, port) not in self._allowed_origins:
            raise ValueError("target is not an allowlisted site")

        self._check_resolved_path(parsed.path)

        netloc = host
        if ":" in host:
            netloc = f"[{host}]"
        if port is not None:
            netloc = f"{netloc}:{port}"

        return urlunsplit(
            (scheme, netloc, parsed.path, parsed.query, parsed.fragment)
        )

    @staticmethod
    def _decoded_and_checked(target):
        if not isinstance(target, str) or not target:
            raise ValueError("target must be a non-empty string")

        value = target
        for _ in range(_MAX_DECODE_ROUNDS):
            ReturnPathGuard._check_characters(value)
            try:
                decoded = unquote(value, errors="strict")
            except (UnicodeDecodeError, ValueError) as exc:
                raise ValueError("target has invalid percent encoding") from exc

            if decoded == value:
                return value
            value = decoded

        raise ValueError("target has too many encoding layers")

    @staticmethod
    def _check_characters(value):
        if "\\" in value:
            raise ValueError("backslashes are not allowed")
        if any(
            unicodedata.category(char).startswith("C")
            or char in "\u2028\u2029"
            for char in value
        ):
            raise ValueError("control characters are not allowed")

    @staticmethod
    def _check_resolved_path(path):
        if path.startswith("//"):
            raise ValueError("target path is protocol-relative")
        resolved_path = urlsplit(urljoin(_PATH_BASE, path)).path
        if resolved_path.startswith("//"):
            raise ValueError("target path resolves to a protocol-relative path")

    @classmethod
    def _allowed_origin(cls, site):
        if not isinstance(site, str) or not site:
            raise ValueError("allowlist entries must be non-empty strings")

        site = cls._decoded_and_checked(site)
        scheme, host, port, _ = cls._split_absolute(site)
        return scheme, host, port

    @staticmethod
    def _split_absolute(target):
        try:
            parsed = urlsplit(target)
            scheme = parsed.scheme.lower()
            host = parsed.hostname
            port = parsed.port
        except ValueError as exc:
            raise ValueError("target is not a valid URL") from exc

        if scheme not in _WEB_SCHEMES or not parsed.netloc or host is None:
            raise ValueError("target must be an absolute web URL")
        if "@" in parsed.netloc:
            raise ValueError("credentials in URLs are not allowed")

        host = host.lower()
        if port == _DEFAULT_PORTS[scheme]:
            port = None
        return scheme, host, port, parsed
