import re
import threading

_HEADER_NAME_RE = re.compile(r"^[!#$%&'*+\-.^_`|~0-9A-Za-z]+$")
_HSTS_MAX_AGE_RE = re.compile(r"(?:^|;)\s*max-age\s*=\s*([^;\s]+)", re.IGNORECASE)

_CSP_HEADER = "Content-Security-Policy"
_HSTS_HEADER = "Strict-Transport-Security"

_STRICTNESS = {
    "Cross-Origin-Opener-Policy": {
        "unsafe-none": 0,
        "same-origin-allow-popups": 1,
        "same-origin": 2,
    },
    "Cross-Origin-Embedder-Policy": {
        "unsafe-none": 0,
        "credentialless": 1,
        "require-corp": 2,
    },
}


def _canonical_name(name):
    return "-".join(part[:1].upper() + part[1:].lower() for part in name.split("-"))


def _validate_name(name):
    if not isinstance(name, str) or not _HEADER_NAME_RE.match(name):
        raise ValueError("invalid header name: %r" % (name,))


def _validate_value(value):
    if not isinstance(value, str):
        raise ValueError("header value must be a string")
    if "\r" in value or "\n" in value or "\x00" in value:
        raise ValueError("header value contains forbidden characters")


def _validate_hsts(value):
    match = _HSTS_MAX_AGE_RE.search(value)
    if match is None:
        raise ValueError("Strict-Transport-Security requires max-age")
    if not match.group(1).isdigit():
        raise ValueError("Strict-Transport-Security max-age must be an integer")


def _parse_csp(value):
    directives = {}
    for chunk in value.split(";"):
        tokens = chunk.split()
        if not tokens:
            continue
        directives.setdefault(tokens[0].lower(), []).extend(tokens[1:])
    return directives


def _format_csp(directives):
    parts = []
    for name in sorted(directives):
        sources = directives[name]
        parts.append(name if not sources else "%s %s" % (name, " ".join(sources)))
    return "; ".join(parts)


class HeaderMergePolicy:
    def __init__(self):
        self._lock = threading.RLock()
        self._headers = {}
        self._csp = {}

    def set_header(self, name, value):
        _validate_name(name)
        _validate_value(value)
        canonical = _canonical_name(name)
        with self._lock:
            if canonical == _CSP_HEADER:
                self._merge_csp_locked(_parse_csp(value))
                return
            if canonical == _HSTS_HEADER:
                _validate_hsts(value)
            ranking = _STRICTNESS.get(canonical)
            if ranking is not None and canonical in self._headers:
                current = self._headers[canonical].strip().lower()
                incoming = value.strip().lower()
                if current in ranking and incoming in ranking:
                    if ranking[incoming] <= ranking[current]:
                        return
            self._headers[canonical] = value

    def merge_csp(self, directives):
        if not isinstance(directives, dict):
            raise ValueError("directives must be a dict of name -> list")
        parsed = {}
        for name, sources in directives.items():
            if not isinstance(name, str) or not name.strip():
                raise ValueError("invalid CSP directive name: %r" % (name,))
            if not isinstance(sources, (list, tuple)):
                raise ValueError("CSP sources for %r must be a list" % (name,))
            for source in sources:
                if not isinstance(source, str) or "\r" in source or "\n" in source:
                    raise ValueError("invalid CSP source: %r" % (source,))
            parsed[name.strip().lower()] = list(sources)
        with self._lock:
            self._merge_csp_locked(parsed)

    def _merge_csp_locked(self, parsed):
        for name, sources in parsed.items():
            existing = self._csp.setdefault(name, [])
            for source in sources:
                if source not in existing:
                    existing.append(source)

    def render(self):
        with self._lock:
            lines = [
                "%s: %s" % (name, self._headers[name])
                for name in sorted(self._headers, key=str.lower)
            ]
            if self._csp:
                lines.append("%s: %s" % (_CSP_HEADER, _format_csp(self._csp)))
                lines.sort(key=lambda line: line.split(":", 1)[0].lower())
            return "\n".join(lines)
