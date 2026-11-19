import re


_EMAIL_RE = re.compile(
    r"(?<![A-Za-z0-9._%+-])[A-Za-z0-9._%+-]+@"
    r"[A-Za-z0-9](?:[A-Za-z0-9-]*[A-Za-z0-9])?"
    r"(?:\.[A-Za-z0-9](?:[A-Za-z0-9-]*[A-Za-z0-9])?)+"
    r"(?![A-Za-z0-9_-])"
)

_ID_RE = re.compile(r"(?<![\dXx])(?:\d{17}[\dXx]|\d{15})(?![\dXx])")

_PHONE_RE = re.compile(
    r"(?<!\d)(?:\+?86[-\s]?)?1[3-9]\d(?:[-\s]?\d{4}){2}(?!\d)"
)

_IPV4_RE = re.compile(
    r"(?<![\d.])"
    r"(?:25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)"
    r"(?:\.(?:25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)){3}"
    r"(?![\d.])"
)

_VERSION_WORD_RE = re.compile(
    r"(?i)(?<![A-Za-z])(?:version|ver|build|release|revision|rev|版本号?)"
    r"[\s:=：-]*$"
)

_VERSION_PREFIX_RE = re.compile(r"(?i)(?<![A-Za-z])v[\s:=：-]*$")


class PiiRedactor:
    def __init__(self):
        self.masks = {"email": "[email]", "phone": "[phone]", "id": "[id]", "ip": "[ip]"}

    def redact(self, value):
        if isinstance(value, str):
            return self._redact_string(value)
        if isinstance(value, dict):
            return {key: self.redact(item) for key, item in value.items()}
        if isinstance(value, list):
            return [self.redact(item) for item in value]
        if isinstance(value, tuple):
            return tuple(self.redact(item) for item in value)
        if isinstance(value, set):
            return {self.redact(item) for item in value}
        if isinstance(value, frozenset):
            return frozenset(self.redact(item) for item in value)
        return value

    def _redact_string(self, value):
        value = _EMAIL_RE.sub(self.masks["email"], value)
        value = _ID_RE.sub(self.masks["id"], value)
        value = _PHONE_RE.sub(self.masks["phone"], value)
        return _IPV4_RE.sub(self._replace_ipv4, value)

    def _replace_ipv4(self, match):
        prefix = match.string[: match.start()]
        if _VERSION_WORD_RE.search(prefix) or _VERSION_PREFIX_RE.search(prefix):
            return match.group(0)
        return self.masks["ip"]
