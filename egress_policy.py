import fnmatch

_EFFECTS = ("allow", "deny")
_REQUEST_FIELDS = ("host", "port", "scheme", "path", "method")


def _normalize_host(host):
    if not isinstance(host, str) or not host.strip():
        raise ValueError("host must be a non-empty string")
    return host.strip().lower().rstrip(".")


def _validate_port(port):
    if isinstance(port, bool) or not isinstance(port, int):
        raise ValueError("port must be an integer")
    if not 1 <= port <= 65535:
        raise ValueError("port out of range")
    return port


def _validate_str_list(rule, key, transform=None):
    values = rule.get(key)
    if values is None:
        return None
    if not isinstance(values, (list, tuple)) or not values:
        raise ValueError("%s must be a non-empty list" % key)
    result = []
    for value in values:
        if not isinstance(value, str) or not value:
            raise ValueError("%s entries must be non-empty strings" % key)
        result.append(transform(value) if transform else value)
    return frozenset(result)


class _Rule:
    __slots__ = ("host", "suffix", "ports", "schemes", "paths", "methods", "effect")

    def __init__(self, rule):
        if not isinstance(rule, dict):
            raise ValueError("rule must be a dict")
        if "host" not in rule:
            raise ValueError("rule requires host")
        host = _normalize_host(rule["host"])
        if "*" in host:
            if not host.startswith("*.") or host.count("*") != 1 or not host[2:]:
                raise ValueError("invalid wildcard host")
            self.suffix = host[2:]
            self.host = None
        else:
            self.host = host
            self.suffix = None
        effect = rule.get("effect")
        if effect not in _EFFECTS:
            raise ValueError("effect must be allow or deny")
        self.effect = effect
        ports = rule.get("ports")
        if ports is None:
            self.ports = None
        else:
            if not isinstance(ports, (list, tuple)) or not ports:
                raise ValueError("ports must be a non-empty list")
            self.ports = frozenset(_validate_port(p) for p in ports)
        self.schemes = _validate_str_list(rule, "schemes", str.lower)
        self.methods = _validate_str_list(rule, "methods", str.upper)
        paths = _validate_str_list(rule, "paths")
        if paths is not None:
            for path in paths:
                if not path.startswith("/"):
                    raise ValueError("paths must start with /")
        self.paths = paths

    def matches(self, host, port, scheme, path, method):
        if self.suffix is not None:
            if host == self.suffix or not host.endswith("." + self.suffix):
                return False
        elif host != self.host:
            return False
        if self.ports is not None and port not in self.ports:
            return False
        if self.schemes is not None and scheme not in self.schemes:
            return False
        if self.methods is not None and method not in self.methods:
            return False
        if self.paths is not None and not any(
            fnmatch.fnmatchcase(path, pattern) for pattern in self.paths
        ):
            return False
        return True


class EgressPolicy:
    def __init__(self, rules):
        if not isinstance(rules, (list, tuple)):
            raise ValueError("rules must be a list")
        self._rules = tuple(_Rule(rule) for rule in rules)

    def check(self, request):
        if not isinstance(request, dict):
            raise ValueError("request must be a dict")
        missing = [field for field in _REQUEST_FIELDS if field not in request]
        if missing:
            raise ValueError("request missing fields: %s" % ", ".join(missing))
        host = _normalize_host(request["host"])
        port = _validate_port(request["port"])
        scheme = request["scheme"]
        if not isinstance(scheme, str) or not scheme:
            raise ValueError("scheme must be a non-empty string")
        scheme = scheme.lower()
        path = request["path"]
        if not isinstance(path, str) or not path.startswith("/"):
            raise ValueError("path must be a string starting with /")
        method = request["method"]
        if not isinstance(method, str) or not method:
            raise ValueError("method must be a non-empty string")
        method = method.upper()
        allowed = False
        for rule in self._rules:
            if rule.matches(host, port, scheme, path, method):
                if rule.effect == "deny":
                    return False
                allowed = True
        return allowed
