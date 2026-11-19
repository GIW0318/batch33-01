def _validate_scope(scope):
    if not isinstance(scope, str) or not scope:
        raise ValueError("scope must be a non-empty string")
    parts = scope.split(":")
    if any(part == "" for part in parts):
        raise ValueError("scope contains an empty segment")
    for part in parts[:-1]:
        if part == "*":
            raise ValueError("wildcard is only allowed as the final segment")


def _scope_matches(granted, requested):
    if granted == "*":
        return True
    if granted.endswith(":*"):
        prefix = granted[:-2]
        head, sep, tail = requested.partition(":")
        return head == prefix and sep == ":" and tail != "" and ":" not in tail
    return granted == requested


class ApiKeyStore:
    def __init__(self):
        self.keys = {}

    def issue(self, key_id, scopes, now, ttl=100):
        if key_id in self.keys:
            raise ValueError("duplicate key id")
        if ttl <= 0:
            raise ValueError("ttl must be positive")
        if not scopes:
            raise ValueError("scopes must be a non-empty list")
        for scope in scopes:
            _validate_scope(scope)
        self.keys[key_id] = {
            "scopes": list(scopes),
            "expires_at": now + ttl,
            "revoked": False,
        }

    def authorize(self, key_id, scope, now):
        record = self.keys.get(key_id)
        if record is None or record["revoked"]:
            return False
        if now >= record["expires_at"]:
            return False
        return any(_scope_matches(granted, scope) for granted in record["scopes"])

    def revoke(self, key_id):
        record = self.keys.get(key_id)
        if record is None:
            raise ValueError("unknown key id")
        record["revoked"] = True
