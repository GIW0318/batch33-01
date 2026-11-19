import json


DANGEROUS_KEYS = frozenset(("__proto__", "constructor", "prototype"))


class JsonMergeGuard:
    def __init__(self, max_depth=8, max_keys=100):
        if not isinstance(max_depth, int) or isinstance(max_depth, bool) or max_depth < 1:
            raise ValueError("max_depth must be a positive integer")
        if not isinstance(max_keys, int) or isinstance(max_keys, bool) or max_keys < 1:
            raise ValueError("max_keys must be a positive integer")
        self.max_depth = max_depth
        self.max_keys = max_keys

    def merge(self, base_json, patch_json):
        base = self._parse(base_json)
        patch = self._parse(patch_json, enforce_limits=True)
        return self._merge(base, patch)

    def _parse(self, text, enforce_limits=False):
        if not isinstance(text, str):
            raise ValueError("input must be a JSON string")

        key_count = 0

        def object_pairs_hook(pairs):
            nonlocal key_count
            obj = {}
            for key, value in pairs:
                if key in obj:
                    raise ValueError("duplicate key detected: %r" % key)
                if key in DANGEROUS_KEYS:
                    raise ValueError("dangerous key rejected: %r" % key)
                obj[key] = value
            key_count += len(pairs)
            if enforce_limits and key_count > self.max_keys:
                raise ValueError(
                    "key count %d exceeds limit of %d" % (key_count, self.max_keys)
                )
            return obj

        try:
            parsed = json.loads(text, object_pairs_hook=object_pairs_hook)
        except ValueError:
            raise
        except Exception as exc:
            raise ValueError("invalid JSON: %s" % exc) from exc

        if not isinstance(parsed, dict):
            raise ValueError("top-level JSON value must be an object")

        if enforce_limits:
            self._check_depth(parsed)
        return parsed

    def _check_depth(self, root):
        stack = [(root, 1)]
        while stack:
            node, depth = stack.pop()
            if depth > self.max_depth:
                raise ValueError(
                    "nesting depth %d exceeds limit of %d" % (depth, self.max_depth)
                )
            if isinstance(node, dict):
                stack.extend((value, depth + 1) for value in node.values())
            elif isinstance(node, list):
                stack.extend((value, depth + 1) for value in node)

    def _merge(self, base, patch):
        if not isinstance(base, dict) or not isinstance(patch, dict):
            return self._copy(patch)
        merged = {}
        for key in base:
            merged[key] = self._copy(base[key])
        for key, patch_value in patch.items():
            base_value = merged.get(key)
            if isinstance(base_value, dict) and isinstance(patch_value, dict):
                merged[key] = self._merge(base_value, patch_value)
            else:
                merged[key] = self._copy(patch_value)
        return merged

    def _copy(self, value):
        if isinstance(value, dict):
            return {key: self._copy(item) for key, item in value.items()}
        if isinstance(value, list):
            return [self._copy(item) for item in value]
        return value
