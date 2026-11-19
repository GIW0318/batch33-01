MAX_ORDER_FIELDS = 2
MIN_LIMIT = 1
MAX_LIMIT = 1000
TENANT_COLUMN = "tenant_id"

ALLOWED_OPERATORS = frozenset(
    {
        "=",
        "!=",
        "<>",
        "<",
        "<=",
        ">",
        ">=",
        "IN",
        "NOT IN",
        "LIKE",
        "NOT LIKE",
        "BETWEEN",
        "IS NULL",
        "IS NOT NULL",
    }
)


class QueryPlanGuard:
    def __init__(self, tables):
        self.tables = tables

    def build(self, plan):
        if not isinstance(plan, dict):
            raise ValueError("query plan must be a dict")

        table = plan.get("table")
        if table not in self.tables:
            raise ValueError("unknown table: %r" % (table,))
        allowed_columns = self.tables[table]

        columns = self._build_columns(plan.get("columns"), allowed_columns)
        filters = self._build_filters(plan.get("filters", []), allowed_columns)
        order_by = self._build_order_by(plan.get("order_by", []), allowed_columns)
        limit = self._build_limit(plan.get("limit"))
        tenant = self._build_tenant(plan.get("tenant"))

        built = {
            "table": table,
            "columns": columns,
            "filters": filters,
            "order_by": order_by,
            "limit": limit,
            "tenant": tenant,
        }
        if TENANT_COLUMN in allowed_columns:
            built["tenant_filter"] = {
                "column": TENANT_COLUMN,
                "op": "=",
                "value": tenant,
            }
        return built

    def _build_columns(self, columns, allowed_columns):
        if not isinstance(columns, list) or not columns:
            raise ValueError("columns must be a non-empty list")
        deduped = []
        seen = set()
        for column in columns:
            if column not in allowed_columns:
                raise ValueError("unknown column: %r" % (column,))
            if column not in seen:
                seen.add(column)
                deduped.append(column)
        return deduped

    def _build_filters(self, filters, allowed_columns):
        if filters is None:
            return []
        if not isinstance(filters, list):
            raise ValueError("filters must be a list")
        sanitized = []
        for node in filters:
            clean = self._sanitize_filter(node, allowed_columns)
            if clean is not None:
                sanitized.append(clean)
        return sanitized

    def _sanitize_filter(self, node, allowed_columns):
        if not isinstance(node, dict):
            raise ValueError("filter must be a dict")

        for combinator in ("or", "and"):
            if combinator in node:
                branches = node[combinator]
                if not isinstance(branches, list):
                    raise ValueError("%s branches must be a list" % combinator)
                clean_branches = []
                for branch in branches:
                    clean = self._sanitize_filter(branch, allowed_columns)
                    if clean is not None:
                        clean_branches.append(clean)
                if not clean_branches:
                    return None
                return {combinator: clean_branches}

        column = node.get("column")
        if column not in allowed_columns:
            raise ValueError("unknown filter column: %r" % (column,))
        op = node.get("op")
        if op not in ALLOWED_OPERATORS:
            raise ValueError("invalid operator: %r" % (op,))
        if column == TENANT_COLUMN:
            return None
        return {"column": column, "op": op, "value": node.get("value")}

    def _build_order_by(self, order_by, allowed_columns):
        if order_by is None:
            return []
        if not isinstance(order_by, list):
            raise ValueError("order_by must be a list")
        if len(order_by) > MAX_ORDER_FIELDS:
            raise ValueError("at most %d order fields are allowed" % MAX_ORDER_FIELDS)
        normalized = []
        for item in order_by:
            if not isinstance(item, dict):
                raise ValueError("order_by entry must be a dict")
            column = item.get("column")
            if column not in allowed_columns:
                raise ValueError("unknown order column: %r" % (column,))
            normalized.append({"column": column, "desc": bool(item.get("desc", False))})
        return normalized

    def _build_limit(self, limit):
        if isinstance(limit, bool) or not isinstance(limit, int):
            raise ValueError("limit must be an integer")
        if limit < MIN_LIMIT or limit > MAX_LIMIT:
            raise ValueError("limit must be between %d and %d" % (MIN_LIMIT, MAX_LIMIT))
        return limit

    def _build_tenant(self, tenant):
        if not isinstance(tenant, str) or not tenant:
            raise ValueError("tenant is required")
        return tenant
