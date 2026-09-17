"""CVM-side execution for validated structured query plans."""

from __future__ import annotations

import time
from decimal import Decimal
from typing import Any

from sql_validator import build_parameterized_sql


def _json_value(value: Any) -> Any:
    if isinstance(value, Decimal):
        return float(value)
    if hasattr(value, 'isoformat'):
        return value.isoformat()
    return value


def execute_validated_plan(conn: Any, plan: dict[str, Any], parameters: dict[str, Any], sql_server: bool) -> dict[str, Any]:
    started = time.perf_counter()
    sql, values = build_parameterized_sql(plan, parameters, sql_server=sql_server)
    cursor = conn.cursor()
    cursor.execute(sql, values)
    columns = [description[0] for description in cursor.description]
    rows = [
        {column: _json_value(value) for column, value in zip(columns, row)}
        for row in cursor.fetchmany(plan.get('limit', 100))
    ]
    return {
        'read_only': True,
        'tables': plan.get('tables') or plan.get('from'),
        'columns': columns,
        'rows': rows,
        'row_count': len(rows),
        'duration_ms': round((time.perf_counter() - started) * 1000, 2),
        'boundary': 'SQL executed inside the application CVM; only serialized results leave the query executor.',
    }
