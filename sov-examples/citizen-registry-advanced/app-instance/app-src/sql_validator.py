"""Strict validation for model-proposed read-only query plans."""

from __future__ import annotations

import re
from typing import Any

from dataset_query import DATASET_SCHEMA

ALLOWED_OPERATORS = {'=', '!=', '<', '<=', '>', '>=', 'LIKE', 'IN'}
ALLOWED_FUNCTIONS = {'COUNT', 'COUNT_DISTINCT', 'SUM', 'AVG', 'MIN', 'MAX'}
MAX_LIMIT = 1000
MAX_JOINS = 4
_IDENTIFIER = re.compile(r'^[A-Za-z_][A-Za-z0-9_]*(?:\.[A-Za-z_][A-Za-z0-9_]*)?$')


def _valid_reference(value: Any, columns: set[str]) -> bool:
    return isinstance(value, str) and _IDENTIFIER.fullmatch(value) is not None and (
        value in columns or value.split('.')[-1] in columns
    )


def validate_query_plan(plan: Any) -> tuple[bool, str]:
    if not isinstance(plan, dict):
        return False, 'query_plan must be an object'
    if plan.get('operation') not in {'aggregate', 'retrieval'}:
        return False, 'operation must be aggregate or retrieval'
    tables = plan.get('tables') or plan.get('from')
    if not isinstance(tables, list) or not tables or any(table not in DATASET_SCHEMA for table in tables):
        return False, 'every table must be in the approved schema'
    if len(tables) > MAX_JOINS + 1:
        return False, 'too many tables'
    allowed_columns = {column for table in tables for column in DATASET_SCHEMA[table]['columns']}
    selected = plan.get('select', [])
    if not isinstance(selected, list) or not selected or len(selected) > 20:
        return False, 'select must contain 1 to 20 fields'
    for field in selected:
        if isinstance(field, dict):
            if field.get('function') not in ALLOWED_FUNCTIONS or not _valid_reference(field.get('column', 'id'), allowed_columns):
                return False, 'invalid aggregate field'
        elif not _valid_reference(field, allowed_columns):
            return False, 'invalid selected column'
    for condition in plan.get('where', []):
        if not isinstance(condition, dict) or condition.get('operator') not in ALLOWED_OPERATORS:
            return False, 'invalid filter'
        if not _valid_reference(condition.get('column'), allowed_columns):
            return False, 'invalid filter column'
        if not isinstance(condition.get('parameter'), str):
            return False, 'filters must use parameter names'
    if len(plan.get('joins', [])) > MAX_JOINS:
        return False, 'too many joins'
    for join in plan.get('joins', []):
        if not isinstance(join, dict) or join.get('table') not in DATASET_SCHEMA:
            return False, 'invalid join table'
        if join.get('table') not in tables or not _valid_reference(join.get('left'), allowed_columns) or not _valid_reference(join.get('right'), allowed_columns):
            return False, 'invalid join reference'
    for field in plan.get('group_by', []) + [item.get('column') for item in plan.get('order_by', [])]:
        if not _valid_reference(field, allowed_columns):
            return False, 'invalid grouping or ordering column'
    if any(item.get('direction') not in {'ASC', 'DESC'} for item in plan.get('order_by', [])):
        return False, 'invalid ordering direction'
    limit = plan.get('limit', 100)
    if not isinstance(limit, int) or limit < 1 or limit > MAX_LIMIT:
        return False, 'limit must be between 1 and 1000'
    return True, 'valid'


def build_parameterized_sql(plan: dict[str, Any], parameters: dict[str, Any], sql_server: bool = True) -> tuple[str, list[Any]]:
    valid, reason = validate_query_plan(plan)
    if not valid:
        raise ValueError(reason)
    tables = plan.get('tables') or plan.get('from')
    select_parts = []
    for field in plan['select']:
        if isinstance(field, dict):
            function = field['function'].replace('_DISTINCT', ' DISTINCT')
            select_parts.append(f"{function}({field.get('column', 'id')})")
        else:
            select_parts.append(field)
    prefix = f"SELECT TOP {plan.get('limit', 100)}" if sql_server else 'SELECT'
    sql = f"{prefix} {', '.join(select_parts)} FROM {tables[0]}"
    for join in plan.get('joins', []):
        sql += f" JOIN {join['table']} ON {join['left']} = {join['right']}"
    values = []
    clauses = []
    for condition in plan.get('where', []):
        clauses.append(f"{condition['column']} {condition['operator']} ?")
        values.append(parameters.get(condition['parameter']))
    if clauses:
        sql += ' WHERE ' + ' AND '.join(clauses)
    if plan.get('group_by'):
        sql += ' GROUP BY ' + ', '.join(plan['group_by'])
    if plan.get('order_by'):
        sql += ' ORDER BY ' + ', '.join(f"{item['column']} {item['direction']}" for item in plan['order_by'])
    if not sql_server:
        sql += f" LIMIT {plan.get('limit', 100)}"
    return sql, values
