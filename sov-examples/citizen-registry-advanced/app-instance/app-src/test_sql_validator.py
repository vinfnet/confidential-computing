import sqlite3
import unittest

from query_executor import execute_validated_plan
from sql_validator import build_parameterized_sql, validate_query_plan


class SqlValidatorTests(unittest.TestCase):
    def setUp(self):
        self.connection = sqlite3.connect(':memory:')
        self.connection.execute('CREATE TABLE citizen_registry (id INTEGER, sex TEXT)')
        self.connection.executemany('INSERT INTO citizen_registry VALUES (?, ?)', [(1, 'F'), (2, 'M')])

    def tearDown(self):
        self.connection.close()

    def test_valid_plan_executes_parameterized_read_only_query(self):
        plan = {
            'operation': 'retrieval',
            'tables': ['citizen_registry'],
            'select': ['id', 'sex'],
            'where': [{'column': 'sex', 'operator': '=', 'parameter': 'gender'}],
            'limit': 10,
        }
        valid, reason = validate_query_plan(plan)
        self.assertTrue(valid, reason)
        sql, values = build_parameterized_sql(plan, {'gender': 'F'}, sql_server=False)
        self.assertIn('?', sql)
        result = execute_validated_plan(self.connection, plan, {'gender': 'F'}, sql_server=False)
        self.assertEqual(result['rows'], [{'id': 1, 'sex': 'F'}])
        self.assertTrue(result['read_only'])

    def test_unknown_table_and_mutating_shape_are_rejected(self):
        valid, _ = validate_query_plan({'operation': 'retrieval', 'tables': ['secrets'], 'select': ['id']})
        self.assertFalse(valid)
        valid, _ = validate_query_plan({'operation': 'update', 'tables': ['citizen_registry'], 'select': ['id']})
        self.assertFalse(valid)


if __name__ == '__main__':
    unittest.main()
