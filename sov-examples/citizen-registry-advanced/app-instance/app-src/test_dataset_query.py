import unittest
import sqlite3

from dataset_query import execute_query_plan, plan_question


class DatasetQueryPlanTests(unittest.TestCase):
    def setUp(self):
        self.connection = sqlite3.connect(':memory:')
        self.connection.executescript('''
            CREATE TABLE citizen_health_records (condition_name TEXT, condition_code TEXT, citizen_id INTEGER, is_active INTEGER);
            INSERT INTO citizen_health_records VALUES ('Fictional allergy', 'DEMO-A', 1, 1), ('Fictional allergy', 'DEMO-A', 2, 1);
            CREATE TABLE norland_companies (company_code TEXT, company_name TEXT, industry_vertical TEXT);
            CREATE TABLE citizen_employment_history (company_code TEXT, citizen_id INTEGER, end_year INTEGER);
            INSERT INTO norland_companies VALUES ('NOR-001', 'Example Works', 'Example industry');
            INSERT INTO citizen_employment_history VALUES ('NOR-001', 1, 2025);
            CREATE TABLE citizen_tax_history (tax_year INTEGER, gross_salary_n NUMERIC, tax_paid_n NUMERIC);
            INSERT INTO citizen_tax_history VALUES (2025, 50000, 7000), (2025, 60000, 9000);
        ''')

    def tearDown(self):
        self.connection.close()

    def test_tax_employment_scope_is_read_only_and_joined(self):
        plan = plan_question('Compare salary and tax paid by employer and year')
        self.assertTrue(plan['read_only'])
        self.assertIn('citizen_tax_history', plan['tables'])
        self.assertIn('citizen_employment_history', plan['tables'])
        self.assertIn('norland_companies', plan['tables'])

    def test_health_scope_includes_condition_and_visit_tables(self):
        plan = plan_question('How many citizens had a hospital visit for each condition?')
        self.assertIn('citizen_health_records', plan['tables'])
        self.assertIn('citizen_hospital_visits', plan['tables'])

    def test_policy_scope_is_explicit(self):
        plan = plan_question('What are the Norland passport and travel rules?')
        self.assertIn('passport', plan['policy_topics'])
        self.assertIn('travel', plan['policy_topics'])

    def test_health_question_executes_fixed_read_only_query(self):
        result = execute_query_plan(self.connection.cursor(), 'How many citizens have each health condition?')
        self.assertTrue(result['read_only'])
        self.assertEqual(result['rows'][0]['citizens'], 2)

    def test_salary_question_executes_fixed_aggregate_query(self):
        result = execute_query_plan(self.connection.cursor(), 'What is the average salary?')
        self.assertEqual(result['operation'], 'aggregate annual salary and tax history')
        self.assertEqual(result['rows'][0]['average_salary_n'], 55000.0)


if __name__ == '__main__':
    unittest.main()
