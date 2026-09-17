import unittest

from dataset_query import plan_question


class DatasetQueryPlanTests(unittest.TestCase):
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


if __name__ == '__main__':
    unittest.main()
