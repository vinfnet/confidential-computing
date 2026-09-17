"""Read-only question scope planning for the fictional Norland dataset."""

from __future__ import annotations

import re
from typing import Any

DATASET_SCHEMA = {
    'citizen_registry': {
        'description': 'Core fictional citizen identity, address, civil, voter, socioeconomic, and summary tax fields.',
        'columns': ['id', 'national_id', 'first_name', 'last_name', 'date_of_birth', 'sex', 'region', 'municipality', 'address_line', 'postal_code', 'household_size', 'marital_status', 'employment_status', 'tax_bracket', 'registered_voter', 'socioeconomic_group', 'tax_paid_last_year'],
        'joins': ['citizen_health_records.citizen_id', 'citizen_hospital_visits.citizen_id', 'citizen_employment_history.citizen_id', 'citizen_tax_history.citizen_id'],
    },
    'citizen_health_records': {
        'description': 'Fictional active and historical health conditions; not medical advice.',
        'columns': ['citizen_id', 'condition_name', 'condition_code', 'onset_date', 'is_active', 'severity'],
        'joins': ['citizen_registry.id'],
    },
    'citizen_hospital_visits': {
        'description': 'Fictional hospital visits and reasons; not a clinical record.',
        'columns': ['citizen_id', 'visit_date', 'visit_reason', 'hospital_name', 'discharge_date'],
        'joins': ['citizen_registry.id'],
    },
    'norland_companies': {
        'description': 'Fictional companies, industry verticals, annual profit, and employee counts.',
        'columns': ['company_code', 'company_name', 'industry_vertical', 'annual_profit_n', 'employee_count'],
        'joins': ['citizen_employment_history.company_code', 'citizen_tax_history.company_code'],
    },
    'citizen_employment_history': {
        'description': 'Fictional company transitions, roles, and start/end years.',
        'columns': ['citizen_id', 'company_code', 'start_year', 'end_year', 'job_title'],
        'joins': ['citizen_registry.id', 'norland_companies.company_code'],
    },
    'citizen_tax_history': {
        'description': 'Fictional annual salary, tax code, rate, and calculated tax paid.',
        'columns': ['citizen_id', 'company_code', 'tax_year', 'gross_salary_n', 'tax_code', 'tax_rate_percent', 'tax_paid_n'],
        'joins': ['citizen_registry.id', 'norland_companies.company_code'],
    },
}

POLICY_TOPICS = {
    'tax': 'NORLAND_TAX_CODE',
    'healthcare': 'NORLAND_HEALTHCARE_POLICY',
    'schooling': 'NORLAND_SCHOOLING_POLICY',
    'passport': 'NORLAND_PASSPORT_POLICY',
    'travel': 'NORLAND_TRAVEL_POLICY',
    'employment': 'NORLAND_EMPLOYMENT_POLICY',
}


def plan_question(question: str) -> dict[str, Any]:
    """Select relevant SQL domains and policy topics without executing SQL."""
    text = question.lower()
    tables = {'citizen_registry'}
    if re.search(r'health|condition|hospital|medical|care', text):
        tables.update(('citizen_health_records', 'citizen_hospital_visits'))
    if re.search(r'company|companies|employer|employment|industry|job|work|salary|income', text):
        tables.update(('norland_companies', 'citizen_employment_history', 'citizen_tax_history'))
    if re.search(r'tax|salary|income|revenue|paid|bracket|rate', text):
        tables.add('citizen_tax_history')
    if re.search(r'passport|travel|border|visa', text):
        tables.add('citizen_registry')
    policies = [topic for topic, policy in POLICY_TOPICS.items() if re.search(topic, text)]
    return {
        'read_only': True,
        'tables': [name for name in DATASET_SCHEMA if name in tables],
        'policy_topics': policies,
        'boundary': 'Application CVM executes allowlisted SQL; H100 receives results only.',
    }
