"""
Citizen Registry Advanced — Flask App with mTLS and Azure Attestation

Deployed on an NCC40ads H100 Confidential GPU VM with:
- Mutual TLS (mTLS) for client-server authentication
- Azure Attestation integration for certificate validation
- SQL Server on ACC for encrypted data storage
- Managed HSM integration for key management
- Attested CUDA portrait generation on an NVIDIA H100
"""

from flask import Flask, jsonify, redirect, request, render_template, send_file, url_for
import base64
import json
import os
import re
import secrets
import ssl
import threading
import time
import pyodbc
import sqlite3
import logging
from collections import Counter
from datetime import datetime, timezone
from decimal import Decimal
from pathlib import Path
from azure.identity import ManagedIdentityCredential, DefaultAzureCredential
import requests
from media_generator import MediaGenerator, get_gpu_attestation_evidence
from citizen_help import MAX_RECORDS, model_metadata, validate_question
from dataset_query import DATASET_SCHEMA, execute_query_plan, plan_question
from query_executor import execute_validated_plan
from sql_validator import validate_query_plan

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s',
    handlers=[
        logging.FileHandler('/var/log/citizen-registry/app.log'),
        logging.StreamHandler()
    ]
)
logger = logging.getLogger(__name__)

app = Flask(__name__)
app.config['SECRET_KEY'] = secrets.token_hex(32)
app.config['MAX_CONTENT_LENGTH'] = 16 * 1024
media_generator = MediaGenerator()


@app.before_request
def enforce_mtls_for_api():
    """Require nginx to verify a client certificate for registry mutations/reads."""
    if MTLS_ENABLED and request.path.startswith('/api') and request.headers.get('X-Client-Verify') != 'SUCCESS':
        return jsonify({'error': 'Valid client certificate required'}), 401


# mTLS Configuration
MTLS_ENABLED = os.environ.get('MTLS_ENABLED', 'true').lower() == 'true'
CERT_PATH = os.environ.get('CERT_PATH', '/etc/citizen-registry/certs/citizen-registry.crt')
KEY_PATH = os.environ.get('KEY_PATH', '/etc/citizen-registry/certs/citizen-registry.key')
ATTESTATION_ENDPOINT = os.environ.get('ATTESTATION_ENDPOINT', '')

# Database configuration
DB_HOST = os.environ.get('DB_HOST', '')
DB_NAME = os.environ.get('DB_NAME', 'citizendb')
DB_USER = os.environ.get('DB_USER', '')
DB_PASSWORD = os.environ.get('DB_PASSWORD', '')
DB_SA_PASSWORD = os.environ.get('DB_SA_PASSWORD', '')
LOCAL_DB_PATH = os.environ.get('LOCAL_DB_PATH', '/var/lib/citizen-registry/citizens.db')

# Managed HSM configuration
HSM_ENDPOINT = os.environ.get('HSM_ENDPOINT', '')
APP_CVM_IP = os.environ.get('APP_CVM_IP', '')
SQL_CVM_IP = os.environ.get('SQL_CVM_IP', DB_HOST)
HSM_NAME = os.environ.get('HSM_NAME', '')
OS_DISK_KEY_NAME = os.environ.get('OS_DISK_KEY_NAME', '')
KEY_RELEASE_STATUS = os.environ.get('KEY_RELEASE_STATUS', 'not_configured')
CPU_ATTESTATION_PATH = os.environ.get(
    'CPU_ATTESTATION_PATH',
    '/var/lib/citizen-registry/cpu-attestation.json',
)
CCTV_VIDEO_PATH = os.environ.get(
    'CCTV_VIDEO_PATH',
    '/opt/citizen-registry/source-media/london-marathon-2026-close-faces.mp4',
)
CCTV_VIDEO_BLOB_URI = os.environ.get('CCTV_VIDEO_BLOB_URI', '')
DVR_STORAGE_ACCOUNT = os.environ.get('DVR_STORAGE_ACCOUNT', '')
DVR_STORAGE_CONTAINER = os.environ.get('DVR_STORAGE_CONTAINER', '')
DVR_STORAGE_KEY_NAME = os.environ.get('DVR_STORAGE_KEY_NAME', '')
DVR_STORAGE_KEY_VERSION = os.environ.get('DVR_STORAGE_KEY_VERSION', '')
CCTV_PROCESSING_ROOT = Path(os.environ.get(
    'CCTV_PROCESSING_ROOT', '/var/lib/citizen-registry/cctv'))
CCTV_STATUS_PATH = CCTV_PROCESSING_ROOT / 'status.json'
CCTV_PLAYLIST_PATH = CCTV_PROCESSING_ROOT / 'hls' / 'index.m3u8'

_credential = None
_credential_lock = threading.Lock()
_database_ready = False
_database_ready_lock = threading.Lock()

PERSONA_GROUPS = [
    ('West African', [
        ('Ama', 'Mensah', 'F'), ('Kwame', 'Boateng', 'M'), ('Kofi', 'Owusu', 'X'),
        ('Adwoa', 'Asante', 'F'), ('Chinedu', 'Okafor', 'M'),
    ]),
    ('East African', [
        ('Wanjiku', 'Kamau', 'F'), ('Dawit', 'Bekele', 'M'), ('Amani', 'Njoroge', 'X'),
        ('Selam', 'Tesfaye', 'F'), ('Abdi', 'Warsame', 'M'),
    ]),
    ('North African', [
        ('Nadia', 'Bensaid', 'F'), ('Karim', 'El Amrani', 'M'), ('Noor', 'Mansouri', 'X'),
        ('Salma', 'Benali', 'F'), ('Youssef', 'Haddad', 'M'),
    ]),
    ('Arab', [
        ('Layla', 'Khalil', 'F'), ('Omar', 'Darwish', 'M'), ('Rayan', 'Nasser', 'X'),
        ('Mariam', 'Saleh', 'F'), ('Zaid', 'Hamdan', 'M'),
    ]),
    ('Persian', [
        ('Shirin', 'Farhadi', 'F'), ('Arman', 'Daryaei', 'M'), ('Kian', 'Navidi', 'X'),
        ('Niloofar', 'Rahimi', 'F'), ('Darius', 'Mehrabi', 'M'),
    ]),
    ('South Asian Indian', [
        ('Priya', 'Nair', 'F'), ('Arjun', 'Mehta', 'M'), ('Kiran', 'Rao', 'X'),
        ('Ananya', 'Iyer', 'F'), ('Vikram', 'Singh', 'M'),
    ]),
    ('South Asian Pakistani', [
        ('Sana', 'Qureshi', 'F'), ('Hamza', 'Khan', 'M'), ('Ari', 'Siddiqui', 'X'),
        ('Mahnoor', 'Abbasi', 'F'), ('Bilal', 'Chaudhry', 'M'),
    ]),
    ('South Asian Bangladeshi', [
        ('Nusrat', 'Rahman', 'F'), ('Tanvir', 'Hossain', 'M'), ('Shafin', 'Karim', 'X'),
        ('Farzana', 'Ahmed', 'F'), ('Rafiq', 'Chowdhury', 'M'),
    ]),
    ('Chinese', [
        ('Mei', 'Chen', 'F'), ('Jian', 'Wang', 'M'), ('Yu', 'Lin', 'X'),
        ('Xia', 'Zhou', 'F'), ('Wei', 'Huang', 'M'),
    ]),
    ('Japanese', [
        ('Aiko', 'Tanaka', 'F'), ('Haruto', 'Sato', 'M'), ('Ren', 'Mori', 'X'),
        ('Yui', 'Nakamura', 'F'), ('Daichi', 'Kobayashi', 'M'),
    ]),
    ('Korean', [
        ('Seo-yeon', 'Kim', 'F'), ('Min-jun', 'Park', 'M'), ('Ji', 'Lee', 'X'),
        ('Hana', 'Choi', 'F'), ('Hyun-woo', 'Kang', 'M'),
    ]),
    ('Southeast Asian', [
        ('Linh', 'Nguyen', 'F'), ('Minh', 'Tran', 'M'), ('Anh', 'Le', 'X'),
        ('Mai', 'Phan', 'F'), ('Duc', 'Vo', 'M'),
    ]),
    ('Filipino', [
        ('Mara', 'Santos', 'F'), ('Paolo', 'Reyes', 'M'), ('Alex', 'Cruz', 'X'),
        ('Liza', 'Bautista', 'F'), ('Ramon', 'Garcia', 'M'),
    ]),
    ('Latin American', [
        ('Camila', 'Alvarez', 'F'), ('Mateo', 'Rojas', 'M'), ('Dani', 'Rivera', 'X'),
        ('Lucia', 'Morales', 'F'), ('Santiago', 'Vega', 'M'),
    ]),
    ('Caribbean', [
        ('Simone', 'Baptiste', 'F'), ('Malik', 'Campbell', 'M'), ('Kai', 'Joseph', 'X'),
        ('Althea', 'Clarke', 'F'), ('Andre', 'Richards', 'M'),
    ]),
    ('Nordic', [
        ('Freja', 'Larsen', 'F'), ('Soren', 'Berg', 'M'), ('Robin', 'Lind', 'X'),
        ('Ingrid', 'Nygaard', 'F'), ('Mikael', 'Sundstrom', 'M'),
    ]),
    ('Eastern European', [
        ('Aneta', 'Novak', 'F'), ('Marek', 'Kowalski', 'M'), ('Sasha', 'Petrov', 'X'),
        ('Iryna', 'Bondarenko', 'F'), ('Tomas', 'Horvat', 'M'),
    ]),
    ('Mediterranean European', [
        ('Sofia', 'Rossi', 'F'), ('Nikos', 'Papadakis', 'M'), ('Andrea', 'Costa', 'X'),
        ('Elena', 'Marino', 'F'), ('Tiago', 'Silva', 'M'),
    ]),
    ('Western European', [
        ('Amelie', 'Dubois', 'F'), ('Jonas', 'Schmidt', 'M'), ('Sam', 'Bennett', 'X'),
        ('Maeve', 'OConnell', 'F'), ('Elias', 'de Vries', 'M'),
    ]),
    ('Mixed heritage', [
        ('Maya', 'Johnson-Chen', 'F'), ('Idris', 'Williams', 'M'), ('Taylor', 'Okafor-Smith', 'X'),
        ('Leila', 'Garcia-Haddad', 'F'), ('Noah', 'Tanaka-Rossi', 'M'),
    ]),
]
LOCATIONS = [
    ('Central', 'Alderwick', 'Cedar Avenue', 'NR1'),
    ('Central', 'Kingshaven', 'Parliament Street', 'NR2'),
    ('North', 'Riverside', 'Mill Lane', 'NR3'),
    ('North', 'Harbor', 'Seafarer Road', 'NR4'),
    ('South', 'Lakeside', 'Willow Crescent', 'NR5'),
    ('South', 'Meadowfield', 'Orchard Way', 'NR6'),
    ('East', 'Hillview', 'Beacon Street', 'NR7'),
    ('East', 'Stonebridge', 'Foundry Road', 'NR8'),
    ('West', 'Oakridge', 'Maple Drive', 'NR9'),
    ('West', 'Westport', 'Quayside Avenue', 'NR10'),
]
SOCIOECONOMIC_GROUPS = [
    'A1 - Professional', 'A2 - Managerial', 'B1 - Skilled',
    'B2 - Intermediate', 'C1 - Service', 'C2 - Supported',
]
HEALTH_CONDITIONS = [
    ('Seasonal allergies', 'DEMO-ALLERGY', 'Mild'),
    ('Mild hypertension', 'DEMO-HTN', 'Moderate'),
    ('Type 2 diabetes, controlled', 'DEMO-T2D', 'Moderate'),
    ('Lower back pain', 'DEMO-BACK', 'Mild'),
    ('Migraine', 'DEMO-MIGRAINE', 'Moderate'),
    ('Mild asthma', 'DEMO-ASTHMA', 'Moderate'),
    ('Eczema', 'DEMO-ECZEMA', 'Mild'),
    ('Iron deficiency', 'DEMO-IRON', 'Mild'),
    ('Repetitive strain injury', 'DEMO-RSI', 'Mild'),
    ('High cholesterol, managed', 'DEMO-CHOLESTEROL', 'Moderate'),
]
HEALTH_HOSPITALS = [
    'Alderwick Community Hospital', 'Kingshaven General Hospital',
    'Riverside Health Centre', 'Lakeside District Hospital',
    'Hillview Medical Pavilion',
]
HEALTH_VISIT_REASONS = [
    'Annual wellness check', 'Routine laboratory work',
    'Physiotherapy review', 'Vaccination appointment',
    'Dietary consultation', 'Follow-up appointment',
]
NORLAND_TAX_CODE = [
    {'code': 'NR-00', 'label': 'Civic exemption band', 'lower_salary': 0, 'upper_salary': 11999.99, 'rate_percent': 0},
    {'code': 'NR-10', 'label': 'Foundational band', 'lower_salary': 12000, 'upper_salary': 29999.99, 'rate_percent': 10},
    {'code': 'NR-20', 'label': 'General band', 'lower_salary': 30000, 'upper_salary': 59999.99, 'rate_percent': 20},
    {'code': 'NR-30', 'label': 'Stewardship band', 'lower_salary': 60000, 'upper_salary': None, 'rate_percent': 30},
]


NORLAND_COMPANIES = [
    ('NOR-001', 'Alderwick Gridworks', 'Energy and utilities', 184000000, 4200),
    ('NOR-002', 'Blue Harbor Systems', 'Software and communications', 96000000, 1850),
    ('NOR-003', 'Cedarline Foods', 'Food manufacturing', 71000000, 2300),
    ('NOR-004', 'Civic Transit Works', 'Transport and infrastructure', 128000000, 5100),
    ('NOR-005', 'Lakeside Biologics', 'Biotechnology and health research', 152000000, 1250),
    ('NOR-006', 'Northstar Learning Cooperative', 'Education services', 43000000, 1700),
    ('NOR-007', 'Stonebridge Finance', 'Financial services', 205000000, 2900),
    ('NOR-008', 'Westport Circular Materials', 'Recycling and advanced materials', 68000000, 1450),
]
NORLAND_JOB_TITLES = (
    'Apprentice', 'Coordinator', 'Analyst', 'Specialist', 'Senior specialist',
    'Team lead', 'Manager', 'Director',
)


def _tax_calculation(annual_salary):
    """Calculate progressive fictional Norland tax from annual salary."""
    salary = max(0.0, float(annual_salary or 0))
    tax_paid = 0.0
    remaining = salary
    previous_upper = 0.0
    marginal_code = NORLAND_TAX_CODE[0]['code']
    marginal_rate = 0
    for band in NORLAND_TAX_CODE:
        upper = band['upper_salary']
        taxable = remaining if upper is None else min(remaining, upper - previous_upper)
        if taxable > 0:
            tax_paid += taxable * band['rate_percent'] / 100
            marginal_code = band['code']
            marginal_rate = band['rate_percent']
            remaining -= taxable
        previous_upper = upper if upper is not None else salary
        if remaining <= 0:
            break
    return {
        'code': marginal_code,
        'rate_percent': marginal_rate,
        'gross_salary_n£': round(salary, 2),
        'tax_paid_n£': round(tax_paid, 2),
        'status': 'fictional demonstration calculation',
    }


def _tax_status(tax_paid, annual_salary=None):
    """Return the fictional Norland tax status for a salary or legacy record."""
    if annual_salary is not None:
        return _tax_calculation(annual_salary)
    amount = float(tax_paid or 0)
    for band in NORLAND_TAX_CODE:
        if band['rate_percent'] == 0 or amount <= band['upper_salary']:
            return {
                'code': band['code'],
                'label': band['label'],
                'rate_percent': band['rate_percent'],
                'annual_tax_paid_n£': round(amount, 2),
                'status': 'fictional demonstration classification',
            }
    raise ValueError('Tax amount did not match a Norland tax band')


def _synthetic_employment_history(citizens):
    """Build deterministic company assignments and annual salary/tax records."""
    employment = []
    tax_history = []
    for citizen_id, citizen in enumerate(citizens, start=1):
        birth_year = int(citizen['date_of_birth'][:4])
        first_year = max(birth_year + 18, 2000)
        last_year = 2025
        if first_year > last_year:
            first_year = last_year
        year = first_year
        job_index = (citizen_id * 3) % len(NORLAND_JOB_TITLES)
        company_index = (citizen_id * 5) % len(NORLAND_COMPANIES)
        while year <= last_year:
            duration = 2 + ((citizen_id + year) % 5)
            end_year = min(last_year, year + duration - 1)
            company = NORLAND_COMPANIES[company_index]
            employment.append({
                'citizen_id': citizen_id,
                'company_code': company[0],
                'start_year': year,
                'end_year': end_year,
                'job_title': NORLAND_JOB_TITLES[job_index],
            })
            for tax_year in range(year, end_year + 1):
                experience = tax_year - first_year
                salary = 18000 + ((citizen_id * 97) % 9000) + experience * 1650 + job_index * 850
                calculation = _tax_calculation(salary)
                tax_history.append({
                    'citizen_id': citizen_id,
                    'company_code': company[0],
                    'tax_year': tax_year,
                    'gross_salary_n£': calculation['gross_salary_n£'],
                    'tax_code': calculation['code'],
                    'tax_rate_percent': calculation['rate_percent'],
                    'tax_paid_n£': calculation['tax_paid_n£'],
                })
            year = end_year + 1
            company_index = (company_index + 1 + citizen_id % 3) % len(NORLAND_COMPANIES)
            job_index = min(len(NORLAND_JOB_TITLES) - 1, job_index + 1)
    return employment, tax_history


def _expanded_personas():
    """Build 1,000 deterministic persona/name combinations from curated pools."""
    grouped_personas = []
    for portrait_profile, group in PERSONA_GROUPS:
        given_names = [(first_name, sex) for first_name, _, sex in group]
        surnames = [last_name for _, last_name, _ in group]
        surname_variants = surnames + [
            f'{surnames[index]}-{surnames[(index + 1) % len(surnames)]}'
            for index in range(len(surnames))
        ]
        group_personas = []
        for first_name, sex in given_names:
            for last_name in surname_variants:
                group_personas.append((first_name, last_name, sex, portrait_profile))
        grouped_personas.append(group_personas)

    personas = []
    for persona_index in range(len(grouped_personas[0])):
        for group_personas in grouped_personas:
            personas.append(group_personas[persona_index])
    return personas


def _synthetic_citizens():
    """Build 1,000 deterministic, entirely fictional Republic of Norland records."""
    citizens = []
    personas = _expanded_personas()
    for index, (first_name, last_name, sex, _) in enumerate(personas, start=1):
        state, town, street, postal_area = LOCATIONS[(index - 1) % len(LOCATIONS)]
        year = 1948 + ((index * 7) % 58)
        month = 1 + ((index * 5) % 12)
        day = 1 + ((index * 11) % 27)
        citizens.append({
            'national_id': f'NLD-{index:04d}X',
            'first_name': first_name,
            'last_name': last_name,
            'date_of_birth': f'{year:04d}-{month:02d}-{day:02d}',
            'sex': sex,
            'region': state,
            'municipality': town,
            'address_line': f'{10 + ((index * 13) % 190)} {street}',
            'postal_code': f'{postal_area} {index % 10}{(index * 7) % 10}Q',
            'socioeconomic_group': SOCIOECONOMIC_GROUPS[(index * 5) % len(SOCIOECONOMIC_GROUPS)],
            'tax_paid_last_year': Decimal(850 + ((index * 1879) % 48600)) + Decimal(index % 100) / 100,
        })
    return citizens


def _portrait_profile(national_id):
    for citizen_index, (_, _, _, portrait_profile) in enumerate(_expanded_personas(), start=1):
        expected_id = f'NLD-{citizen_index:04d}X'
        if national_id == expected_id:
            return portrait_profile
    return None


def _synthetic_health_records(citizens):
    """Build deterministic, fictional, non-critical health records."""
    conditions = []
    visits = []
    for citizen_id, citizen in enumerate(citizens, start=1):
        if citizen_id % 2 == 0:
            condition = HEALTH_CONDITIONS[citizen_id % len(HEALTH_CONDITIONS)]
            conditions.append({
                'citizen_id': citizen_id,
                'condition_name': condition[0],
                'condition_code': condition[1],
                'onset_date': f'{2018 + citizen_id % 7:04d}-{1 + citizen_id % 9:02d}-15',
                'is_active': True,
                'severity': condition[2],
            })
        if citizen_id % 3 == 0:
            visits.append({
                'citizen_id': citizen_id,
                'visit_date': f'2025-{1 + citizen_id % 9:02d}-{1 + citizen_id % 20:02d}',
                'visit_reason': HEALTH_VISIT_REASONS[citizen_id % len(HEALTH_VISIT_REASONS)],
                'hospital_name': HEALTH_HOSPITALS[citizen_id % len(HEALTH_HOSPITALS)],
                'discharge_date': f'2025-{1 + citizen_id % 9:02d}-{2 + citizen_id % 20:02d}',
            })
    return conditions, visits

# ============================================================================
# Database Connection Management
# ============================================================================

def _build_sql_auth_conn_str(server, database, user, password):
    """Build SQL Server connection string with SQL authentication"""
    return (
        f"Driver={{ODBC Driver 18 for SQL Server}};"
        f"Server=tcp:{server},1433;"
        f"Database={database};"
        f"UID={user};PWD={password};"
        "Encrypt=yes;TrustServerCertificate=yes;"
    )


def _bootstrap_demo_database(server, database, db_user, db_password):
    """Bootstrap database schema and users (demo deployment helper)"""
    logger.info(f"Bootstrapping database: {database}")
    
    if not DB_SA_PASSWORD:
        raise RuntimeError('DB_SA_PASSWORD env var required for database bootstrap')
    
    admin_conn = pyodbc.connect(
        _build_sql_auth_conn_str(server, 'master', 'sa', DB_SA_PASSWORD),
        autocommit=True,
    )
    try:
        cur = admin_conn.cursor()
        cur.execute(f"IF DB_ID(N'{database}') IS NULL CREATE DATABASE [{database}]")
        cur.execute(
            f"IF SUSER_ID(N'{db_user}') IS NULL "
            f"CREATE LOGIN [{db_user}] WITH PASSWORD = '{db_password}' "
            f"ELSE ALTER LOGIN [{db_user}] WITH PASSWORD = '{db_password}'"
        )
        cur.execute(f"ALTER LOGIN [{db_user}] WITH DEFAULT_DATABASE = [{database}]")
        cur.execute(f"USE [{database}]")
        cur.execute(
            f"IF USER_ID(N'{db_user}') IS NULL CREATE USER [{db_user}] FOR LOGIN [{db_user}]"
        )
        cur.execute(f"ALTER USER [{db_user}] WITH LOGIN = [{db_user}]")
        cur.execute(
            f"ALTER ROLE db_datareader ADD MEMBER [{db_user}]"
        )
        cur.execute(
            f"ALTER ROLE db_datawriter ADD MEMBER [{db_user}]"
        )

        # Gunicorn workers can initialize concurrently after deployment. Hold a
        # session lock so schema migration and baseline seeding run exactly once.
        cur.execute("""
            DECLARE @lock_result INT;
            EXEC @lock_result = sys.sp_getapplock
                @Resource = N'citizen-registry-seed-v106',
                @LockMode = N'Exclusive',
                @LockOwner = N'Session',
                @LockTimeout = 30000;
            IF @lock_result < 0 THROW 51000, 'Could not acquire seed lock', 1;
        """)
        
        # Create citizen_registry table
        cur.execute("""
            IF OBJECT_ID(N'dbo.citizen_registry', N'U') IS NULL
            BEGIN
                CREATE TABLE dbo.citizen_registry (
                    id INT IDENTITY(1,1) PRIMARY KEY,
                    national_id NVARCHAR(20) NOT NULL UNIQUE,
                    first_name NVARCHAR(100) NOT NULL,
                    last_name NVARCHAR(100) NOT NULL,
                    date_of_birth DATE NOT NULL,
                    sex NVARCHAR(10),
                    region NVARCHAR(100),
                    municipality NVARCHAR(100),
                    address_line NVARCHAR(200),
                    postal_code NVARCHAR(10),
                    household_size INT DEFAULT 1,
                    marital_status NVARCHAR(20) DEFAULT N'Single',
                    employment_status NVARCHAR(30) DEFAULT N'Employed',
                    tax_bracket NVARCHAR(10) DEFAULT N'B',
                    registered_voter BIT DEFAULT 1,
                    socioeconomic_group NVARCHAR(40),
                    tax_paid_last_year DECIMAL(12,2),
                    created_date DATETIME DEFAULT GETUTCDATE(),
                    modified_date DATETIME DEFAULT GETUTCDATE()
                )
            END
        """)

        cur.execute("""
            IF COL_LENGTH('dbo.citizen_registry', 'socioeconomic_group') IS NULL
                ALTER TABLE dbo.citizen_registry ADD socioeconomic_group NVARCHAR(40) NULL;
            IF COL_LENGTH('dbo.citizen_registry', 'tax_paid_last_year') IS NULL
                ALTER TABLE dbo.citizen_registry ADD tax_paid_last_year DECIMAL(12,2) NULL;
            IF OBJECT_ID(N'dbo.demo_metadata', N'U') IS NULL
                CREATE TABLE dbo.demo_metadata (seed_version INT NOT NULL);
            IF OBJECT_ID(N'dbo.citizen_health_records', N'U') IS NULL
            BEGIN
                CREATE TABLE dbo.citizen_health_records (
                    id INT IDENTITY(1,1) PRIMARY KEY,
                    citizen_id INT NOT NULL,
                    condition_name NVARCHAR(120) NOT NULL,
                    condition_code NVARCHAR(40) NOT NULL,
                    onset_date DATE NOT NULL,
                    is_active BIT NOT NULL,
                    severity NVARCHAR(20) NOT NULL,
                    created_date DATETIME DEFAULT GETUTCDATE(),
                    modified_date DATETIME DEFAULT GETUTCDATE(),
                    CONSTRAINT FK_health_citizen FOREIGN KEY (citizen_id)
                        REFERENCES dbo.citizen_registry(id) ON DELETE CASCADE
                )
            END
            IF OBJECT_ID(N'dbo.citizen_hospital_visits', N'U') IS NULL
            BEGIN
                CREATE TABLE dbo.citizen_hospital_visits (
                    id INT IDENTITY(1,1) PRIMARY KEY,
                    citizen_id INT NOT NULL,
                    visit_date DATE NOT NULL,
                    visit_reason NVARCHAR(120) NOT NULL,
                    hospital_name NVARCHAR(120) NOT NULL,
                    discharge_date DATE NULL,
                    created_date DATETIME DEFAULT GETUTCDATE(),
                    CONSTRAINT FK_visit_citizen FOREIGN KEY (citizen_id)
                        REFERENCES dbo.citizen_registry(id) ON DELETE CASCADE
                )
            END
            IF OBJECT_ID(N'dbo.norland_companies', N'U') IS NULL
            BEGIN
                CREATE TABLE dbo.norland_companies (
                    company_code NVARCHAR(20) PRIMARY KEY,
                    company_name NVARCHAR(160) NOT NULL,
                    industry_vertical NVARCHAR(120) NOT NULL,
                    annual_profit_n DECIMAL(18,2) NOT NULL,
                    employee_count INT NOT NULL
                )
            END
            IF OBJECT_ID(N'dbo.citizen_employment_history', N'U') IS NULL
            BEGIN
                CREATE TABLE dbo.citizen_employment_history (
                    id INT IDENTITY(1,1) PRIMARY KEY,
                    citizen_id INT NOT NULL,
                    company_code NVARCHAR(20) NOT NULL,
                    start_year INT NOT NULL,
                    end_year INT NOT NULL,
                    job_title NVARCHAR(100) NOT NULL,
                    CONSTRAINT FK_employment_citizen FOREIGN KEY (citizen_id)
                        REFERENCES dbo.citizen_registry(id) ON DELETE CASCADE,
                    CONSTRAINT FK_employment_company FOREIGN KEY (company_code)
                        REFERENCES dbo.norland_companies(company_code)
                )
            END
            IF OBJECT_ID(N'dbo.citizen_tax_history', N'U') IS NULL
            BEGIN
                CREATE TABLE dbo.citizen_tax_history (
                    id INT IDENTITY(1,1) PRIMARY KEY,
                    citizen_id INT NOT NULL,
                    company_code NVARCHAR(20) NOT NULL,
                    tax_year INT NOT NULL,
                    gross_salary_n DECIMAL(12,2) NOT NULL,
                    tax_code NVARCHAR(20) NOT NULL,
                    tax_rate_percent DECIMAL(5,2) NOT NULL,
                    tax_paid_n DECIMAL(12,2) NOT NULL,
                    CONSTRAINT FK_tax_history_citizen FOREIGN KEY (citizen_id)
                        REFERENCES dbo.citizen_registry(id) ON DELETE CASCADE,
                    CONSTRAINT FK_tax_history_company FOREIGN KEY (company_code)
                        REFERENCES dbo.norland_companies(company_code)
                )
            END
        """)

        cur.execute("SELECT COUNT(*) FROM dbo.demo_metadata WHERE seed_version = 106")
        if cur.fetchone()[0] == 0:
            cur.execute("DELETE FROM dbo.citizen_tax_history; DELETE FROM dbo.citizen_employment_history; DELETE FROM dbo.citizen_health_records; DELETE FROM dbo.citizen_hospital_visits; DELETE FROM dbo.norland_companies; DELETE FROM dbo.citizen_registry; DBCC CHECKIDENT ('dbo.citizen_registry', RESEED, 0)")
            insert_sql = """
                INSERT INTO dbo.citizen_registry
                (national_id, first_name, last_name, date_of_birth, sex, region,
                 municipality, address_line, postal_code, socioeconomic_group,
                 tax_paid_last_year)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            """
            generated_citizens = _synthetic_citizens()
            for citizen in generated_citizens:
                cur.execute(insert_sql, (
                    citizen['national_id'], citizen['first_name'], citizen['last_name'],
                    citizen['date_of_birth'], citizen['sex'], citizen['region'],
                    citizen['municipality'], citizen['address_line'],
                    citizen['postal_code'], citizen['socioeconomic_group'],
                    citizen['tax_paid_last_year'],
                ))
            conditions, visits = _synthetic_health_records(generated_citizens)
            employment, tax_history = _synthetic_employment_history(generated_citizens)
            cur.fast_executemany = True
            cur.executemany("""
                INSERT INTO dbo.norland_companies
                (company_code, company_name, industry_vertical, annual_profit_n, employee_count)
                VALUES (?, ?, ?, ?, ?)
            """, NORLAND_COMPANIES)
            cur.executemany("""
                INSERT INTO dbo.citizen_employment_history
                (citizen_id, company_code, start_year, end_year, job_title)
                VALUES (?, ?, ?, ?, ?)
            """, [(item['citizen_id'], item['company_code'], item['start_year'], item['end_year'], item['job_title']) for item in employment])
            cur.executemany("""
                INSERT INTO dbo.citizen_tax_history
                (citizen_id, company_code, tax_year, gross_salary_n, tax_code, tax_rate_percent, tax_paid_n)
                VALUES (?, ?, ?, ?, ?, ?, ?)
            """, [(item['citizen_id'], item['company_code'], item['tax_year'], item['gross_salary_n£'], item['tax_code'], item['tax_rate_percent'], item['tax_paid_n£']) for item in tax_history])
            cur.executemany(
                "UPDATE dbo.citizen_registry SET tax_paid_last_year = ? WHERE id = ?",
                [(item['tax_paid_n£'], item['citizen_id']) for item in tax_history if item['tax_year'] == 2025],
            )
            cur.executemany("""
                INSERT INTO dbo.citizen_health_records
                (citizen_id, condition_name, condition_code, onset_date, is_active, severity)
                VALUES (?, ?, ?, ?, ?, ?)
            """, [(
                item['citizen_id'], item['condition_name'], item['condition_code'],
                item['onset_date'], item['is_active'], item['severity'],
            ) for item in conditions])
            cur.executemany("""
                INSERT INTO dbo.citizen_hospital_visits
                (citizen_id, visit_date, visit_reason, hospital_name, discharge_date)
                VALUES (?, ?, ?, ?, ?)
            """, [(
                item['citizen_id'], item['visit_date'], item['visit_reason'],
                item['hospital_name'], item['discharge_date'],
            ) for item in visits])
            cur.execute("DELETE FROM dbo.demo_metadata")
            cur.execute("INSERT INTO dbo.demo_metadata (seed_version) VALUES (106)")
        
        logger.info(f"Database {database} bootstrapped successfully")
    finally:
        admin_conn.close()


def _get_credential():
    """Get Azure credentials for managed identity"""
    global _credential
    if _credential is not None:
        return _credential
    
    with _credential_lock:
        if _credential is not None:
            return _credential
        
        client_id = os.environ.get('AZURE_CLIENT_ID', '')
        if client_id:
            # Azure Policy can attach other identities, so select the identity
            # that owns the key-scoped CMK metadata permission explicitly.
            _credential = ManagedIdentityCredential(client_id=client_id)
        else:
            _credential = DefaultAzureCredential()
        return _credential


def _get_db_conn():
    """Get database connection with automatic bootstrap on first run"""
    if not DB_HOST:
        os.makedirs(os.path.dirname(LOCAL_DB_PATH), exist_ok=True)
        conn = sqlite3.connect(LOCAL_DB_PATH)
        conn.execute(
            """
            CREATE TABLE IF NOT EXISTS citizen_registry (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                national_id TEXT NOT NULL UNIQUE,
                first_name TEXT NOT NULL,
                last_name TEXT NOT NULL,
                date_of_birth TEXT NOT NULL,
                sex TEXT,
                region TEXT,
                municipality TEXT,
                address_line TEXT,
                postal_code TEXT,
                household_size INTEGER DEFAULT 1,
                marital_status TEXT DEFAULT 'Single',
                employment_status TEXT DEFAULT 'Employed',
                tax_bracket TEXT DEFAULT 'B',
                registered_voter INTEGER DEFAULT 1,
                socioeconomic_group TEXT,
                tax_paid_last_year NUMERIC,
                created_date TEXT DEFAULT CURRENT_TIMESTAMP,
                modified_date TEXT DEFAULT CURRENT_TIMESTAMP
            )
            """
        )
        existing_columns = {
            row[1] for row in conn.execute('PRAGMA table_info(citizen_registry)').fetchall()
        }
        if 'socioeconomic_group' not in existing_columns:
            conn.execute('ALTER TABLE citizen_registry ADD COLUMN socioeconomic_group TEXT')
        if 'tax_paid_last_year' not in existing_columns:
            conn.execute('ALTER TABLE citizen_registry ADD COLUMN tax_paid_last_year NUMERIC')
        conn.execute('CREATE TABLE IF NOT EXISTS demo_metadata (seed_version INTEGER NOT NULL)')
        conn.execute('''
            CREATE TABLE IF NOT EXISTS citizen_health_records (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                citizen_id INTEGER NOT NULL,
                condition_name TEXT NOT NULL,
                condition_code TEXT NOT NULL,
                onset_date TEXT NOT NULL,
                is_active INTEGER NOT NULL,
                severity TEXT NOT NULL,
                created_date TEXT DEFAULT CURRENT_TIMESTAMP,
                modified_date TEXT DEFAULT CURRENT_TIMESTAMP
            )
        ''')
        conn.execute('''
            CREATE TABLE IF NOT EXISTS citizen_hospital_visits (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                citizen_id INTEGER NOT NULL,
                visit_date TEXT NOT NULL,
                visit_reason TEXT NOT NULL,
                hospital_name TEXT NOT NULL,
                discharge_date TEXT,
                created_date TEXT DEFAULT CURRENT_TIMESTAMP
            )
        ''')
        conn.execute('''
            CREATE TABLE IF NOT EXISTS norland_companies (
                company_code TEXT PRIMARY KEY,
                company_name TEXT NOT NULL,
                industry_vertical TEXT NOT NULL,
                annual_profit_n NUMERIC NOT NULL,
                employee_count INTEGER NOT NULL
            )
        ''')
        conn.execute('''
            CREATE TABLE IF NOT EXISTS citizen_employment_history (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                citizen_id INTEGER NOT NULL,
                company_code TEXT NOT NULL,
                start_year INTEGER NOT NULL,
                end_year INTEGER NOT NULL,
                job_title TEXT NOT NULL
            )
        ''')
        conn.execute('''
            CREATE TABLE IF NOT EXISTS citizen_tax_history (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                citizen_id INTEGER NOT NULL,
                company_code TEXT NOT NULL,
                tax_year INTEGER NOT NULL,
                gross_salary_n NUMERIC NOT NULL,
                tax_code TEXT NOT NULL,
                tax_rate_percent NUMERIC NOT NULL,
                tax_paid_n NUMERIC NOT NULL
            )
        ''')
        if conn.execute('SELECT COUNT(*) FROM demo_metadata WHERE seed_version = 106').fetchone()[0] == 0:
            conn.execute('DELETE FROM citizen_tax_history')
            conn.execute('DELETE FROM citizen_employment_history')
            conn.execute('DELETE FROM citizen_health_records')
            conn.execute('DELETE FROM citizen_hospital_visits')
            conn.execute('DELETE FROM norland_companies')
            conn.execute('DELETE FROM citizen_registry')
            conn.execute("DELETE FROM sqlite_sequence WHERE name = 'citizen_registry'")
            generated_citizens = _synthetic_citizens()
            conn.executemany(
                """
                INSERT INTO citizen_registry
                (national_id, first_name, last_name, date_of_birth, sex, region,
                 municipality, address_line, postal_code, socioeconomic_group,
                 tax_paid_last_year)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                """,
                [
                    tuple(float(value) if isinstance(value, Decimal) else value for value in citizen.values())
                    for citizen in generated_citizens
                ],
            )
            conditions, visits = _synthetic_health_records(generated_citizens)
            employment, tax_history = _synthetic_employment_history(generated_citizens)
            conn.executemany(
                'INSERT INTO norland_companies (company_code, company_name, industry_vertical, annual_profit_n, employee_count) VALUES (?, ?, ?, ?, ?)',
                NORLAND_COMPANIES,
            )
            conn.executemany(
                'INSERT INTO citizen_employment_history (citizen_id, company_code, start_year, end_year, job_title) VALUES (?, ?, ?, ?, ?)',
                [(item['citizen_id'], item['company_code'], item['start_year'], item['end_year'], item['job_title']) for item in employment],
            )
            conn.executemany(
                'INSERT INTO citizen_tax_history (citizen_id, company_code, tax_year, gross_salary_n, tax_code, tax_rate_percent, tax_paid_n) VALUES (?, ?, ?, ?, ?, ?, ?)',
                [(item['citizen_id'], item['company_code'], item['tax_year'], item['gross_salary_n£'], item['tax_code'], item['tax_rate_percent'], item['tax_paid_n£']) for item in tax_history],
            )
            conn.executemany(
                'UPDATE citizen_registry SET tax_paid_last_year = ? WHERE id = ?',
                [(item['tax_paid_n£'], item['citizen_id']) for item in tax_history if item['tax_year'] == 2025],
            )
            conn.executemany(
                """
                INSERT INTO citizen_health_records
                (citizen_id, condition_name, condition_code, onset_date, is_active, severity)
                VALUES (?, ?, ?, ?, ?, ?)
                """,
                [(
                    item['citizen_id'], item['condition_name'], item['condition_code'],
                    item['onset_date'], int(item['is_active']), item['severity'],
                ) for item in conditions],
            )
            conn.executemany(
                """
                INSERT INTO citizen_hospital_visits
                (citizen_id, visit_date, visit_reason, hospital_name, discharge_date)
                VALUES (?, ?, ?, ?, ?)
                """,
                [(
                    item['citizen_id'], item['visit_date'], item['visit_reason'],
                    item['hospital_name'], item['discharge_date'],
                ) for item in visits],
            )
            conn.execute('DELETE FROM demo_metadata')
            conn.execute('INSERT INTO demo_metadata (seed_version) VALUES (106)')
            conn.commit()
        return conn
    
    if DB_USER and DB_PASSWORD:
        conn_str = _build_sql_auth_conn_str(DB_HOST, DB_NAME, DB_USER, DB_PASSWORD)
        try:
            conn = pyodbc.connect(conn_str)
            _ensure_database_ready()
            return conn
        except pyodbc.Error as e:
            error_text = str(e)
            if '4060' in error_text and DB_SA_PASSWORD:
                # Database doesn't exist, bootstrap it
                _bootstrap_demo_database(DB_HOST, DB_NAME, DB_USER, DB_PASSWORD)
                return pyodbc.connect(conn_str)
            raise
    else:
        raise RuntimeError('Database credentials not configured')


def _ensure_database_ready():
    """Apply the demo schema and deterministic seed once per app process."""
    global _database_ready
    if _database_ready or not DB_SA_PASSWORD:
        return
    with _database_ready_lock:
        if not _database_ready:
            _bootstrap_demo_database(DB_HOST, DB_NAME, DB_USER, DB_PASSWORD)
            _database_ready = True


def _citizens_for_media():
    conn = _get_db_conn()
    cursor = conn.cursor()
    cursor.execute("""
        SELECT id, national_id, first_name, last_name, date_of_birth,
               address_line, municipality, region, socioeconomic_group,
               tax_paid_last_year, sex, postal_code
        FROM citizen_registry ORDER BY id
    """)
    citizens = [{
        'id': row[0],
        'national_id': row[1],
        'first_name': row[2],
        'last_name': row[3],
        'date_of_birth': str(row[4]),
        'address_line': row[5],
        'municipality': row[6],
        'region': row[7],
        'socioeconomic_group': row[8],
        'tax_paid_last_year': float(row[9] or 0),
        'sex': row[10],
        'postal_code': row[11],
        'portrait_profile': _portrait_profile(row[1]),
    } for row in cursor.fetchall()]
    conn.close()
    return citizens


def _schedule_media_generation():
    def wait_for_database():
        for attempt in range(60):
            try:
                media_generator.ensure_started(_citizens_for_media())
                return
            except Exception as error:
                if attempt == 59:
                    logger.error(f'Could not start GPU media generation: {error}')
                    return
                time.sleep(5)

    threading.Thread(
        target=wait_for_database,
        daemon=True,
        name='citizen-media-startup',
    ).start()


# ============================================================================
# Attestation and mTLS Functions
# ============================================================================

def _validate_attestation():
    """Check Azure Attestation provider metadata availability."""
    if not ATTESTATION_ENDPOINT:
        return {'status': 'not_configured'}
    
    try:
        response = requests.get(
            f"{ATTESTATION_ENDPOINT}/.well-known/openid-configuration",
            timeout=5
        )
        if response.status_code == 200:
            logger.info("Azure Attestation provider metadata is reachable")
            return {
                'status': 'provider_reachable',
                'endpoint': ATTESTATION_ENDPOINT,
                'verification': 'metadata_only',
            }
    except Exception as e:
        logger.warning(f"Attestation check failed: {e}")
    
    return {'status': 'provider_unreachable'}


def _get_cpu_attestation_evidence():
    """Return selected claims from a successful current-boot MAA attestation."""
    try:
        with open(CPU_ATTESTATION_PATH, encoding='utf-8') as evidence_file:
            evidence = json.load(evidence_file)
        with open('/proc/sys/kernel/random/boot_id', encoding='utf-8') as boot_file:
            current_boot = evidence.get('boot_id') == boot_file.read().strip()
    except (FileNotFoundError, json.JSONDecodeError):
        return {
            'verified': False,
            'current_boot': False,
            'status': 'evidence unavailable',
            'claims': {},
        }

    claims = evidence.get('claims', {})
    token_current = claims.get('expires_at', 0) > int(time.time())
    verified = bool(evidence.get('verified')) and current_boot and token_current
    return {
        'verified': verified,
        'current_boot': current_boot,
        'token_current': token_current,
        'status': 'verified for current boot' if verified else 'stale or unverified',
        'verifier': evidence.get('verifier', 'Microsoft Azure Attestation'),
        'result': evidence.get('result', 'not reported'),
        'attested_at': evidence.get('attested_at', 'not reported'),
        'token_sha256': evidence.get('token_sha256', 'not reported'),
        'claims': claims,
    }


def _verify_mtls_certificate():
    """Verify mTLS certificate configuration"""
    if not MTLS_ENABLED:
        return {'status': 'disabled'}
    
    try:
        if os.path.exists(CERT_PATH) and os.path.exists(KEY_PATH):
            logger.info("✓ mTLS certificates found")
            return {'status': 'ready', 'cert_path': CERT_PATH}
    except Exception as e:
        logger.error(f"mTLS certificate check failed: {e}")
    
    return {'status': 'not_configured'}


def _get_cmk_evidence():
    """Read non-secret CMK metadata and its decoded SKR policy from Managed HSM."""
    if not HSM_ENDPOINT or not OS_DISK_KEY_NAME:
        return {'status': 'not_configured'}

    try:
        # Managed HSM protects key metadata on its data plane. The app identity
        # therefore needs Crypto Auditor on this key to read attributes and the
        # release policy; that role cannot release, wrap, unwrap, export, or alter it.
        credential = _get_credential()
        token = credential.get_token('https://managedhsm.azure.net/.default')
        response = requests.get(
            f"{HSM_ENDPOINT}/keys/{OS_DISK_KEY_NAME}",
            params={'api-version': '7.4'},
            headers={'Authorization': f'Bearer {token.token}'},
            timeout=5,
        )
        response.raise_for_status()
        key_document = response.json()
        key = key_document.get('key', {})
        attributes = key_document.get('attributes', {})
        release_policy = key_document.get('release_policy', {})
        encoded_policy = release_policy.get('data', '')
        decoded_policy = None
        if encoded_policy:
            padded_policy = encoded_policy + '=' * (-len(encoded_policy) % 4)
            decoded_policy = json.loads(
                base64.urlsafe_b64decode(padded_policy).decode('utf-8')
            )

        # Return only evidence needed by the UI. Do not return RSA public
        # parameters or any other fields from the complete HSM response.
        return {
            'status': 'retrieved',
            'key_url': key.get('kid'),
            'key_type': key.get('kty'),
            'key_operations': key.get('key_ops', []),
            'enabled': attributes.get('enabled'),
            'exportable': attributes.get('exportable'),
            'release_policy': decoded_policy,
            'release_policy_content_type': release_policy.get('contentType'),
        }
    except Exception as error:
        logger.warning(f"Managed HSM CMK evidence unavailable: {error}")
        return {
            'status': 'unavailable',
            'reason': type(error).__name__,
        }


# ============================================================================
# Flask Routes
# ============================================================================

def _citizen_help_context(question):
    """Return bounded records plus server-computed facts for aggregate questions."""
    query_plan = plan_question(question)
    stop_words = {
        'which', 'what', 'where', 'when', 'who', 'how', 'is', 'are', 'the',
        'a', 'an', 'in', 'on', 'for', 'of', 'to', 'and', 'or', 'did', 'does',
        'she', 'he', 'they', 'them', 'much', 'that', 'pay',
        'registered',
        'citizen', 'citizens', 'region', 'state', 'town', 'address',
        'postal', 'code', 'status', 'employment', 'employed', 'voter',
        'voting', 'tax', 'bracket', 'rate', 'fictional', 'norland', 'company',
        'work', 'worked', 'working', 'salary', 'salaries', 'paid', 'payment',
        'payments', 'year', 'years',
    }
    terms = [
        term for term in re.findall(r'[A-Za-z0-9-]{2,}', question.lower())
        if term not in stop_words and not (term.isdigit() and len(term) == 4)
    ][:6]
    conn = _get_db_conn()
    cursor = conn.cursor()
    query_result = execute_query_plan(cursor, question)
    cursor.execute("""
        SELECT municipality, region, tax_paid_last_year, date_of_birth
        FROM citizen_registry
    """)
    summary_rows = cursor.fetchall()
    total_tax = sum((Decimal(row[2] or 0) for row in summary_rows), Decimal('0'))
    total_count = len(summary_rows)
    today = datetime.now(timezone.utc).date()
    ages = []
    for row in summary_rows:
        birth_date = row[3]
        if isinstance(birth_date, str):
            birth_date = datetime.fromisoformat(birth_date).date()
        ages.append(today.year - birth_date.year - ((today.month, today.day) < (birth_date.month, birth_date.day)))
    average_tax = total_tax / total_count if total_count else Decimal('0')
    town_counts = Counter(row[0] for row in summary_rows)
    region_counts = Counter(row[1] for row in summary_rows)
    cursor.execute("""
        SELECT tax_year, AVG(gross_salary_n), AVG(tax_paid_n), SUM(tax_paid_n), COUNT(*)
        FROM citizen_tax_history
        GROUP BY tax_year
        ORDER BY tax_year
    """)
    salary_rows = cursor.fetchall()
    latest_salary = next((row for row in reversed(salary_rows) if row[0] == 2025), None)
    tax_code_counts = Counter()
    cursor.execute("SELECT tax_code, COUNT(*) FROM citizen_tax_history GROUP BY tax_code ORDER BY tax_code")
    tax_code_counts.update({row[0]: int(row[1]) for row in cursor.fetchall()})
    cursor.execute("""
        SELECT c.sex, COUNT(*), SUM(lifetime.total_tax), AVG(lifetime.total_tax)
        FROM citizen_registry c
        JOIN (
            SELECT citizen_id, SUM(tax_paid_n) AS total_tax
            FROM citizen_tax_history
            GROUP BY citizen_id
        ) lifetime ON lifetime.citizen_id = c.id
        GROUP BY c.sex
        ORDER BY c.sex
    """)
    gender_tax_rows = cursor.fetchall()
    cursor.execute("""
        SELECT c.company_code, c.company_name, c.industry_vertical,
               c.annual_profit_n, c.employee_count, COUNT(DISTINCT h.citizen_id)
        FROM norland_companies c
        LEFT JOIN citizen_employment_history h ON h.company_code = c.company_code
        GROUP BY c.company_code, c.company_name, c.industry_vertical,
                 c.annual_profit_n, c.employee_count
        ORDER BY COUNT(DISTINCT h.citizen_id) DESC, c.company_name
    """)
    company_rows = cursor.fetchall()
    cursor.execute("""
        SELECT condition_code, condition_name, COUNT(DISTINCT citizen_id)
        FROM citizen_health_records
        WHERE is_active = 1
        GROUP BY condition_code, condition_name
        ORDER BY condition_name
    """)
    health_condition_rows = cursor.fetchall()
    cursor.execute("""
        SELECT c.company_code, c.company_name, c.industry_vertical,
               c.annual_profit_n, c.employee_count, COUNT(DISTINCT h.citizen_id)
        FROM norland_companies c
        LEFT JOIN citizen_employment_history h
          ON h.company_code = c.company_code AND h.end_year = 2025
        GROUP BY c.company_code, c.company_name, c.industry_vertical,
                 c.annual_profit_n, c.employee_count
        ORDER BY COUNT(DISTINCT h.citizen_id) DESC, c.company_name
    """)
    current_company_rows = cursor.fetchall()
    cursor.execute("""
           SELECT CASE
                  WHEN DATEDIFF(YEAR, c.date_of_birth, GETUTCDATE()) -
                      CASE WHEN DATEADD(YEAR, DATEDIFF(YEAR, c.date_of_birth, GETUTCDATE()), c.date_of_birth) > GETUTCDATE() THEN 1 ELSE 0 END BETWEEN 20 AND 29 THEN '20s'
                  WHEN DATEDIFF(YEAR, c.date_of_birth, GETUTCDATE()) -
                      CASE WHEN DATEADD(YEAR, DATEDIFF(YEAR, c.date_of_birth, GETUTCDATE()), c.date_of_birth) > GETUTCDATE() THEN 1 ELSE 0 END BETWEEN 30 AND 39 THEN '30s'
                  WHEN DATEDIFF(YEAR, c.date_of_birth, GETUTCDATE()) -
                      CASE WHEN DATEADD(YEAR, DATEDIFF(YEAR, c.date_of_birth, GETUTCDATE()), c.date_of_birth) > GETUTCDATE() THEN 1 ELSE 0 END BETWEEN 40 AND 49 THEN '40s'
                  WHEN DATEDIFF(YEAR, c.date_of_birth, GETUTCDATE()) -
                      CASE WHEN DATEADD(YEAR, DATEDIFF(YEAR, c.date_of_birth, GETUTCDATE()), c.date_of_birth) > GETUTCDATE() THEN 1 ELSE 0 END BETWEEN 50 AND 59 THEN '50s'
                END AS age_band,
                c.sex, AVG(t.gross_salary_n), COUNT(DISTINCT c.id)
           FROM citizen_registry c
           JOIN citizen_tax_history t ON t.citizen_id = c.id AND t.tax_year = 2025
           GROUP BY CASE
                  WHEN DATEDIFF(YEAR, c.date_of_birth, GETUTCDATE()) - CASE WHEN DATEADD(YEAR, DATEDIFF(YEAR, c.date_of_birth, GETUTCDATE()), c.date_of_birth) > GETUTCDATE() THEN 1 ELSE 0 END BETWEEN 20 AND 29 THEN '20s'
                  WHEN DATEDIFF(YEAR, c.date_of_birth, GETUTCDATE()) - CASE WHEN DATEADD(YEAR, DATEDIFF(YEAR, c.date_of_birth, GETUTCDATE()), c.date_of_birth) > GETUTCDATE() THEN 1 ELSE 0 END BETWEEN 30 AND 39 THEN '30s'
                  WHEN DATEDIFF(YEAR, c.date_of_birth, GETUTCDATE()) - CASE WHEN DATEADD(YEAR, DATEDIFF(YEAR, c.date_of_birth, GETUTCDATE()), c.date_of_birth) > GETUTCDATE() THEN 1 ELSE 0 END BETWEEN 40 AND 49 THEN '40s'
                  WHEN DATEDIFF(YEAR, c.date_of_birth, GETUTCDATE()) - CASE WHEN DATEADD(YEAR, DATEDIFF(YEAR, c.date_of_birth, GETUTCDATE()), c.date_of_birth) > GETUTCDATE() THEN 1 ELSE 0 END BETWEEN 50 AND 59 THEN '50s'
                END, c.sex
           ORDER BY age_band, c.sex
    """)
    salary_age_gender_rows = cursor.fetchall()
    analytics = {
        'query_plan': query_plan,
        'query_result': query_result,
        'query_schema': DATASET_SCHEMA,
        'retrieval_boundary': 'SQL executes inside the confidential application/database boundary; the H100 receives serialized results only.',
        'total_citizens': int(total_count),
        'average_age_years': round(sum(ages) / len(ages), 2) if ages else 0,
        'age_reference_date': today.isoformat(),
        'total_tax_revenue_n£': round(float(total_tax), 2),
        'average_tax_paid_n£': round(float(average_tax), 2),
        'historical_tax_years': [
            {
                'year': int(row[0]),
                'average_salary_n£': round(float(row[1]), 2),
                'average_tax_paid_n£': round(float(row[2]), 2),
                'total_tax_paid_n£': round(float(row[3]), 2),
                'citizens': int(row[4]),
            }
            for row in salary_rows
        ],
        'average_salary_2025_n£': round(float(latest_salary[1]), 2) if latest_salary else 0,
        'average_tax_paid_2025_n£': round(float(latest_salary[2]), 2) if latest_salary else 0,
        'total_tax_paid_all_historical_years_n£': round(sum(float(row[3]) for row in salary_rows), 2),
        'lifetime_tax_by_gender': [
            {
                'gender': row[0],
                'citizens': int(row[1]),
                'total_tax_paid_n£': round(float(row[2]), 2),
                'average_lifetime_tax_paid_n£': round(float(row[3]), 2),
            }
            for row in gender_tax_rows
        ],
        'companies_by_historical_citizen_count': [
            {
                'company_code': row[0],
                'company_name': row[1],
                'industry_vertical': row[2],
                'annual_profit_n£': round(float(row[3]), 2),
                'employee_count': int(row[4]),
                'citizens_with_historical_employment': int(row[5]),
            }
            for row in company_rows
        ],
        'companies_by_current_citizen_count_2025': [
            {
                'company_code': row[0],
                'company_name': row[1],
                'industry_vertical': row[2],
                'annual_profit_n£': round(float(row[3]), 2),
                'employee_count': int(row[4]),
                'current_citizens_2025': int(row[5]),
            }
            for row in current_company_rows
        ],
        'health_conditions_by_citizen_count': [
            {'condition_code': row[0], 'condition_name': row[1], 'citizens': int(row[2])}
            for row in health_condition_rows
        ],
        'average_salary_by_age_band_and_gender_2025': [
            {
                'age_band': row[0], 'gender': row[1],
                'average_salary_n£': round(float(row[2]), 2), 'citizens': int(row[3]),
            }
            for row in salary_age_gender_rows if row[0] is not None
        ],
        'fictional_tax_code_rules': NORLAND_TAX_CODE,
        'citizens_by_tax_code': [
            {'code': code, 'citizens': count}
            for code, count in sorted(tax_code_counts.items())
        ],
        'most_populous_towns': [
            {'town': town, 'citizens': count}
            for town, count in sorted(town_counts.items(), key=lambda item: (-item[1], item[0]))[:5]
        ],
        'citizens_by_region': [
            {'region': region, 'citizens': count}
            for region, count in sorted(region_counts.items(), key=lambda item: (-item[1], item[0]))
        ],
    }
    question_lower = question.lower()
    year_match = re.search(r'\b(20\d{2})\b', question_lower)
    if 'tax' in question_lower and any(word in question_lower for word in ('increase', 'increased', 'change', 'difference')) and year_match:
        requested_year = int(year_match.group(1))
        yearly = {int(row[0]): row for row in salary_rows}
        current = yearly.get(requested_year)
        previous = yearly.get(requested_year - 1)
        if current and previous:
            analytics['tax_year_comparison'] = {
                'year': requested_year,
                'previous_year': requested_year - 1,
                'total_tax_paid_n£': round(float(current[3]), 2),
                'previous_total_tax_paid_n£': round(float(previous[3]), 2),
                'total_increase_n£': round(float(current[3] - previous[3]), 2),
                'average_tax_paid_n£': round(float(current[2]), 2),
                'previous_average_tax_paid_n£': round(float(previous[2]), 2),
                'average_increase_n£': round(float(current[2] - previous[2]), 2),
            }
            analytics['answer_hint'] = (
                f"Across all citizens, total fictional tax paid increased by "
                f"N£{float(current[3] - previous[3]):,.2f} from {requested_year - 1} "
                f"to {requested_year}; average tax paid increased by "
                f"N£{float(current[2] - previous[2]):,.2f} per citizen."
            )
    if 'tax' in question_lower and any(word in question_lower for word in ('total', 'revenue', 'sum')):
        analytics['answer_hint'] = (
            f"Total tax revenue across all {total_count} fictional citizens is "
            f"N£{float(total_tax):,.2f}."
        )
    elif 'salary' in question_lower and any(word in question_lower for word in ('average', 'mean')):
        analytics['answer_hint'] = (
            f"The average fictional gross salary in 2025 was "
            f"N£{analytics['average_salary_2025_n£']:,.2f} across {total_count} citizens."
        )
    elif 'salary' in question_lower and 'gender' in question_lower and any(word in question_lower for word in ('age', 'band', '20', '30', '40', '50')):
        analytics['answer_hint'] = 'Average 2025 fictional salary by age band and gender: ' + '; '.join(
            f"{item['age_band']} {item['gender']}: N£{item['average_salary_n£']:,.2f} across {item['citizens']} citizens"
            for item in analytics['average_salary_by_age_band_and_gender_2025']
        ) + '.'
    elif 'age' in question_lower and any(word in question_lower for word in ('average', 'mean', 'calculate')):
        analytics['answer_hint'] = (
            f"The average age is {analytics['average_age_years']:.2f} years, calculated from "
            f"all {total_count} stored dates of birth as of {analytics['age_reference_date']}."
        )
    elif 'tax' in question_lower and 'gender' in question_lower and any(word in question_lower for word in ('lifetime', 'total', 'average')):
        analytics['answer_hint'] = (
            'Average lifetime fictional tax paid by gender: ' + '; '.join(
                f"{item['gender']}: N£{item['average_lifetime_tax_paid_n£']:,.2f} across {item['citizens']} citizens"
                for item in analytics['lifetime_tax_by_gender']
            ) + '.'
        )
    elif any(word in question_lower for word in ('company', 'companies', 'industry', 'employer')):
        analytics['answer_hint'] = 'Top fictional companies by current 2025 citizen employment: ' + '; '.join(
            f"{item['company_name']} ({item['industry_vertical']}): {item['current_citizens_2025']} citizens"
            for item in analytics['companies_by_current_citizen_count_2025'][:5]
        ) + '.'
    elif any(word in question_lower for word in ('health', 'condition', 'conditions')):
        analytics['answer_hint'] = 'Fictional active health conditions by citizen count: ' + '; '.join(
            f"{item['condition_name']}: {item['citizens']} citizens"
            for item in analytics['health_conditions_by_citizen_count']
        ) + '.'
    elif any(word in question_lower for word in ('populous', 'population', 'largest')):
        top_town = sorted(town_counts.items(), key=lambda item: (-item[1], item[0]))[0]
        analytics['answer_hint'] = (
            f"The most populous town is {top_town[0]}, with {top_town[1]} fictional citizens."
        )
    if not terms:
        conn.close()
        return [], analytics
    clauses = []
    values = []
    for term in terms:
        like = f'%{term}%'
        clauses.append(
            '(LOWER(first_name) LIKE ? OR LOWER(last_name) LIKE ? '
            'OR LOWER(national_id) LIKE ? OR LOWER(region) LIKE ? '
            'OR LOWER(municipality) LIKE ?)'
        )
        values.extend([like, like, like, like, like])
    cursor.execute(f"""
         SELECT id, national_id, first_name, last_name, date_of_birth, sex,
             region, municipality, address_line, postal_code, household_size,
             marital_status, employment_status, tax_bracket, registered_voter,
             socioeconomic_group, tax_paid_last_year, created_date, modified_date
        FROM citizen_registry
        WHERE {' AND '.join(clauses)}
        ORDER BY last_name, first_name
    """, values)
    rows = cursor.fetchall()[:MAX_RECORDS]
    records = [
        {
            'id': row[0],
            'national_id': row[1],
            'first_name': row[2],
            'last_name': row[3],
            'date_of_birth': str(row[4]),
            'sex': row[5],
            'region': row[6],
            'municipality': row[7],
            'address_line': row[8],
            'postal_code': row[9],
            'household_size': row[10],
            'marital_status': row[11],
            'employment_status': row[12],
            'tax_bracket': row[13],
            'registered_voter': bool(row[14]),
            'socioeconomic_group': row[15],
            'tax_paid_last_year': float(row[16] or 0),
            'tax_status': _tax_status(row[16]),
            'created_date': str(row[17]) if row[17] is not None else None,
            'modified_date': str(row[18]) if row[18] is not None else None,
        }
        for row in rows
    ]
    for record in records:
        cursor.execute('''
            SELECT h.company_code, c.company_name, c.industry_vertical,
                   h.start_year, h.end_year, h.job_title
            FROM citizen_employment_history h
            JOIN norland_companies c ON c.company_code = h.company_code
            WHERE h.citizen_id = ? ORDER BY h.start_year
        ''', (record['id'],))
        record['employment_history'] = [{
            'company_code': row[0], 'company_name': row[1], 'industry_vertical': row[2],
            'start_year': row[3], 'end_year': row[4], 'job_title': row[5],
        } for row in cursor.fetchall()]
        cursor.execute('''
            SELECT t.tax_year, t.company_code, c.company_name, t.gross_salary_n,
                   t.tax_code, t.tax_rate_percent, t.tax_paid_n
            FROM citizen_tax_history t
            JOIN norland_companies c ON c.company_code = t.company_code
            WHERE t.citizen_id = ? ORDER BY t.tax_year
        ''', (record['id'],))
        record['tax_history'] = [{
            'tax_year': row[0], 'company_code': row[1], 'company_name': row[2],
            'gross_salary_n£': float(row[3]), 'tax_code': row[4],
            'tax_rate_percent': float(row[5]), 'tax_paid_n£': float(row[6]),
        } for row in cursor.fetchall()]
    conn.close()
    return records, analytics

@app.route('/health', methods=['GET'])
def health():
    """Health check endpoint"""
    try:
        # Check database connectivity
        conn = _get_db_conn()
        cursor = conn.cursor()
        cursor.execute("SELECT 1")
        conn.close()
        db_status = "healthy"
    except Exception as e:
        logger.error(f"Database health check failed: {e}")
        db_status = "unhealthy"
    
    attestation = _validate_attestation()
    mtls = _verify_mtls_certificate()
    
    return jsonify({
        'status': 'healthy',
        'timestamp': datetime.utcnow().isoformat(),
        'components': {
            'database': db_status,
            'attestation': attestation,
            'mtls': mtls
        }
    })


@app.route('/db/status', methods=['GET'])
def db_status():
    """Database status endpoint"""
    try:
        conn = _get_db_conn()
        cursor = conn.cursor()
        cursor.execute("SELECT COUNT(*) FROM citizen_registry")
        count = cursor.fetchone()[0]
        conn.close()
        
        return jsonify({
            'status': 'connected',
            'database': DB_NAME,
            'record_count': count,
            'timestamp': datetime.utcnow().isoformat()
        })
    except Exception as e:
        logger.error(f"Database status check failed: {e}")
        return jsonify({'status': 'error', 'message': str(e)}), 500


@app.route('/', methods=['GET'])
def index():
    """Redirect the server root to the primary application."""
    response = redirect(url_for('citizens'))
    response.autocorrect_location_header = False
    return response


@app.route('/citizens', methods=['GET'])
def citizens():
    """Main citizen registry page"""
    try:
        citizens = _citizens_for_media()
        media_generator.ensure_started(citizens)
        
        return render_template('index.html', citizens=citizens, mtls_enabled=MTLS_ENABLED, current_page='citizens')
    except Exception as e:
        logger.error(f"Error loading citizen list: {e}")
        return jsonify({'status': 'error', 'message': str(e)}), 500


DATA_EXPLORER_TABLES = (
    'citizen_registry', 'citizen_health_records', 'citizen_hospital_visits',
    'norland_companies', 'citizen_employment_history', 'citizen_tax_history',
    'demo_metadata',
)


def _data_explorer_schema():
    conn = _get_db_conn()
    cursor = conn.cursor()
    tables = []
    for table_name in DATA_EXPLORER_TABLES:
        if DB_HOST:
            cursor.execute('''
                SELECT COLUMN_NAME, DATA_TYPE, IS_NULLABLE
                FROM INFORMATION_SCHEMA.COLUMNS
                WHERE TABLE_SCHEMA = 'dbo' AND TABLE_NAME = ?
                ORDER BY ORDINAL_POSITION
            ''', (table_name,))
            columns = [
                {'name': row[0], 'type': row[1], 'nullable': row[2] == 'YES'}
                for row in cursor.fetchall()
            ]
        else:
            columns = [
                {'name': row[1], 'type': row[2], 'nullable': not row[3]}
                for row in cursor.execute(f'PRAGMA table_info({table_name})').fetchall()
            ]
        cursor.execute(f'SELECT COUNT(*) FROM {table_name}')
        tables.append({'name': table_name, 'row_count': int(cursor.fetchone()[0]), 'columns': columns})
    conn.close()
    return tables


@app.route('/data-explorer', methods=['GET'])
def data_explorer():
    """Render the read-only SQL database explorer."""
    return render_template('data_explorer.html', current_page='data_explorer')


@app.route('/api/data-explorer/schema', methods=['GET'])
def data_explorer_schema():
    """Return the allowlisted fictional database tree and column metadata."""
    try:
        return jsonify({'database': DB_NAME, 'read_only': True, 'fictional_only': True, 'tables': _data_explorer_schema()})
    except Exception as error:
        logger.error('Data Explorer schema failed: %s', type(error).__name__)
        return jsonify({'error': 'Database schema is unavailable.'}), 503


@app.route('/api/data-explorer/table/<table_name>', methods=['GET'])
def data_explorer_table(table_name):
    """Return a bounded preview from one allowlisted SQL table."""
    if table_name not in DATA_EXPLORER_TABLES:
        return jsonify({'error': 'Table is not available in the read-only explorer.'}), 404
    try:
        limit = min(max(request.args.get('limit', 25, type=int), 1), 100)
        conn = _get_db_conn()
        cursor = conn.cursor()
        cursor.execute(f'SELECT TOP {limit} * FROM {table_name}' if DB_HOST else f'SELECT * FROM {table_name} LIMIT {limit}')
        columns = [description[0] for description in cursor.description]
        def json_value(value):
            if isinstance(value, Decimal):
                return float(value)
            return value.isoformat() if hasattr(value, 'isoformat') else value
        rows = [
            {column: json_value(value) for column, value in zip(columns, row)}
            for row in cursor.fetchall()
        ]
        cursor.execute(f'SELECT COUNT(*) FROM {table_name}')
        row_count = int(cursor.fetchone()[0])
        conn.close()
        return jsonify({'database': DB_NAME, 'table': table_name, 'row_count': row_count, 'columns': columns, 'rows': rows, 'read_only': True, 'fictional_only': True})
    except Exception as error:
        logger.error('Data Explorer table failed: %s', type(error).__name__)
        return jsonify({'error': 'Table preview is unavailable.'}), 503


@app.route('/cctv', methods=['GET'])
def cctv():
    """Render the confidential CCTV application."""
    return render_template('cctv.html', current_page='cctv')


@app.route('/citizenhelp', methods=['GET'])
def citizen_help():
    """Render the GPU-only Norland Citizen Help experience."""
    return render_template('citizenhelp.html', current_page='citizen_help')


@app.route('/api/citizenhelp/model', methods=['GET'])
def citizen_help_model():
    """Return non-secret metadata for the active local open model."""
    return jsonify(model_metadata('cuda:0'))


@app.route('/api/citizenhelp', methods=['POST'])
def citizen_help_chat():
    """Retrieve bounded synthetic citizen context and call the localhost GPU service."""
    try:
        payload = request.get_json(silent=True) or {}
        question = validate_question(payload.get('question'))
        records, analytics = _citizen_help_context(question)
        try:
            planner_response = requests.post(
                'http://127.0.0.1:8010/plan',
                json={'question': question},
                timeout=90,
            )
            planner_response.raise_for_status()
            proposed_plan = planner_response.json().get('query_plan')
            valid, reason = validate_query_plan(proposed_plan)
            if valid:
                plan_conn = _get_db_conn()
                try:
                    analytics['llm_query_result'] = execute_validated_plan(
                        plan_conn, proposed_plan, {}, sql_server=bool(DB_HOST)
                    )
                finally:
                    plan_conn.close()
            else:
                analytics['llm_query_rejected'] = reason
                logger.info('H100 query plan rejected by CVM validator: %s', reason)
        except Exception as planner_error:
            logger.warning('Structured H100 query planning fell back: %s', type(planner_error).__name__)
            analytics['llm_query_fallback'] = True
        response = requests.post(
            'http://127.0.0.1:8010/generate',
            json={'question': question, 'records': records, 'analytics': analytics},
            timeout=90,
        )
        response.raise_for_status()
        result = response.json()
        result['matches'] = [
            {'id': record['id'], 'name': f"{record['first_name']} {record['last_name']}"}
            for record in records
        ]
        return jsonify(result)
    except PermissionError as error:
        return jsonify({'answer': str(error), 'blocked': True}), 200
    except ValueError as error:
        return jsonify({'error': str(error)}), 400
    except requests.RequestException:
        return jsonify({'error': 'Citizen Help GPU service is not ready.'}), 503
    except Exception as error:
        logger.error('Citizen Help request failed: %s', type(error).__name__)
        return jsonify({'error': 'Citizen Help could not complete the request.'}), 503


@app.route('/api/citizenhelp/query-plan', methods=['POST'])
def citizen_help_query_plan():
    """Validate and execute a structured read-only plan inside the application CVM."""
    try:
        payload = request.get_json(silent=True) or {}
        plan = payload.get('query_plan')
        parameters = payload.get('parameters') or {}
        valid, reason = validate_query_plan(plan)
        if not valid:
            return jsonify({'status': 'rejected', 'read_only': True, 'reason': reason}), 400
        conn = _get_db_conn()
        try:
            result = execute_validated_plan(conn, plan, parameters, sql_server=bool(DB_HOST))
        finally:
            conn.close()
        return jsonify({'status': 'ok', 'query_plan_validated': True, 'query_result': result})
    except ValueError as error:
        return jsonify({'status': 'rejected', 'read_only': True, 'reason': str(error)}), 400
    except Exception as error:
        logger.error('Structured query execution failed: %s', type(error).__name__)
        return jsonify({'status': 'error', 'read_only': True, 'reason': 'Query execution failed.'}), 503


@app.route('/api/citizen/<int:citizen_id>/history', methods=['GET'])
def citizen_history(citizen_id):
    """Return read-only fictional employment and annual tax history."""
    try:
        conn = _get_db_conn()
        cursor = conn.cursor()
        cursor.execute('SELECT id, first_name, last_name FROM citizen_registry WHERE id = ?', (citizen_id,))
        citizen = cursor.fetchone()
        if not citizen:
            conn.close()
            return jsonify({'error': 'Citizen not found'}), 404
        cursor.execute('''
            SELECT h.company_code, c.company_name, c.industry_vertical,
                   c.annual_profit_n, c.employee_count, h.start_year, h.end_year, h.job_title
            FROM citizen_employment_history h
            JOIN norland_companies c ON c.company_code = h.company_code
            WHERE h.citizen_id = ? ORDER BY h.start_year
        ''', (citizen_id,))
        employment = [{
            'company_code': row[0], 'company_name': row[1], 'industry_vertical': row[2],
            'annual_profit_n£': float(row[3]), 'employee_count': row[4],
            'start_year': row[5], 'end_year': row[6], 'job_title': row[7],
        } for row in cursor.fetchall()]
        cursor.execute('''
            SELECT t.tax_year, t.company_code, c.company_name, t.gross_salary_n,
                   t.tax_code, t.tax_rate_percent, t.tax_paid_n
            FROM citizen_tax_history t
            JOIN norland_companies c ON c.company_code = t.company_code
            WHERE t.citizen_id = ? ORDER BY t.tax_year
        ''', (citizen_id,))
        taxes = [{
            'tax_year': row[0], 'company_code': row[1], 'company_name': row[2],
            'gross_salary_n£': float(row[3]), 'tax_code': row[4],
            'tax_rate_percent': float(row[5]), 'tax_paid_n£': float(row[6]),
        } for row in cursor.fetchall()]
        conn.close()
        return jsonify({
            'citizen_id': citizen[0],
            'citizen_name': f'{citizen[1]} {citizen[2]}',
            'fictional_only': True,
            'read_only': True,
            'tax_policy': NORLAND_TAX_CODE,
            'employment_history': employment,
            'tax_history': taxes,
        })
    except Exception as error:
        logger.error('Citizen history retrieval failed: %s', type(error).__name__)
        return jsonify({'error': 'Citizen history is unavailable.'}), 503


@app.route('/cctv/status', methods=['GET'])
def cctv_status():
    """Return non-sensitive anonymizer health and confidential GPU evidence."""
    try:
        status = json.loads(CCTV_STATUS_PATH.read_text(encoding='utf-8'))
        updated_at = datetime.fromisoformat(status['updated_at'].replace('Z', '+00:00'))
        stale = (datetime.now(timezone.utc) - updated_at).total_seconds() > 15
    except (FileNotFoundError, KeyError, ValueError, json.JSONDecodeError):
        return jsonify({
            'state': 'unavailable',
            'message': 'The anonymized stream is not ready.',
        }), 503

    completed = status.get('state') == 'completed'
    if ((stale and not completed) or status.get('state') == 'failed'
            or not CCTV_PLAYLIST_PATH.is_file()):
        return jsonify({
            'state': 'unavailable',
            'message': 'The anonymized stream is not available.',
            'updated_at': status.get('updated_at'),
        }), 503

    public_fields = (
        'state', 'message', 'updated_at', 'frames_processed', 'current_faces',
        'faces_detected', 'processing_fps', 'frames_behind', 'lag_scale_frames',
        'output', 'detector',
        'confidence_threshold', 'confidential_gpu',
    )
    return jsonify({key: status[key] for key in public_fields if key in status})


@app.route('/cctv/technical-details', methods=['GET'])
def cctv_technical_details():
    """Describe the private DVR source and at-rest encryption without secrets."""
    if not CCTV_VIDEO_BLOB_URI or not DVR_STORAGE_KEY_NAME:
        return jsonify({'status': 'not_configured'}), 503
    return jsonify({
        'status': 'configured',
        'video_source': {
            'architecture': 'CCTV camera to private DVR Blob Storage to confidential analyzer',
            'blob_uri': CCTV_VIDEO_BLOB_URI,
            'storage_account': DVR_STORAGE_ACCOUNT,
            'container': DVR_STORAGE_CONTAINER,
            'authentication': 'Microsoft Entra managed identity',
            'network_access': 'Blob Private Link only; public network access disabled',
            'analyzer_cache': CCTV_VIDEO_PATH,
        },
        'at_rest_encryption': {
            'model': 'Azure Storage service encryption with customer-managed key',
            'key_store': 'Azure Managed HSM',
            'key_name': DVR_STORAGE_KEY_NAME,
            'key_version': DVR_STORAGE_KEY_VERSION,
            'key_uri': f'{HSM_ENDPOINT}/keys/{DVR_STORAGE_KEY_NAME}/{DVR_STORAGE_KEY_VERSION}',
            'key_type': 'RSA-HSM 3072',
            'key_operations': ['wrapKey', 'unwrapKey'],
            'exportable': False,
            'data_key_note': 'The HSM key wraps the Storage account encryption key; it is not exposed to the app.',
        },
    })


@app.route('/cctv/video', methods=['GET'])
def cctv_video():
    """Stream the bundled CCTV source footage with browser range support."""
    if not os.path.isfile(CCTV_VIDEO_PATH):
        return jsonify({'error': 'CCTV source video is unavailable'}), 404
    return send_file(
        CCTV_VIDEO_PATH,
        mimetype='video/mp4',
        conditional=True,
        max_age=3600,
    )


@app.route('/media/status', methods=['GET'])
def media_status():
    """Return CUDA portrait-generation progress without exposing citizen data."""
    return jsonify(media_generator.status())


@app.route('/media/portrait/<int:citizen_id>', methods=['GET'])
def citizen_portrait(citizen_id):
    """Return a completed fictional citizen portrait."""
    path = media_generator.portrait_path(citizen_id)
    if not path.is_file():
        return jsonify({'error': 'Portrait is not ready'}), 404
    return send_file(path, mimetype='image/jpeg', conditional=True, max_age=86400)


@app.route('/media/credential/<int:citizen_id>', methods=['GET'])
def citizen_credential(citizen_id):
    """Return a completed, visibly fictional Norland credential."""
    path = media_generator.credential_path(citizen_id)
    if not path.is_file():
        return jsonify({'error': 'Credential is not ready'}), 404
    return send_file(path, mimetype='image/jpeg', conditional=True, max_age=86400)


@app.route('/api/citizens', methods=['GET'])
def get_citizens():
    """Get all citizens (API endpoint)"""
    try:
        conn = _get_db_conn()
        cursor = conn.cursor()
        cursor.execute("""
            SELECT id, national_id, first_name, last_name, date_of_birth, 
                     address_line, municipality, region, socioeconomic_group,
                     tax_paid_last_year, sex, postal_code
            FROM citizen_registry
            ORDER BY id
        """)
        
        citizens = []
        for row in cursor.fetchall():
            citizens.append({
                'id': row[0],
                'national_id': row[1],
                'first_name': row[2],
                'last_name': row[3],
                'date_of_birth': str(row[4]),
                'address_line': row[5],
                'municipality': row[6],
                'region': row[7],
                'socioeconomic_group': row[8],
                'tax_paid_last_year': float(row[9] or 0),
                'sex': row[10],
                'postal_code': row[11],
            })
        conn.close()
        
        return jsonify({'citizens': citizens})
    except Exception as e:
        logger.error(f"Error retrieving citizens: {e}")
        return jsonify({'error': str(e)}), 500


@app.route('/api/citizens/health/status', methods=['GET'])
def health_status():
    """Return compact health counts for all fictional citizens."""
    try:
        conn = _get_db_conn()
        cursor = conn.cursor()
        cursor.execute("""
            SELECT citizen_id, COUNT(*)
            FROM citizen_health_records
            WHERE is_active = 1
            GROUP BY citizen_id
        """)
        status = {str(row[0]): int(row[1]) for row in cursor.fetchall()}
        conn.close()
        return jsonify({'status': status})
    except Exception as error:
        logger.error('Health status retrieval failed: %s', type(error).__name__)
        return jsonify({'error': 'Health status is unavailable.'}), 503


@app.route('/api/citizen/<int:citizen_id>/health', methods=['GET'])
def citizen_health(citizen_id):
    """Return read-only fictional health details for one citizen."""
    try:
        conn = _get_db_conn()
        cursor = conn.cursor()
        cursor.execute("""
            SELECT condition_name, condition_code, onset_date, is_active, severity
            FROM citizen_health_records
            WHERE citizen_id = ?
            ORDER BY onset_date DESC
        """, (citizen_id,))
        conditions = [{
            'condition_name': row[0], 'condition_code': row[1],
            'onset_date': str(row[2]), 'is_active': bool(row[3]), 'severity': row[4],
        } for row in cursor.fetchall()]
        cursor.execute("""
            SELECT visit_date, visit_reason, hospital_name, discharge_date
            FROM citizen_hospital_visits
            WHERE citizen_id = ?
            ORDER BY visit_date DESC
        """, (citizen_id,))
        visits = [{
            'visit_date': str(row[0]), 'visit_reason': row[1],
            'hospital_name': row[2],
            'discharge_date': str(row[3]) if row[3] else None,
        } for row in cursor.fetchall()]
        conn.close()
        return jsonify({
            'citizen_id': citizen_id,
            'fictional_only': True,
            'medical_advice': False,
            'conditions': conditions,
            'hospital_visits': visits,
        })
    except Exception as error:
        logger.error('Citizen health retrieval failed: %s', type(error).__name__)
        return jsonify({'error': 'Health details are unavailable.'}), 503


@app.route('/api/citizens/health/conditions', methods=['GET'])
def health_conditions():
    """Return condition counts for fictional registry analytics."""
    try:
        conn = _get_db_conn()
        cursor = conn.cursor()
        cursor.execute("""
            SELECT condition_name, condition_code, COUNT(*)
            FROM citizen_health_records
            WHERE is_active = 1
            GROUP BY condition_name, condition_code
            ORDER BY condition_name
        """)
        conditions = [
            {'condition_name': row[0], 'condition_code': row[1], 'citizens': int(row[2])}
            for row in cursor.fetchall()
        ]
        conn.close()
        return jsonify({'fictional_only': True, 'conditions': conditions})
    except Exception as error:
        logger.error('Condition summary retrieval failed: %s', type(error).__name__)
        return jsonify({'error': 'Condition summary is unavailable.'}), 503


@app.route('/api/citizens/health/summary', methods=['GET'])
def health_summary():
    """Return aggregate fictional health-record counts."""
    try:
        conn = _get_db_conn()
        cursor = conn.cursor()
        cursor.execute("SELECT COUNT(DISTINCT citizen_id) FROM citizen_health_records WHERE is_active = 1")
        citizens_with_conditions = int(cursor.fetchone()[0])
        cursor.execute("SELECT COUNT(*) FROM citizen_hospital_visits")
        hospital_visits = int(cursor.fetchone()[0])
        conn.close()
        return jsonify({
            'fictional_only': True,
            'medical_advice': False,
            'citizens_with_active_conditions': citizens_with_conditions,
            'hospital_visits': hospital_visits,
        })
    except Exception as error:
        logger.error('Health summary retrieval failed: %s', type(error).__name__)
        return jsonify({'error': 'Health summary is unavailable.'}), 503


@app.route('/api/citizen/<int:citizen_id>', methods=['GET'])
def get_citizen(citizen_id):
    """Get specific citizen details"""
    try:
        conn = _get_db_conn()
        cursor = conn.cursor()
        cursor.execute("""
            SELECT id, national_id, first_name, last_name, date_of_birth, sex,
                   region, municipality, address_line, postal_code,
                   socioeconomic_group, tax_paid_last_year
            FROM citizen_registry WHERE id = ?
        """, (citizen_id,))
        row = cursor.fetchone()
        conn.close()
        
        if not row:
            return jsonify({'error': 'Citizen not found'}), 404
        
        return jsonify({
            'id': row[0],
            'national_id': row[1],
            'first_name': row[2],
            'last_name': row[3],
            'date_of_birth': str(row[4]),
            'sex': row[5],
            'region': row[6],
            'municipality': row[7],
            'address_line': row[8],
            'postal_code': row[9],
            'socioeconomic_group': row[10],
            'tax_paid_last_year': float(row[11] or 0),
        })
    except Exception as e:
        logger.error(f"Error retrieving citizen {citizen_id}: {e}")
        return jsonify({'error': str(e)}), 500


@app.route('/api/citizen', methods=['POST'])
def create_citizen():
    """Create new citizen record"""
    try:
        data = request.json
        conn = _get_db_conn()
        cursor = conn.cursor()
        
        cursor.execute("""
            INSERT INTO citizen_registry 
            (national_id, first_name, last_name, date_of_birth, sex, region,
             municipality, address_line, postal_code, socioeconomic_group,
             tax_paid_last_year)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
        """, (
            data['national_id'],
            data['first_name'],
            data['last_name'],
            data['date_of_birth'],
            data.get('sex', 'M'),
            data.get('region', 'Central'),
            data.get('municipality', 'Capital'),
            data.get('address_line', ''),
            data.get('postal_code', ''),
            data.get('socioeconomic_group', 'B1 - Skilled'),
            data.get('tax_paid_last_year', 0),
        ))
        
        conn.commit()
        conn.close()
        _schedule_media_generation()
        
        logger.info(f"Created citizen record: {data['national_id']}")
        return jsonify({'status': 'created'}), 201
    except Exception as e:
        logger.error(f"Error creating citizen: {e}")
        return jsonify({'error': str(e)}), 500


@app.route('/api/citizen/<int:citizen_id>', methods=['PUT'])
def update_citizen(citizen_id):
    """Update citizen record"""
    try:
        data = request.json
        conn = _get_db_conn()
        cursor = conn.cursor()
        
        cursor.execute("""
            UPDATE citizen_registry
            SET national_id = ?, first_name = ?, last_name = ?, date_of_birth = ?,
                sex = ?, region = ?, municipality = ?, address_line = ?,
                postal_code = ?, socioeconomic_group = ?, tax_paid_last_year = ?,
                modified_date = CURRENT_TIMESTAMP
            WHERE id = ?
        """, (
            data.get('national_id'),
            data.get('first_name'),
            data.get('last_name'),
            data.get('date_of_birth'),
            data.get('sex'),
            data.get('region'),
            data.get('municipality'),
            data.get('address_line'),
            data.get('postal_code'),
            data.get('socioeconomic_group'),
            data.get('tax_paid_last_year'),
            citizen_id
        ))
        
        conn.commit()
        conn.close()
        _schedule_media_generation()
        
        logger.info(f"Updated citizen record: {citizen_id}")
        return jsonify({'status': 'updated'})
    except Exception as e:
        logger.error(f"Error updating citizen {citizen_id}: {e}")
        return jsonify({'error': str(e)}), 500


@app.route('/api/citizen/<int:citizen_id>', methods=['DELETE'])
def delete_citizen(citizen_id):
    """Delete citizen record"""
    try:
        conn = _get_db_conn()
        cursor = conn.cursor()
        cursor.execute("DELETE FROM citizen_registry WHERE id = ?", (citizen_id,))
        conn.commit()
        conn.close()
        _schedule_media_generation()
        
        logger.info(f"Deleted citizen record: {citizen_id}")
        return jsonify({'status': 'deleted'})
    except Exception as e:
        logger.error(f"Error deleting citizen {citizen_id}: {e}")
        return jsonify({'error': str(e)}), 500


@app.route('/config', methods=['GET'])
def config():
    """Display runtime configuration (non-sensitive)"""
    return jsonify({
        'application': 'citizen-registry-advanced',
        'version': '2.0',
        'environment': {
            'mtls_enabled': MTLS_ENABLED,
            'attestation_configured': bool(ATTESTATION_ENDPOINT),
            'database_configured': bool(DB_HOST) or bool(LOCAL_DB_PATH),
            'hsm_configured': bool(HSM_ENDPOINT)
        }
    })


@app.route('/security/evidence', methods=['GET'])
def security_evidence():
    """Return non-secret evidence used by the security detail panels."""
    return jsonify({
        'mtls': {
            'enabled': MTLS_ENABLED,
            'server_certificate': CERT_PATH,
            'client_certificate_check': 'nginx ssl_verify_client + X-Client-Verify',
            'client_certificate': '/etc/citizen-registry/certs/citizen.crt',
            'handshake_result': request.headers.get('X-Client-Verify', 'not_present'),
            'client_subject': request.headers.get('X-Client-DN', 'not_present'),
        },
        'attestation': {
            'endpoint': ATTESTATION_ENDPOINT,
            'result': _validate_attestation(),
            'cvm_measurement_source': 'Azure Confidential VM vTPM/SEV-SNP',
        },
        'cpu_attestation': _get_cpu_attestation_evidence(),
        'gpu_attestation': get_gpu_attestation_evidence(),
        'private_link': {
            'app_cvm_ip': APP_CVM_IP,
            'sql_cvm_ip': SQL_CVM_IP,
            'sql_port': 1433,
            'hsm_endpoint': HSM_ENDPOINT,
        },
        'encryption_at_rest': {
            'os_disk_encryption': 'Confidential OS disk encryption',
            'key_name': OS_DISK_KEY_NAME,
            'hsm_name': HSM_NAME,
            'secure_key_release': KEY_RELEASE_STATUS,
            'cmk': _get_cmk_evidence(),
        },
    })


# ============================================================================
# Error Handlers
# ============================================================================

@app.errorhandler(404)
def not_found(e):
    return jsonify({'error': 'Not found'}), 404


@app.errorhandler(500)
def server_error(e):
    logger.error(f"Server error: {e}")
    return jsonify({'error': 'Internal server error'}), 500


# ============================================================================
# Application Startup
# ============================================================================

_schedule_media_generation()

if __name__ == '__main__':
    logger.info("╔════════════════════════════════════════════════════════════╗")
    logger.info("║  Citizen Registry Advanced — Confidential VM Deployment   ║")
    logger.info("╚════════════════════════════════════════════════════════════╝")
    
    logger.info(f"Configuration:")
    logger.info(f"  Database: {DB_HOST}/{DB_NAME}")
    logger.info(f"  mTLS Enabled: {MTLS_ENABLED}")
    logger.info(f"  Attestation: {ATTESTATION_ENDPOINT}")
    logger.info(f"  HSM Endpoint: {HSM_ENDPOINT}")
    
    # Verify attestation
    attestation_status = _validate_attestation()
    logger.info(f"  Attestation Status: {attestation_status['status']}")
    
    # Verify mTLS
    mtls_status = _verify_mtls_certificate()
    logger.info(f"  mTLS Status: {mtls_status['status']}")
    
    logger.info("")
    logger.info("Application starting...")
    
    # Start Flask development server (will be proxied by nginx in production)
    app.run(
        host='127.0.0.1',
        port=8000,
        debug=False,
        use_reloader=False,
        threaded=True
    )
