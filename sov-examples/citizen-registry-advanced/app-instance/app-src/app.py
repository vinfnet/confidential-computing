"""
Citizen Registry Advanced — Flask App with mTLS and Azure Attestation

Deployed on Confidential VM (C-vn2) with:
- Mutual TLS (mTLS) for client-server authentication
- Azure Attestation integration for certificate validation
- SQL Server on ACC for encrypted data storage
- Managed HSM integration for key management
"""

from flask import Flask, jsonify, request, render_template, redirect, url_for
import base64
import json
import os
import secrets
import ssl
import threading
import pyodbc
import sqlite3
import logging
from datetime import datetime
from decimal import Decimal
from azure.identity import ManagedIdentityCredential, DefaultAzureCredential
import requests

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

_credential = None
_credential_lock = threading.Lock()
_database_ready = False
_database_ready_lock = threading.Lock()

FIRST_NAMES = [
    'Aisha', 'Alex', 'Amara', 'Daniel', 'Elena', 'Elias', 'Freya', 'Grace',
    'Hana', 'Idris', 'Jonas', 'Leila', 'Mateo', 'Maya', 'Nora', 'Omar',
    'Priya', 'Samuel', 'Sofia', 'Tomas',
]
LAST_NAMES = [
    'Bennett', 'Berg', 'Chen', 'Costa', 'Dubois', 'Garcia', 'Haddad', 'Ivanov',
    'Johnson', 'Khan', 'Larsen', 'Mensah', 'Novak', 'Okafor', 'Petrova',
    'Rossi', 'Silva', 'Smith', 'Tanaka', 'Williams',
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


def _synthetic_citizens():
    """Build 100 deterministic, entirely fictional Republic of Norland records."""
    citizens = []
    for index in range(1, 101):
        state, town, street, postal_area = LOCATIONS[(index - 1) % len(LOCATIONS)]
        year = 1948 + ((index * 7) % 58)
        month = 1 + ((index * 5) % 12)
        day = 1 + ((index * 11) % 27)
        citizens.append({
            'national_id': f'NLD-{year % 100:02d}{chr(65 + index % 26)}-{index:04d}X',
            'first_name': FIRST_NAMES[(index * 3) % len(FIRST_NAMES)],
            'last_name': LAST_NAMES[(index * 7) % len(LAST_NAMES)],
            'date_of_birth': f'{year:04d}-{month:02d}-{day:02d}',
            'sex': ('F', 'M', 'X')[index % 3],
            'region': state,
            'municipality': town,
            'address_line': f'{10 + ((index * 13) % 190)} {street}',
            'postal_code': f'{postal_area} {index % 10}{(index * 7) % 10}Q',
            'socioeconomic_group': SOCIOECONOMIC_GROUPS[(index * 5) % len(SOCIOECONOMIC_GROUPS)],
            'tax_paid_last_year': Decimal(850 + ((index * 1879) % 48600)) + Decimal(index % 100) / 100,
        })
    return citizens

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
                @Resource = N'citizen-registry-seed-v100',
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
        """)

        cur.execute("SELECT COUNT(*) FROM dbo.demo_metadata WHERE seed_version = 100")
        if cur.fetchone()[0] == 0:
            cur.execute("DELETE FROM dbo.citizen_registry")
            insert_sql = """
                INSERT INTO dbo.citizen_registry
                (national_id, first_name, last_name, date_of_birth, sex, region,
                 municipality, address_line, postal_code, socioeconomic_group,
                 tax_paid_last_year)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            """
            for citizen in _synthetic_citizens():
                cur.execute(insert_sql, (
                    citizen['national_id'], citizen['first_name'], citizen['last_name'],
                    citizen['date_of_birth'], citizen['sex'], citizen['region'],
                    citizen['municipality'], citizen['address_line'],
                    citizen['postal_code'], citizen['socioeconomic_group'],
                    citizen['tax_paid_last_year'],
                ))
            cur.execute("DELETE FROM dbo.demo_metadata")
            cur.execute("INSERT INTO dbo.demo_metadata (seed_version) VALUES (100)")
        
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
        if conn.execute('SELECT COUNT(*) FROM demo_metadata WHERE seed_version = 100').fetchone()[0] == 0:
            conn.execute('DELETE FROM citizen_registry')
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
                    for citizen in _synthetic_citizens()
                ],
            )
            conn.execute('DELETE FROM demo_metadata')
            conn.execute('INSERT INTO demo_metadata (seed_version) VALUES (100)')
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
    """Main citizen registry page"""
    try:
        conn = _get_db_conn()
        cursor = conn.cursor()
        cursor.execute("""
            SELECT id, national_id, first_name, last_name, date_of_birth,
                   address_line, municipality, region, socioeconomic_group,
                   tax_paid_last_year
            FROM citizen_registry ORDER BY id
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
            })
        conn.close()
        
        return render_template('index.html', citizens=citizens, mtls_enabled=MTLS_ENABLED)
    except Exception as e:
        logger.error(f"Error loading citizen list: {e}")
        return jsonify({'status': 'error', 'message': str(e)}), 500


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
            ORDER BY last_name, first_name
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
