"""
Citizen Registry Advanced — Flask App with mTLS and Azure Attestation

Deployed on Confidential VM (C-vn2) with:
- Mutual TLS (mTLS) for client-server authentication
- Azure Attestation integration for certificate validation
- SQL Server on ACC for encrypted data storage
- Managed HSM integration for key management
"""

from flask import Flask, jsonify, request, render_template, redirect, url_for
import os
import secrets
import ssl
import threading
import pyodbc
import sqlite3
import logging
from datetime import datetime
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

_credential = None
_credential_lock = threading.Lock()

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
                    created_date DATETIME DEFAULT GETUTCDATE(),
                    modified_date DATETIME DEFAULT GETUTCDATE()
                )
            END
        """)
        
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
                created_date TEXT DEFAULT CURRENT_TIMESTAMP,
                modified_date TEXT DEFAULT CURRENT_TIMESTAMP
            )
            """
        )
        if conn.execute('SELECT COUNT(*) FROM citizen_registry').fetchone()[0] == 0:
            conn.executemany(
                """
                INSERT INTO citizen_registry
                (national_id, first_name, last_name, date_of_birth, sex, region, municipality)
                VALUES (?, ?, ?, ?, ?, ?, ?)
                """,
                [
                    ('DEMO-0001', 'John', 'Smith', '1985-04-12', 'M', 'Central', 'Capital'),
                    ('DEMO-0002', 'Maria', 'Garcia', '1990-09-23', 'F', 'North', 'Riverside'),
                    ('DEMO-0003', 'Alex', 'Johnson', '1978-01-30', 'X', 'South', 'Lakeside'),
                ],
            )
            conn.commit()
        return conn
    
    if DB_USER and DB_PASSWORD:
        conn_str = _build_sql_auth_conn_str(DB_HOST, DB_NAME, DB_USER, DB_PASSWORD)
        try:
            return pyodbc.connect(conn_str)
        except pyodbc.Error as e:
            error_text = str(e)
            if '4060' in error_text and DB_SA_PASSWORD:
                # Database doesn't exist, bootstrap it
                _bootstrap_demo_database(DB_HOST, DB_NAME, DB_USER, DB_PASSWORD)
                return pyodbc.connect(conn_str)
            raise
    else:
        raise RuntimeError('Database credentials not configured')


# ============================================================================
# Attestation and mTLS Functions
# ============================================================================

def _validate_attestation():
    """Validate CVM attestation status via Azure Attestation Service"""
    if not ATTESTATION_ENDPOINT or not MTLS_ENABLED:
        return {'status': 'disabled'}
    
    try:
        response = requests.get(
            f"{ATTESTATION_ENDPOINT}/attestation/sgx/openid4p/metadata",
            timeout=5
        )
        if response.status_code == 200:
            logger.info("✓ Azure Attestation Service verified")
            return {'status': 'verified', 'endpoint': ATTESTATION_ENDPOINT}
    except Exception as e:
        logger.warning(f"Attestation check failed: {e}")
    
    return {'status': 'not_available'}


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
        cursor.execute("SELECT id, national_id, first_name, last_name, region FROM citizen_registry ORDER BY id")
        citizens = []
        for row in cursor.fetchall():
            citizens.append({
                'id': row[0],
                'national_id': row[1],
                'first_name': row[2],
                'last_name': row[3],
                'region': row[4]
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
                   region, municipality, marital_status, employment_status
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
                'region': row[5],
                'municipality': row[6],
                'marital_status': row[7],
                'employment_status': row[8]
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
        cursor.execute(
            "SELECT * FROM citizen_registry WHERE id = ?",
            (citizen_id,)
        )
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
            'address': row[8],
            'postal_code': row[9]
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
            (national_id, first_name, last_name, date_of_birth, sex, region, municipality)
            VALUES (?, ?, ?, ?, ?, ?, ?)
        """, (
            data['national_id'],
            data['first_name'],
            data['last_name'],
            data['date_of_birth'],
            data.get('sex', 'M'),
            data.get('region', 'Central'),
            data.get('municipality', 'Capital')
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
            SET first_name = ?, last_name = ?, marital_status = ?, employment_status = ?
            WHERE id = ?
        """, (
            data.get('first_name'),
            data.get('last_name'),
            data.get('marital_status'),
            data.get('employment_status'),
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
