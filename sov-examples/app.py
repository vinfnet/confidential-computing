import os
import secrets
import threading
from datetime import date

from flask import Flask, flash, redirect, render_template, request, url_for
import psycopg2
import psycopg2.pool

FICTIONAL_COUNTRY = "Republic of Norland"

app = Flask(__name__)
app.config["SECRET_KEY"] = os.environ.get("FLASK_SECRET", secrets.token_hex(32))
app.config["MAX_CONTENT_LENGTH"] = 32 * 1024

_db_pool = None
_db_pool_lock = threading.Lock()
_schema_ready = False
_schema_lock = threading.Lock()


def _get_db_pool():
    global _db_pool
    if _db_pool is not None:
        return _db_pool

    with _db_pool_lock:
        if _db_pool is not None:
            return _db_pool

        db_host = os.environ.get("DB_HOST", "")
        db_name = os.environ.get("DB_NAME", "norlandregistry")
        db_user = os.environ.get("DB_USER", "")
        db_password = os.environ.get("DB_PASSWORD", "")
        db_port = int(os.environ.get("DB_PORT", "5432"))

        if not db_host or not db_user:
            return None

        _db_pool = psycopg2.pool.ThreadedConnectionPool(
            minconn=1,
            maxconn=8,
            host=db_host,
            dbname=db_name,
            user=db_user,
            password=db_password,
            port=db_port,
            sslmode=os.environ.get("DB_SSLMODE", "require"),
            connect_timeout=10,
        )
        return _db_pool


def _get_conn():
    pool = _get_db_pool()
    if pool is None:
        raise RuntimeError("Database settings missing. Set DB_HOST, DB_USER, DB_PASSWORD.")
    return pool.getconn()


def _put_conn(conn):
    pool = _get_db_pool()
    if pool and conn:
        pool.putconn(conn)


def _init_schema():
    conn = _get_conn()
    try:
        with conn.cursor() as cur:
            cur.execute(
                """
                CREATE TABLE IF NOT EXISTS citizen_registry (
                    id SERIAL PRIMARY KEY,
                    national_id VARCHAR(18) NOT NULL UNIQUE,
                    first_name VARCHAR(64) NOT NULL,
                    last_name VARCHAR(64) NOT NULL,
                    date_of_birth DATE NOT NULL,
                    sex VARCHAR(12) NOT NULL,
                    region VARCHAR(64) NOT NULL,
                    municipality VARCHAR(64) NOT NULL,
                    address_line VARCHAR(160) NOT NULL,
                    postal_code VARCHAR(16) NOT NULL,
                    household_size INTEGER NOT NULL,
                    marital_status VARCHAR(20) NOT NULL,
                    employment_status VARCHAR(32) NOT NULL,
                    tax_bracket VARCHAR(16) NOT NULL,
                    registered_voter BOOLEAN NOT NULL DEFAULT TRUE,
                    last_updated TIMESTAMP NOT NULL DEFAULT NOW()
                )
                """
            )
            cur.execute("CREATE INDEX IF NOT EXISTS idx_citizen_region ON citizen_registry(region)")
            cur.execute("CREATE INDEX IF NOT EXISTS idx_citizen_municipality ON citizen_registry(municipality)")
            cur.execute("CREATE INDEX IF NOT EXISTS idx_citizen_voter ON citizen_registry(registered_voter)")
        conn.commit()
    finally:
        _put_conn(conn)


def _seed_if_requested():
    if os.environ.get("AUTO_SEED", "false").lower() != "true":
        return

    conn = _get_conn()
    try:
        with conn.cursor() as cur:
            cur.execute("SELECT COUNT(*) FROM citizen_registry")
            row_count = cur.fetchone()[0]
            if row_count > 0:
                return

            seed_file = os.path.join(os.path.dirname(__file__), "seed-data.sql")
            if not os.path.exists(seed_file):
                return

            with open(seed_file, "r", encoding="utf-8") as f:
                cur.execute(f.read())
        conn.commit()
    finally:
        _put_conn(conn)


def _validate_payload(form_data):
    payload = {
        "national_id": form_data.get("national_id", "").strip(),
        "first_name": form_data.get("first_name", "").strip(),
        "last_name": form_data.get("last_name", "").strip(),
        "sex": form_data.get("sex", "").strip(),
        "region": form_data.get("region", "").strip(),
        "municipality": form_data.get("municipality", "").strip(),
        "address_line": form_data.get("address_line", "").strip(),
        "postal_code": form_data.get("postal_code", "").strip(),
        "marital_status": form_data.get("marital_status", "").strip(),
        "employment_status": form_data.get("employment_status", "").strip(),
        "tax_bracket": form_data.get("tax_bracket", "").strip(),
        "registered_voter": form_data.get("registered_voter", "true") == "true",
    }

    required = [
        "national_id",
        "first_name",
        "last_name",
        "sex",
        "region",
        "municipality",
        "address_line",
        "postal_code",
        "marital_status",
        "employment_status",
        "tax_bracket",
    ]
    missing = [field for field in required if not payload[field]]
    if missing:
        raise ValueError(f"Missing required fields: {', '.join(missing)}")

    payload["household_size"] = int(form_data.get("household_size", "1").strip())
    payload["date_of_birth"] = date.fromisoformat(form_data.get("date_of_birth", "").strip())

    if payload["household_size"] < 1 or payload["household_size"] > 20:
        raise ValueError("household_size must be between 1 and 20")

    return payload


@app.before_request
def ensure_schema():
    global _schema_ready
    if _schema_ready:
        return
    if _get_db_pool() is None:
        return
    with _schema_lock:
        if _schema_ready:
            return
        _init_schema()
        _seed_if_requested()
        _schema_ready = True


@app.after_request
def add_security_headers(response):
    response.headers["X-Content-Type-Options"] = "nosniff"
    response.headers["X-Frame-Options"] = "DENY"
    response.headers["Referrer-Policy"] = "strict-origin-when-cross-origin"
    return response


@app.route("/")
def index():
    try:
        page = max(int(request.args.get("page", "1")), 1)
    except ValueError:
        page = 1

    page_size = 50
    offset = (page - 1) * page_size

    conn = _get_conn()
    try:
        with conn.cursor() as cur:
            cur.execute("SELECT COUNT(*) FROM citizen_registry")
            total_rows = cur.fetchone()[0]

            cur.execute(
                """
                SELECT id, national_id, first_name, last_name, date_of_birth, sex,
                       region, municipality, address_line, postal_code, household_size,
                       marital_status, employment_status, tax_bracket, registered_voter
                FROM citizen_registry
                ORDER BY id ASC
                LIMIT %s OFFSET %s
                """,
                (page_size, offset),
            )
            citizens = cur.fetchall()
    finally:
        _put_conn(conn)

    total_pages = (total_rows + page_size - 1) // page_size
    return render_template(
        "index.html",
        citizens=citizens,
        page=page,
        total_pages=total_pages,
        total_rows=total_rows,
        country_name=FICTIONAL_COUNTRY,
    )


@app.route("/citizen/new", methods=["GET", "POST"])
def create_citizen():
    if request.method == "POST":
        try:
            payload = _validate_payload(request.form)
            conn = _get_conn()
            try:
                with conn.cursor() as cur:
                    cur.execute(
                        """
                        INSERT INTO citizen_registry (
                            national_id, first_name, last_name, date_of_birth, sex,
                            region, municipality, address_line, postal_code, household_size,
                            marital_status, employment_status, tax_bracket, registered_voter, last_updated
                        ) VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, NOW())
                        """,
                        (
                            payload["national_id"], payload["first_name"], payload["last_name"], payload["date_of_birth"], payload["sex"],
                            payload["region"], payload["municipality"], payload["address_line"], payload["postal_code"], payload["household_size"],
                            payload["marital_status"], payload["employment_status"], payload["tax_bracket"], payload["registered_voter"],
                        ),
                    )
                conn.commit()
            finally:
                _put_conn(conn)

            flash("Citizen record added.", "success")
            return redirect(url_for("index"))
        except Exception as ex:
            flash(f"Unable to add citizen record: {ex}", "error")

    return render_template("employee_form.html", mode="create", citizen=None, country_name=FICTIONAL_COUNTRY)


@app.route("/citizen/<int:citizen_id>/edit", methods=["GET", "POST"])
def edit_citizen(citizen_id):
    conn = _get_conn()
    try:
        if request.method == "POST":
            try:
                payload = _validate_payload(request.form)
                with conn.cursor() as cur:
                    cur.execute(
                        """
                        UPDATE citizen_registry
                        SET national_id=%s, first_name=%s, last_name=%s, date_of_birth=%s,
                            sex=%s, region=%s, municipality=%s, address_line=%s, postal_code=%s,
                            household_size=%s, marital_status=%s, employment_status=%s,
                            tax_bracket=%s, registered_voter=%s, last_updated=NOW()
                        WHERE id=%s
                        """,
                        (
                            payload["national_id"], payload["first_name"], payload["last_name"], payload["date_of_birth"], payload["sex"],
                            payload["region"], payload["municipality"], payload["address_line"], payload["postal_code"],
                            payload["household_size"], payload["marital_status"], payload["employment_status"],
                            payload["tax_bracket"], payload["registered_voter"], citizen_id,
                        ),
                    )
                conn.commit()
                flash("Citizen record updated.", "success")
                return redirect(url_for("index"))
            except Exception as ex:
                flash(f"Unable to update citizen record: {ex}", "error")

        with conn.cursor() as cur:
            cur.execute(
                """
                SELECT id, national_id, first_name, last_name, date_of_birth, sex,
                       region, municipality, address_line, postal_code, household_size,
                       marital_status, employment_status, tax_bracket, registered_voter
                FROM citizen_registry
                WHERE id=%s
                """,
                (citizen_id,),
            )
            citizen = cur.fetchone()
            if citizen is None:
                flash("Citizen record not found.", "error")
                return redirect(url_for("index"))
    finally:
        _put_conn(conn)

    return render_template("employee_form.html", mode="edit", citizen=citizen, country_name=FICTIONAL_COUNTRY)


@app.route("/citizen/<int:citizen_id>/delete", methods=["POST"])
def delete_citizen(citizen_id):
    conn = _get_conn()
    try:
        with conn.cursor() as cur:
            cur.execute("DELETE FROM citizen_registry WHERE id=%s", (citizen_id,))
            deleted = cur.rowcount
        conn.commit()
    finally:
        _put_conn(conn)

    if deleted:
        flash("Citizen record deleted.", "success")
    else:
        flash("Citizen record not found.", "error")
    return redirect(url_for("index"))


@app.route("/health")
def health():
    return {"status": "ok"}


@app.route("/db/status")
def db_status():
    conn = _get_conn()
    try:
        with conn.cursor() as cur:
            cur.execute("SELECT COUNT(*) FROM citizen_registry")
            count = cur.fetchone()[0]
    finally:
        _put_conn(conn)
    return {
        "status": "connected",
        "country": FICTIONAL_COUNTRY,
        "record_count": count,
        "dataset": "fictional citizen registry",
    }


@app.route("/security/policy")
def security_policy():
    return {
        "securityPolicyHash": os.environ.get("SECURITY_POLICY_HASH", ""),
        "containerSku": "Confidential",
    }


if __name__ == "__main__":
    app.run(host="0.0.0.0", port=8000)
