import argparse
import random
from datetime import date, timedelta

FICTIONAL_COUNTRY = "Republic of Norland"

REGIONS = [
    "North Coast",
    "Central Plains",
    "Highland Province",
    "Eastern Corridor",
    "Southern Delta",
]

MUNICIPALITIES = {
    "North Coast": ["Port Azure", "Cedar Bay", "Northhaven"],
    "Central Plains": ["Rivergate", "Stonefield", "Meadowridge"],
    "Highland Province": ["Ironford", "Pinecrest", "Silver Ridge"],
    "Eastern Corridor": ["Sunvale", "Eastbridge", "Lakeside"],
    "Southern Delta": ["Southport", "Mariner's Point", "Greenwater"],
}

FIRST_NAMES = [
    "Aarav", "Anaya", "Amelia", "Noah", "Olivia", "Liam", "Emma", "Sophia", "Mia", "Ethan",
    "Lucas", "Isabella", "Aisha", "Yusuf", "Fatima", "Daniel", "Sakura", "Hana", "Arjun", "Priya",
]

LAST_NAMES = [
    "Patel", "Nakamura", "Smith", "Brown", "Garcia", "Martinez", "Andersson", "Silva", "Khan", "Zhou",
    "Meyer", "Singh", "Haddad", "Reddy", "Fischer", "Tanaka", "Williams", "Lopez", "Gupta", "Ibrahim",
]

SEXES = ["Female", "Male"]
MARITAL_STATUSES = ["Single", "Married", "Divorced", "Widowed"]
EMPLOYMENT_STATUSES = ["Employed", "Self-Employed", "Unemployed", "Student", "Retired"]
TAX_BRACKETS = ["A", "B", "C", "D", "E"]


def _national_id(idx: int) -> str:
    # Example fictional format: NOR-YYYY-XXXXXX
    year = random.randint(1950, 2007)
    return f"NOR-{year}-{idx:06d}"


def _address_line(municipality: str) -> str:
    street_no = random.randint(1, 999)
    street_name = random.choice(["Oak", "Harbor", "Maple", "Sunrise", "Civic", "River", "Hill", "Unity"])
    suffix = random.choice(["Street", "Road", "Avenue", "Lane"])
    return f"{street_no} {street_name} {suffix}, {municipality}"


def _postal_code() -> str:
    return f"N{random.randint(1000, 9999)}"


def _random_date_of_birth() -> date:
    start = date(1950, 1, 1)
    end = date(2007, 12, 31)
    return start + timedelta(days=random.randint(0, (end - start).days))


def _escape_sql(value: str) -> str:
    return value.replace("'", "''")


def _generate_insert_rows(count: int):
    for idx in range(1, count + 1):
        first_name = random.choice(FIRST_NAMES)
        last_name = random.choice(LAST_NAMES)
        dob = _random_date_of_birth()
        sex = random.choice(SEXES)
        region = random.choice(REGIONS)
        municipality = random.choice(MUNICIPALITIES[region])
        address_line = _address_line(municipality)
        postal_code = _postal_code()
        household_size = random.randint(1, 8)
        marital_status = random.choice(MARITAL_STATUSES)
        employment_status = random.choice(EMPLOYMENT_STATUSES)
        tax_bracket = random.choice(TAX_BRACKETS)
        registered_voter = "TRUE" if (dob <= date(2008, 4, 23) and random.random() > 0.06) else "FALSE"

        vals = (
            _national_id(idx),
            _escape_sql(first_name),
            _escape_sql(last_name),
            dob.isoformat(),
            _escape_sql(sex),
            _escape_sql(region),
            _escape_sql(municipality),
            _escape_sql(address_line),
            _escape_sql(postal_code),
            household_size,
            _escape_sql(marital_status),
            _escape_sql(employment_status),
            _escape_sql(tax_bracket),
            registered_voter,
        )

        yield (
            "("
            f"'{vals[0]}', '{vals[1]}', '{vals[2]}', '{vals[3]}', '{vals[4]}', "
            f"'{vals[5]}', '{vals[6]}', '{vals[7]}', '{vals[8]}', {vals[9]}, "
            f"'{vals[10]}', '{vals[11]}', '{vals[12]}', {vals[13]}, NOW()"
            ")"
        )


def write_seed_sql(output_path: str, count: int):
    rows = list(_generate_insert_rows(count))

    with open(output_path, "w", encoding="utf-8") as f:
        f.write("-- Auto-generated seed data for sov-examples citizen registry demo\n")
        f.write("-- Data profile: fictional citizens and addresses in a representative national registry model\n")
        f.write(f"-- Country profile: {FICTIONAL_COUNTRY}\n")
        f.write(f"-- Record count: {count}\n\n")

        f.write("DROP TABLE IF EXISTS citizen_registry;\n\n")

        f.write(
            """
CREATE TABLE citizen_registry (
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
);

CREATE INDEX idx_citizen_region ON citizen_registry(region);
CREATE INDEX idx_citizen_municipality ON citizen_registry(municipality);
CREATE INDEX idx_citizen_voter ON citizen_registry(registered_voter);

"""
        )

        f.write(
            "INSERT INTO citizen_registry (national_id, first_name, last_name, date_of_birth, sex, "
            "region, municipality, address_line, postal_code, household_size, marital_status, "
            "employment_status, tax_bracket, registered_voter, last_updated) VALUES\n"
        )

        for i, row in enumerate(rows):
            sep = ",\n" if i < len(rows) - 1 else ";\n"
            f.write(row + sep)


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Generate fictional citizen registry seed SQL")
    parser.add_argument("--count", type=int, default=5000)
    parser.add_argument("--output", default="seed-data.sql")
    parser.add_argument("--seed", type=int, default=42)
    args = parser.parse_args()

    random.seed(args.seed)
    write_seed_sql(args.output, args.count)
    print(f"Generated {args.count} records at {args.output}")
