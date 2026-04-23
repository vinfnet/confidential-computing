# SOV Examples: End-to-End ACC Data Protection

This folder contains sovereign-focused sample applications that demonstrate how sensitive workloads can be protected with Azure Confidential Computing (ACC) in an end-to-end manner.

These scenarios are common in sovereign environments where organizations must keep control of sensitive citizen, financial, and mission data while still using cloud scale services.

## Included Sample

### Norland Citizen Registry App

A containerized Flask application connected to PostgreSQL Flexible Server with:

- Confidential ACI container deployment with ccepolicy generated using az confcom.
- PostgreSQL-backed fictional citizen records with CRUD operations (view, add, edit, delete).
- Random fictional citizen seed data generation (about 5000 records).
- Secure-by-default deployment pattern aligned with ACC samples in this repository.

The dataset is intentionally fictional (synthetic citizens and addresses) for the fictional Republic of Norland, while remaining representative of records that a typical national government might collect for civil administration.

## Folder Contents

- app.py: Flask web application with citizen registry CRUD and DB status endpoints.
- templates/index.html: Main records list and paging view.
- templates/employee_form.html: Add/edit citizen form.
- generate_citizen_data.py: Generates realistic random fictional citizen data and writes SQL seed file.
- seed-data.sql: Pre-generated SQL with around 5000 fictional citizen records.
- Dockerfile: Combined Flask + Nginx + SKR runtime image.
- deployment-template.json: Confidential ACI ARM template with ccePolicy field.
- Deploy-NorlandCitizenRegistry.ps1: Build/deploy helper script for Azure resources and ccepolicy generation.

## Quick Start

1. Build image and baseline resources:

```powershell
cd sov-examples
./Deploy-NorlandCitizenRegistry.ps1 -Prefix sgall -Build
```

2. Deploy VNet, PostgreSQL, seed data, generate ccepolicy, and deploy Confidential ACI:

```powershell
./Deploy-NorlandCitizenRegistry.ps1 -Prefix sgall -Deploy
```

3. Cleanup resources:

```powershell
./Deploy-NorlandCitizenRegistry.ps1 -Cleanup
```

## Local Data Generation

Regenerate the seed file anytime:

```powershell
python ./generate_citizen_data.py --count 5000 --output ./seed-data.sql
```

## Notes

- The deployment script uses az confcom to generate and inject ccepolicy before deployment.
- The app uses parameterized SQL statements for CRUD operations.
- This sample is for demonstration and learning. Review and harden before production use.
