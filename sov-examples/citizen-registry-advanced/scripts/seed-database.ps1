<#
.SYNOPSIS
    Seed the citizen registry database with demo data.

.DESCRIPTION
    Connects to the SQL Server database on ACC and seeds it with
    fictional Republic of Norland citizen records.

.PARAMETER DbServer
    SQL Server connection string or IP address.

.PARAMETER DbName
    Database name (default: citizendb).

.PARAMETER DbUsername
    Database admin username.

.PARAMETER DbPassword
    Database admin password.

.PARAMETER DataFile
    Path to JSON file containing citizen records (default: ../citizen-registry-config.json).

.EXAMPLE
    .\seed-database.ps1 -DbServer "sgall-sql.local" `
      -DbName "citizendb" `
      -DbUsername "sqladmin" `
      -DbPassword "P@ssw0rd!"
#>
param(
    [Parameter(Mandatory = $true)]
    [string]$DbServer,

    [string]$DbName = "citizendb",

    [Parameter(Mandatory = $true)]
    [string]$DbUsername,

    [Parameter(Mandatory = $true)]
    [string]$DbPassword,

    [string]$DataFile = "../citizen-registry-config.json"
)

$ErrorActionPreference = "Stop"

Write-Host "╔════════════════════════════════════════════════════════════╗" -ForegroundColor Cyan
Write-Host "║  Seeding Citizen Registry Database                         ║" -ForegroundColor Cyan
Write-Host "╚════════════════════════════════════════════════════════════╝" -ForegroundColor Cyan
Write-Host ""

Write-Host "Database Configuration:" -ForegroundColor Yellow
Write-Host "  Server: $DbServer"
Write-Host "  Database: $DbName"
Write-Host "  Username: $DbUsername"
Write-Host ""

# Check if data file exists
if (-not (Test-Path $DataFile)) {
    Write-Host "⚠ Data file not found: $DataFile" -ForegroundColor Yellow
    Write-Host "Using default demo data..." -ForegroundColor Yellow
    
    # Create default demo data (simplified)
    $demoData = @{
        citizens = @(
            @{ id = 1; firstName = "John"; lastName = "Smith"; region = "Central"; municipality = "Capital"; dateOfBirth = "1985-04-12"; idNumber = "DEMO-0001" },
            @{ id = 2; firstName = "Maria"; lastName = "Garcia"; region = "North"; municipality = "Riverside"; dateOfBirth = "1990-09-23"; idNumber = "DEMO-0002" },
            @{ id = 3; firstName = "Alex"; lastName = "Johnson"; region = "South"; municipality = "Lakeside"; dateOfBirth = "1978-01-30"; idNumber = "DEMO-0003" },
            @{ id = 4; firstName = "Aisha"; lastName = "Khan"; region = "East"; municipality = "Hillview"; dateOfBirth = "1988-06-17"; idNumber = "DEMO-0004" },
            @{ id = 5; firstName = "Daniel"; lastName = "Rossi"; region = "West"; municipality = "Oakridge"; dateOfBirth = "1972-12-05"; idNumber = "DEMO-0005" },
            @{ id = 6; firstName = "Elena"; lastName = "Petrova"; region = "Central"; municipality = "Capital"; dateOfBirth = "1995-02-28"; idNumber = "DEMO-0006" },
            @{ id = 7; firstName = "Samuel"; lastName = "Okafor"; region = "North"; municipality = "Harbor"; dateOfBirth = "1981-10-11"; idNumber = "DEMO-0007" },
            @{ id = 8; firstName = "Nora"; lastName = "Bennett"; region = "South"; municipality = "Lakeside"; dateOfBirth = "2000-07-09"; idNumber = "DEMO-0008" },
            @{ id = 9; firstName = "Mateo"; lastName = "Silva"; region = "East"; municipality = "Border"; dateOfBirth = "1969-03-21"; idNumber = "DEMO-0009" },
            @{ id = 10; firstName = "Hana"; lastName = "Tanaka"; region = "West"; municipality = "Coast"; dateOfBirth = "1983-11-14"; idNumber = "DEMO-0010" },
            @{ id = 11; firstName = "Grace"; lastName = "Williams"; region = "Central"; municipality = "Capital"; dateOfBirth = "1998-05-03"; idNumber = "DEMO-0011" },
            @{ id = 12; firstName = "Omar"; lastName = "Haddad"; region = "North"; municipality = "Riverside"; dateOfBirth = "1976-08-26"; idNumber = "DEMO-0012" }
        )
    }
} else {
    Write-Host "Loading data from: $DataFile" -ForegroundColor Yellow
    $demoData = Get-Content $DataFile | ConvertFrom-Json
}

Write-Host "✓ Loaded $(($demoData.citizens | Measure-Object).Count) citizen records" -ForegroundColor Green
Write-Host ""

# Generate SQL script
Write-Host "Generating database initialization script..." -ForegroundColor Yellow

$sqlScript = @"
-- Citizen Registry Database Initialization
-- Republic of Norland

IF NOT EXISTS (SELECT name FROM sys.databases WHERE name = N'$DbName')
BEGIN
    CREATE DATABASE [$DbName];
END
GO

USE [$DbName];
GO

-- Create citizen_registry table
IF NOT EXISTS (SELECT * FROM sys.tables WHERE name = 'citizen_registry')
BEGIN
    CREATE TABLE citizen_registry (
        id INT PRIMARY KEY IDENTITY(1,1),
        first_name VARCHAR(100) NOT NULL,
        last_name VARCHAR(100) NOT NULL,
        date_of_birth DATE NOT NULL,
        national_id VARCHAR(50) UNIQUE NOT NULL,
        region VARCHAR(100),
        municipality VARCHAR(100),
        created_date DATETIME DEFAULT GETUTCDATE(),
        modified_date DATETIME DEFAULT GETUTCDATE(),
        archived BIT DEFAULT 0
    );
    
    CREATE INDEX idx_id_number ON citizen_registry(id_number);
    CREATE INDEX idx_last_name ON citizen_registry(last_name);
    CREATE INDEX idx_region ON citizen_registry(region);
    
    PRINT 'Created citizen_registry table';
END
GO

-- Insert demo data
DECLARE @citizenCount INT;
SELECT @citizenCount = COUNT(*) FROM citizen_registry;

IF @citizenCount = 0
BEGIN
    INSERT INTO citizen_registry (national_id, first_name, last_name, date_of_birth, sex, region, municipality)
    VALUES
        ('DEMO-0001', 'John', 'Smith', '1985-04-12', 'M', 'Central', 'Capital'),
        ('DEMO-0002', 'Maria', 'Garcia', '1990-09-23', 'F', 'North', 'Riverside'),
        ('DEMO-0003', 'Alex', 'Johnson', '1978-01-30', 'X', 'South', 'Lakeside'),
        ('DEMO-0004', 'Aisha', 'Khan', '1988-06-17', 'F', 'East', 'Hillview'),
        ('DEMO-0005', 'Daniel', 'Rossi', '1972-12-05', 'M', 'West', 'Oakridge'),
        ('DEMO-0006', 'Elena', 'Petrova', '1995-02-28', 'F', 'Central', 'Capital'),
        ('DEMO-0007', 'Samuel', 'Okafor', '1981-10-11', 'M', 'North', 'Harbor'),
        ('DEMO-0008', 'Nora', 'Bennett', '2000-07-09', 'F', 'South', 'Lakeside'),
        ('DEMO-0009', 'Mateo', 'Silva', '1969-03-21', 'M', 'East', 'Border'),
        ('DEMO-0010', 'Hana', 'Tanaka', '1983-11-14', 'F', 'West', 'Coast'),
        ('DEMO-0011', 'Grace', 'Williams', '1998-05-03', 'F', 'Central', 'Capital'),
        ('DEMO-0012', 'Omar', 'Haddad', '1976-08-26', 'M', 'North', 'Riverside');
    
    PRINT 'Inserted 5 citizen records';
END

SELECT COUNT(*) AS record_count FROM citizen_registry;
"@

# Save SQL script
$scriptPath = "./seed-database.sql"
$sqlScript | Out-File -FilePath $scriptPath -Encoding UTF8

Write-Host "✓ SQL script created: $scriptPath" -ForegroundColor Green
Write-Host ""

Write-Host "Next Steps:" -ForegroundColor Cyan
Write-Host "1. Copy seed-database.sql to the database server"
Write-Host "2. Run on SQL Server:"
Write-Host "   sqlcmd -S $DbServer -U $DbUsername -P (prompt) -i seed-database.sql"
Write-Host "3. Verify data with:"
Write-Host "   sqlcmd -S $DbServer -U $DbUsername -d $DbName -Q \"SELECT COUNT(*) FROM citizen_registry\""
Write-Host ""

Write-Host "✓ Database seeding script ready" -ForegroundColor Green
