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
            @{ id = 1; firstName = "John"; lastName = "Smith"; region = "Central"; municipality = "Capital"; dateOfBirth = "1980-01-15"; idNumber = "CC-2024-001" },
            @{ id = 2; firstName = "Maria"; lastName = "Garcia"; region = "Northern"; municipality = "Harbor"; dateOfBirth = "1990-05-20"; idNumber = "CC-2024-002" },
            @{ id = 3; firstName = "Ahmed"; lastName = "Hassan"; region = "Eastern"; municipality = "Border"; dateOfBirth = "1985-03-10"; idNumber = "CC-2024-003" },
            @{ id = 4; firstName = "Sophie"; lastName = "Dubois"; region = "Western"; municipality = "Coast"; dateOfBirth = "1992-11-08"; idNumber = "CC-2024-004" },
            @{ id = 5; firstName = "Li"; lastName = "Chen"; region = "Southern"; municipality = "Industrial"; dateOfBirth = "1988-07-22"; idNumber = "CC-2024-005" }
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
        id_number VARCHAR(50) UNIQUE NOT NULL,
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
    INSERT INTO citizen_registry (first_name, last_name, date_of_birth, id_number, region, municipality)
    VALUES
        ('John', 'Smith', '1980-01-15', 'CC-2024-001', 'Central', 'Capital'),
        ('Maria', 'Garcia', '1990-05-20', 'CC-2024-002', 'Northern', 'Harbor'),
        ('Ahmed', 'Hassan', '1985-03-10', 'CC-2024-003', 'Eastern', 'Border'),
        ('Sophie', 'Dubois', '1992-11-08', 'CC-2024-004', 'Western', 'Coast'),
        ('Li', 'Chen', '1988-07-22', 'CC-2024-005', 'Southern', 'Industrial');
    
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
