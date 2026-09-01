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

.PARAMETER DataFile
    Path to JSON file containing citizen records (default: ../citizen-registry-config.json).

.EXAMPLE
    .\seed-database.ps1 -DbServer "sgall-sql.local" `
      -DbName "citizendb" `
    -DbUsername "sqladmin"
#>
param(
    [Parameter(Mandatory = $true)]
    [string]$DbServer,

    [string]$DbName = "citizendb",

    [Parameter(Mandatory = $true)]
    [string]$DbUsername,

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
    
    $firstNames = @('Aisha', 'Alex', 'Amara', 'Daniel', 'Elena', 'Elias', 'Freya', 'Grace', 'Hana', 'Idris', 'Jonas', 'Leila', 'Mateo', 'Maya', 'Nora', 'Omar', 'Priya', 'Samuel', 'Sofia', 'Tomas')
    $lastNames = @('Bennett', 'Berg', 'Chen', 'Costa', 'Dubois', 'Garcia', 'Haddad', 'Ivanov', 'Johnson', 'Khan', 'Larsen', 'Mensah', 'Novak', 'Okafor', 'Petrova', 'Rossi', 'Silva', 'Smith', 'Tanaka', 'Williams')
    $locations = @(
        @('Central', 'Alderwick', 'Cedar Avenue', 'NR1'), @('Central', 'Kingshaven', 'Parliament Street', 'NR2'),
        @('North', 'Riverside', 'Mill Lane', 'NR3'), @('North', 'Harbor', 'Seafarer Road', 'NR4'),
        @('South', 'Lakeside', 'Willow Crescent', 'NR5'), @('South', 'Meadowfield', 'Orchard Way', 'NR6'),
        @('East', 'Hillview', 'Beacon Street', 'NR7'), @('East', 'Stonebridge', 'Foundry Road', 'NR8'),
        @('West', 'Oakridge', 'Maple Drive', 'NR9'), @('West', 'Westport', 'Quayside Avenue', 'NR10')
    )
    $groups = @('A1 - Professional', 'A2 - Managerial', 'B1 - Skilled', 'B2 - Intermediate', 'C1 - Service', 'C2 - Supported')
    $citizens = for ($index = 1; $index -le 100; $index++) {
        $location = $locations[($index - 1) % $locations.Count]
        $year = 1948 + (($index * 7) % 58)
        $month = 1 + (($index * 5) % 12)
        $day = 1 + (($index * 11) % 27)
        [pscustomobject]@{
            idNumber = 'NLD-{0:D2}{1}-{2:D4}X' -f ($year % 100), [char](65 + ($index % 26)), $index
            firstName = $firstNames[($index * 3) % $firstNames.Count]
            lastName = $lastNames[($index * 7) % $lastNames.Count]
            dateOfBirth = '{0:D4}-{1:D2}-{2:D2}' -f $year, $month, $day
            sex = @('F', 'M', 'X')[$index % 3]
            region = $location[0]
            municipality = $location[1]
            addressLine = '{0} {1}' -f (10 + (($index * 13) % 190)), $location[2]
            postalCode = '{0} {1}{2}Q' -f $location[3], ($index % 10), (($index * 7) % 10)
            socioeconomicGroup = $groups[($index * 5) % $groups.Count]
            taxPaidLastYear = 850 + (($index * 1879) % 48600) + (($index % 100) / 100)
        }
    }
    $demoData = @{ citizens = $citizens }
} else {
    Write-Host "Loading data from: $DataFile" -ForegroundColor Yellow
    $demoData = Get-Content $DataFile | ConvertFrom-Json
}

Write-Host "✓ Loaded $(($demoData.citizens | Measure-Object).Count) citizen records" -ForegroundColor Green
Write-Host ""

# Generate SQL script
Write-Host "Generating database initialization script..." -ForegroundColor Yellow

$valuesSql = ($demoData.citizens | ForEach-Object {
    $tax = [string]::Format([Globalization.CultureInfo]::InvariantCulture, '{0:F2}', [decimal]$_.taxPaidLastYear)
    "('$($_.idNumber)', '$($_.firstName)', '$($_.lastName)', '$($_.dateOfBirth)', '$($_.sex)', '$($_.region)', '$($_.municipality)', '$($_.addressLine)', '$($_.postalCode)', '$($_.socioeconomicGroup)', $tax)"
}) -join ",`n        "

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
        sex VARCHAR(10),
        region VARCHAR(100),
        municipality VARCHAR(100),
        address_line VARCHAR(200),
        postal_code VARCHAR(10),
        household_size INT DEFAULT 1,
        marital_status VARCHAR(20) DEFAULT 'Single',
        employment_status VARCHAR(30) DEFAULT 'Employed',
        tax_bracket VARCHAR(10) DEFAULT 'B',
        registered_voter BIT DEFAULT 1,
        socioeconomic_group VARCHAR(40),
        tax_paid_last_year DECIMAL(12,2),
        created_date DATETIME DEFAULT GETUTCDATE(),
        modified_date DATETIME DEFAULT GETUTCDATE()
    );
    
    CREATE INDEX idx_national_id ON citizen_registry(national_id);
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
    INSERT INTO citizen_registry (national_id, first_name, last_name, date_of_birth, sex, region, municipality, address_line, postal_code, socioeconomic_group, tax_paid_last_year)
    VALUES
        $valuesSql;
    
    PRINT 'Inserted 100 fictional citizen records';
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
Write-Host "   sqlcmd -S $DbServer -U $DbUsername -d $DbName -Q `"SELECT COUNT(*) FROM citizen_registry`""
Write-Host ""

Write-Host "✓ Database seeding script ready" -ForegroundColor Green
