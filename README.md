# AWS Secrets Manager Lister

A Go program to list AWS Secrets Manager secrets and output to Parquet format for querying with DuckDB.

## Features

- Lists all secrets accessible to the authenticated user
- Outputs to Parquet format with proper data types
- `created_date` as TIMESTAMP (millisecond precision)
- `last_accessed_date` as DATE
- Tags stored as MAP(VARCHAR, VARCHAR)
- Gracefully handles "Not Authorized" errors
- Supports AWS SSO authentication via `--profile` flag

## Prerequisites

- Go 1.21 or later
- AWS CLI v2 configured with SSO profiles
- SSO login completed before running (`aws sso login --profile <profile>`)

## Installation

```bash
# Clone or download the files
cd secrets-lister

# Download dependencies
go mod tidy

# Build the binary
go build -o secrets-lister .
```

## Usage

```bash
# Using default credentials (writes to secrets.parquet)
./secrets-lister

# Using a specific SSO profile
./secrets-lister --profile my-sso-profile

# Specify output file
./secrets-lister --profile my-sso-profile --output my-secrets.parquet

# Using a specific region
./secrets-lister --region us-west-2

# Full example
./secrets-lister --profile my-sso-profile --region us-east-1 --output secrets.parquet
```

## Querying with DuckDB

```sql
-- Load the parquet file
SELECT * FROM 'secrets.parquet' LIMIT 10;

-- Query by date
SELECT name, created_date, last_accessed_date 
FROM 'secrets.parquet'
WHERE last_accessed_date < '2024-01-01';

-- Find secrets not accessed in 90 days
SELECT name, last_accessed_date
FROM 'secrets.parquet'
WHERE last_accessed_date < CURRENT_DATE - INTERVAL 90 DAY;

-- Query by tags
SELECT name, tags['Environment'] as env, tags['Team'] as team
FROM 'secrets.parquet'
WHERE tags['Environment'] = 'production';

-- Count secrets by environment tag
SELECT tags['Environment'] as environment, COUNT(*) as count
FROM 'secrets.parquet'
GROUP BY tags['Environment'];

-- Find secrets without specific tag
SELECT name 
FROM 'secrets.parquet'
WHERE tags['Owner'] IS NULL;
```

## Schema

| Column | Type | Description |
|--------|------|-------------|
| name | VARCHAR | Secret name |
| description | VARCHAR | Secret description (nullable) |
| created_date | TIMESTAMP | When the secret was created |
| last_accessed_date | DATE | When the secret was last accessed |
| tags | MAP(VARCHAR, VARCHAR) | Key-value tags |

## Required IAM Permissions

```json
{
    "Version": "2012-10-17",
    "Statement": [
        {
            "Effect": "Allow",
            "Action": "secretsmanager:ListSecrets",
            "Resource": "*"
        }
    ]
}
```

## Notes

- Authorization errors are logged to stderr and skipped gracefully
- The program assumes SSO login is completed before running
- Output file defaults to `secrets.parquet` in current directory
