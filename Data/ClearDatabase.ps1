# Database connection parameters
$server = "localhost\SQLEXPRESS"
$database = "EduSyncDB"

# Path to the SQL script
$sqlScriptPath = Join-Path $PSScriptRoot "ClearDatabase.sql"

# Read the SQL script content
$sqlScript = Get-Content -Path $sqlScriptPath -Raw

# Create the connection string using Windows Authentication
$connectionString = "Server=$server;Database=$database;Trusted_Connection=True;TrustServerCertificate=True"

try {
    # Create a new SQL connection
    $connection = New-Object System.Data.SqlClient.SqlConnection
    $connection.ConnectionString = $connectionString
    $connection.Open()

    # Create a command object
    $command = New-Object System.Data.SqlClient.SqlCommand
    $command.Connection = $connection
    $command.CommandText = $sqlScript

    # Execute the script
    Write-Host "Executing database cleanup script..."
    $command.ExecuteNonQuery() | Out-Null

    Write-Host "Database cleanup completed successfully!"
}
catch {
    Write-Host "Error executing database cleanup script: $_"
}
finally {
    if ($connection.State -eq 'Open') {
        $connection.Close()
    }
} 