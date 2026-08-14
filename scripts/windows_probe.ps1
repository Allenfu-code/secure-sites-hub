param(
    [string]$Ports = "",
    [switch]$Discover
)

$requestedPorts = @()
if ($Ports) {
    $requestedPorts = @(
        $Ports.Split(",") |
            ForEach-Object {
                $parsed = 0
                if ([int]::TryParse($_, [ref]$parsed) -and $parsed -ge 1 -and $parsed -le 65535) {
                    $parsed
                }
            } |
            Sort-Object -Unique
    )
}

$connections = Get-NetTCPConnection -State Listen -ErrorAction SilentlyContinue
if ($Discover) {
    $connections = $connections | Where-Object {
        $_.LocalPort -ge 1024 -and $_.LocalPort -le 20000
    }
} else {
    $connections = $connections | Where-Object {
        $_.LocalPort -in $requestedPorts
    }
}

$rows = foreach ($connection in $connections) {
    $process = Get-Process -Id $connection.OwningProcess -ErrorAction SilentlyContinue
    [pscustomobject]@{
        port = [int]$connection.LocalPort
        address = [string]$connection.LocalAddress
        pid = [int]$connection.OwningProcess
        process = if ($process) { [string]$process.ProcessName } else { "" }
    }
}

@($rows | Sort-Object port, pid -Unique) | ConvertTo-Json -Compress
