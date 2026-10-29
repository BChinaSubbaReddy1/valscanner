$ErrorActionPreference = "Stop"
$root = Split-Path -Parent $MyInvocation.MyCommand.Path
$project = "browser-egress-test-$PID"
$composeFile = Join-Path $root "compose.boundary.yml"

function Get-ContainerIp($containerName, $networkName) {
    $inspection = docker inspect $containerName | ConvertFrom-Json
    if ($LASTEXITCODE -ne 0 -or $inspection.Count -eq 0) {
        return ""
    }
    $network = $inspection[0].NetworkSettings.Networks.PSObject.Properties[$networkName]
    if ($null -eq $network) {
        return ""
    }
    return $network.Value.IPAddress
}

function Get-NetworkForContainer($containerId) {
    $inspection = docker inspect $containerId | ConvertFrom-Json
    if ($LASTEXITCODE -ne 0 -or $inspection.Count -eq 0) {
        throw "Could not inspect worker container $containerId"
    }
    $networks = @($inspection[0].NetworkSettings.Networks.PSObject.Properties.Name)
    if ($networks.Count -ne 1) {
        throw "Worker has unexpected network attachments: $($networks -join ',')"
    }
    return $networks[0]
}

$backendIp = Get-ContainerIp "vulnscanner-backend" "vulnscanner-lab"
$mysqlIp = Get-ContainerIp "vulnscanner-mysql" "vulnscanner-lab"
$decoyIp = Get-ContainerIp "welcome-to-docker" "bridge"
$blockedIps = @($backendIp, $mysqlIp, $decoyIp) | Where-Object { $_ }
$env:BOUNDARY_BLOCKED_IPS = $blockedIps -join ","
Write-Output "Container-isolation probes: $($env:BOUNDARY_BLOCKED_IPS)"

Push-Location $root
try {
    docker compose -p $project -f $composeFile config --quiet
    if ($LASTEXITCODE -ne 0) {
        throw "Docker Compose configuration validation failed"
    }

    docker compose -p $project -f $composeFile build
    if ($LASTEXITCODE -ne 0) {
        throw "Could not build boundary test images"
    }

    $env:BOUNDARY_EXPIRES_AT = (Get-Date).ToUniversalTime().AddSeconds(50).ToString("yyyy-MM-dd'T'HH:mm:ss'Z'")
    docker compose -p $project -f $composeFile up --wait --wait-timeout 90 -d `
        egress-gateway egress-gateway-scan-b egress-gateway-expiry `
        fixture-target fixture-decoy fixture-dns egress-sentinel
    if ($LASTEXITCODE -ne 0) {
        throw "Could not start healthy boundary gateways and fixtures"
    }

    $workerAName = "$project-worker-a"
    $workerBName = "$project-worker-b"
    $workerAOutput = & $env:ComSpec /c "docker compose -p $project -f `"$composeFile`" run -d --no-deps --name $workerAName test-worker worker_test.py 2>NUL"
    $workerAId = $workerAOutput | Where-Object { "$_" -match "^[0-9a-f]{64}$" } |
        Select-Object -Last 1
    if ($LASTEXITCODE -ne 0 -or -not $workerAId) {
        throw "Could not start scan A worker"
    }
    $workerBOutput = & $env:ComSpec /c "docker compose -p $project -f `"$composeFile`" run -d --no-deps --name $workerBName test-worker-scan-b worker_isolation_test.py 2>NUL"
    $workerBId = $workerBOutput | Where-Object { "$_" -match "^[0-9a-f]{64}$" } |
        Select-Object -Last 1
    if ($LASTEXITCODE -ne 0 -or -not $workerBId) {
        throw "Could not start scan B worker"
    }
    $workerExpiryName = "$project-worker-expiry"
    $workerExpiryOutput = & $env:ComSpec /c "docker compose -p $project -f `"$composeFile`" run -d --no-deps --name $workerExpiryName test-worker-expiry worker_expiry_test.py 2>NUL"
    $workerExpiryId = $workerExpiryOutput | Where-Object { "$_" -match "^[0-9a-f]{64}$" } |
        Select-Object -Last 1
    if ($LASTEXITCODE -ne 0 -or -not $workerExpiryId) {
        throw "Could not start live relay-expiry worker"
    }

    $workerANetwork = Get-NetworkForContainer $workerAId
    $workerBNetwork = Get-NetworkForContainer $workerBId
    $workerExpiryNetwork = Get-NetworkForContainer $workerExpiryId
    if ($workerANetwork -notlike "*browser-worker" -or $workerBNetwork -notlike "*browser-worker-b" -or
        $workerExpiryNetwork -notlike "*browser-worker-c") {
        throw "Scan workers are attached to unexpected networks: $workerANetwork, $workerBNetwork, $workerExpiryNetwork"
    }
    foreach ($networkName in @($workerANetwork, $workerBNetwork, $workerExpiryNetwork)) {
        $network = docker network inspect $networkName | ConvertFrom-Json
        if ($LASTEXITCODE -ne 0 -or -not $network[0].Internal) {
            throw "Worker network $networkName is not isolated"
        }
        $members = @($network[0].Containers.PSObject.Properties.Value.Name)
        if ($members.Count -ne 2 -or
            -not ($members | Where-Object { $_ -like "*egress-gateway*" }) -or
            -not ($members | Where-Object { $_ -like "*worker-*" })) {
            throw "Unexpected containers on $networkName`: $($members -join ',')"
        }
    }
    Write-Output "PASS: simultaneous workers and gateways occupy separate internal networks"

    $gatewayAId = docker compose -p $project -f $composeFile ps -q egress-gateway
    $gatewayBId = docker compose -p $project -f $composeFile ps -q egress-gateway-scan-b
    $gatewayExpiryId = docker compose -p $project -f $composeFile ps -q egress-gateway-expiry
    foreach ($gatewayId in @($gatewayAId, $gatewayBId, $gatewayExpiryId)) {
        $gatewayInspection = docker inspect $gatewayId | ConvertFrom-Json
        $gatewayNetworks = @($gatewayInspection[0].NetworkSettings.Networks.PSObject.Properties.Name)
        if ($gatewayNetworks.Count -lt 2 -or
            -not ($gatewayNetworks | Where-Object { $_ -like "*browser-worker*" }) -or
            -not ($gatewayNetworks | Where-Object { $_ -like "*browser-fixtures" })) {
            throw "Gateway network attachments do not match the isolated topology"
        }
        if ($gatewayId -ne $gatewayExpiryId) {
            if (-not ($gatewayNetworks | Where-Object { $_ -like "*browser-outbound" })) {
                throw "Per-scan fixture gateway is missing its outbound test network"
            }
            $policyMount = @($gatewayInspection[0].Mounts |
                Where-Object { $_.Destination -eq "/etc/browser-egress/policy.json" })
            if ($policyMount.Count -ne 1 -or $policyMount[0].RW) {
                throw "Gateway policy fixture is not mounted read-only"
            }
        }
    }
    foreach ($workerId in @($workerAId, $workerBId, $workerExpiryId)) {
        $workerInspection = docker inspect $workerId | ConvertFrom-Json
        if (@($workerInspection[0].Mounts).Count -ne 0) {
            throw "Worker unexpectedly has a host mount"
        }
    }
    Write-Output "PASS: per-scan policies are mounted read-only and not exposed to workers"

    $workerAExit = docker wait $workerAId
    $workerBExit = docker wait $workerBId
    $workerExpiryExit = docker wait $workerExpiryId
    if ($workerAExit.Trim() -ne "0" -or $workerBExit.Trim() -ne "0" -or
        $workerExpiryExit.Trim() -ne "0") {
        docker logs $workerAId
        docker logs $workerBId
        docker logs $workerExpiryId
        foreach ($gatewayService in @(
                "egress-gateway", "egress-gateway-scan-b", "egress-gateway-expiry")) {
            $gatewayId = docker compose -p $project -f $composeFile ps -q $gatewayService
            docker logs $gatewayId
        }
        throw "Scan-worker tests failed: A=$workerAExit B=$workerBExit expiry=$workerExpiryExit"
    }
    docker logs $workerAId
    docker logs $workerBId
    docker logs $workerExpiryId
    Write-Output "PASS: live HTTP and HTTPS relays closed at policy expiry"
    Write-Output "PASS: HTTPS CONNECT, IPv6, concurrency, timeout, DNS, and policy checks"

    $cancelName = "$project-cancel-worker"
    $cancelOutput = & $env:ComSpec /c "docker compose -p $project -f `"$composeFile`" run -d --no-deps --name $cancelName test-worker worker_hold.py 2>NUL"
    $cancelId = $cancelOutput | Where-Object { "$_" -match "^[0-9a-f]{64}$" } |
        Select-Object -Last 1
    if ($LASTEXITCODE -ne 0 -or -not $cancelId) {
        throw "Could not start cancellation worker"
    }
    $cancelNetwork = Get-NetworkForContainer $cancelId
    $network = docker network inspect $cancelNetwork | ConvertFrom-Json
    $members = @($network[0].Containers.PSObject.Properties.Value.Name)
    if ($members.Count -ne 2 -or
        -not ($members | Where-Object { $_ -like "*cancel-worker" }) -or
        -not ($members | Where-Object { $_ -like "*egress-gateway*" })) {
        throw "Unexpected network members during cancellation: $($members -join ',')"
    }
    Write-Output "PASS: worker is the only scan process attached to its gateway network"

    docker stop --time 2 $cancelId | Out-Null
    if ($LASTEXITCODE -ne 0) {
        throw "Cancellation did not stop worker"
    }
    $cancelInspection = docker inspect $cancelId | ConvertFrom-Json
    if ($cancelInspection[0].State.Running) {
        throw "Worker remains active after cancellation"
    }
    docker rm $cancelId | Out-Null
    Write-Output "PASS: worker process terminates on cancellation"

    $ErrorActionPreference = "Continue"
    & $env:ComSpec /c "docker compose -p $project -f `"$composeFile`" down --remove-orphans >NUL 2>&1"
    $ErrorActionPreference = "Stop"
    if ($LASTEXITCODE -ne 0) {
        throw "Could not clean up boundary test containers"
    }
    $remaining = docker ps -aq --filter "label=com.docker.compose.project=$project"
    $remainingNetworks = docker network ls -q --filter "label=com.docker.compose.project=$project"
    if ($remaining -or $remainingNetworks) {
        throw "Test containers or networks remain after cleanup"
    }
    Write-Output "PASS: gateway, worker, and network resources are removed"
}
finally {
    $ErrorActionPreference = "Continue"
    & $env:ComSpec /c "docker compose -p $project -f `"$composeFile`" down --remove-orphans >NUL 2>&1"
    $ErrorActionPreference = "Stop"
    Pop-Location
    Remove-Item Env:\BOUNDARY_BLOCKED_IPS -ErrorAction SilentlyContinue
    Remove-Item Env:\BOUNDARY_EXPIRES_AT -ErrorAction SilentlyContinue
}
