$ErrorActionPreference = 'Stop'

$entrypoint = Join-Path $PSScriptRoot 'entrypoint.sh'
$squidConfig = Join-Path $PSScriptRoot 'squid.conf'
$squidImage = 'ubuntu/squid@sha256:6a097f68bae708cedbabd6188d68c7e2e7a38cedd05a176e1cc0ba29e3bbe029'
$serverName = "zap-egress-test-server-$([guid]::NewGuid().ToString('N'))"

if (-not (Test-Path $entrypoint) -or -not (Test-Path $squidConfig)) {
    throw 'Required test files were not found.'
}

try {
    # Start a real HTTP server for the approved lab target.
    & docker run -d --rm `
        --name $serverName `
        --network bridge `
        --entrypoint /bin/sh `
        busybox:1.36 `
        -c 'mkdir -p /www; printf "egress-test-ok\n" > /www/index.html; exec httpd -f -p 18080 -h /www'

    if ($LASTEXITCODE -ne 0) {
        throw 'Could not start the temporary HTTP server.'
    }

    $labIp = (& docker inspect $serverName --format '{{range .NetworkSettings.Networks}}{{.IPAddress}}{{end}}').Trim()
    if ($LASTEXITCODE -ne 0 -or [string]::IsNullOrWhiteSpace($labIp)) {
        throw 'Could not determine the HTTP server IP.'
    }

    Start-Sleep -Seconds 2

    $containerTest = @'
set -euo pipefail

/usr/local/bin/zap-egress-entrypoint.sh >/tmp/squid.log 2>&1 &
proxy_pid=$!
trap 'kill "$proxy_pid" 2>/dev/null || true; wait "$proxy_pid" 2>/dev/null || true' EXIT

ready=0
for i in $(seq 1 20); do
    if (echo >/dev/tcp/127.0.0.1/3128) 2>/dev/null; then
        ready=1
        break
    fi
    sleep 1
done

if [ "$ready" -ne 1 ]; then
    cat /tmp/squid.log
    echo "Squid did not become ready" >&2
    exit 20
fi

grep -Fqx 'acl approved_lab_1 dstdomain lab.example' /run/squid/approved-labs.conf
grep -Fqx 'acl approved_lab_port_1 port 18080' /run/squid/approved-labs.conf
grep -Fqx "acl approved_lab_addr_1 dst $LAB_IP" /run/squid/approved-labs.conf
grep -Fqx 'http_access allow approved_lab_1 approved_lab_port_1 approved_lab_addr_1' /run/squid/approved-labs.conf

request_status() {
    local url=$1
    local host=$2
    local status_line
    local status_code

    exec 3<>/dev/tcp/127.0.0.1/3128
    printf 'GET %s HTTP/1.1\r\nHost: %s\r\nConnection: close\r\n\r\n' "$url" "$host" >&3

    if ! IFS= read -r -t 15 status_line <&3; then
        exec 3>&-
        printf 'No HTTP response for %s\n' "$url" >&2
        return 1
    fi

    exec 3>&-
    status_line=${status_line%$'\r'}
    status_code=${status_line#* }
    status_code=${status_code%% *}
    printf '%s' "$status_code"
}

private_status=$(request_status http://private.example/ private.example)
metadata_status=$(request_status http://metadata.example/ metadata.example)
metadata6_status=$(request_status http://metadata6.example/ metadata6.example)
documentation6_status=$(request_status http://documentation6.example/ documentation6.example)
mapped_metadata_status=$(request_status http://mapped-metadata.example/ mapped-metadata.example)
lab_status=$(request_status http://lab.example:18080/ lab.example)
lab_wrong_port_status=$(request_status http://lab.example:18081/ lab.example)
lab_subdomain_status=$(request_status http://sub.lab.example:18080/ sub.lab.example)
public_status=$(request_status http://public.example/ public.example)

printf 'private=%s\nmetadata=%s\nmetadata6=%s\ndocumentation6=%s\nmapped_metadata=%s\nlab=%s\nlab_wrong_port=%s\nlab_subdomain=%s\npublic=%s\n' \
    "$private_status" "$metadata_status" "$metadata6_status" "$documentation6_status" "$mapped_metadata_status" \
    "$lab_status" "$lab_wrong_port_status" "$lab_subdomain_status" "$public_status"

case "$private_status" in 403) ;; *) echo "Private destination not denied" >&2; exit 11 ;; esac
case "$metadata_status" in 403) ;; *) echo "IPv4 metadata not denied" >&2; exit 12 ;; esac
case "$metadata6_status" in 403) ;; *) echo "IPv6 metadata not denied" >&2; exit 13 ;; esac
case "$documentation6_status" in 403) ;; *) echo "IPv6 documentation range not denied" >&2; exit 19 ;; esac
case "$mapped_metadata_status" in 403) ;; *) echo "Mapped metadata not denied" >&2; exit 14 ;; esac
case "$lab_status" in 200) ;; *) echo "Approved lab target did not return 200" >&2; exit 15 ;; esac
case "$lab_wrong_port_status" in 403) ;; *) echo "Wrong lab port not denied" >&2; exit 16 ;; esac
case "$lab_subdomain_status" in 403) ;; *) echo "Unapproved subdomain not denied" >&2; exit 17 ;; esac

case "$public_status" in
    403) echo "Public destination was denied" >&2; exit 18 ;;
    503) echo "Public egress inconclusive: upstream returned 503" >&2; exit 21 ;;
    000|'') echo "Public egress inconclusive: no valid HTTP response" >&2; exit 22 ;;
    *) echo "Public destination returned an HTTP response" ;;
esac
'@

    $containerTest = $containerTest -replace "`r`n", "`n"

    # Base64 avoids PowerShell splitting the multiline Bash script.
    $encodedTest = [Convert]::ToBase64String(
        [System.Text.Encoding]::UTF8.GetBytes($containerTest)
    )

    $dockerArgs = @(
        'run', '--rm', '--network', 'bridge',
        '--add-host', 'private.example:10.0.0.1',
        '--add-host', 'metadata.example:169.254.169.254',
        '--add-host', 'metadata6.example:[fd00:ec2::254]',
        '--add-host', 'documentation6.example:[2001:db8::1]',
        '--add-host', 'mapped-metadata.example:[::ffff:169.254.169.254]',
        '--add-host', "lab.example:$labIp",
        '--add-host', "sub.lab.example:$labIp",
        '--add-host', 'public.example:104.20.23.154',
        '--entrypoint', '/bin/bash',
        '--mount', "type=bind,source=$entrypoint,target=/usr/local/bin/zap-egress-entrypoint.sh,readonly",
        '--mount', "type=bind,source=$squidConfig,target=/etc/squid/squid.conf,readonly",
        '-e', "LAB_IP=$labIp",
        '-e', "TEST_SCRIPT_B64=$encodedTest",
	'-e', 'SCANNER_ALLOWED_PRIVATE_TARGET_ORIGINS=http://lab.example:18080,http://metadata.example:80,http://mapped-metadata.example:80',
        $squidImage,
        '-c', 'printf "%s" "$TEST_SCRIPT_B64" | base64 -d > /tmp/test-policy.sh && exec /bin/bash /tmp/test-policy.sh'
    )

    & docker @dockerArgs

    if ($LASTEXITCODE -ne 0) {
        throw "ZAP egress policy regression test failed with exit code $LASTEXITCODE"
    }
}
finally {
    & docker rm -f $serverName 2>$null | Out-Null
}
