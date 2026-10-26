$ErrorActionPreference = 'Stop'

$entrypoint = Join-Path $PSScriptRoot 'entrypoint.sh'
$squidConfig = Join-Path $PSScriptRoot 'squid.conf'
$containerTest = @'
set -euo pipefail

/usr/local/bin/zap-egress-entrypoint.sh >/tmp/squid.log 2>&1 &
proxy_pid=$!
trap 'kill "$proxy_pid" 2>/dev/null || true; wait "$proxy_pid" 2>/dev/null || true' EXIT
sleep 2

grep -Fqx 'acl approved_lab_1 dstdomain lab.example' /run/squid/approved-labs.conf
grep -Fqx 'acl approved_lab_port_1 port 18080' /run/squid/approved-labs.conf
grep -Fqx 'acl approved_lab_addr_1 dst 127.0.0.1' /run/squid/approved-labs.conf
grep -Fqx 'http_access allow approved_lab_1 approved_lab_port_1 approved_lab_addr_1' /run/squid/approved-labs.conf

request_status() {
    local url=$1
    local host=$2
    local status_line
    exec 3<>/dev/tcp/127.0.0.1/3128
    printf 'GET %s HTTP/1.1\r\nHost: %s\r\nConnection: close\r\n\r\n' "$url" "$host" >&3
    IFS= read -r status_line <&3
    exec 3>&-
    status_line=${status_line%$'\r'}
    status_code=${status_line#* }
    status_code=${status_code%% *}
    printf '%s' "$status_code"
}

private_status=$(request_status http://private.example/ private.example)
metadata_status=$(request_status http://metadata.example/ metadata.example)
metadata6_status=$(request_status http://metadata6.example/ metadata6.example)
mapped_metadata_status=$(request_status http://mapped-metadata.example/ mapped-metadata.example)
lab_status=$(request_status http://lab.example:18080/ lab.example)
lab_wrong_port_status=$(request_status http://lab.example:18081/ lab.example)
lab_subdomain_status=$(request_status http://sub.lab.example:18080/ sub.lab.example)
public_status=$(request_status http://public.example/ public.example)

printf 'private=%s\nmetadata=%s\nmetadata6=%s\nmapped_metadata=%s\nlab=%s\nlab_wrong_port=%s\nlab_subdomain=%s\npublic=%s\n' \
    "$private_status" "$metadata_status" "$metadata6_status" "$mapped_metadata_status" \
    "$lab_status" "$lab_wrong_port_status" "$lab_subdomain_status" "$public_status"
case "$private_status" in 403) ;; *) exit 11 ;; esac
case "$metadata_status" in 403) ;; *) exit 12 ;; esac
case "$metadata6_status" in 403) ;; *) exit 13 ;; esac
case "$mapped_metadata_status" in 403) ;; *) exit 14 ;; esac
case "$lab_status" in 403) exit 15 ;; esac
case "$lab_wrong_port_status" in 403) ;; *) exit 16 ;; esac
case "$lab_subdomain_status" in 403) ;; *) exit 17 ;; esac
case "$public_status" in 403) exit 18 ;; esac
'@
$containerTest = $containerTest -replace "`r`n", "`n"

$dockerArgs = @(
    'run', '--rm', '--network', 'none',
    '--add-host', 'private.example:10.0.0.1',
    '--add-host', 'metadata.example:169.254.169.254',
    '--add-host', 'metadata6.example:[fd00:ec2::254]',
    '--add-host', 'mapped-metadata.example:[::ffff:169.254.169.254]',
    '--add-host', 'lab.example:127.0.0.1',
    '--add-host', 'sub.lab.example:127.0.0.1',
    '--add-host', 'public.example:93.184.216.34',
    '--entrypoint', '/bin/bash',
    '--mount', "type=bind,source=$entrypoint,target=/usr/local/bin/zap-egress-entrypoint.sh,readonly",
    '--mount', "type=bind,source=$squidConfig,target=/etc/squid/squid.conf,readonly",
    '-e', 'SCANNER_ALLOWED_PRIVATE_TARGET_ORIGINS=http://lab.example:18080,http://metadata.example:80,http://metadata6.example:80,http://mapped-metadata.example:80',
    'ubuntu/squid@sha256:6a097f68bae708cedbabd6188d68c7e2e7a38cedd05a176e1cc0ba29e3bbe029',
    '-c', $containerTest
)

& docker @dockerArgs
if ($LASTEXITCODE -ne 0) {
    throw "ZAP egress policy regression test failed with exit code $LASTEXITCODE"
}
