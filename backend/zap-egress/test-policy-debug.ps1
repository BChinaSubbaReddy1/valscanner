$ErrorActionPreference = 'Stop'

$entrypoint = Join-Path $PSScriptRoot 'entrypoint.sh'
$squidConfig = Join-Path $PSScriptRoot 'squid-debug.conf'
$containerTest = @'
set -euo pipefail

dump_diagnostics() {
    echo "=== /run/squid/approved-labs.conf ===" >&2
    if [ -r /run/squid/approved-labs.conf ]; then
        awk '{ printf "%5d %s\n", NR, $0 }' /run/squid/approved-labs.conf >&2
    else
        echo "(missing)" >&2
    fi
    echo "=== entrypoint startup output and Squid stdout/stderr ===" >&2
    cat /tmp/squid.log >&2 || echo "(missing)" >&2
    echo "=== Squid configuration check ===" >&2
    if /usr/sbin/squid -k parse -f /etc/squid/squid.conf >/tmp/squid-config-check.log 2>&1; then
        config_status=0
    else
        config_status=$?
    fi
    cat /tmp/squid-config-check.log >&2 || echo "(missing)" >&2
    echo "Squid configuration-check exit status: $config_status" >&2
    for log_file in /var/log/squid/cache.log /var/log/squid/access.log; do
        if [ -r "$log_file" ]; then
            echo "=== $log_file ===" >&2
            cat "$log_file" >&2
        fi
    done
    echo "=== end diagnostics ===" >&2
}
fail() {
    echo "DEBUG-HARNESS FAILURE: $1 (exit status ${2:-1})" >&2
    dump_diagnostics
    exit "${2:-1}"
}

/usr/local/bin/zap-egress-entrypoint.sh >/tmp/squid.log 2>&1 &
proxy_pid=$!
trap 'kill "$proxy_pid" 2>/dev/null || true; wait "$proxy_pid" 2>/dev/null || true' EXIT
sleep 2
if ! kill -0 "$proxy_pid" 2>/dev/null; then
    if wait "$proxy_pid"; then entrypoint_status=0; else entrypoint_status=$?; fi
    if [ "$entrypoint_status" -eq 0 ]; then entrypoint_status=20; fi
    fail "entrypoint/squid process exited before assertions ran; command exit status $entrypoint_status" "$entrypoint_status"
fi

echo "=== generated approved-labs ACL ===" >&2
awk '{ printf "%5d %s\n", NR, $0 }' /run/squid/approved-labs.conf >&2
grep -Fqx 'acl approved_lab_1 dstdomain lab.example' /run/squid/approved-labs.conf \
    || fail "approved-labs.conf missing expected dstdomain line" 21
grep -Fqx 'acl approved_lab_port_1 port 18080' /run/squid/approved-labs.conf \
    || fail "approved-labs.conf missing expected port line" 22
grep -Fqx 'acl approved_lab_addr_1 dst 127.0.0.1' /run/squid/approved-labs.conf \
    || fail "approved-labs.conf missing expected dst line" 23
grep -Fqx 'http_access allow approved_lab_1 approved_lab_port_1 approved_lab_addr_1' /run/squid/approved-labs.conf \
    || fail "approved-labs.conf missing expected http_access line" 24

request_status() {
    local url=$1
    local host=$2
    local probe=$3
    local status_line
    if ! exec 3<>/dev/tcp/127.0.0.1/3128; then
        fail "$probe: connection to Squid proxy failed" 30
    fi
    printf 'GET %s HTTP/1.1\r\nHost: %s\r\nConnection: close\r\n\r\n' "$url" "$host" >&3
    if ! IFS= read -r status_line <&3; then
        exec 3>&-
        fail "$probe: no HTTP status line received" 31
    fi
    exec 3>&-
    status_line=${status_line%$'\r'}
    if [[ ! $status_line =~ ^HTTP/[0-9]+(\.[0-9]+)?[[:space:]]([0-9]{3})([[:space:]]|$) ]]; then
        fail "$probe: malformed HTTP status line: $status_line" 32
    fi
    status_code=${BASH_REMATCH[2]}
    printf '%s' "$status_code"
}

private_status=$(request_status http://private.example/ private.example private)
metadata_status=$(request_status http://metadata.example/ metadata.example metadata)
metadata6_status=$(request_status http://metadata6.example/ metadata6.example metadata6)
mapped_metadata_status=$(request_status http://mapped-metadata.example/ mapped-metadata.example mapped-metadata)
mapped_private_status=$(request_status 'http://[::ffff:10.0.0.1]/' '[::ffff:10.0.0.1]' mapped-private)
mapped_loopback_status=$(request_status 'http://[::ffff:127.0.0.1]/' '[::ffff:127.0.0.1]' mapped-loopback)
mapped_link_local_status=$(request_status 'http://[::ffff:169.254.169.254]/' '[::ffff:169.254.169.254]' mapped-link-local)
mapped_public_status=$(request_status 'http://[::ffff:93.184.216.34]/' '[::ffff:93.184.216.34]' mapped-public)
lab_status=$(request_status http://lab.example:18080/ lab.example lab)
lab_wrong_port_status=$(request_status http://lab.example:18081/ lab.example lab-wrong-port)
lab_subdomain_status=$(request_status http://sub.lab.example:18080/ sub.lab.example lab-subdomain)
public_status=$(request_status http://public.example/ public.example public)

printf 'private=%s\nmetadata=%s\nmetadata6=%s\nmapped_metadata=%s\nmapped_private=%s\nmapped_loopback=%s\nmapped_link_local=%s\nmapped_public=%s\nlab=%s\nlab_wrong_port=%s\nlab_subdomain=%s\npublic=%s\n' \
    "$private_status" "$metadata_status" "$metadata6_status" "$mapped_metadata_status" \
    "$mapped_private_status" "$mapped_loopback_status" "$mapped_link_local_status" "$mapped_public_status" \
    "$lab_status" "$lab_wrong_port_status" "$lab_subdomain_status" "$public_status"
case "$private_status" in 403) ;; *) fail "private.example expected 403, got $private_status" 11 ;; esac
case "$metadata_status" in 403) ;; *) fail "metadata.example expected 403, got $metadata_status" 12 ;; esac
case "$metadata6_status" in 403) ;; *) fail "metadata6.example expected 403, got $metadata6_status" 13 ;; esac
case "$mapped_metadata_status" in 403) ;; *) fail "mapped-metadata.example expected 403, got $mapped_metadata_status" 14 ;; esac
case "$mapped_private_status" in 403) ;; *) fail "mapped private IPv4 expected 403, got $mapped_private_status" 15 ;; esac
case "$mapped_loopback_status" in 403) ;; *) fail "mapped loopback IPv4 expected 403, got $mapped_loopback_status" 16 ;; esac
case "$mapped_link_local_status" in 403) ;; *) fail "mapped link-local IPv4 expected 403, got $mapped_link_local_status" 17 ;; esac
case "$mapped_public_status" in 403) fail "mapped public IPv4 expected non-403, got 403" 18 ;; esac
case "$lab_status" in 403) fail "lab.example expected allow, got 403" 20 ;; esac
case "$lab_wrong_port_status" in 403) ;; *) fail "lab.example:wrong-port expected 403, got $lab_wrong_port_status" 21 ;; esac
case "$lab_subdomain_status" in 403) ;; *) fail "sub.lab.example expected 403, got $lab_subdomain_status" 22 ;; esac
case "$public_status" in 403) fail "public.example expected allow, got 403" 23 ;; esac
'@
$containerTest = $containerTest -replace "`r", ''
$encodedContainerTest = [Convert]::ToBase64String([Text.Encoding]::UTF8.GetBytes($containerTest))
$containerCommand = "printf '%s' '$encodedContainerTest' | base64 -d | /bin/bash -s"

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
    '-c', $containerCommand
)

& docker @dockerArgs
if ($LASTEXITCODE -ne 0) {
    throw "ZAP egress policy regression test failed with exit code $LASTEXITCODE"
}
