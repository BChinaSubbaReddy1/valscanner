#!/bin/sh
set -eu

origins=${SCANNER_ALLOWED_PRIVATE_TARGET_ORIGINS:-}
acl_file=/run/squid/approved-labs.conf
mkdir -p /run/squid
: > "$acl_file"

old_ifs=$IFS
IFS=','
set -f
index=0
for origin in $origins; do
    origin=$(printf '%s' "$origin" | sed 's/^[[:space:]]*//;s/[[:space:]]*$//')
    [ -n "$origin" ] || continue

    case "$origin" in
        http://*) scheme=http; authority=${origin#http://} ;;
        https://*) scheme=https; authority=${origin#https://} ;;
        *) echo "Invalid configured private target origin" >&2; exit 1 ;;
    esac
    port_specified=0
    case "$authority" in
        ""|*/*|*\?*|*#*|*@*) echo "Invalid configured private target origin" >&2; exit 1 ;;
    esac

    case "$authority" in
        \[*\]*)
            host=${authority#\[}
            host=${host%%]*}
            suffix=${authority#*]}
            case "$suffix" in
                "") port= ;;
                :*) port=${suffix#:}; port_specified=1 ;;
                *) echo "Invalid configured private target origin" >&2; exit 1 ;;
            esac
            case "$host" in
                ""|*[!A-Fa-f0-9:.]*) echo "Invalid configured private target origin" >&2; exit 1 ;;
            esac
            ;;
        *:*)
            host=${authority%:*}
            port=${authority##*:}
            port_specified=1
            case "$host" in
                *:*) echo "IPv6 private target origins must use brackets" >&2; exit 1 ;;
            esac
            case "$host" in
                ""|*[!A-Za-z0-9.-]*) echo "Invalid configured private target origin" >&2; exit 1 ;;
            esac
            ;;
        *)
            host=$authority
            port=
            case "$host" in
                ""|*[!A-Za-z0-9.-]*) echo "Invalid configured private target origin" >&2; exit 1 ;;
            esac
            ;;
    esac

    if [ "$port_specified" -eq 0 ]; then
        if [ "$scheme" = https ]; then port=443; else port=80; fi
    fi
    case "$port" in
        ""|*[!0-9]*) echo "Invalid configured private target origin" >&2; exit 1 ;;
    esac
    if ! awk -v port="$port" 'BEGIN { exit !(port >= 1 && port <= 65535) }'; then
        echo "Invalid configured private target origin" >&2
        exit 1
    fi

resolved_addresses=$(getent ahosts "$host" | awk 'NF { print $1 }' | sort -u | tr '\n' ' ')
resolved_addresses=${resolved_addresses% }
    if [ -z "$resolved_addresses" ]; then
        echo "Unable to resolve configured private target origin" >&2
        exit 1
    fi

    index=$((index + 1))
    printf 'acl approved_lab_%s dstdomain %s\n' "$index" "$host" >> "$acl_file"
    printf 'acl approved_lab_port_%s port %s\n' "$index" "$port" >> "$acl_file"
    printf 'acl approved_lab_addr_%s dst %s\n' "$index" "$resolved_addresses" >> "$acl_file"
    printf 'http_access allow approved_lab_%s approved_lab_port_%s approved_lab_addr_%s\n' "$index" "$index" "$index" >> "$acl_file"
done
IFS=$old_ifs

exec /usr/sbin/squid -N -f /etc/squid/squid.conf
