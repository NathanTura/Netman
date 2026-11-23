#!/usr/bin/env bash
# Netman Common Networking Library (WSL Ubuntu)
# Shared discovery and helper functions for Netman NOC

set -u

# Suppress stderr noise from WSL systemd if any
exec 2>/dev/null

get_default_iface() {
    local iface
    iface=$(ip route show default 2>/dev/null | awk '/default/ {print $5; exit}')
    if [ -z "$iface" ]; then
        iface=$(ip link show up 2>/dev/null | awk -F': ' '$2 != "lo" && $2 != "" {print $2; exit}')
    fi
    [ -z "$iface" ] && iface="eth0"
    echo "$iface"
}

get_default_gateway() {
    local gw
    gw=$(ip route show default 2>/dev/null | awk '/default/ {print $3; exit}')
    echo "$gw"
}

get_local_ip() {
    local iface="${1:-eth0}"
    local ip
    ip=$(ip -4 addr show "$iface" 2>/dev/null | awk '/inet / {print $2; exit}' | cut -d/ -f1)
    echo "$ip"
}

get_local_mac() {
    local iface="${1:-eth0}"
    local mac=""
    if [ -f "/sys/class/net/${iface}/address" ]; then
        mac=$(cat "/sys/class/net/${iface}/address" 2>/dev/null)
    fi
    echo "$mac"
}

get_dns_servers() {
    local dns=""
    if [ -f "/etc/resolv.conf" ]; then
        dns=$(awk '/^nameserver/ {print $2}' /etc/resolv.conf | tr '\n' ',' | sed 's/,$//')
    fi
    [ -z "$dns" ] && dns="Not Available"
    echo "$dns"
}

format_bytes() {
    local bytes="${1:-0}"
    if [ "$bytes" -ge 1073741824 ]; then
        echo "$(awk "BEGIN {printf \"%.2f GB\", $bytes / 1073741824}")"
    elif [ "$bytes" -ge 1048576 ]; then
        echo "$(awk "BEGIN {printf \"%.2f MB\", $bytes / 1048576}")"
    elif [ "$bytes" -ge 1024 ]; then
        echo "$(awk "BEGIN {printf \"%.2f KB\", $bytes / 1024}")"
    else
        echo "${bytes} B"
    fi
}
