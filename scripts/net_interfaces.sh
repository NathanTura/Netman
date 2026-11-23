#!/usr/bin/env bash
# Netman Interfaces and Sockets Telemetry Script (WSL Ubuntu)
# Inspects Linux network adapters and active sockets using 'ip' and 'ss'.

set -u
exec 2>/dev/null

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
source "${SCRIPT_DIR}/net_common.sh"

# 1. Collect Interfaces
interfaces_json="["
first_iface=1

for dev_path in /sys/class/net/*; do
    [ -d "$dev_path" ] || continue
    ifname=$(basename "$dev_path")

    operstate="UNKNOWN"
    [ -f "${dev_path}/operstate" ] && operstate=$(cat "${dev_path}/operstate" 2>/dev/null)

    mac="N/A"
    [ -f "${dev_path}/address" ] && mac=$(cat "${dev_path}/address" 2>/dev/null)

    mtu="N/A"
    [ -f "${dev_path}/mtu" ] && mtu=$(cat "${dev_path}/mtu" 2>/dev/null)

    rx_b="0"
    [ -f "${dev_path}/statistics/rx_bytes" ] && rx_b=$(cat "${dev_path}/statistics/rx_bytes" 2>/dev/null)

    tx_b="0"
    [ -f "${dev_path}/statistics/tx_bytes" ] && tx_b=$(cat "${dev_path}/statistics/tx_bytes" 2>/dev/null)

    rx_p="0"
    [ -f "${dev_path}/statistics/rx_packets" ] && rx_p=$(cat "${dev_path}/statistics/rx_packets" 2>/dev/null)

    tx_p="0"
    [ -f "${dev_path}/statistics/tx_packets" ] && tx_p=$(cat "${dev_path}/statistics/tx_packets" 2>/dev/null)

    ipv4=$(ip -o -f inet addr show "$ifname" 2>/dev/null | awk '{print $4; exit}')
    [ -z "$ipv4" ] && ipv4="Not Configured"

    # Driver & Speed
    driver="Virtual / Kernel"
    speed="Unsupported"
    if command -v ethtool >/dev/null 2>&1; then
        drv_out=$(ethtool -i "$ifname" 2>/dev/null | awk '/driver:/ {print $2}')
        [ -n "$drv_out" ] && driver="$drv_out"
    fi
    if [ -f "${dev_path}/speed" ]; then
        s_val=$(cat "${dev_path}/speed" 2>/dev/null)
        if [ -n "$s_val" ] && [ "$s_val" -gt 0 ] 2>/dev/null; then
            speed="${s_val} Mbps"
        fi
    fi

    rx_fmt=$(format_bytes "$rx_b")
    tx_fmt=$(format_bytes "$tx_b")

    if [ $first_iface -eq 0 ]; then
        interfaces_json="${interfaces_json},"
    fi
    first_iface=0

    interfaces_json="${interfaces_json}
    {
      \"name\": \"${ifname}\",
      \"state\": \"${operstate^^}\",
      \"ipv4\": \"${ipv4}\",
      \"mac\": \"${mac}\",
      \"mtu\": ${mtu:-1500},
      \"driver\": \"${driver}\",
      \"speed\": \"${speed}\",
      \"rx_bytes\": ${rx_b:-0},
      \"tx_bytes\": ${tx_b:-0},
      \"rx_formatted\": \"${rx_fmt}\",
      \"tx_formatted\": \"${tx_fmt}\",
      \"rx_packets\": ${rx_p:-0},
      \"tx_packets\": ${tx_p:-0}
    }"
done
interfaces_json="${interfaces_json}
  ]"

# 2. Collect Listening Sockets (LISTEN, UNCONN)
listening_json="["
first_listen=1

while IFS= read -r line; do
    [ -z "$line" ] && continue
    proto=$(echo "$line" | awk '{print $1}')
    state=$(echo "$line" | awk '{print $2}')
    local_full=$(echo "$line" | awk '{print $5}')

    # Extract IP and Port
    local_ip="${local_full%:*}"
    local_port="${local_full##*:}"

    scope="All Interfaces"
    if [[ "$local_ip" =~ ^127\. || "$local_ip" == "[::1]" || "$local_ip" == *"%lo" ]]; then
        scope="Local Loopback (Isolated)"
    elif [[ "$local_ip" =~ ^(10\.|172\.|192\.168\.) ]]; then
        scope="Host Subnet"
    fi

    if [ $first_listen -eq 0 ]; then
        listening_json="${listening_json},"
    fi
    first_listen=0

    listening_json="${listening_json}
    {
      \"protocol\": \"${proto^^}\",
      \"state\": \"${state}\",
      \"local_address\": \"${local_ip}\",
      \"port\": \"${local_port}\",
      \"scope\": \"${scope}\"
    }"
done < <(ss -H -t -u -l -n 2>/dev/null)

listening_json="${listening_json}
  ]"

# 3. Collect Established / Active Sockets
established_json="["
first_estab=1

while IFS= read -r line; do
    [ -z "$line" ] && continue
    proto=$(echo "$line" | awk '{print $1}')
    state=$(echo "$line" | awk '{print $2}')
    local_full=$(echo "$line" | awk '{print $5}')
    peer_full=$(echo "$line" | awk '{print $6}')

    # Only non-listening states
    [ "$state" = "LISTEN" ] && continue
    [ "$state" = "UNCONN" ] && continue

    if [ $first_estab -eq 0 ]; then
        established_json="${established_json},"
    fi
    first_estab=0

    established_json="${established_json}
    {
      \"protocol\": \"${proto^^}\",
      \"state\": \"${state}\",
      \"local_endpoint\": \"${local_full}\",
      \"peer_endpoint\": \"${peer_full}\"
    }"
done < <(ss -H -t -u -a -n 2>/dev/null)

established_json="${established_json}
  ]"

TOTAL_IFACES=$(echo "$interfaces_json" | grep -c '"name":' || echo 0)
TOTAL_LISTEN=$(echo "$listening_json" | grep -c '"protocol":' || echo 0)
TOTAL_ESTAB=$(echo "$established_json" | grep -c '"protocol":' || echo 0)

TIMESTAMP=$(date -Iseconds 2>/dev/null || date +"%Y-%m-%dT%H:%M:%S")

cat <<EOF
{
  "timestamp": "${TIMESTAMP}",
  "total_interfaces": ${TOTAL_IFACES},
  "total_listening_ports": ${TOTAL_LISTEN},
  "total_established_connections": ${TOTAL_ESTAB},
  "interfaces": ${interfaces_json},
  "listening_ports": ${listening_json},
  "active_connections": ${established_json}
}
EOF
