#!/usr/bin/env bash
# Netman Security and Firewall Audit Script (WSL Ubuntu)
# Audits real firewall status, exposed listening ports, ARP integrity, and kernel network hardening.
# Absolutely no fake security events.

set -u
exec 2>/dev/null

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
source "${SCRIPT_DIR}/net_common.sh"

IFACE="${1:-$(get_default_iface)}"
GATEWAY=$(get_default_gateway)

# 1. Check Firewall Framework
fw_status="Not Available"
fw_details="iptables / ufw not installed in standard WSL image"
fw_rules_count=0

if command -v ufw >/dev/null 2>&1; then
    ufw_out=$(ufw status 2>&1 || true)
    if echo "$ufw_out" | grep -qi "Status: active"; then
        fw_status="Active"
        fw_details="UFW is active and enforcing rules"
    elif echo "$ufw_out" | grep -qi "Status: inactive"; then
        fw_status="Inactive"
        fw_details="UFW is installed but inactive"
    elif echo "$ufw_out" | grep -qi "permission denied\|must be root"; then
        fw_status="Permission Required"
        fw_details="UFW requires root privileges to query status"
    fi
elif command -v iptables >/dev/null 2>&1; then
    ipt_out=$(iptables -L -n 2>&1 || true)
    if echo "$ipt_out" | grep -qi "Chain"; then
        fw_status="Active"
        fw_rules_count=$(echo "$ipt_out" | grep -c -E 'ACCEPT|DROP|REJECT' || echo 0)
        fw_details="iptables kernel rules present (${fw_rules_count} rules)"
    elif echo "$ipt_out" | grep -qi "permission denied\|must be root"; then
        fw_status="Permission Required"
        fw_details="iptables queries require root privileges inside WSL"
    else
        fw_status="Not Available"
        fw_details="iptables backend unavailable"
    fi
elif command -v nft >/dev/null 2>&1; then
    nft_out=$(nft list ruleset 2>&1 || true)
    if echo "$nft_out" | grep -qi "table"; then
        fw_status="Active"
        fw_details="nftables ruleset active"
    else
        fw_status="Permission Required"
        fw_details="nftables requires root permissions"
    fi
else
    fw_status="Permission Required / Unsupported"
    fw_details="Netfilter/iptables tools require root privileges or host Hyper-V management"
fi

# 2. Open Sockets Attack Surface Audit
exposed_count=0
loopback_count=0

while IFS= read -r line; do
    [ -z "$line" ] && continue
    local_full=$(echo "$line" | awk '{print $5}')
    local_ip="${local_full%:*}"

    if [[ "$local_ip" =~ ^127\. || "$local_ip" == "[::1]" || "$local_ip" == *"%lo" ]]; then
        loopback_count=$((loopback_count + 1))
    elif [[ "$local_ip" == "0.0.0.0" || "$local_ip" == "[::]" || "$local_ip" == "*" ]]; then
        exposed_count=$((exposed_count + 1))
    else
        exposed_count=$((exposed_count + 1))
    fi
done < <(ss -H -t -u -l -n 2>/dev/null)

# 3. Kernel Hardening Parameters
ip_forward="0"
[ -f "/proc/sys/net/ipv4/ip_forward" ] && ip_forward=$(cat "/proc/sys/net/ipv4/ip_forward" 2>/dev/null)

syn_cookies="0"
[ -f "/proc/sys/net/ipv4/tcp_syncookies" ] && syn_cookies=$(cat "/proc/sys/net/ipv4/tcp_syncookies" 2>/dev/null)

# 4. Gateway ARP Verification
arp_status="Not Available"
gw_mac="Not Available"
if [ -n "$GATEWAY" ] && [ "$GATEWAY" != "Not Available" ]; then
    gw_arp=$(ip neigh show "$GATEWAY" 2>/dev/null)
    gw_mac=$(echo "$gw_arp" | awk '{for(i=1;i<=NF;i++) if($i=="lladdr") print $(i+1); exit}')
    gw_state=$(echo "$gw_arp" | awk '{print $NF}')
    if [ -n "$gw_mac" ]; then
        arp_status="Verified (${gw_state:-REACHABLE} - ${gw_mac})"
    else
        arp_status="Unresolved"
    fi
fi

# Build Findings JSON array
findings_json="["
findings_json="${findings_json}
  \"Firewall Engine: ${fw_status} · ${fw_details}\","

if [ "$exposed_count" -eq 0 ]; then
    findings_json="${findings_json}
  \"Socket Audit: All ${loopback_count} listening services bound to local loopback/host interface. No open 0.0.0.0 wildcard listeners.\","
else
    findings_json="${findings_json}
  \"Socket Audit: ${exposed_count} listening services accessible externally · ${loopback_count} loopback-isolated.\","
fi

if [ "$ip_forward" = "0" ]; then
    findings_json="${findings_json}
  \"IPv4 Packet Forwarding: Disabled (Protected host isolation).\","
else
    findings_json="${findings_json}
  \"IPv4 Packet Forwarding: Enabled (Routing active).\","
fi

if [ "$syn_cookies" = "1" ]; then
    findings_json="${findings_json}
  \"TCP SYN Flood Protection: Enabled (syncookies active).\","
fi

findings_json="${findings_json}
  \"ARP Gateway Integrity: ${arp_status}\""

findings_json="${findings_json}
]"

TIMESTAMP=$(date -Iseconds 2>/dev/null || date +"%Y-%m-%dT%H:%M:%S")

cat <<EOF
{
  "timestamp": "${TIMESTAMP}",
  "firewall_status": "${fw_status}",
  "firewall_details": "${fw_details}",
  "firewall_rules_count": ${fw_rules_count},
  "exposed_listening_ports": ${exposed_count},
  "loopback_listening_ports": ${loopback_count},
  "ip_forwarding_enabled": $(( ip_forward == 1 )),
  "tcp_syncookies_enabled": $(( syn_cookies == 1 )),
  "gateway_arp_status": "${arp_status}",
  "gateway_mac": "${gw_mac}",
  "findings": ${findings_json}
}
EOF
