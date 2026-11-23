#!/usr/bin/env bash
# Netman Real-time Interface Bandwidth & Telemetry Script
# Reads Linux network counters, calculates delta throughput, and measures ping latency.

set -u
exec 2>/dev/null

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
source "${SCRIPT_DIR}/net_common.sh"

IFACE="${1:-$(get_default_iface)}"
SAMPLE_INTERVAL="${2:-1}"

get_rx_bytes() {
    local iface="$1"
    if [ -f "/sys/class/net/${iface}/statistics/rx_bytes" ]; then
        cat "/sys/class/net/${iface}/statistics/rx_bytes" 2>/dev/null
    else
        awk -v dev="$iface" '$1 ~ "^"dev":" {print $2}' /proc/net/dev 2>/dev/null
    fi
}

get_tx_bytes() {
    local iface="$1"
    if [ -f "/sys/class/net/${iface}/statistics/tx_bytes" ]; then
        cat "/sys/class/net/${iface}/statistics/tx_bytes" 2>/dev/null
    else
        awk -v dev="$iface" '$1 ~ "^"dev":" {print $10}' /proc/net/dev 2>/dev/null
    fi
}

get_rx_packets() {
    local iface="$1"
    if [ -f "/sys/class/net/${iface}/statistics/rx_packets" ]; then
        cat "/sys/class/net/${iface}/statistics/rx_packets" 2>/dev/null
    else
        echo 0
    fi
}

get_tx_packets() {
    local iface="$1"
    if [ -f "/sys/class/net/${iface}/statistics/tx_packets" ]; then
        cat "/sys/class/net/${iface}/statistics/tx_packets" 2>/dev/null
    else
        echo 0
    fi
}

get_rx_errors() {
    local iface="$1"
    if [ -f "/sys/class/net/${iface}/statistics/rx_errors" ]; then
        cat "/sys/class/net/${iface}/statistics/rx_errors" 2>/dev/null
    else
        echo 0
    fi
}

get_tx_errors() {
    local iface="$1"
    if [ -f "/sys/class/net/${iface}/statistics/tx_errors" ]; then
        cat "/sys/class/net/${iface}/statistics/tx_errors" 2>/dev/null
    else
        echo 0
    fi
}

measure_ping() {
    local target="$1"
    local ping_out rtt loss
    ping_out=$(ping -c 2 -W 1 "$target" 2>/dev/null)
    if [ -z "$ping_out" ]; then
        echo "0.0 0.0 100.0"
        return
    fi

    loss=$(echo "$ping_out" | awk -F',' '/packet loss/ {for(i=1;i<=NF;i++) if($i~/packet loss/) {gsub(/[^0-9.]/,"",$i); print $i}}')
    [ -z "$loss" ] && loss="0.0"

    local rtt_avg rtt_mdev
    rtt_avg=$(echo "$ping_out" | awk -F'/' '/rtt|round-trip/ {print $5}')
    rtt_mdev=$(echo "$ping_out" | awk -F'/' '/rtt|round-trip/ {print $7}' | awk '{print $1}')
    [ -z "$rtt_avg" ] && rtt_avg="0.0"
    [ -z "$rtt_mdev" ] && rtt_mdev="0.0"

    echo "$rtt_avg $rtt_mdev $loss"
}

RX1=$(get_rx_bytes "$IFACE")
TX1=$(get_tx_bytes "$IFACE")
T1=$(date +%s%N 2>/dev/null || date +%s)

sleep "$SAMPLE_INTERVAL"

RX2=$(get_rx_bytes "$IFACE")
TX2=$(get_tx_bytes "$IFACE")
T2=$(date +%s%N 2>/dev/null || date +%s)

RX1=${RX1:-0}
TX1=${TX1:-0}
RX2=${RX2:-0}
TX2=${TX2:-0}

DELTA_RX=$(( RX2 >= RX1 ? RX2 - RX1 : 0 ))
DELTA_TX=$(( TX2 >= TX1 ? TX2 - TX1 : 0 ))

# Calculate actual elapsed seconds
DELTA_TIME=$(awk -v t1="$T1" -v t2="$T2" -v def="$SAMPLE_INTERVAL" 'BEGIN {
    dt = (t2 - t1) / 1000000000;
    if (dt <= 0.001 || dt > 10.0) dt = def;
    printf "%.4f", dt;
}')

# Compute real Mbps: (bytes * 8) / (seconds * 1,000,000)
DOWN_MBPS=$(awk -v drx="$DELTA_RX" -v dt="$DELTA_TIME" 'BEGIN {
    mbps = (drx * 8.0) / (dt * 1000000.0);
    printf "%.3f", mbps;
}')

UP_MBPS=$(awk -v dtx="$DELTA_TX" -v dt="$DELTA_TIME" 'BEGIN {
    mbps = (dtx * 8.0) / (dt * 1000000.0);
    printf "%.3f", mbps;
}')

RX_PKTS=$(get_rx_packets "$IFACE")
TX_PKTS=$(get_tx_packets "$IFACE")
RX_ERRS=$(get_rx_errors "$IFACE")
TX_ERRS=$(get_tx_errors "$IFACE")

GATEWAY=$(get_default_gateway)
[ -z "$GATEWAY" ] && GATEWAY="Not Available"

LATENCY_AVG="0.0"
LATENCY_JITTER="0.0"
PACKET_LOSS="0.0"

if [ "$GATEWAY" != "Not Available" ]; then
    read -r LATENCY_AVG LATENCY_JITTER PACKET_LOSS <<< "$(measure_ping "$GATEWAY")"
fi

LOCAL_IP=$(get_local_ip "$IFACE")
[ -z "$LOCAL_IP" ] && LOCAL_IP="Not Available"

LOCAL_MAC=$(get_local_mac "$IFACE")
[ -z "$LOCAL_MAC" ] && LOCAL_MAC="Not Available"

FORMATTED_RX=$(format_bytes "$RX2")
FORMATTED_TX=$(format_bytes "$TX2")

TIMESTAMP=$(date -Iseconds 2>/dev/null || date +"%Y-%m-%dT%H:%M:%S")
TIME_STR=$(date +"%H:%M:%S")

cat <<EOF
{
  "timestamp": "${TIMESTAMP}",
  "time_str": "${TIME_STR}",
  "interface": "${IFACE}",
  "local_ip": "${LOCAL_IP}",
  "local_mac": "${LOCAL_MAC}",
  "gateway_ip": "${GATEWAY}",
  "download_mbps": ${DOWN_MBPS},
  "upload_mbps": ${UP_MBPS},
  "delta_rx_bytes": ${DELTA_RX},
  "delta_tx_bytes": ${DELTA_TX},
  "total_rx_bytes": ${RX2},
  "total_tx_bytes": ${TX2},
  "total_rx_formatted": "${FORMATTED_RX}",
  "total_tx_formatted": "${FORMATTED_TX}",
  "rx_packets": ${RX_PKTS},
  "tx_packets": ${TX_PKTS},
  "rx_errors": ${RX_ERRS},
  "tx_errors": ${TX_ERRS},
  "latency_ms": ${LATENCY_AVG},
  "jitter_ms": ${LATENCY_JITTER},
  "packet_loss_pct": ${PACKET_LOSS},
  "sample_interval_sec": ${DELTA_TIME}
}
EOF
