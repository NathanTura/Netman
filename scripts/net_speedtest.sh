#!/usr/bin/env bash
# Netman Real On-Demand Internet Speed Test (WSL Ubuntu)
# Explicitly initiated benchmark against external CDN.
# Distinguishes internet speed test from local interface throughput.

set -u
exec 2>/dev/null

TEST_URL="${1:-https://speed.cloudflare.com/__down?bytes=10000000}"
PROVIDER="Cloudflare CDN"

# Run benchmark with 6-second timeout
curl_out=$(curl -s -w "%{http_code} %{speed_download} %{size_download} %{time_total}" -o /dev/null --max-time 6 "$TEST_URL" 2>/dev/null)

http_code=$(echo "$curl_out" | awk '{print $1}')
speed_bytes_sec=$(echo "$curl_out" | awk '{print $2}')
size_bytes=$(echo "$curl_out" | awk '{print $3}')
total_time=$(echo "$curl_out" | awk '{print $4}')

[ -z "$speed_bytes_sec" ] && speed_bytes_sec=0
[ -z "$total_time" ] && total_time=0
[ -z "$size_bytes" ] && size_bytes=0

# Convert bytes/sec to Mbps: (bytes/sec * 8) / 1,000,000
speed_mbps=$(awk -v bps="$speed_bytes_sec" 'BEGIN {printf "%.2f", (bps * 8.0) / 1000000.0}')

TIMESTAMP=$(date -Iseconds 2>/dev/null || date +"%Y-%m-%dT%H:%M:%S")

if [ "$http_code" = "200" ] && [ "$(awk -v mbps="$speed_mbps" 'BEGIN {print (mbps > 0.0) ? 1 : 0}')" -eq 1 ]; then
    success="true"
    msg="Speed benchmark completed successfully"
else
    success="false"
    msg="Benchmark failed or timed out. Check external internet connectivity."
fi

cat <<EOF
{
  "timestamp": "${TIMESTAMP}",
  "success": ${success},
  "message": "${msg}",
  "provider": "${PROVIDER}",
  "download_speed_mbps": ${speed_mbps},
  "bytes_downloaded": ${size_bytes},
  "duration_seconds": ${total_time}
}
EOF
