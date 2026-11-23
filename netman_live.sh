#!/usr/bin/env bash
# Netman Live Network Telemetry Engine (WSL)
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
exec "${SCRIPT_DIR}/scripts/netman_live.sh" "$@"
