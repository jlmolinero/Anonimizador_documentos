#!/usr/bin/env bash
set -euo pipefail

CACHE_DIR="${CACHE_DIR:-.web_cache}"
PID_FILE="${PID_FILE:-$CACHE_DIR/web_metadata_app.pid}"

if [[ ! -f "$PID_FILE" ]]; then
  echo "No PID file found at $PID_FILE"
  exit 0
fi

pid="$(cat "$PID_FILE")"
if [[ -z "$pid" ]]; then
  rm -f "$PID_FILE"
  echo "Removed empty PID file"
  exit 0
fi

if kill -0 "$pid" 2>/dev/null; then
  kill "$pid"
  echo "Stopped metadata web UI with PID $pid"
else
  echo "No running process found for PID $pid"
fi
rm -f "$PID_FILE"
