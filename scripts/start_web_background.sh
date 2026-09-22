#!/usr/bin/env bash
set -euo pipefail

HOST="${HOST:-0.0.0.0}"
PORT="${PORT:-8000}"
CACHE_DIR="${CACHE_DIR:-.web_cache}"
LOG_FILE="${LOG_FILE:-$CACHE_DIR/web_metadata_app.log}"
PID_FILE="${PID_FILE:-$CACHE_DIR/web_metadata_app.pid}"
PYTHON_BIN="${PYTHON_BIN:-python}"

mkdir -p "$CACHE_DIR"

if [[ -f "$PID_FILE" ]]; then
  old_pid="$(cat "$PID_FILE")"
  if [[ -n "$old_pid" ]] && kill -0 "$old_pid" 2>/dev/null; then
    echo "Web UI already running with PID $old_pid"
    echo "URL: http://127.0.0.1:$PORT"
    echo "LAN: http://<this-computer-ip>:$PORT"
    exit 0
  fi
  rm -f "$PID_FILE"
fi

nohup "$PYTHON_BIN" web_metadata_app.py --host "$HOST" --port "$PORT" --cache-dir "$CACHE_DIR" >"$LOG_FILE" 2>&1 &
pid="$!"
echo "$pid" > "$PID_FILE"

echo "Started metadata web UI in the background"
echo "PID: $pid"
echo "URL: http://127.0.0.1:$PORT"
if [[ "$HOST" == "0.0.0.0" || "$HOST" == "::" ]]; then
  echo "LAN: http://<this-computer-ip>:$PORT"
fi
echo "Log: $LOG_FILE"
echo "Stop: kill $(cat "$PID_FILE")"
