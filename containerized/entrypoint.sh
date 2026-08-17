#!/usr/bin/env bash
set -euo pipefail

cleanup() {
  echo
  echo "Cleaning up…"

  # kill tracer & tail
  kill "${TRACER_PID:-}" "${TAIL_PID:-}" 2>/dev/null || true
  wait "${TRACER_PID:-}" 2>/dev/null || true
  wait "${TAIL_PID:-}"   2>/dev/null || true

  # print final trace to console
  echo
  echo "Final contents of ${TRACE}:"
  cat "$TRACE" || echo "Couldn't read $TRACE"

  TS=$(date +%Y%m%d_%H%M%S)
  DEST="/logs/c-jbpf-tracelog-${TS}.txt"
  if [[ -d /logs ]]; then
    cp "$TRACE" "$DEST"
    echo "Trace file also saved to $DEST"
  else
    echo "⚠️  /logs not mounted; could not persist trace"
  fi

  exit 0
}

trap 'cleanup; exit 130' SIGINT

FILTER=""
if [[ $# -ge 1 ]]; then
  FILTER="$1"
  echo "Using filter: '$FILTER'"
else
  echo "No filter, collecting all methods"
fi

TRACE="/opt/app/method_trace.txt"
TRACER="/opt/app/tool/ebpf-jagent"

echo "Trace file: $TRACE"

java -cp /opt/app/java-app/out \
     -XX:+DTraceAllocProbes -XX:+DTraceMethodProbes \
     com.example.Main &
JAVA_PID=$!
echo "Java app started (PID=${JAVA_PID})"

sleep 1  # let probes register

: > "$TRACE"
if [[ -n "$FILTER" ]]; then
  echo "Starting tracer for PID=${JAVA_PID} with filter='$FILTER' → $TRACE"
  "$TRACER" "-p $JAVA_PID" "-f$FILTER" "method_trace.txt" &
else
  echo "Starting tracer for PID=${JAVA_PID} (no filter) → $TRACE"
  "$TRACER" "-p $JAVA_PID" &
fi
TRACER_PID=$!
echo "eBPF tracer started (PID=${TRACER_PID})"

tail -n +1 -F "$TRACE" &
TAIL_PID=$!

echo "Waiting for Java (PID=${JAVA_PID}) to exit…"
wait "$JAVA_PID"
echo "Java app exited"

kill "$TRACER_PID" "$TAIL_PID" 2>/dev/null || true
wait "$TRACER_PID" 2>/dev/null || true
wait "$TAIL_PID"   2>/dev/null || true

echo
echo "Final contents of ${TRACE}:"
cat "$TRACE" || echo "⚠️  Couldn't read $TRACE"

if [[ -d /logs ]]; then
  cp "$TRACE" /logs/
  echo "Trace file also saved to /logs/$(basename "$TRACE")"
else
  echo "⚠️  /logs directory not found — could not persist trace"
fi

exit 0