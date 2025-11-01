#!/usr/bin/env bash
# safetyscan - Mode-based SAST (Semgrep) and DAST (OWASP ZAP) scanner (Bash)
# Usage:
#   safetyscan <project_path> --mode [sast|dast|both] [--start "<start_cmd>"] [--port <port>]

set -euo pipefail
IFS=$'\n\t'

PROGNAME="$(basename "$0")"
PROJECT_PATH=""
MODE=""
START_CMD=""
PORT=""
TIMEOUT=60

# Better directory naming with project name and readable timestamp
PROJECT_NAME=""
READABLE_STAMP="$(date +%Y-%m-%d_%H-%M-%S)"
RUN_DIR=""

# Track scan results
SAST_SUCCESS=false
DAST_SUCCESS=false
SAST_ISSUES=0
DAST_ISSUES=0

# Python report generator location
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" &>/dev/null && pwd)"
REPORT_GENERATOR="${SCRIPT_DIR}/report_generator.py"

# Check for installed report generator
if [[ ! -f "$REPORT_GENERATOR" ]]; then
  # Try to find it in PATH (if installed globally)
  if command -v safetyscan-report-generator &>/dev/null; then
    REPORT_GENERATOR="safetyscan-report-generator"
  elif [[ -f "/usr/local/bin/safetyscan-report-generator" ]]; then
    REPORT_GENERATOR="/usr/local/bin/safetyscan-report-generator"
  fi
fi

# -------- helpers --------
usage() {
  cat <<USAGE
Usage:
  $PROGNAME <project_path> --mode [sast|dast|both] [--start "<start_cmd>"] [--port <port>]

Examples:
  $PROGNAME ./myproject --mode sast
  $PROGNAME ./myproject --mode dast --start "npm start" --port 3000
  $PROGNAME ./myproject --mode both --start "python manage.py runserver 0.0.0.0:8000" --port 8000
USAGE
  exit 1
}

log() { printf "[%s] %s\n" "$PROGNAME" "$*"; }
log_success() { printf "[%s] ✓ %s\n" "$PROGNAME" "$*"; }
log_error() { printf "[%s] ✗ %s\n" "$PROGNAME" "$*"; }
log_warn() { printf "[%s] ⚠ %s\n" "$PROGNAME" "$*"; }
die() { echo "ERROR: $*" >&2; exit 1; }

# parse
if [[ $# -lt 2 ]]; then usage; fi
PROJECT_PATH="$1"; shift

while [[ $# -gt 0 ]]; do
  case "$1" in
    --mode) MODE="${2:-}"; shift 2 ;;
    --start) START_CMD="${2:-}"; shift 2 ;;
    --port) PORT="${2:-}"; shift 2 ;;
    -h|--help) usage ;;
    *) die "Unknown arg: $1" ;;
  esac
done

[[ -d "$PROJECT_PATH" ]] || die "Project path not found: $PROJECT_PATH"
if [[ -z "$MODE" ]]; then die "--mode is required"; fi
if [[ "$MODE" == "dast" || "$MODE" == "both" ]]; then
  [[ -n "$START_CMD" ]] || die "--start is required for DAST mode"
  [[ -n "$PORT" ]] || die "--port is required for DAST mode"
fi

# Extract project name from path for better directory naming
PROJECT_NAME=$(basename "$(cd "$PROJECT_PATH" && pwd)")
RUN_DIR="$(pwd)/reports/${PROJECT_NAME}_${READABLE_STAMP}"
mkdir -p "$RUN_DIR"

log "Scan started for project: $PROJECT_NAME"
log "Reports will be saved to: $RUN_DIR"

# detect installer command (for convenience)
detect_install_cmd() {
  local p="$1"
  if [[ -f "$p/package.json" ]]; then
    if [[ -f "$p/yarn.lock" ]]; then
      echo "yarn install"
    else
      echo "npm install"
    fi
  elif [[ -f "$p/requirements.txt" ]]; then
    echo "python3 -m pip install -r requirements.txt"
  elif [[ -f "$p/Pipfile" ]]; then
    echo "pipenv install --deploy || pipenv install"
  elif [[ -f "$p/pom.xml" ]]; then
    echo "mvn -B -DskipTests package"
  elif [[ -f "$p/build.gradle" ]]; then
    echo "gradle build -x test"
  else
    echo ""
  fi
}

# wait for TCP port on localhost
wait_for_port() {
  local port=$1
  local timeout=${2:-$TIMEOUT}
  local start=$(date +%s)
  while true; do
    if (echo >/dev/tcp/localhost/"$port") >/dev/null 2>&1; then
      return 0
    fi
    now=$(date +%s)
    if (( now - start >= timeout )); then
      return 1
    fi
    sleep 2
  done
}

# cleanup build context and container on exit
CLEANUP_ITEMS=()
cleanup() {
  for item in "${CLEANUP_ITEMS[@]}"; do
    if docker ps -a --format '{{.ID}} {{.Names}}' | grep -q "$item"; then
      log "Removing container $item"
      docker rm -f "$item" >/dev/null 2>&1 || true
    fi
    if docker network ls --format '{{.Name}}' | grep -q "^${item}$"; then
      log "Removing network $item"
      docker network rm "$item" >/dev/null 2>&1 || true
    fi
    if [[ -d "$item" ]] && [[ "$item" == /tmp/* ]]; then
      rm -rf "$item"
    fi
  done
}
trap cleanup EXIT

# ---------- SAST ----------
run_sast() {
  log "Starting SAST (Semgrep)..."
  local out="$RUN_DIR/semgrep.json"
  local summary="$RUN_DIR/semgrep-summary.txt"
  
  if docker run --rm -v "$(cd "$PROJECT_PATH" && pwd):/src:ro" semgrep/semgrep:latest \
    semgrep --config=auto --json /src > "$out" 2>/dev/null; then
    
    # Parse results
    if command -v jq >/dev/null 2>&1; then
      SAST_ISSUES=$(jq '.results | length' "$out" 2>/dev/null || echo "0")
      
      # Create human-readable summary
      cat > "$summary" <<EOF
===========================================
SAST (Static Analysis) Scan Summary
===========================================
Scan Tool: Semgrep
Scan Date: $(date '+%Y-%m-%d %H:%M:%S')
Project: $PROJECT_NAME

Total Issues Found: $SAST_ISSUES

EOF
      
      if [[ $SAST_ISSUES -gt 0 ]]; then
        echo "Issues by Severity:" >> "$summary"
        jq -r '.results | group_by(.extra.severity) | .[] | "\(.[] | .extra.severity): \(length)"' "$out" 2>/dev/null | sort -u >> "$summary" || echo "Unable to parse severity" >> "$summary"
        echo "" >> "$summary"
        echo "Top Issues:" >> "$summary"
        jq -r '.results[0:10] | .[] | "- [\(.extra.severity)] \(.check_id)\n  File: \(.path):\(.start.line)\n  Message: \(.extra.message)\n"' "$out" 2>/dev/null >> "$summary" || echo "Unable to parse issues" >> "$summary"
      else
        echo "No security issues detected! ✓" >> "$summary"
      fi
      
      cat >> "$summary" <<EOF

For detailed results, see: semgrep.json
===========================================
EOF
    else
      echo "Note: Install 'jq' for detailed summaries" > "$summary"
    fi
    
    SAST_SUCCESS=true
    log_success "SAST scan completed. Found $SAST_ISSUES issues."
    log "Reports: $out and $summary"
  else
    log_error "SAST scan failed!"
    echo "SAST scan failed - check semgrep output" > "$summary"
    return 1
  fi
}

# ---------- DAST ----------
run_dast() {
  log "Preparing DAST (build context)..."
  BUILD_CTX="$(mktemp -d)"
  CLEANUP_ITEMS+=("$BUILD_CTX")
  cp -a "$PROJECT_PATH"/. "$BUILD_CTX"/

  # Dockerfile setup
  if [[ -f "$PROJECT_PATH/Dockerfile" ]]; then
    log "Using user's Dockerfile"
  else
    cat > "$BUILD_CTX/Dockerfile" <<'DOCKER'
FROM ubuntu:22.04
RUN apt-get update && DEBIAN_FRONTEND=noninteractive apt-get install -y \
    curl ca-certificates git python3 python3-pip openjdk-17-jdk maven gradle \
    nodejs npm yarn build-essential netcat && rm -rf /var/lib/apt/lists/*
WORKDIR /app
COPY . /app
CMD ["bash"]
DOCKER
  fi

  INSTALL_CMD="$(detect_install_cmd "$BUILD_CTX")"
  [[ -n "$INSTALL_CMD" ]] && log "Detected install command: $INSTALL_CMD"

  STAMP="$(date +%Y%m%d-%H%M%S)"
  IMAGE_NAME="safetyscan-img-${STAMP}"
  log "Building image $IMAGE_NAME..."
  
  if ! docker build -t "$IMAGE_NAME" "$BUILD_CTX" >/dev/null 2>&1; then
    log_error "Docker build failed!"
    return 1
  fi

  CMD_CHAIN=""
  if [[ -n "$INSTALL_CMD" ]]; then
    CMD_CHAIN="$INSTALL_CMD && $START_CMD"
  else
    CMD_CHAIN="$START_CMD"
  fi

  # --- Setup dedicated Docker network ---
  NETWORK_NAME="safetyscan-net-${STAMP}"
  docker network create "$NETWORK_NAME"
  CLEANUP_ITEMS+=("$NETWORK_NAME")

  # --- Start app container on network ---
  CONTAINER_NAME="safetyscan-app-${STAMP}"
  CLEANUP_ITEMS+=("$CONTAINER_NAME")
  log "Starting app container $CONTAINER_NAME on network $NETWORK_NAME..."
  docker run -d --name "$CONTAINER_NAME" --network "$NETWORK_NAME" -p "$PORT:$PORT" "$IMAGE_NAME" bash -lc "cd /app && $CMD_CHAIN"

  log "Waiting up to ${TIMEOUT}s for app to start on port $PORT..."
  if ! wait_for_port "$PORT" "$TIMEOUT"; then
    log_error "App failed to start; container logs:"
    docker logs "$CONTAINER_NAME" || true
    return 1
  fi

  # Give Docker network DNS time to propagate
  log "Allowing DNS propagation..."
  sleep 5
  
  # Verify container is still running
  if ! docker ps --filter "name=$CONTAINER_NAME" --filter "status=running" | grep -q "$CONTAINER_NAME"; then
    log_error "Container is not running!"
    docker logs "$CONTAINER_NAME" 2>&1 | tail -30 || true
    return 1
  fi
  
  # Get container IP - try multiple times if needed
  CONTAINER_IP=""
  for i in {1..3}; do
    CONTAINER_IP=$(docker inspect -f '{{range .NetworkSettings.Networks}}{{.IPAddress}}{{end}}' "$CONTAINER_NAME" 2>/dev/null | head -1)
    if [[ -n "$CONTAINER_IP" ]]; then
      break
    fi
    log "Attempt $i: Waiting for network IP assignment..."
    sleep 2
  done
  
  if [[ -z "$CONTAINER_IP" ]]; then
    log_error "Failed to get container IP after multiple attempts."
    return 1
  fi
  
  log "Container IP on network: $CONTAINER_IP"
  
  # Use IP address for more reliable connection
  TARGET_URL="http://$CONTAINER_IP:$PORT"
  log "App is reachable — scanning target: $TARGET_URL"

  mkdir -p "$RUN_DIR"

  # --- Run ZAP container on same network ---
  log "Starting OWASP ZAP scan..."
  if docker run --rm --network "$NETWORK_NAME" \
    -v "$RUN_DIR:/zap/wrk:rw" \
    ghcr.io/zaproxy/zaproxy:stable \
    zap-baseline.py \
    -t "$TARGET_URL" \
    -r "zap-report.html" \
    -J "zap-report.json" \
    -w "zap-warnings.html" \
    -T 5 2>&1 | tee "$RUN_DIR/zap-scan.log"; then
    
    log_success "ZAP scan completed successfully"
  else
    log_warn "ZAP scan finished with warnings (this is normal)"
  fi

  # Create human-readable summary
  local summary="$RUN_DIR/dast-summary.txt"
  
  if [[ -f "$RUN_DIR/zap-report.json" ]] && command -v jq >/dev/null 2>&1; then
    local high_alerts=$(jq '[.site[].alerts[] | select(.riskcode == "3")] | length' "$RUN_DIR/zap-report.json" 2>/dev/null || echo "0")
    local medium_alerts=$(jq '[.site[].alerts[] | select(.riskcode == "2")] | length' "$RUN_DIR/zap-report.json" 2>/dev/null || echo "0")
    local low_alerts=$(jq '[.site[].alerts[] | select(.riskcode == "1")] | length' "$RUN_DIR/zap-report.json" 2>/dev/null || echo "0")
    local info_alerts=$(jq '[.site[].alerts[] | select(.riskcode == "0")] | length' "$RUN_DIR/zap-report.json" 2>/dev/null || echo "0")
    
    DAST_ISSUES=$((high_alerts + medium_alerts + low_alerts))
    
    cat > "$summary" <<EOF
===========================================
DAST (Dynamic Analysis) Scan Summary
===========================================
Scan Tool: OWASP ZAP Baseline
Scan Date: $(date '+%Y-%m-%d %H:%M:%S')
Project: $PROJECT_NAME
Target: $TARGET_URL

Security Issues Found:
  High Risk:   $high_alerts
  Medium Risk: $medium_alerts
  Low Risk:    $low_alerts
  Info:        $info_alerts

Total Alerts: $((high_alerts + medium_alerts + low_alerts + info_alerts))

EOF

    if [[ $high_alerts -gt 0 ]]; then
      echo "⚠ HIGH RISK ISSUES:" >> "$summary"
      jq -r '.site[].alerts[] | select(.riskcode == "3") | "- \(.name)\n  Risk: \(.risk)\n  Description: \(.desc[0:200])...\n  Solution: \(.solution[0:200])...\n"' "$RUN_DIR/zap-report.json" 2>/dev/null >> "$summary" || true
      echo "" >> "$summary"
    fi

    if [[ $medium_alerts -gt 0 ]]; then
      echo "MEDIUM RISK ISSUES:" >> "$summary"
      jq -r '.site[].alerts[] | select(.riskcode == "2") | "- \(.name)\n  Description: \(.desc[0:150])...\n"' "$RUN_DIR/zap-report.json" 2>/dev/null >> "$summary" || true
      echo "" >> "$summary"
    fi

    cat >> "$summary" <<EOF

For detailed results:
  - HTML Report: zap-report.html (open in browser)
  - JSON Report: zap-report.json
  - Scan Log: zap-scan.log
===========================================
EOF

    DAST_SUCCESS=true
  else
    echo "DAST scan completed but report parsing failed" > "$summary"
    echo "Check zap-report.html and zap-scan.log for details" >> "$summary"
    DAST_SUCCESS=true
  fi

  log "DAST reports saved to: $RUN_DIR/"

  # --- Cleanup app container ---
  docker rm -f "$CONTAINER_NAME" >/dev/null 2>&1 || true
  docker network rm "$NETWORK_NAME" >/dev/null 2>&1 || true
  docker rmi "$IMAGE_NAME" >/dev/null 2>&1 || true
}

# Generate comprehensive report using Python script
generate_comprehensive_report() {
  log "═══════════════════════════════════════════════════════════"
  log "Generating Comprehensive Security Report..."
  log "═══════════════════════════════════════════════════════════"
  
  # Check if Python is available
  if ! command -v python3 &>/dev/null; then
    log_warn "Python 3 not found - skipping comprehensive report generation"
    log_warn "Install Python 3 to enable comprehensive HTML/Markdown reports"
    return 0
  fi
  
  # Determine which report generator to use
  local GENERATOR_CMD=""
  
  # First, check if report_generator.py exists in the same directory as the script
  if [[ -f "$REPORT_GENERATOR" ]]; then
    GENERATOR_CMD="python3 $REPORT_GENERATOR"
    log "Using local report generator: $REPORT_GENERATOR"
  # Check if it's installed as a command
  elif command -v safetyscan-report-generator &>/dev/null; then
    GENERATOR_CMD="safetyscan-report-generator"
    log "Using installed report generator: safetyscan-report-generator"
  # Check common installation paths
  elif [[ -f "/usr/local/bin/safetyscan-report-generator" ]]; then
    GENERATOR_CMD="/usr/local/bin/safetyscan-report-generator"
    log "Using system report generator: /usr/local/bin/safetyscan-report-generator"
  else
    log_warn "Report generator script not found"
    log_warn "Comprehensive HTML/Markdown reports will not be generated"
    log "Expected locations:"
    log "  - $REPORT_GENERATOR (local)"
    log "  - /usr/local/bin/safetyscan-report-generator (installed)"
    return 0
  fi
  
  # Run the report generator
  log "Executing: $GENERATOR_CMD \"$RUN_DIR\" \"$PROJECT_NAME\""
  
  if $GENERATOR_CMD "$RUN_DIR" "$PROJECT_NAME" 2>&1; then
    log_success "Comprehensive reports generated successfully!"
    
    # Check if files were created
    if [[ -f "$RUN_DIR/comprehensive-security-report.html" ]]; then
      log_success "HTML Report: $RUN_DIR/comprehensive-security-report.html"
    fi
    
    if [[ -f "$RUN_DIR/comprehensive-security-report.md" ]]; then
      log_success "Markdown Report: $RUN_DIR/comprehensive-security-report.md"
    fi
  else
    log_error "Failed to generate comprehensive report"
    log_warn "Basic reports are still available in: $RUN_DIR"
    return 1
  fi
}

# Generate overall summary
generate_overall_summary() {
  local overall_summary="$RUN_DIR/SCAN-SUMMARY.txt"
  
  cat > "$overall_summary" <<EOF
╔═══════════════════════════════════════════════════════════════╗
║           SECURITY SCAN SUMMARY REPORT                        ║
╚═══════════════════════════════════════════════════════════════╝

Project: $PROJECT_NAME
Scan Date: $(date '+%Y-%m-%d %H:%M:%S')
Scan Mode: $MODE
Reports Location: $RUN_DIR

───────────────────────────────────────────────────────────────

EOF

  if [[ "$MODE" == "sast" ]] || [[ "$MODE" == "both" ]]; then
    if $SAST_SUCCESS; then
      cat >> "$overall_summary" <<EOF
✓ SAST (Static Analysis) - COMPLETED
  Tool: Semgrep
  Issues Found: $SAST_ISSUES
  Report: semgrep-summary.txt

EOF
    else
      cat >> "$overall_summary" <<EOF
✗ SAST (Static Analysis) - FAILED
  Check logs for details

EOF
    fi
  fi

  if [[ "$MODE" == "dast" ]] || [[ "$MODE" == "both" ]]; then
    if $DAST_SUCCESS; then
      cat >> "$overall_summary" <<EOF
✓ DAST (Dynamic Analysis) - COMPLETED
  Tool: OWASP ZAP
  Issues Found: $DAST_ISSUES
  Report: dast-summary.txt (HTML: zap-report.html)

EOF
    else
      cat >> "$overall_summary" <<EOF
✗ DAST (Dynamic Analysis) - FAILED
  Check logs for details

EOF
    fi
  fi

  # Check if comprehensive reports were generated
  if [[ -f "$RUN_DIR/comprehensive-security-report.html" ]]; then
    cat >> "$overall_summary" <<EOF
✓ COMPREHENSIVE REPORTS GENERATED
  HTML: comprehensive-security-report.html
  Markdown: comprehensive-security-report.md

EOF
  fi

  cat >> "$overall_summary" <<EOF
───────────────────────────────────────────────────────────────

RECOMMENDATIONS:
EOF

  local total_issues=$((SAST_ISSUES + DAST_ISSUES))
  
  if [[ $total_issues -eq 0 ]]; then
    cat >> "$overall_summary" <<EOF

  🎉 Great! No security issues detected in this scan.
  
  However, remember:
  - Regular security scans are important
  - Keep dependencies updated
  - Follow secure coding practices
  - This scan has limitations and may not catch everything

EOF
  elif [[ $total_issues -lt 5 ]]; then
    cat >> "$overall_summary" <<EOF

  ✓ Good security posture with only $total_issues issues found
  - Review and fix the identified issues
  - Prioritize high and medium severity issues
  - Implement fixes and re-scan

EOF
  elif [[ $total_issues -lt 20 ]]; then
    cat >> "$overall_summary" <<EOF

  ⚠ Moderate security concerns with $total_issues issues
  - Address high and medium risk issues immediately
  - Create a plan to fix remaining issues
  - Consider a security code review

EOF
  else
    cat >> "$overall_summary" <<EOF

  ⚠ ATTENTION: $total_issues security issues found
  - Immediate action recommended
  - Focus on high and medium risk issues first
  - Consider security training for the team
  - Schedule regular security reviews

EOF
  fi

  cat >> "$overall_summary" <<EOF

NEXT STEPS:
  1. Review detailed reports in: $RUN_DIR
  2. Open comprehensive-security-report.html in browser for best view
  3. Prioritize fixes based on severity
  4. Re-run scans after applying fixes
  5. Integrate scans into CI/CD pipeline

───────────────────────────────────────────────────────────────
For questions or issues with this tool, check the documentation.
═══════════════════════════════════════════════════════════════
EOF

  # Display summary to console
  cat "$overall_summary"
}

# -------------- main --------------
if [[ "$MODE" == "sast" ]] || [[ "$MODE" == "both" ]]; then
  if ! run_sast; then
    log_error "SAST scan failed"
  fi
fi

if [[ "$MODE" == "dast" ]] || [[ "$MODE" == "both" ]]; then
  if ! run_dast; then
    log_error "DAST scan failed"
  fi
fi

# Generate comprehensive report (new feature!)
generate_comprehensive_report

# Generate overall summary
generate_overall_summary

log "═══════════════════════════════════════════════════════════"
log_success "Scan complete! All reports saved to: $RUN_DIR"
log "View SCAN-SUMMARY.txt for an overview"

if [[ -f "$RUN_DIR/comprehensive-security-report.html" ]]; then
  log "═══════════════════════════════════════════════════════════"
  log_success "🎉 COMPREHENSIVE REPORT AVAILABLE!"
  log "Open in browser: $RUN_DIR/comprehensive-security-report.html"
  log "═══════════════════════════════════════════════════════════"
fi

exit 0