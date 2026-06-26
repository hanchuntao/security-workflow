#!/usr/bin/env bash
# =============================================================================
# Enterprise production-grade incremental code security pre-check hook
# Trigger: file save (single-file scan), pre-command, pre-Git-commit (full scan)
#
# Usage:
#   ./check-bash.sh              # Full project scan (Git commit / command exec)
#   ./check-bash.sh <filepath>   # Single file scan (file save trigger)
#
# Exit codes:
#   0 = Pass — no blocking risks (or Low-risk only)
#   1 = Warning — potential risks but non-blocking (Medium-risk)
#   2 = Blocked — High-risk blocking issues detected (operation halted)
# =============================================================================
set -euo pipefail

# ── Argument parsing ─────────────────────────────────────────────────────
TARGET="${1:-.}"
TIMESTAMP="$(date -u +%Y-%m-%dT%H:%M:%SZ 2>/dev/null || date -u '+%Y-%m-%dT%H:%M:%SZ')"

# Validate TARGET is a legitimate path
if [[ -n "${1:-}" ]]; then
  if command -v realpath &>/dev/null; then
    TARGET=$(realpath "$1" 2>/dev/null || echo "$1")
  elif [[ -f "$1" ]] || [[ -d "$1" ]]; then
    TARGET="$(cd "$(dirname "$1")" 2>/dev/null && pwd)/$(basename "$1")"
  fi
fi

echo "[Security-Hook] ${TIMESTAMP} Running code security compliance pre-check..."
echo "[Security-Hook] Target: ${TARGET}"

# ── Environment check: macOS BSD grep lacks \b support ────────────
if ! echo "test" | grep -q -E '\btest\b' 2>/dev/null; then
  echo "[Security-Hook] ⚠️  Current grep does not support \b word boundaries (common with macOS BSD grep)"
  echo "[Security-Hook] ⚠️  All scan patterns will silently fail. Install GNU grep: brew install grep"
  echo "[Security-Hook] ⚠️  After install, use ggrep or export PATH=\"/usr/local/opt/grep/libexec/gnubin:\$PATH\""
fi

# ── Determine target type ────────────────────────────────────────────────
SCAN_MODE="full"
if [[ -f "$TARGET" ]]; then
  SCAN_MODE="single_file"
fi

# ── Utility functions ─────────────────────────────────────────────────────
# Strip inline comments before matching: remove // comments (JS/TS/Java/C), then # comments (Python/Shell/YAML)
# Only scan code portions to avoid missed detections from end-of-line comments
strip_inline_comments() {
  sed -E \
    -e 's|//.*$||g' \
    -e 's|#[^"]*$||g' \
    "$1" 2>/dev/null || cat "$1"
}

# Strip Python/JS string literal content (>3 chars), preserve quotes for code structure
# Purpose: prevent false positives from mock data descriptions like "os.system call", "MD5"
# Note: this function is ONLY used for code pattern detection, NOT credential detection (credentials live inside strings)
strip_string_content() {
  sed -E \
    -e 's/"[^"]{4,}"//g' \
    -e "s/'[^']{4,}'//g" \
    -e 's/`[^`]{4,}`//g'
}

# Skip intentionally crafted vulnerability test sample directories to avoid production tickets
skip_vuln_dirs() {
  local file="$1"
  case "$file" in
    */vuln_cases/*|*/vuln_samples/*|*/security_test_fixtures/*)
      return 0
      ;;
  esac
  return 1
}

# High-risk match counter
HIGH_COUNT=0
MEDIUM_COUNT=0
LOW_COUNT=0

# ── Determine scan scope ─────────────────────────────────────────────────
scan_file() {
  local file="$1"
  # Skip non-files, binaries, and oversized files (>5MB)
  [[ -f "$file" ]] || return
  [[ -s "$file" ]] || return
  local fsize
  fsize=$(wc -c < "$file" 2>/dev/null) || {
    fsize=0
    echo "  [WARN] Cannot read file size: ${file}" >&2
  }
  [[ "$fsize" -lt 5242880 ]] || { echo "  [SKIP] ${file} — File too large (${fsize} bytes)"; return; }

  # Skip intentionally crafted vuln test sample directories
  if skip_vuln_dirs "$file"; then
    echo "  [SKIP] ${file} — Vuln test sample directory, skipping"
    return
  fi

  local ext="${file##*.}"
  local stripped          # Comment-only strip — for credential detection (string content must stay)
  local stripped_code     # Comment + string strip — for code pattern detection (mock data false-positive prevention)

  # ── 1. Credential leak detection (High) ───────────────────────────
  # Strip comments first, then match credential patterns in code
  # Note: do NOT use strip_string_content — credentials live inside strings
  case "$ext" in
    py|js|ts|java|go|php|vue|yml|yaml|json|sh|bash|zsh)
      stripped=$(strip_inline_comments "$file")
      # Match assignment/declaration credential patterns (word boundaries to avoid false positives)
      if echo "$stripped" | grep -q -i -E '\b(password|passwd|secret|api[_-]?key|access[_-]?key|private[_-]?key|token|auth[_-]?token)\b\s*[=:]\s*['"'"'"]?[a-zA-Z0-9+/=_-]{16,}' 2>/dev/null; then
        echo "  [HIGH] ${file} — Suspected hardcoded credential"
        HIGH_COUNT=$((HIGH_COUNT + 1))
      fi
      ;;
  esac

  # Generate code-pattern-only content (stripped comments + stripped string literals for mock data false-positive prevention)
  stripped_code=$(strip_inline_comments "$file" | strip_string_content)

  # ── 2. Dangerous function execution detection (High) ────────────
  case "$ext" in
    py)
      if echo "$stripped_code" | grep -q -E '\b(os\.system\s*\(|subprocess\.call\s*\(|subprocess\.Popen\s*\(|eval\s*\(|exec\s*\(|__import__\s*\()' 2>/dev/null; then
        echo "  [HIGH] ${file} — Suspected dangerous call (os.system/subprocess/eval/exec)"
        HIGH_COUNT=$((HIGH_COUNT + 1))
      fi
      if echo "$stripped_code" | grep -q -E '\b(pickle\.loads|yaml\.load\s*\()' 2>/dev/null; then
        echo "  [HIGH] ${file} — Suspected unsafe deserialization (pickle/yaml.load)"
        HIGH_COUNT=$((HIGH_COUNT + 1))
      fi
      ;;
    js|ts|vue)
      if echo "$stripped_code" | grep -q -E '\b(eval\s*\(|new\s+Function\s*\()' 2>/dev/null; then
        echo "  [HIGH] ${file} — Suspected dangerous call (eval/Function)"
        HIGH_COUNT=$((HIGH_COUNT + 1))
      fi
      ;;
    java)
      if echo "$stripped_code" | grep -q -E '\b(Runtime\.getRuntime\(\)\.exec|ProcessBuilder)' 2>/dev/null; then
        echo "  [HIGH] ${file} — Suspected command execution (Runtime.exec/ProcessBuilder)"
        HIGH_COUNT=$((HIGH_COUNT + 1))
      fi
      ;;
    php)
      if echo "$stripped_code" | grep -q -E '\b(eval\s*\(|exec\s*\(|system\s*\(|shell_exec\s*\()' 2>/dev/null; then
        echo "  [HIGH] ${file} — Suspected dangerous call (eval/exec/system/shell_exec)"
        HIGH_COUNT=$((HIGH_COUNT + 1))
      fi
      ;;
  esac

  # ── 3. SQL injection detection (High) ───────────────────────────
  case "$ext" in
    py|js|ts|java|go|php)
      if echo "$stripped_code" | grep -q -E '(\+.*SELECT|\"\s*SELECT|'"'"'\s*SELECT|fmt\.Sprintf.*SELECT|sprintf.*SELECT)' 2>/dev/null; then
        echo "  [HIGH] ${file} — Suspected SQL string concatenation"
        HIGH_COUNT=$((HIGH_COUNT + 1))
      fi
      ;;
  esac

  # ── 4. Weak cryptography (Medium) ───────────────────────────────
  case "$ext" in
    py|js|ts|java|go|php)
      if echo "$stripped_code" | grep -q -i -E '\b(MD5|SHA1|SHA-1|DES|3DES|RC4|ECB)\b' 2>/dev/null; then
        echo "  [MEDIUM] ${file} — Suspected weak crypto/hash (MD5/SHA1/DES/3DES/RC4/ECB)"
        MEDIUM_COUNT=$((MEDIUM_COUNT + 1))
      fi
      ;;
  esac

  # ── 5. Insecure random (Medium) ─────────────────────────────────
  case "$ext" in
    py)
      if echo "$stripped_code" | grep -q -E '\brandom\.(random|randint|choice|sample)\b' 2>/dev/null; then
        echo "  [MEDIUM] ${file} — Suspected insecure random (random module used for security context)"
        MEDIUM_COUNT=$((MEDIUM_COUNT + 1))
      fi
      ;;
    js|ts)
      if echo "$stripped_code" | grep -q -E '\bMath\.random\b' 2>/dev/null; then
        echo "  [MEDIUM] ${file} — Suspected insecure random (Math.random used for security context)"
        MEDIUM_COUNT=$((MEDIUM_COUNT + 1))
      fi
      ;;
  esac

  # ── 6. CORS wildcard (Medium) ───────────────────────────────────
  case "$ext" in
    js|ts|vue|json)
      if echo "$stripped_code" | grep -q -E 'origin["'"'"']?\s*:\s*["'"'"']?\*' 2>/dev/null; then
        echo "  [MEDIUM] ${file} — CORS origin configured as wildcard *"
        MEDIUM_COUNT=$((MEDIUM_COUNT + 1))
      fi
      ;;
  esac
}

# ── Execute scan ────────────────────────────────────────────────────────────────
if [[ "$SCAN_MODE" == "single_file" ]]; then
  echo "[Security-Hook] Scan mode: single-file incremental"
  scan_file "$TARGET"
else
  echo "[Security-Hook] Scan mode: full project"
  # Use find instead of grep -r to avoid cross-platform --include compatibility issues
  # Also leverage git ls-files to respect .gitignore
  if git rev-parse --git-dir >/dev/null 2>&1; then
    while IFS= read -r file; do
      [[ -f "$file" ]] || continue
      scan_file "$file"
    done < <(git ls-files --cached --others --exclude-standard -- '*.py' '*.js' '*.ts' '*.java' '*.go' '*.php' '*.rb' '*.rs' '*.c' '*.cpp' '*.cc' '*.cxx' '*.h' '*.hpp' '*.hxx' '*.cs' '*.swift' '*.kt' '*.kts' '*.scala' '*.dart' '*.lua' '*.sql' '*.vue' '*.html' '*.sh' '*.bash' '*.zsh' '*.yml' '*.yaml' '*.json' '*.xml' '*.toml' '*.ini' '*.cfg' '*.conf' 2>/dev/null)
  else
    # Non-git repo fallback to find
    while IFS= read -r file; do
      scan_file "$file"
    done < <(find . \( -name '*.py' -o -name '*.js' -o -name '*.ts' -o -name '*.java' -o -name '*.go' -o -name '*.php' -o -name '*.rb' -o -name '*.rs' -o -name '*.c' -o -name '*.cpp' -o -name '*.cc' -o -name '*.cxx' -o -name '*.h' -o -name '*.hpp' -o -name '*.hxx' -o -name '*.cs' -o -name '*.swift' -o -name '*.kt' -o -name '*.kts' -o -name '*.scala' -o -name '*.dart' -o -name '*.lua' -o -name '*.sql' -o -name '*.vue' -o -name '*.html' -o -name '*.sh' -o -name '*.bash' -o -name '*.yml' -o -name '*.yaml' -o -name '*.json' -o -name '*.xml' -o -name '*.toml' -o -name '*.ini' -o -name '*.cfg' -o -name '*.conf' \) -type f 2>/dev/null)
  fi
fi

# ── Summary & verdict ────────────────────────────────────────────────────────────────
echo ""
echo "[Security-Hook] ========== Pre-Check Summary =========="
echo "[Security-Hook] High-risk (blocking): ${HIGH_COUNT}"
echo "[Security-Hook] Medium-risk (warnings): ${MEDIUM_COUNT}"
echo "[Security-Hook] ================================"

if [[ "$HIGH_COUNT" -gt 0 ]]; then
  echo "[Security-Hook] ⛔ High-risk issues detected — operation blocked. Remediate High-risk vulnerabilities first."
  exit 2
elif [[ "$MEDIUM_COUNT" -gt 0 ]]; then
  echo "[Security-Hook] ⚠️  Medium-risk issues found — remediation recommended by deadline (non-blocking)."
  exit 1
else
  echo "[Security-Hook] ✅ Security pre-check passed — no blocking risks."
  exit 0
fi
