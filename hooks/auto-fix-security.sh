#!/usr/bin/env bash
# =============================================================================
# Enterprise production-grade Low-risk vulnerability auto-fix hook
# Trigger: before Git commit (pre_git_commit), not on file save
#
# Design principles:
#   1. Surgical precision matching — only remove 100% confirmed debug/temp/deprecated Low-risk code lines
#   2. Never touch production logs — console.log(business), print(business) will not be removed
#   3. Default dry-run mode — audit report only; explicit env var required to modify files
#   4. Full-chain audit — every modification logged with timestamp
#   5. Triple safety — backup + .gitignore-aware + idempotent (repeat runs are no-op)
#
# Usage:
#   ./auto-fix-security.sh                           # Dry-run mode (audit only)
#   SECURITY_FIX_APPLY=true ./auto-fix-security.sh   # Apply fix
#
# Environment variables:
#   SECURITY_FIX_APPLY=true  enable actual fix (default false, audit only)
#   SECURITY_FIX_VERBOSE=true show full diff output
# =============================================================================
set -euo pipefail

# ── Configuration ────────────────────────────────────────────────────────────────────
DRY_RUN="${SECURITY_FIX_APPLY:-false}"
DRY_RUN="$([[ "$DRY_RUN" == "true" ]] && echo "false" || echo "true")"
VERBOSE="${SECURITY_FIX_VERBOSE:-false}"

TIMESTAMP="$(date -u +%Y%m%d-%H%M%S 2>/dev/null || date -u '+%Y%m%d-%H%M%S')"
AUDIT_DIR="${SECURITY_WORKFLOW_DATA:-.security-workflow-data}/fix-audit"
AUDIT_LOG="${AUDIT_DIR}/fix-${TIMESTAMP}.log"
BACKUP_DIR="${AUDIT_DIR}/backups/${TIMESTAMP}"

mkdir -p "$AUDIT_DIR" "$BACKUP_DIR"

# ── Surgical Low-risk pattern library ──────────────────────────────────────────────────────
# Each pattern is a human-audited regex 100% confirmed as debug/temp/deprecated code
# Core principle: better to miss a thousand than falsely delete one

# Bash version check: declare -A (associative arrays) require Bash 4.0+
if [[ "${BASH_VERSINFO[0]}" -lt 4 ]]; then
  echo "[ERROR] This script requires Bash 4.0+. Current version: ${BASH_VERSION}" >&2
  echo "[ERROR] macOS default bash 3.2 does not support associative arrays. Install Bash 4+:" >&2
  echo "[ERROR]   brew install bash" >&2
  exit 1
fi

declare -A SURGICAL_PATTERNS
SURGICAL_PATTERNS=(
  # ── Python debug/temp statements ──
  ["py_debug_print"]='^\s*print\s*\(\s*["\x27](debug|DEBUG|temp|TEMP|test|TEST|tmp|TMP)[[:space:]:_,-]'
  ["py_bare_print"]='^\s*print\s*\(\s*["\x27]\s*["\x27]\s*\)'            # empty print() placeholder
  ["py_pdb_trace"]='^\s*(import\s+pdb|pdb\.set_trace|breakpoint\s*\()'   # debug breakpoint

  # ── JS/TS debug statements ──
  ["js_debug_console"]='^\s*console\.(log|debug)\s*\(\s*["\x27](debug|DEBUG|temp|TEMP|test|TEST|tmp|TMP)[[:space:]:_,-]'
  ["js_bare_console"]='^\s*console\.(log|debug)\s*\(\s*["\x27]\s*["\x27]\s*\)'
  ["js_debugger"]='^\s*debugger\s*;?\s*$'

  # ── Generic useless security comment lines ──
  ["comment_temp_key"]='^\s*(//|#|<!--)\s*(临时|测试|temp|test|debug)\s*(密钥|密码|key|secret|token|password)'
  ["comment_todo_empty"]='^\s*(//|#)\s*(TODO|FIXME|HACK)\s*:\s*$'       # empty no-action TODO
)

# ── File scope: only operate on git-tracked files, respect .gitignore ────────────────────────
get_tracked_files() {
  if git rev-parse --git-dir >/dev/null 2>&1; then
    git ls-files --cached --others --exclude-standard -- '*.py' '*.js' '*.ts' '*.java' '*.vue' 2>/dev/null || true
  else
    find . \( -name '*.py' -o -name '*.js' -o -name '*.ts' -o -name '*.java' -o -name '*.vue' \) -type f 2>/dev/null || true
  fi
}

# ── Safe pattern matching on a single file ────────────────────────────────────────
match_pattern_in_file() {
  local file="$1"
  local pattern_label="$2"
  local pattern="$3"

  # Skip node_modules, .git, __pycache__, venv, etc.
  case "$file" in
    */node_modules/*|*/.git/*|*/__pycache__/*|*/venv/*|*/.venv/*|*/vendor/*|*/vuln_cases/*|*/vuln_samples/*|*/security_test_fixtures/*) return ;;
  esac

  [[ -f "$file" ]] || return
  [[ -s "$file" ]] || return

  grep -n -E "$pattern" "$file" 2>/dev/null || true
}

# ── Safely delete matching lines from file (cross-platform perl) ──────────────────────
apply_fix() {
  local file="$1"
  local pattern="$2"
  local label="$3"

  # Create backup
  local backup="${BACKUP_DIR}/$(echo "$file" | tr '/' '_')"
  cp "$file" "$backup"

  # Use perl instead of sed -i (fully resolves BSD/GNU compatibility)
  local before_lines
  before_lines=$(wc -l < "$file")
  # Use Perl -s switch for safe variable passing, avoiding shell var interpolation into Perl code
  perl -i.bak -sne 'print unless $pat' -- -pat="$pattern" "$file" 2>/dev/null || {
    echo "  [ERROR] perl fix failed: ${file}" | tee -a "$AUDIT_LOG"
    cp "$backup" "$file"  # rollback
    return 1
  }
  rm -f "${file}.bak" 2>/dev/null || true  # clean up perl -i generated .bak

  local after_lines
  after_lines=$(wc -l < "$file")
  local removed=$((before_lines - after_lines))

  if [[ "$removed" -gt 0 ]]; then
    echo "  [FIXED] ${file} — Mode:${label} — Deleted ${removed} line(s) (backup: ${backup})" | tee -a "$AUDIT_LOG"
    if [[ "$VERBOSE" == "true" ]]; then
      echo "  --- diff ---" >> "$AUDIT_LOG"
      diff -u "$backup" "$file" >> "$AUDIT_LOG" 2>/dev/null || true
      echo "  ------------" >> "$AUDIT_LOG"
    fi
    return 0
  else
    # No changes, discard backup
    rm -f "$backup" 2>/dev/null || true
    return 0
  fi
}

# ── Main flow ──────────────────────────────────────────────────────────────────
echo "╔══════════════════════════════════════════════════════════════╗"
echo "║  Security Fix Hook — Low-risk vulnerability auto-fix audit                  ║"
echo "║  Time: ${TIMESTAMP}                                          ║"
echo "║  Mode: $( [[ "$DRY_RUN" == "true" ]] && echo '🔍 Dry-run audit (no file modification)' || echo '🔧 Apply fix' )║"
echo "╚══════════════════════════════════════════════════════════════╝"
echo ""

{
  echo "═══════════════════════════════════════════════════════════════"
  echo "  Security Fix Audit — ${TIMESTAMP}"
  echo "  Mode: $( [[ "$DRY_RUN" == "true" ]] && echo 'DRY RUN (no changes)' || echo 'APPLY (with backups)' )"
  echo "═══════════════════════════════════════════════════════════════"
  echo ""
} >> "$AUDIT_LOG"

# ── Phase 1: Full match scan ────────────────────────────────────────────────────
TOTAL_MATCHES=0
declare -A FILE_MATCHES

echo "[Phase 1] Scanning for Low-risk debug/temp/deprecated code..."
while IFS= read -r file; do
  for label in "${!SURGICAL_PATTERNS[@]}"; do
    pattern="${SURGICAL_PATTERNS[$label]}"
    matches=$(match_pattern_in_file "$file" "$label" "$pattern")
    if [[ -n "$matches" ]]; then
      while IFS= read -r match_line; do
        lineno="${match_line%%:*}"
        content="${match_line#*:}"
        echo "  MATCH: ${file}:${lineno} [${label}] → ${content}" | tee -a "$AUDIT_LOG"
        FILE_MATCHES["${file}|${label}"]="${FILE_MATCHES["${file}|${label}"]-}${match_line}
"
        TOTAL_MATCHES=$((TOTAL_MATCHES + 1))
      done <<< "$matches"
    fi
  done
done < <(get_tracked_files)

echo ""
echo "[Phase 1] Scan complete — found ${TOTAL_MATCHES} Low-risk fixable items"

if [[ "$TOTAL_MATCHES" -eq 0 ]]; then
  echo "[Security-Fix-Hook] ✅ No Low-risk fixable items — audit complete."
  exit 0
fi

# ── Phase 2: Apply fixes (non-dry-run only) ──────────────────────────────────────
if [[ "$DRY_RUN" == "true" ]]; then
  echo ""
  echo "[Phase 2] ⏭️  Skipping fixes — current mode is dry-run"
  echo "  To apply fixes, run: SECURITY_FIX_APPLY=true ./auto-fix-security.sh"
  echo ""
  echo "═══════════════════════════════════════════════════════════════" >> "$AUDIT_LOG"
  echo "  DRY RUN COMPLETE — ${TOTAL_MATCHES} matches found, 0 files modified" >> "$AUDIT_LOG"
  echo "═══════════════════════════════════════════════════════════════" >> "$AUDIT_LOG"
  exit 0
fi

echo ""
echo "[Phase 2] Apply fix (Backups created in ${BACKUP_DIR})..."
FIXED_COUNT=0
ERROR_COUNT=0

for key in "${!FILE_MATCHES[@]}"; do
  file="${key%%|*}"
  label="${key##*|}"
  pattern="${SURGICAL_PATTERNS[$label]}"

  if apply_fix "$file" "$pattern" "$label"; then
    FIXED_COUNT=$((FIXED_COUNT + 1))
  else
    ERROR_COUNT=$((ERROR_COUNT + 1))
  fi
done

# ── Phase 3: Post-fix compliance self-check ──────────────────────────────────────────────
echo ""
echo "[Phase 3] Post-fix compliance self-check..."

# Verify fixed files have no syntax errors (Python)
while IFS= read -r file; do
  case "${file##*.}" in
    py)
      if command -v python3 &>/dev/null; then
        python3 -m py_compile "$file" 2>/dev/null || echo "  [WARN] ${file} — Post-fix Python syntax validation failed — manual review required"
      fi
      ;;
  esac
done < <(get_tracked_files | grep '\.py$' || true)

# ── Audit summary ────────────────────────────────────────────────────────────────
{
  echo ""
  echo "═══════════════════════════════════════════════════════════════"
  echo "  FIX SUMMARY — ${TIMESTAMP}"
  echo "  Total matches: ${TOTAL_MATCHES}"
  echo "  Successfully fixed: ${FIXED_COUNT}"
  echo "  Fix errors: ${ERROR_COUNT}"
  echo "  Backup directory: ${BACKUP_DIR}"
  echo "═══════════════════════════════════════════════════════════════"
} | tee -a "$AUDIT_LOG"

echo ""
echo "[Security-Fix-Hook] ✅ Low-risk vulnerability fix complete. Audit log: ${AUDIT_LOG}"

if [[ "$ERROR_COUNT" -gt 0 ]]; then
  exit 1
fi
exit 0
