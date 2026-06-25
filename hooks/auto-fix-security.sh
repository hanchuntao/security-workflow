#!/usr/bin/env bash
# =============================================================================
# 企业生产级低危安全漏洞自动修复钩子
# 触发时机：Git 提交前 (pre_git_commit)，不触发于文件保存
#
# 设计原则:
#   1. 手术刀式精准匹配 — 只删除 100% 确定为调试/临时/废弃的低危代码行
#   2. 绝不触碰生产日志 — console.log(业务)、print(业务) 不会被删除
#   3. 默认干跑模式 — 仅输出审计报告，需显式设置环境变量才实际修改文件
#   4. 全链路审计 — 每一条修改记录均写带时间戳的审计日志
#   5. 三重安全保障 — 备份 + .gitignore 感知 + 幂等（重复运行无副作用）
#
# 使用方式:
#   ./auto-fix-security.sh                           # 干跑模式 (仅审计)
#   SECURITY_FIX_APPLY=true ./auto-fix-security.sh   # 执行修复
#
# 环境变量:
#   SECURITY_FIX_APPLY=true  开启实际修复（默认 false，仅审计）
#   SECURITY_FIX_VERBOSE=true 显示完整 diff 输出
# =============================================================================
set -euo pipefail

# ── 配置 ────────────────────────────────────────────────────────────────────
DRY_RUN="${SECURITY_FIX_APPLY:-false}"
DRY_RUN="$([[ "$DRY_RUN" == "true" ]] && echo "false" || echo "true")"
VERBOSE="${SECURITY_FIX_VERBOSE:-false}"

TIMESTAMP="$(date -u +%Y%m%d-%H%M%S 2>/dev/null || date -u '+%Y%m%d-%H%M%S')"
AUDIT_DIR="${SECURITY_WORKFLOW_DATA:-.security-workflow-data}/fix-audit"
AUDIT_LOG="${AUDIT_DIR}/fix-${TIMESTAMP}.log"
BACKUP_DIR="${AUDIT_DIR}/backups/${TIMESTAMP}"

mkdir -p "$AUDIT_DIR" "$BACKUP_DIR"

# ── 手术刀式低危模式库 ──────────────────────────────────────────────────────
# 每一条都是经过人工审计的、100% 确定为调试/临时/废弃代码的正则
# 核心原则：宁可漏删一千，不可误删一行

# 校验 Bash 版本：declare -A (关联数组) 需要 Bash 4.0+
if [[ "${BASH_VERSINFO[0]}" -lt 4 ]]; then
  echo "[ERROR] 此脚本需要 Bash 4.0 或更高版本，当前版本: ${BASH_VERSION}" >&2
  echo "[ERROR] macOS 默认 bash 3.2 不支持关联数组，请安装 Bash 4+:" >&2
  echo "[ERROR]   brew install bash" >&2
  exit 1
fi

declare -A SURGICAL_PATTERNS
SURGICAL_PATTERNS=(
  # ── Python 调试/临时语句 ──
  ["py_debug_print"]='^\s*print\s*\(\s*["\x27](debug|DEBUG|temp|TEMP|test|TEST|tmp|TMP)[[:space:]:_,-]'
  ["py_bare_print"]='^\s*print\s*\(\s*["\x27]\s*["\x27]\s*\)'            # 空 print() 占位
  ["py_pdb_trace"]='^\s*(import\s+pdb|pdb\.set_trace|breakpoint\s*\()'   # 调试断点

  # ── JS/TS 调试语句 ──
  ["js_debug_console"]='^\s*console\.(log|debug)\s*\(\s*["\x27](debug|DEBUG|temp|TEMP|test|TEST|tmp|TMP)[[:space:]:_,-]'
  ["js_bare_console"]='^\s*console\.(log|debug)\s*\(\s*["\x27]\s*["\x27]\s*\)'
  ["js_debugger"]='^\s*debugger\s*;?\s*$'

  # ── 通用无用安全注释行 ──
  ["comment_temp_key"]='^\s*(//|#|<!--)\s*(临时|测试|temp|test|debug)\s*(密钥|密码|key|secret|token|password)'
  ["comment_todo_empty"]='^\s*(//|#)\s*(TODO|FIXME|HACK)\s*:\s*$'       # 空的无行动 TODO
)

# ── 文件范围：只操作 git 追踪文件，尊重 .gitignore ────────────────────────
get_tracked_files() {
  if git rev-parse --git-dir >/dev/null 2>&1; then
    git ls-files --cached --others --exclude-standard -- '*.py' '*.js' '*.ts' '*.java' '*.vue' 2>/dev/null || true
  else
    find . \( -name '*.py' -o -name '*.js' -o -name '*.ts' -o -name '*.java' -o -name '*.vue' \) -type f 2>/dev/null || true
  fi
}

# ── 对单个文件的单条模式做安全匹配 ────────────────────────────────────────
match_pattern_in_file() {
  local file="$1"
  local pattern_label="$2"
  local pattern="$3"

  # 跳过 node_modules、.git、__pycache__、venv 等
  case "$file" in
    */node_modules/*|*/.git/*|*/__pycache__/*|*/venv/*|*/.venv/*|*/vendor/*|*/vuln_cases/*|*/vuln_samples/*|*/security_test_fixtures/*) return ;;
  esac

  [[ -f "$file" ]] || return
  [[ -s "$file" ]] || return

  grep -n -E "$pattern" "$file" 2>/dev/null || true
}

# ── 安全地删除文件中的匹配行 (使用 perl 跨平台兼容) ──────────────────────
apply_fix() {
  local file="$1"
  local pattern="$2"
  local label="$3"

  # 创建备份
  local backup="${BACKUP_DIR}/$(echo "$file" | tr '/' '_')"
  cp "$file" "$backup"

  # 使用 perl 而非 sed -i (彻底解决 BSD/GNU 兼容性问题)
  local before_lines
  before_lines=$(wc -l < "$file")
  # 使用 Perl -s 开关安全传递变量，避免 Shell 变量内插到 Perl 代码字符串中
  perl -i.bak -sne 'print unless $pat' -- -pat="$pattern" "$file" 2>/dev/null || {
    echo "  [ERROR] perl 修复失败: ${file}" | tee -a "$AUDIT_LOG"
    cp "$backup" "$file"  # 回滚
    return 1
  }
  rm -f "${file}.bak" 2>/dev/null || true  # 清理 perl -i 产生的 .bak

  local after_lines
  after_lines=$(wc -l < "$file")
  local removed=$((before_lines - after_lines))

  if [[ "$removed" -gt 0 ]]; then
    echo "  [FIXED] ${file} — 模式:${label} — 删除 ${removed} 行 (备份: ${backup})" | tee -a "$AUDIT_LOG"
    if [[ "$VERBOSE" == "true" ]]; then
      echo "  --- diff ---" >> "$AUDIT_LOG"
      diff -u "$backup" "$file" >> "$AUDIT_LOG" 2>/dev/null || true
      echo "  ------------" >> "$AUDIT_LOG"
    fi
    return 0
  else
    # 无变化，回收备份
    rm -f "$backup" 2>/dev/null || true
    return 0
  fi
}

# ── 主流程 ──────────────────────────────────────────────────────────────────
echo "╔══════════════════════════════════════════════════════════════╗"
echo "║  Security Fix Hook — 低危漏洞自动修复审计                  ║"
echo "║  时间: ${TIMESTAMP}                                          ║"
echo "║  模式: $( [[ "$DRY_RUN" == "true" ]] && echo '🔍 干跑审计 (不修改文件)' || echo '🔧 执行修复' )║"
echo "╚══════════════════════════════════════════════════════════════╝"
echo ""

{
  echo "═══════════════════════════════════════════════════════════════"
  echo "  Security Fix Audit — ${TIMESTAMP}"
  echo "  Mode: $( [[ "$DRY_RUN" == "true" ]] && echo 'DRY RUN (no changes)' || echo 'APPLY (with backups)' )"
  echo "═══════════════════════════════════════════════════════════════"
  echo ""
} >> "$AUDIT_LOG"

# ── 阶段1: 全量匹配扫描 ────────────────────────────────────────────────────
TOTAL_MATCHES=0
declare -A FILE_MATCHES

echo "[阶段1] 扫描低危调试/临时/废弃代码..."
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
echo "[阶段1] 扫描完成 — 共发现 ${TOTAL_MATCHES} 处低危可修复项"

if [[ "$TOTAL_MATCHES" -eq 0 ]]; then
  echo "[Security-Fix-Hook] ✅ 无低危修复项，审计完成。"
  exit 0
fi

# ── 阶段2: 应用修复 (仅在非干跑模式) ──────────────────────────────────────
if [[ "$DRY_RUN" == "true" ]]; then
  echo ""
  echo "[阶段2] ⏭️  跳过修复 — 当前为干跑模式"
  echo "  如需执行修复，请运行: SECURITY_FIX_APPLY=true ./auto-fix-security.sh"
  echo ""
  echo "═══════════════════════════════════════════════════════════════" >> "$AUDIT_LOG"
  echo "  DRY RUN COMPLETE — ${TOTAL_MATCHES} matches found, 0 files modified" >> "$AUDIT_LOG"
  echo "═══════════════════════════════════════════════════════════════" >> "$AUDIT_LOG"
  exit 0
fi

echo ""
echo "[阶段2] 执行修复 (已创建备份至 ${BACKUP_DIR})..."
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

# ── 阶段3: 输出修复后合规自检 ──────────────────────────────────────────────
echo ""
echo "[阶段3] 修复后合规自检..."

# 验证修复后的文件没有语法错误 (Python)
while IFS= read -r file; do
  case "${file##*.}" in
    py)
      if command -v python3 &>/dev/null; then
        python3 -m py_compile "$file" 2>/dev/null || echo "  [WARN] ${file} — 修复后 Python 语法校验失败，请人工检查"
      fi
      ;;
  esac
done < <(get_tracked_files | grep '\.py$' || true)

# ── 审计汇总 ────────────────────────────────────────────────────────────────
{
  echo ""
  echo "═══════════════════════════════════════════════════════════════"
  echo "  FIX SUMMARY — ${TIMESTAMP}"
  echo "  总匹配项: ${TOTAL_MATCHES}"
  echo "  成功修复: ${FIXED_COUNT}"
  echo "  修复失败: ${ERROR_COUNT}"
  echo "  备份目录: ${BACKUP_DIR}"
  echo "═══════════════════════════════════════════════════════════════"
} | tee -a "$AUDIT_LOG"

echo ""
echo "[Security-Fix-Hook] ✅ 低危漏洞修复完成。审计日志: ${AUDIT_LOG}"

if [[ "$ERROR_COUNT" -gt 0 ]]; then
  exit 1
fi
exit 0
