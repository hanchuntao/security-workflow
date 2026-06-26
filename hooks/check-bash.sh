#!/usr/bin/env bash
# =============================================================================
# 企业生产级代码增量安全预检钩子
# 触发时机：文件保存 (单文件扫描)、命令执行前、Git 提交前 (全量扫描)
#
# 使用方式:
#   ./check-bash.sh              # 全项目扫描 (Git 提交/命令执行)
#   ./check-bash.sh <filepath>   # 单文件扫描 (文件保存触发)
#
# 退出码:
#   0 = 安全校验通过（无阻断级风险，或仅存在低危项）
#   1 = 检测到潜在风险但非阻断级（中危项）
#   2 = 检测到高危阻断级风险（阻止操作继续）
# =============================================================================
set -euo pipefail

# ── 参数解析 ────────────────────────────────────────────────────────────────
TARGET="${1:-.}"
TIMESTAMP="$(date -u +%Y-%m-%dT%H:%M:%SZ 2>/dev/null || date -u '+%Y-%m-%dT%H:%M:%SZ')"

# 校验 TARGET 为合法路径
if [[ -n "$1" ]]; then
  if command -v realpath &>/dev/null; then
    TARGET=$(realpath "$1" 2>/dev/null || echo "$1")
  elif [[ -f "$1" ]] || [[ -d "$1" ]]; then
    TARGET="$(cd "$(dirname "$1")" 2>/dev/null && pwd)/$(basename "$1")"
  fi
fi

echo "[Security-Hook] ${TIMESTAMP} 执行代码安全合规预检..."
echo "[Security-Hook] 目标: ${TARGET}"

# ── 环境自检：macOS 自带 BSD grep 不支持 \b ─────────────────────────────
if ! echo "test" | grep -q -E '\btest\b' 2>/dev/null; then
  echo "[Security-Hook] ⚠️  当前 grep 不支持 \b 词边界 (常见于 macOS BSD grep)"
  echo "[Security-Hook] ⚠️  所有扫描模式会静默失效，请安装 GNU grep: brew install grep"
  echo "[Security-Hook] ⚠️  安装后用 ggrep 路径或 export PATH=\"/usr/local/opt/grep/libexec/gnubin:\$PATH\""
fi

# ── 判定目标类型 ────────────────────────────────────────────────────────────
SCAN_MODE="full"
if [[ -f "$TARGET" ]]; then
  SCAN_MODE="single_file"
fi

# ── 工具函数 ────────────────────────────────────────────────────────────────
# 去除行内注释后再做匹配：先删 // 注释 (JS/TS/Java/C), 再删 # 注释 (Python/Shell/YAML)
# 只对代码部分做安全检测，避免行末注释导致漏报
strip_inline_comments() {
  sed -E \
    -e 's|//.*$||g' \
    -e 's|#[^"]*$||g' \
    "$1" 2>/dev/null || cat "$1"
}

# 去除 Python/JS 字符串字面量内容（>3 字符），保留引号以维持代码结构
# 用途：避免 mock 数据中的 "os.system调用"、"MD5" 等描述性文本被误判
# 注意：此函数仅用于代码模式检测，不用于凭证检测（凭证就在字符串内）
strip_string_content() {
  sed -E \
    -e 's/"[^"]{4,}"//g' \
    -e "s/'[^']{4,}'//g" \
    -e 's/`[^`]{4,}`//g'
}

# 跳过故意包含漏洞的测试样本目录，避免产生生产工单
skip_vuln_dirs() {
  local file="$1"
  case "$file" in
    */vuln_cases/*|*/vuln_samples/*|*/security_test_fixtures/*)
      return 0
      ;;
  esac
  return 1
}

# 高危匹配计数
HIGH_COUNT=0
MEDIUM_COUNT=0
LOW_COUNT=0

# ── 扫描范围确定 ────────────────────────────────────────────────────────────
scan_file() {
  local file="$1"
  # 跳过非文件、二进制、超大型文件 (>5MB)
  [[ -f "$file" ]] || return
  [[ -s "$file" ]] || return
  local fsize
  fsize=$(wc -c < "$file" 2>/dev/null) || {
    fsize=0
    echo "  [WARN] 无法读取文件大小: ${file}" >&2
  }
  [[ "$fsize" -lt 5242880 ]] || { echo "  [SKIP] ${file} — 文件过大 (${fsize} bytes)"; return; }

  # 跳过故意包含漏洞的测试样本目录
  if skip_vuln_dirs "$file"; then
    echo "  [SKIP] ${file} — 漏洞测试样本目录，跳过扫描"
    return
  fi

  local ext="${file##*.}"
  local stripped          # 仅去注释，用于凭证检测（字符串内容不可剥离）
  local stripped_code     # 去注释 + 去字符串内容，用于代码模式检测（防 mock 数据误报）

  # ── 1. 凭证泄露检测 (高危) ──────────────────────────────────────────
  # 先去除注释，再在代码部分匹配凭证模式
  # 注意：不能用 strip_string_content，凭证就在字符串内
  case "$ext" in
    py|js|ts|java|go|php|vue|yml|yaml|json|sh|bash|zsh)
      stripped=$(strip_inline_comments "$file")
      # 匹配赋值/声明类凭证模式（使用词边界避免误报）
      if echo "$stripped" | grep -q -i -E '\b(password|passwd|secret|api[_-]?key|access[_-]?key|private[_-]?key|token|auth[_-]?token)\b\s*[=:]\s*['"'"'"]?[a-zA-Z0-9+/=_-]{16,}' 2>/dev/null; then
        echo "  [HIGH] ${file} — 疑似硬编码凭证"
        HIGH_COUNT=$((HIGH_COUNT + 1))
      fi
      ;;
  esac

  # 生成代码模式检测专用内容（去注释 + 去字符串字面量，防 mock 数据误报）
  stripped_code=$(strip_inline_comments "$file" | strip_string_content)

  # ── 2. 危险函数执行检测 (高危) ──────────────────────────────────────
  case "$ext" in
    py)
      if echo "$stripped_code" | grep -q -E '\b(os\.system\s*\(|subprocess\.call\s*\(|subprocess\.Popen\s*\(|eval\s*\(|exec\s*\(|__import__\s*\()' 2>/dev/null; then
        echo "  [HIGH] ${file} — 疑似危险函数调用 (os.system/subprocess/eval/exec)"
        HIGH_COUNT=$((HIGH_COUNT + 1))
      fi
      if echo "$stripped_code" | grep -q -E '\b(pickle\.loads|yaml\.load\s*\()' 2>/dev/null; then
        echo "  [HIGH] ${file} — 疑似不安全反序列化 (pickle/yaml.load)"
        HIGH_COUNT=$((HIGH_COUNT + 1))
      fi
      ;;
    js|ts|vue)
      if echo "$stripped_code" | grep -q -E '\b(eval\s*\(|new\s+Function\s*\()' 2>/dev/null; then
        echo "  [HIGH] ${file} — 疑似危险函数调用 (eval/Function)"
        HIGH_COUNT=$((HIGH_COUNT + 1))
      fi
      ;;
    java)
      if echo "$stripped_code" | grep -q -E '\b(Runtime\.getRuntime\(\)\.exec|ProcessBuilder)' 2>/dev/null; then
        echo "  [HIGH] ${file} — 疑似命令执行 (Runtime.exec/ProcessBuilder)"
        HIGH_COUNT=$((HIGH_COUNT + 1))
      fi
      ;;
    php)
      if echo "$stripped_code" | grep -q -E '\b(eval\s*\(|exec\s*\(|system\s*\(|shell_exec\s*\()' 2>/dev/null; then
        echo "  [HIGH] ${file} — 疑似危险函数调用 (eval/exec/system/shell_exec)"
        HIGH_COUNT=$((HIGH_COUNT + 1))
      fi
      ;;
  esac

  # ── 3. SQL注入检测 (高危) ──────────────────────────────────────────
  case "$ext" in
    py|js|ts|java|go|php)
      if echo "$stripped_code" | grep -q -E '(\+.*SELECT|\"\s*SELECT|'"'"'\s*SELECT|fmt\.Sprintf.*SELECT|sprintf.*SELECT)' 2>/dev/null; then
        echo "  [HIGH] ${file} — 疑似SQL字符串拼接"
        HIGH_COUNT=$((HIGH_COUNT + 1))
      fi
      ;;
  esac

  # ── 4. 弱加密算法 (中危) ──────────────────────────────────────────
  case "$ext" in
    py|js|ts|java|go|php)
      if echo "$stripped_code" | grep -q -i -E '\b(MD5|SHA1|SHA-1|DES|3DES|RC4|ECB)\b' 2>/dev/null; then
        echo "  [MEDIUM] ${file} — 疑似弱加密/哈希算法 (MD5/SHA1/DES/3DES/RC4/ECB)"
        MEDIUM_COUNT=$((MEDIUM_COUNT + 1))
      fi
      ;;
  esac

  # ── 5. 不安全随机数 (中危) ────────────────────────────────────────
  case "$ext" in
    py)
      if echo "$stripped_code" | grep -q -E '\brandom\.(random|randint|choice|sample)\b' 2>/dev/null; then
        echo "  [MEDIUM] ${file} — 疑似使用非安全随机数 (random模块用于安全场景)"
        MEDIUM_COUNT=$((MEDIUM_COUNT + 1))
      fi
      ;;
    js|ts)
      if echo "$stripped_code" | grep -q -E '\bMath\.random\b' 2>/dev/null; then
        echo "  [MEDIUM] ${file} — 疑似使用非安全随机数 (Math.random用于安全场景)"
        MEDIUM_COUNT=$((MEDIUM_COUNT + 1))
      fi
      ;;
  esac

  # ── 6. CORS 全域名放行 (中危) ──────────────────────────────────────
  case "$ext" in
    js|ts|vue|json)
      if echo "$stripped_code" | grep -q -E 'origin["'"'"']?\s*:\s*["'"'"']?\*' 2>/dev/null; then
        echo "  [MEDIUM] ${file} — CORS origin 配置为通配符 *"
        MEDIUM_COUNT=$((MEDIUM_COUNT + 1))
      fi
      ;;
  esac
}

# ── 执行扫描 ────────────────────────────────────────────────────────────────
if [[ "$SCAN_MODE" == "single_file" ]]; then
  echo "[Security-Hook] 扫描模式: 单文件增量"
  scan_file "$TARGET"
else
  echo "[Security-Hook] 扫描模式: 全项目"
  # 使用 find 而非 grep -r，回避 grep 跨平台 --include 兼容性问题
  # 同时利用 git ls-files 尊重 .gitignore
  if git rev-parse --git-dir >/dev/null 2>&1; then
    while IFS= read -r file; do
      [[ -f "$file" ]] || continue
      scan_file "$file"
    done < <(git ls-files --cached --others --exclude-standard -- '*.py' '*.js' '*.ts' '*.java' '*.go' '*.php' '*.rb' '*.rs' '*.c' '*.cpp' '*.cc' '*.cxx' '*.h' '*.hpp' '*.hxx' '*.cs' '*.swift' '*.kt' '*.kts' '*.scala' '*.dart' '*.lua' '*.sql' '*.vue' '*.html' '*.sh' '*.bash' '*.zsh' '*.yml' '*.yaml' '*.json' '*.xml' '*.toml' '*.ini' '*.cfg' '*.conf' 2>/dev/null)
  else
    # 非 git 仓库回退到 find
    while IFS= read -r file; do
      scan_file "$file"
    done < <(find . \( -name '*.py' -o -name '*.js' -o -name '*.ts' -o -name '*.java' -o -name '*.go' -o -name '*.php' -o -name '*.rb' -o -name '*.rs' -o -name '*.c' -o -name '*.cpp' -o -name '*.cc' -o -name '*.cxx' -o -name '*.h' -o -name '*.hpp' -o -name '*.hxx' -o -name '*.cs' -o -name '*.swift' -o -name '*.kt' -o -name '*.kts' -o -name '*.scala' -o -name '*.dart' -o -name '*.lua' -o -name '*.sql' -o -name '*.vue' -o -name '*.html' -o -name '*.sh' -o -name '*.bash' -o -name '*.yml' -o -name '*.yaml' -o -name '*.json' -o -name '*.xml' -o -name '*.toml' -o -name '*.ini' -o -name '*.cfg' -o -name '*.conf' \) -type f 2>/dev/null)
  fi
fi

# ── 汇总判定 ────────────────────────────────────────────────────────────────
echo ""
echo "[Security-Hook] ========== 预检汇总 =========="
echo "[Security-Hook] 高危阻断项: ${HIGH_COUNT}"
echo "[Security-Hook] 中危整改项: ${MEDIUM_COUNT}"
echo "[Security-Hook] ================================"

if [[ "$HIGH_COUNT" -gt 0 ]]; then
  echo "[Security-Hook] ⛔ 发现高危风险项，阻止操作继续。请先整改高危漏洞。"
  exit 2
elif [[ "$MEDIUM_COUNT" -gt 0 ]]; then
  echo "[Security-Hook] ⚠️  发现中危风险项，建议限期整改（本次不阻断）。"
  exit 1
else
  echo "[Security-Hook] ✅ 安全预检通过，无阻断级风险。"
  exit 0
fi
