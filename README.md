# Security Workflow — 企业代码安全评审插件

Claude Code 插件 + Python MCP 流程引擎，实现 **扫描 → 分级修复 → 工单流转 → 超时审计 → 上线卡点** 全闭环。

## 整体架构

```
Claude Code 插件层                     MCP 流程引擎 (Python)
┌──────────────────────────┐       ┌──────────────────────────┐
│  commands/               │       │  security_workflow/      │
│   /review  (安全评审)     │──RPC──│   mcp_server.py (入口)    │
│   /deploy  (上线卡点)     │       │   core/         (引擎)    │
│                          │       │   definition/   (枚举)    │
│  agents/                 │       │   model/        (数据)    │
│   security-scanner       │       │   persistence/  (存储)    │
│   quick-fix              │       │   timer/        (超时)    │
│                          │       │   spi/          (扩展)    │
│  hooks/                  │       └──────────────────────────┘
│   check-bash.sh (预检)    │
│   auto-fix-security.sh    │
└──────────────────────────┘
```

## 快速开始

### 前置条件

| 条件 | 必需？ | 说明 |
|------|--------|------|
| Python 3.10+ | 🟡 可选 | MCP 流程引擎（工单流转、上线卡点）。不装也能用扫描功能 |
| Bash 4.0+ | ✅ 必需 | 钩子脚本运行环境。macOS 自带 3.2 版本过低，需 `brew install bash`；Linux 一般已内置 5.x；Windows 需 Git Bash 或 WSL |
| Git | ✅ 必需 | 脚本优先用 `git ls-files` 获取追踪文件（自动尊重 `.gitignore`） |
| Perl 5+ | ✅ 必需 | `auto-fix-security.sh` 用于跨平台安全删除行。macOS/Linux 已内置；Windows 随 Git Bash 内置 |
| GNU grep | 🟡 推荐 | macOS 自带 BSD grep 不支持 `\b` 词边界，所有扫描模式会静默失效。安装：`brew install grep`（之后系统用 `ggrep` 命令） |
| Claude Code | ✅ 必需 | 插件宿主 |

Python 端零依赖 — 只用标准库（`json`, `datetime`, `pathlib`, `threading`, `enum`），无需 `pip install`。

### 1. 安装插件

```bash
claude plugins marketplace add security-workflow hanchuntao/security-workflow
claude plugins install security-workflow@security-workflow
```

安装后 `/review` 和 `/deploy` 即可使用。MCP 流程引擎由 Claude Code 自动启动（通过 `.mcp.json` 配置），无需用户手动运行。

### 2. 验证 MCP 流程引擎能启动

```bash
cd security-workflow
echo '{"jsonrpc":"2.0","id":1,"method":"initialize","params":{}}' | python3 -m security_workflow.mcp_server
```

预期输出包含 `"serverInfo":{"name":"security-workflow-mcp-engine","version":"1.0.1"}`。

如果输出乱码或报错，检查 Python 版本 ≥ 3.10，且 `security_workflow/` 目录在当前路径下。

### 3. 跑集成测试

```bash
python3 tests/integration_test.py
```

模拟 `/review` → 建工单 → `/deploy` 卡点 → 整改闭环 → 再次卡点的完整链路。测试结束后输出审计轨迹和 PASS/FAIL 判定。

### 4. 手动测试各个组件

```bash
# 安全预检钩子（单文件）
bash hooks/check-bash.sh tests/vuln_cases/high_risk_demo.py   # 预期: 高危阻断 exit 2
bash hooks/check-bash.sh tests/vuln_cases/mid_risk_demo.js    # 预期: 中危警告 exit 1
bash hooks/check-bash.sh tests/vuln_cases/low_risk_demo.ts    # 预期: 通过 exit 0

# 安全预检钩子（全项目）
bash hooks/check-bash.sh                                      # 扫描整个仓库

# 低危自动修复（干跑 — 默认安全）
bash hooks/auto-fix-security.sh

# 低危自动修复（实际应用）
SECURITY_FIX_APPLY=true bash hooks/auto-fix-security.sh
```

## 命令参考

### `/review` — 代码安全评审

```
/review scope=project level=all mode=full workflow=true
```

| 参数 | 可选值 | 默认 | 说明 |
|------|--------|------|------|
| scope | file / project | project | `project` = 全项目扫描；`file` = 仅当前文件 |
| level | low / mid / high / all | all | 最低检测风险等级 |
| mode | increment / full | full | 增量快扫 / 全量深度 |
| workflow | true / false | true | 是否创建工单、联动流程引擎 |

### `/deploy` — 上线安全卡点

```
/deploy branch=main
```

| 参数 | 可选值 | 默认 | 说明 |
|------|--------|------|------|
| branch | 分支名 | main | 待上线分支 |
| skip-review | false | false | 生产强制 false |
| force | true / false | false | 紧急热修复用，需安全负责人审批 |
| workflow | true / false | true | 联动流程引擎 |

## 项目名配置

创建工单时需要关联项目名。**默认自动检测**，无需手动填写：

| 优先级 | 来源 | 说明 |
|--------|------|------|
| 1 | `SECURITY_WORKFLOW_PROJECT` 环境变量 | 最高优先级，适合 CI/CD 场景 |
| 2 | `.security-workflow` 配置文件 | 在项目根目录创建 `{"project": "my-app"}` |
| 3 | 当前目录名 | 默认回退，无需任何配置 |

```bash
# 方式1: 环境变量（CI/CD 推荐）
export SECURITY_WORKFLOW_PROJECT="my-backend-api"

# 方式2: 配置文件（项目内推荐）
echo '{"project": "my-backend-api"}' > .security-workflow

# 方式3: 什么都不做，自动取目录名
# cd ~/work/my-backend-api → project = "my-backend-api"
```

## 环境变量

| 变量 | 默认值 | 说明 |
|------|--------|------|
| `SECURITY_FIX_APPLY` | false | `true` 启用实际修复（默认干跑） |
| `SECURITY_FIX_VERBOSE` | false | `true` 输出完整 diff |
| `SECURITY_WORKFLOW_DATA` | .security-workflow-data | 统一数据目录（日志、备份、工单、审计） |
| `SECURITY_WORKFLOW_PROJECT` | (当前目录名) | 项目名，用于工单分组和上线卡点过滤 |
| `SECURITY_WORKFLOW_ENGINE_PATH` | ./security_workflow | MCP 引擎 Python 包路径 |
| `SECURITY_WORKFLOW_ENV` | production | 运行环境标识 |

## 钩子

### check-bash.sh — 安全预检

| 触发时机 | 行为 |
|---------|------|
| 文件保存 | 单文件增量扫描 |
| 命令执行前 | 全项目扫描 |
| Git 提交前 | 全项目扫描 |

退出码: `0`=通过, `1`=中危警告(不阻断), `2`=高危阻断

### auto-fix-security.sh — 低危自动修复

- **仅触发于 Git 提交前**（不在文件保存时执行）
- **默认干跑**：`SECURITY_FIX_APPLY=true` 才实际修改
- **手术刀式匹配**：只删 `console.log("debug...")` / `print("temp...")` / `pdb.set_trace()` / `debugger;` / 空 TODO 注释
- **备份+回滚**：修改前自动备份，失败自动恢复
- **审计日志**：每次运行写入 `$SECURITY_WORKFLOW_DATA/fix-audit/`

## 各平台兼容性

| 依赖 | macOS | Linux | Windows |
|------|-------|-------|---------|
| Bash 4.0+ | `brew install bash` | 已内置 | Git Bash / WSL |
| GNU grep（`\b` 支持） | `brew install grep` | 已内置 | Git Bash 内置 |
| Perl 5+ | 已内置 | 已内置 | Git Bash 内置 |
| Git | `xcode-select --install` | `apt install git` | Git Bash / WSL |
| Python 3.10+ | 🟡 可选（已内置 3.x，检查版本） | 🟡 可选 | 🟡 可选 |

> **macOS 特别提醒**：macOS 自带 BSD grep **不支持 `\b` 词边界**，会导致所有安全扫描模式静默失效（不报错，但匹配不到任何东西）。安装 GNU grep 后，`check-bash.sh` 启动时会自动检测并告警。

## 统一数据目录

所有运行时产出存放在 `$SECURITY_WORKFLOW_DATA`（默认 `.security-workflow-data/`）：

```
.security-workflow-data/
├── fix-audit/                    # auto-fix-security.sh 产出
│   ├── fix-{timestamp}.log       #   审计日志
│   └── backups/{timestamp}/      #   修复前备份
├── tickets.json                  # MCP engine 工单存储
└── audit_log.jsonl               # MCP engine 操作轨迹
```

已加入 `.gitignore`，不会误提交。

## 目录结构

```
security-workflow/
├── .claude-plugin/plugin.json    # 插件注册
├── .mcp.json                     # MCP 引擎连接配置
├── commands/                     # /review, /deploy
├── agents/                       # security-scanner, quick-fix
├── skills/                       # 安全评审规范
├── hooks/                        # check-bash.sh, auto-fix-security.sh
├── security_workflow/            # Python MCP 流程引擎
│   ├── mcp_server.py             #   入口 (6 tools)
│   ├── core/                     #   工单流转、卡点判定
│   ├── definition/               #   枚举定义
│   ├── model/                    #   数据模型
│   ├── persistence/              #   JSON 持久化
│   ├── timer/                    #   超时计算
│   └── spi/                      #   通知扩展点
├── tests/
│   ├── vuln_cases/               # 漏洞测试样本（高/中/低）
│   ├── regression/               # 回归测试
│   └── integration_test.py       # 联动集成测试
└── examples/                     # 各语言安全编码样板
```

## 变更记录

### v1.0.1 (2026-06-25) — smoke test 修复版

**已修复的 bug (6 个)**：
- CRITICAL #2: `review.md`/`deploy.md` — YAML frontmatter 方括号被解析为流式序列，命令无法加载 → 加引号
- BUG #5: `auto-fix-security.sh` — `[\s:_,-]` 在 POSIX ERE 方括号内不识别 `\s`，所有匹配模式永不命中 → 改为 `[[:space:]:_,-]`
- BUG #6: `auto-fix-security.sh` — `set -u` 下访问未初始化关联数组键 crash → 加 `${VAR-}` 默认值
- CRITICAL #3: `auto-fix-security.sh` — 已由原始 sed -i 重写为 perl + 干跑 + 手术刀匹配 + 备份回滚
- CRITICAL #4: `check-bash.sh` — 已由 grep -v "#" 改为 sed -E 精确剥离注释
- CRITICAL #1: `security-scanner.md` — xxd 验证无 BOM、无前置文字，无法复现

**新增**：
- Python MCP 流程引擎完整实现（10 个 .py 文件，6 个 MCP tools）
- `tests/integration_test.py` — `/review` → `/deploy` 联动集成测试
- 统一数据目录 `$SECURITY_WORKFLOW_DATA`
- `.gitignore` 防止运行时数据误提交

**已验证**：
- `check-bash.sh`: 3/3 分级正确（高危阻断 exit 2、中危警告 exit 1、低危通过 exit 0）
- `auto-fix-security.sh`: 干跑检测 2/2、实际修复精准删除 2 行、备份+日志完整
- MCP engine: 6/6 tools 响应正常，工单创建→流转→驳回→卡点→审计全链路通过
- 集成测试: 8/8 步骤通过，PASS
