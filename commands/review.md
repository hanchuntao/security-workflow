---
description: 企业生产级代码安全评审 -- 扫描、分级修复、工单流转、安全卡点全闭环
argument-hint: "[scope=project|file] [level=low|mid|high|all] [mode=increment|full] [workflow=true|false]"
allowed-tools: "Read, Grep, Glob, Bash(git diff:*), Bash(git log:*)"
---

# /review
## 命令概述
企业生产级代码安全评审核心指令，联动 security-scanner 扫描智能体、quick-fix 修复智能体、security-workflow 流程引擎，实现「代码扫描-风险分级-智能修复-工单创建-流程流转-安全卡点」全自动化闭环。
适配日常开发增量校验、MR代码评审、版本上线前全量安全审计，是整套安全流水线唯一核心评审入口。

## 核心能力（生产闭环）
1. 全量/增量差异化安全扫描，严格遵循三级风险分级规范
2. 自动匹配对应漏洞修复策略（高危人工、中危半自动、低危全自动）
3. 自动创建标准化安全评审工单，初始化对应流转状态
4. 联动流程引擎实现超时提醒、抄送、驳回、上线拦截卡点
5. 输出结构化审计报告，满足等保合规、企业安全审计要求

## 命令参数
| 参数名 | 可选值 | 默认值 | 说明 |
|-------|--------|--------|------|
| scope | file / project | project | 扫描范围：单文件扫描 / 全项目扫描 |
| level | low / mid / high / all | all | 扫描校验等级，限定最低检测风险等级 |
| workflow | true / false | true | 是否自动创建安全评审工单、联动流程引擎流转 |
| mode | increment / full | full | 扫描模式：increment增量变更扫描 / full全量深度扫描 |

## 标准使用示例
```
# 全项目全等级深度安全评审（生产上线必备）
/review scope=project level=all mode=full workflow=true

# 单文件增量评审（日常开发调试）
/review scope=file level=all mode=increment workflow=true

# 高危漏洞专项评审（紧急卡点校验）
/review scope=project level=high mode=full workflow=true
```

## 完整执行链路（100%对齐双Agent规范）
### 步骤1：初始化扫描规则
根据传入参数确定扫描范围、模式、风险等级阈值，调用 security-scanner 执行标准化扫描，严格匹配统一漏洞分级清单。

### 步骤2：结构化漏洞扫描输出
Scanner 输出固定9项标准化字段数据，包含risk_id、risk_level、file_path、line_no、risk_desc、compliance_rule、fix_suggest、scan_mode、workflow_status，为修复和工单流转提供唯一数据源。

### 步骤3：自动匹配分级修复策略
联动 quick-fix执行差异化修复逻辑，严格对齐全局统一规则：
1. 高危漏洞：禁止自动修复，仅生成精准整改方案，工单初始状态「待人工整改+双人评审+禁止上线」
2. 中危漏洞：生成半自动修复代码，需人工确认生效，工单初始状态「待修复确认+限期整改」
3.低危漏洞：全自动静默修复，自动消除风险，工单自动闭环留存审计

### 步骤4：流程引擎工单联动
workflow=true 时自动触发流程引擎能力：
1. 按漏洞等级初始化对应工单状态
2. 高危漏洞自动阻断MR合并、版本上线
3. 中危漏洞启动限期计时，超时自动抄送安全负责人
4. 同步留存扫描、修复、整改全链路日志，用于合规审计

### 步骤5：自动生成评审报告并落盘
调用 `generate_review_report()` 汇总全局风险统计、单条漏洞详情、修复方案、工单流转状态、安全评级，自动生成结构化 Markdown 报告并保存至 `.security-workflow-data/reports/{project}-review-{timestamp}.md`。报告包含六大部分：全局风险汇总、安全工单状态、单条漏洞详情、上线准入判定、整改要求、审计合规声明。

## 生产强制约束
1. 全量上线评审必须使用 `mode=full level=all`，禁止增量扫描替代上线卡点校验
2. 检测出高危漏洞时，强制阻断后续发布流程，不支持跳过豁免
3. 所有扫描、修复、工单变更记录永久结构化留存，不可删除篡改
4. 严格遵循双Agent分级规范，禁止私自降级漏洞风险、跳过整改流程
5. 中危漏洞超期未整改自动升级风险，触发二次评审提醒

## 输出内容规范
1. 全局安全风险汇总：高危/中危/低危漏洞数量、项目整体安全评级
2. 单条漏洞结构化详情：完整对齐Scanner输出字段
3. 分级修复结果：修复模式、修复前后代码对比、风险消除说明
4. 安全工单状态：当前流转节点、待操作事项、超时时间
5. 合规审计结论：本次评审合规性判定、整改要求、上线准入结论

## 联动依赖说明
1. 依赖 Agent：security-scanner（扫描数据源）、quick-fix（漏洞整改）
2. 依赖引擎：security-workflow 流程引擎（工单流转、卡点、超时提醒）
3. 依赖钩子：文件保存、Git提交前置安全校验能力
