# 插件版本回归校验清单 (v1.0.1)
## 校验项（每次更新规则必须全量校验）
### Agent 与命令
1. ✅ security-scanner Agent 正常加载 (frontmatter 从文件首行开始)
2. ✅ quick-fix Agent 工具权限受限 (无 Write/Edit，仅 Read/Grep/Glob)
3. ✅ /review 命令可被 Claude Code 识别 (argument-hint 正常显示)
4. ✅ /deploy 命令可被 Claude Code 识别 (argument-hint 正常显示)

### 漏洞分级
5. ✅ 高危漏洞全部识别、禁止自动修复、标记阻断上线
6. ✅ 中危漏洞精准识别、进入半自动修复流程、限期整改
7. ✅ 低危漏洞自动识别、静默修复、自动闭环工单
8. ✅ 扫描 9 项结构化字段完整输出

### 钩子行为
9. ✅ check-bash.sh 单文件保存时仅扫描变更文件 (增量)
10. ✅ check-bash.sh Git 提交时全项目扫描
11. ✅ check-bash.sh 分级退出码正确 (0=通过/1=中危/2=高危阻断)
12. ✅ auto-fix-security.sh 仅触发于 Git 提交前 (不在文件保存时)
13. ✅ auto-fix-security.sh 默认干跑模式 (不修改文件)
14. ✅ auto-fix-security.sh 手术刀式匹配 (不误删业务日志)
15. ✅ auto-fix-security.sh 审计日志完整留存
16. ✅ auto-fix-security.sh 备份机制正常工作

### 平台兼容
17. ✅ Shell 脚本跨平台 (perl 替代 sed -i, env bash shebang)
18. ✅ .mcp.json 无硬编码绝对路径 (使用环境变量 + 相对路径)

### 数据完整性
19. ✅ 高危漏洞无漏判 (注释行末凭证不被 grep -v "#" 跳过)
20. ✅ TypeScript 测试用例语法正确 (console.log 替代 print)

## 回归验收标准
无漏判、无误判、无策略错乱、无卡点失效、无跨平台兼容性问题

## 已知限制
1. MCP 流程引擎 (security_workflow Python 包) 需单独安装，不在本仓库中
2. auto-fix-security.sh 的 perl 依赖 (Windows 需 Git Bash / WSL 环境)
3. 超过 5MB 的大文件在 check-bash.sh 中会被跳过
