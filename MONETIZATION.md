# Security Workflow — 分发与商业化方案

## 一、用户如何安装（三条路径）

### 路径 A：Slash Command 安装（最推荐，30秒）

用户在 Claude Code 中输入：

```
/plugin marketplace add security-workflow hanchuntao/security-workflow
/plugin install security-workflow@security-workflow
```

安装完成即可使用 `/security-workflow:review` 和 `/security-workflow:deploy`。

### 路径 B：手动 settings.json（适合团队批量部署）

在团队的 `~/.claude/settings.json` 中配置：

```json
{
  "extraKnownMarketplaces": {
    "security-workflow": {
      "source": { "source": "github", "repo": "hanchuntao/security-workflow" }
    }
  },
  "enabledPlugins": {
    "security-workflow@security-workflow": true
  }
}
```

### 路径 C：CI/CD 流水线集成（企业标准化）

```bash
# GitHub Actions / GitLab CI
- name: Install Security Workflow
  run: |
    claude plugins marketplace add security-workflow hanchuntao/security-workflow
    claude plugins install security-workflow@security-workflow --scope project

- name: Run deploy gate
  run: |
    export SECURITY_WORKFLOW_PROJECT="${{ github.event.repository.name }}"
    claude -p "/security-workflow:deploy branch=main"
```

### 路径 D：npx 一行安装（社区工具）

```bash
npx -y openplugin@latest hanchuntao/security-workflow
# 或
npx claude-plugins install @hanchuntao/security-workflow
```

---

## 二、推广策略（让更多人知道）

| 渠道 | 动作 | 预期效果 |
|------|------|---------|
| **awesome-claude-plugins** | 提 PR 收录到 [GiladShoham/awesome-claude-plugins](https://github.com/GiladShoham/awesome-claude-plugins) | 被 2000+ star 列表收录，持续流量 |
| **claude-plugins-community** | 提交到 [clau.de/plugin-directory-submission](https://clau.de/plugin-directory-submission) | 进入 Anthropic 官方社区镜像 |
| **掘金/知乎/Dev.to** | 写一篇「Claude Code 插件实现企业级 DevSecOps」实战文章 | 技术品牌 + SEO 长尾流量 |
| **Reddit r/ClaudeAI** | 发布插件介绍 + Demo GIF | 海外开发者社区曝光 |
| **GitHub 仓库优化** | 加 Topics: `claude-code-plugin` `devsecops` `sast` `security` | 被 GitHub Explore 推荐 |
| **Demo 视频** | 3分钟录屏：安装→扫描→修复→报告 | 提升安装转化率 |

---

## 三、商业化路线（三条路，可以同时走）

### 路线 1：AgentStore 付费插件（轻量，直接卖插件）

[AgentStore](https://agentstore.tools) 是唯一支持 Claude Code 插件定价的第三方市场。

**定价参考：**

| 版本 | 价格 | 包含 |
|------|------|------|
| 社区版 | 免费 | github.com 安装，核心扫描+修复，社区 issue 支持 |
| 专业版 | $39/人 | AgentStore 购买，含 MCP 引擎优先支持、规则自动更新 |
| 团队版 | $199/5人 | 含私有部署指导、自定义规则适配 |

**收入测算（保守）：**
```
月销 20 个专业版:  20 × $39  × 80% = $624/月
月销 5 个团队版:    5 × $199 × 80% = $796/月
合计: ~$1,420/月
```

**优点**：被动收入，一次开发持续卖
**缺点**：AgentStore 还处于早期，流量有限

### 路线 2：免费插件 + 企业增值服务（最稳，赚服务费）

插件完全免费开源，靠服务赚钱。

| 服务项目 | 定价 | 卖给谁 | 交付周期 |
|---------|------|--------|---------|
| **安全规则定制** — 对接企业内部编码规范 | ¥15,000-30,000/次 | 有合规需求的中大型企业 | 2-3周 |
| **私有化部署** — MCP引擎 + 数据库 + SSO | ¥50,000-120,000/年 | 金融、医疗、政务单位 | 1-2个月 |
| **DevSecOps 培训** — 基于本插件的落地实训 | ¥8,000-15,000/天 | 研发团队 20-50人 | 1天 |
| **漏洞库订阅** — 每月更新 CVE + 框架规则 | ¥2,000-5,000/月 | 安全意识强的团队 | 持续 |
| **年度护航** — 规则维护 + 应急响应 + 技术支持 | ¥20,000-50,000/年 | 已有部署的企业 | 持续 |

**收入测算（中型企业客户示例）：**
```
私有化部署:      ¥80,000/年  × 3个客户 = ¥240,000/年
漏洞库订阅:      ¥3,000/月    × 10个客户 = ¥360,000/年
定制+培训:       ¥20,000/次   × 5次/年    = ¥100,000/年
合计: ~¥700,000/年
```

**优点**：客单价高，中国企业愿意为合规买单
**缺点**：需要销售能力，不适合纯技术人员

### 路线 3：SaaS 托管 MCP 引擎（增长型，赚订阅费）

把 MCP 流程引擎做成云端服务，用户本地只装插件，工单和审计数据存你的服务器。

```
┌──────────────────────┐       ┌─────────────────────────┐
│ 用户本地 Claude Code  │─HTTPS─│  你的 SaaS 服务           │
│ 插件 (免费)           │       │  security-workflow.cloud │
│ hooks + agents       │       │  ├─ 多项目管理            │
│                      │       │  ├─ 团队协作              │
└──────────────────────┘       │  ├─ 合规报表导出          │
                               │  ├─ 通知集成 (飞书/钉钉)  │
                               │  └─ SSO + 审计日志        │
                               └─────────────────────────┘
```

**定价：**

| 套餐 | 月费 | 适合 |
|------|------|------|
| Free | $0 | 1人，1个项目，本地存储 |
| Team | $29/月 | 5人，10个项目，云端存储 |
| Business | $199/月 | 50人，不限项目，SSO，飞书/钉钉通知 |
| Enterprise | 议价 | 私有部署，SLA，定制规则 |

**收入测算（6个月后）：**
```
50个 Team 客户:   50 × $29   = $1,450/月
10个 Business 客户: 10 × $199  = $1,990/月
2个 Enterprise:    2 × $1,000  = $2,000/月
合计: ~$5,440/月 ≈ ¥39,000/月
```

**优点**：可规模化，持续收入，估值模型好
**缺点**：需要运维基础设施，前期投入大

---

## 四、推荐执行路径（三阶段）

### 阶段 1 — 现在 → 第 2 周：免费发布 + 获取用户

```
✅ 已完成: README、plugin.json、marketplace.json
⬜ 待做: 录 3 分钟 Demo 视频 (GIF)
⬜ 待做: 写一篇「Claude Code 插件实战 DevSecOps」文章发掘金
⬜ 待做: 提 PR 到 awesome-claude-plugins
⬜ 待做: GitHub 仓库加 Topics + 配封面图
⬜ 待做: Reddit r/ClaudeAI 发帖
```

**衡量标准**：2周内 GitHub Star > 100，即可进入阶段 2

### 阶段 2 — 第 3 周 → 第 8 周：验证商业化方向

```
⬜ 路线 1 测试: 在 AgentStore 上架 Pro 版 ($39)，看付费转化率
⬜ 路线 2 启动: 在 Upwork/猪八戒接 2-3 个安全审计小单，验证服务定价
⬜ 用户反馈收集: 在 README 加「企业咨询」联系方式
```

**衡量标准**：如果有 3+ 个企业主动咨询 → 优先路线 2；如果付费转化率 > 3% → 加强路线 1

### 阶段 3 — 第 9 周 → 第 16 周：规模化

```
⬜ 如果路线 2 验证成功: 注册公司，正式推企业服务
⬜ 如果路线 3 想尝试: 用 FastAPI + SQLite → PostgreSQL 搭建 SaaS MVP
⬜ 持续内容营销: 每月一篇技术文章，保持 SEO 流量
```

---

## 五、关键数字参考

| 指标 | 保守 | 可能 |
|------|------|------|
| 免费安装量 (6个月) | 500 | 2,000 |
| 付费转化率 | 2% | 5% |
| 企业咨询转化 | 2家 | 8家 |
| 6个月总收入 | $5,000 | $30,000 |
| 12个月总收入 | $20,000 | $80,000 |

---

## 六、一个不可忽略的提醒

**你的插件最大的护城河是"合规"二字。**

中国等保2.0、金融行业安全编码规范、政务系统安全准入——这些是硬需求，而且是只有中国开发者才真正理解的场景。Anthropic 官方做的 security-guidance 插件不会深度覆盖这些。

所以在内容营销时，关键词应该是：
- "Claude Code + 等保2.0"
- "AI 辅助 DevSecOps 合规审计"
- "企业安全编码规范自动化落地"

这些关键词在中文技术社区几乎没有竞品。
