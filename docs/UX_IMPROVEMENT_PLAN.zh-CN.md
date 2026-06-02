# AgentReady 用户体验全面提升方案

## 目标

本方案用于提升 AgentReady 从首次接触、安装、第一次扫描、理解报告、接入 CI，到长期维护 baseline 和规则配置的完整体验。

核心判断：当前 AgentReady 已经具备可运行 MVP，但用户体验仍偏“工程工具初版”。下一阶段不应继续堆规则，而应优先降低采用成本、提高报告可行动性、降低误报处理成本，并让发布和维护路径更清晰。

## 设计原则

1. 三分钟跑起来

新用户不应该先理解所有命令。默认路径必须是：

```bash
npx agentready scan .
```

然后得到清楚的风险摘要和下一步动作。

2. 零信任但不恐吓

报告应明确风险原因、影响和修复动作，但避免把所有发现都写成严重事故。安全工具如果过度制造噪音，用户会很快关闭它。

3. 老项目可渐进采用

真实项目通常不是干净仓库。baseline 机制应成为官方推荐路径之一，让团队先记录既有问题，再阻断新增风险。

4. 配置可发现

用户不能靠翻源码找 rule id、配置项和失败阈值。CLI、README、schema、示例和报告都要让配置路径可发现。

5. 输出面向动作

每个 finding 都应该回答三个问题：

- 这是什么问题
- 为什么对 AI coding agent 有风险
- 下一步应该做什么

6. 默认保护隐私

AgentReady 是本地扫描器。默认不发送 telemetry、不上传报告、不打印完整 secrets。后续如果做匿名统计，必须显式 opt-in。

7. 命令行为可预测

CLI 会被人手动运行，也会被 CI、脚本和 AI agent 调用。输出、退出码、错误信息和 JSON/SARIF 结构必须稳定，不能只追求人类可读。

8. 新手路径和专家路径分离

默认命令应该简单，专家能力应该通过显式参数打开。不要让新用户在第一次运行时理解 baseline、SARIF、CI 阈值和 rule override。

## 目标用户画像

### 个人开发者

诉求：

- 快速知道仓库是否适合给 AI coding agent 使用
- 不想配置复杂安全平台
- 希望本地运行，不上传代码和 findings

关键体验：

- `npx agentready scan .` 能直接给出可行动结果
- 报告不应要求安全背景才能理解
- 修复建议要短、明确、能立即执行

### 开源维护者

诉求：

- 保护 contributors、CI、secrets 和维护者机器
- 给项目建立 agent 使用边界
- 让外部贡献者理解哪些路径和命令不应让 agent 触碰

关键体验：

- `AGENTS.md` 和 `.agentignore` 生成质量要高
- Markdown 报告要适合贴到 PR 或 issue
- baseline 和 rule 配置要可审计

### 小团队技术负责人

诉求：

- 渐进接入，不因历史问题阻断开发
- 在 CI 中阻断新增高风险问题
- 能向团队解释为什么某条 finding 重要

关键体验：

- baseline 生命周期清楚
- CI 模式有 report-only、new-only、strict
- JSON/SARIF 输出稳定，便于接入内部流程

### AI Agent / 自动化调用方

诉求：

- 能通过机器可读输出判断是否继续操作
- 不被冗长人类文本干扰
- 能定位修复优先级和安全边界

关键体验：

- JSON 输出稳定
- 退出码语义清楚
- `--quiet` / `--format json` / `--ci` 行为一致

## 当前体验缺口

### 安装和首次使用

当前 README 主要描述本地开发安装：

```bash
npm install
npm link
agentready scan
```

这适合开发者维护项目，不适合普通用户试用。正式发布后，首要路径应改成：

```bash
npx agentready scan .
npm install -D agentready
pnpm dlx agentready scan .
bunx agentready scan .
```

缺口：

- 缺少 `--version`
- 缺少 `quickstart` 或首次引导命令
- 缺少 npm / pnpm / yarn / bun 安装矩阵
- 缺少 Windows、macOS、Linux 的命令兼容说明
- 缺少 “第一次扫描后怎么处理” 的明确路径

### 报告体验

当前 text 报告已经能展示 severity、rule、location、evidence、fix，但还缺：

- 顶部风险摘要不够决策化
- finding 没有解释 “为什么 AI agent 场景下危险”
- 没有 grouped view，例如按文件、按类别、按严重级别
- 没有 “recommended next commands”
- 没有 “baseline suppressed debt” 的后续处理建议
- Markdown 报告还不适合直接贴到 PR comment

### 配置体验

当前配置能力已经具备，但学习成本偏高：

- `.agentready.json` 不会解释字段用途
- `list-rules` 有 rule id，但没有按类别筛选
- 未知 rule id 能 warning，但用户不一定看见 warning 后如何处理
- `baselinePath` 写入配置后，用户需要理解 baseline 文件生命周期
- 没有 `agentready config explain` 或 `agentready config validate`

### CI 接入体验

当前 `docs/CI.md` 可用，但还不够产品化：

- 缺少 “只跑报告不阻断” 的软启动模式
- 缺少 “先 baseline，再阻断新增风险” 的推荐 CI 模式
- 缺少 GitHub PR comment 示例
- 缺少 SARIF 与普通 CI exit code 的选择说明
- 缺少 GitHub Action 封装，用户需要手写 Node setup 和 npx 命令

### 长期维护体验

当前 baseline 能抑制旧 findings，但缺少生命周期工具：

- 缺少 `baseline update`
- 缺少 `baseline prune`
- 缺少 `baseline diff`
- 缺少 baseline 老化策略
- 缺少 “哪些 baseline 已不再匹配，应删除” 的报告

### 错误处理体验

当前 CLI 已经会处理部分错误，但用户体验仍可增强：

- 配置文件 JSON 错误应指出文件路径和可能修复方式
- `--config` 文件不存在应提示 `agentready init`
- baseline 文件不存在应提示生成命令
- unsupported format / fail threshold 应展示可用值和示例
- CI 模式退出码应在文档中清楚定义

### 命令契约体验

当前命令能工作，但还没有形成明确契约：

- 缺少退出码表
- 缺少 stdout/stderr 约定
- 缺少 JSON 输出版本字段
- 缺少 `--quiet`、`--verbose` 和 `--no-color`
- 缺少机器调用时的稳定错误格式
- 缺少 “哪些字段会长期稳定，哪些字段可能变化” 的说明

建议定义：

- `0`：扫描完成，未达到失败阈值
- `1`：扫描完成，达到 `failOn` 阈值
- `2`：CLI 参数错误
- `3`：配置或 baseline 文件错误
- `4`：扫描过程发生不可恢复错误

stdout/stderr 建议：

- 正常报告输出到 stdout
- 错误、warning、debug 输出到 stderr
- `--format json` 时 stdout 必须只包含 JSON
- `--output` 写文件时 stdout 只输出简短完成信息

### 信任和隐私体验

安全工具自身必须先让用户信任。

缺口：

- README 中还没有明确 “不上传代码、不上传 findings、不发送 telemetry”
- 没有 `docs/PRIVACY.md`
- 没有说明 secret redaction 的边界
- 没有说明 CI artifact 和 PR comment 仍可能泄露路径、文件名或 evidence
- 没有说明 baseline 文件本身应如何处理

建议：

- 增加隐私承诺文档
- 报告中避免打印完整 secret-like value
- Markdown/JSON/SARIF 文档中说明输出仍应按敏感信息处理
- baseline 文档说明是否建议提交到仓库，以及提交前如何审查

### 故障排查体验

首次使用中常见阻断不是安全规则，而是运行环境。

缺口：

- 没有 Troubleshooting 文档
- 没有 Node 版本错误示例
- 没有 Windows PowerShell quoting 示例
- 没有 `npx` 缓存、网络、权限问题说明
- 没有 “扫描太慢/文件太多/输出太长” 的处理建议

建议新增：

- `docs/TROUBLESHOOTING.md`
- `agentready doctor` 输出下一步修复命令
- `--debug` 输出配置路径、baseline 路径、跳过文件统计

## 目标用户路径

### 路径 1：新用户试用

目标：不安装到项目，直接看到价值。

推荐体验：

```bash
npx agentready scan .
```

理想输出：

```text
AgentReady scanned 184 files in 1.8s

Risk summary:
  high    1
  medium  3
  low     4
  info    2

Top risks:
  [HIGH] .env:2 Secret-like assignment is present
  [MED]  .github/workflows/ci.yml:9 GitHub Actions grants contents write permission

Next steps:
  1. Move secrets out of repository files.
  2. Run `agentready init .` to create AGENTS.md and .agentignore.
  3. Run `agentready scan . --format markdown --output agentready-report.md` for a shareable report.
```

需要实现：

- 更好的 text summary
- 扫描耗时
- top risks
- next steps
- `--version`
- README 首屏改为 npx 试用路径

### 路径 2：新项目初始化

目标：把 agent boundary 作为新项目标准配置。

推荐体验：

```bash
agentready init .
agentready scan .
```

理想能力：

- `init --preset balanced`
- `init --preset strict`
- `init --preset legacy`
- `init --with-ci`
- `init --dry-run`

建议默认：

- `balanced`：适合大多数项目
- `strict`：适合包含 secrets、infra、客户数据的项目
- `legacy`：适合老项目，默认写入 baseline 引导

### 路径 3：老项目接入

目标：不被历史问题阻断。

推荐体验：

```bash
agentready scan .
agentready baseline . --output .agentready-baseline.json
agentready scan . --baseline .agentready-baseline.json --ci
```

更好的体验：

```bash
agentready onboard .
```

`onboard` 可以做：

- 扫描当前仓库
- 询问是否生成 baseline
- 生成 `.agentready.json`
- 生成 `AGENTS.md` 和 `.agentignore`
- 输出 CI 接入建议

非交互环境中：

```bash
agentready onboard . --legacy --yes
```

### 路径 4：CI 接入

目标：复制粘贴即可跑。

推荐体验：

```bash
agentready init . --with-ci
```

生成：

- `.github/workflows/agentready.yml`
- `.agentready.json`
- 可选 `.agentready-baseline.json`

CI 模式分三档：

- `report-only`：只生成报告，不失败
- `new-only`：使用 baseline，只阻断新增风险
- `strict`：无 baseline，按 `failOn` 阻断

### 路径 5：长期维护

目标：团队能持续减少风险，而不是永久依赖 baseline。

推荐命令：

```bash
agentready baseline diff
agentready baseline prune
agentready baseline update
agentready debt
```

需要报告：

- baseline 当前抑制了多少 findings
- 哪些 baseline 条目已经不再出现
- 哪些 baseline 条目超过 N 天
- 哪些 high findings 长期未修

## 具体工程方案

### 阶段 1：首次使用体验

优先级：P0

目标：用户第一次运行就能理解结果。

实施项：

- 增加 `--version`
- `scan` 输出扫描耗时
- text 报告增加 `Top risks`
- text 报告增加 `Next steps`
- finding 增加 `category`
- finding 增加 `why` 字段
- finding 增加 `fixCommand` 或 `fixHint`
- README 首屏改为 `npx agentready scan .`
- 增加 install matrix

验收标准：

- 用户只读 README 前 30 行即可运行第一次扫描
- 有 high finding 时，报告能明确下一步动作
- 无 finding 时，报告给出合理后续，例如 `agentready init .` 或 CI 示例

### 阶段 2：初始化和 onboarding

优先级：P0

目标：把 “工具安装” 变成 “项目接入”。

实施项：

- 增加 `onboard` 命令
- `init` 增加 `--preset balanced|strict|legacy`
- `init` 增加 `--with-ci`
- `init` 增加 `--dry-run`
- `init` 输出创建文件列表和下一步命令
- `.agentready.json` 生成时带注释不可行，因为 JSON 不支持注释；改为同时生成 `docs/agentready.md` 或在 README 里解释

验收标准：

- 新项目可以一条命令生成 agent boundary 和配置
- 老项目可以一条命令生成 baseline 接入建议
- 所有生成文件都不会覆盖已有文件，除非显式 `--force`

### 阶段 3：报告体验

优先级：P0

目标：报告能直接进入 PR、issue、CI artifact。

实施项：

- Markdown 报告增加 executive summary
- Markdown 报告增加 category grouping
- Markdown 报告增加 baseline section
- SARIF 增加 rule metadata，包括 help text、precision、tags
- JSON 输出增加 machine-readable `nextSteps`
- text 输出支持 `--verbose` 和 `--quiet`
- 增加 `--max-findings` 防止大项目输出爆炸

验收标准：

- Markdown 报告可以直接贴到 PR comment
- SARIF 在 GitHub code scanning 中能显示清楚 rule 帮助
- text 输出默认不超过合理长度，大项目仍可读

### 阶段 4：配置和误报管理

优先级：P1

目标：降低误报处理成本，避免用户直接弃用工具。

实施项：

- 增加 `config validate`
- 增加 `config explain`
- `list-rules --category github-actions`
- `list-rules --severity high`
- finding 输出建议 `--ignore-rule` 示例，但只对 low/info 提示
- 支持 inline suppression，例如：

```text
# agentready-ignore secret.generic_assignment
```

需要谨慎：inline suppression 可能被滥用，应默认在报告里显示 suppression。

验收标准：

- 错误配置能被明确定位
- 用户能快速找到可忽略 rule id
- suppression 不会静默隐藏风险

### 阶段 5：baseline 生命周期

优先级：P1

目标：让 baseline 从“临时绕过”变成“可管理债务”。

实施项：

- baseline 文件记录 `firstSeenAt`
- baseline 文件记录 `lastSeenAt`
- baseline 文件记录 `reviewedBy` 可选字段
- `baseline diff`
- `baseline prune`
- `baseline update`
- `debt` 命令展示 baseline 风险债务

验收标准：

- 已修复 finding 可被 prune
- 新增 finding 仍会让 CI 失败
- baseline 报告能显示 high/medium debt 数量

### 阶段 6：CI 和 GitHub Action 产品化

优先级：P1

目标：减少复制 CI yaml 的成本。

实施项：

- 发布官方 GitHub Action 包装
- 支持 action inputs：
  - `path`
  - `fail-on`
  - `baseline`
  - `format`
  - `upload-sarif`
- `init --with-ci` 生成 workflow
- 文档增加 report-only、new-only、strict 三种模式

验收标准：

- 用户不需要手写 setup-node
- GitHub Actions 示例可直接复制
- SARIF 上传失败不会掩盖 scan 结果

### 阶段 7：安装和发布体验

优先级：P1

目标：正式发布后安装稳定，版本可追踪。

实施项：

- 确认 npm 包名可用
- 增加 `version` 命令或 `--version`
- 增加 release checklist
- 增加 changelog
- npm `package.json` 增加 homepage/repository/bugs，等真实仓库确定后再填
- 增加 provenance 发布说明
- 增加 `npm create` 或 starter 后续评估

验收标准：

- npm 包页面信息完整
- 用户能报告 issue
- 用户能确认自己运行的版本

### 阶段 8：性能和大仓库体验

优先级：P2

目标：大仓库中扫描速度可控。

实施项：

- 显示 scanned/skipped 文件数量
- 增加 `--debug` 查看跳过原因
- 增加 `--max-file-size`
- 增加并发读取限制
- 增加超大仓库性能测试 fixture
- 增加 binary detection，而不仅依赖扩展名

验收标准：

- 大仓库扫描不会无反馈卡住
- 用户能知道哪些文件被跳过
- CI 扫描时间可预测

### 阶段 9：CLI 契约和机器可读体验

优先级：P1

目标：让 AgentReady 可以被 CI、脚本和 AI agent 稳定调用。

实施项：

- 增加 `--version`
- 增加退出码约定
- 增加 `--quiet`
- 增加 `--verbose`
- 增加 `--no-color`
- JSON 输出增加 `schemaVersion`
- 错误输出统一走 stderr
- 参数错误、配置错误、扫描错误使用不同退出码
- 增加 `docs/CLI_REFERENCE.md`

验收标准：

- `--format json` 的 stdout 可被直接 `JSON.parse`
- CI 能根据退出码区分 finding failure 和工具错误
- 自动化调用方不需要解析人类文本来判断结果

### 阶段 10：信任、隐私和故障排查

优先级：P1

目标：让用户明确知道工具做了什么、没做什么，以及出错时如何恢复。

实施项：

- 增加 `docs/PRIVACY.md`
- 增加 `docs/TROUBLESHOOTING.md`
- README 明确本地扫描和无默认 telemetry
- 文档说明报告、baseline、SARIF 的敏感信息处理
- `doctor` 输出更具体的修复建议
- 增加 Windows PowerShell、bash、CI 的 quoting 示例

验收标准：

- 用户能确认工具不会上传代码
- 用户知道报告文件是否适合贴到公开 issue
- 常见安装和运行错误能通过文档解决

## 推荐优先级

### 第一轮必须做

- `--version`
- README 首屏改为 npx
- scan text 输出增加 top risks、next steps、duration
- finding 增加 `category` 和 `why`
- Markdown 报告改成 PR-friendly
- `init --dry-run`
- `init` 输出下一步命令
- stdout/stderr 约定
- 退出码表
- README 明确本地扫描和无默认 telemetry

原因：这些直接决定用户第一次是否继续使用。

### 第二轮必须做

- `onboard`
- `init --preset`
- `init --with-ci`
- `config validate`
- `list-rules --category`
- `baseline diff/prune`
- `--quiet`、`--verbose`、`--no-color`
- JSON 输出 `schemaVersion`
- `docs/PRIVACY.md`
- `docs/TROUBLESHOOTING.md`

原因：这些决定真实项目是否能长期接入。

### 第三轮再做

- 官方 GitHub Action
- SARIF rule metadata 深化
- inline suppression
- baseline aging
- 大仓库性能优化
- 官方 CLI reference 完整文档

原因：这些对成熟度重要，但应在基础 UX 稳定后推进。

## 不建议现在做

- Web dashboard
- 遥测统计
- 复杂交互 TUI
- 大规模规则插件系统
- TypeScript 迁移与 UX 改造同时做

原因：当前最重要的是让 CLI 采用路径顺畅。过早做 dashboard、插件或重构会推迟发布验证。

## 文档结构调整建议

README 应重排为：

1. 一句话价值
2. Quick start
3. Example output
4. Install
5. Common workflows
6. CI
7. Configuration
8. Baseline
9. Rule catalog
10. Contributing / Security

新增文档：

- `docs/GETTING_STARTED.md`
- `docs/REPORTS.md`
- `docs/BASELINE.md`
- `docs/RULES.md`
- `docs/CONFIGURATION.md`
- `docs/CLI_REFERENCE.md`
- `docs/PRIVACY.md`
- `docs/TROUBLESHOOTING.md`
- `docs/RELEASE.md`

## UX 验收清单

发布前应逐项验证：

- 空仓库运行 `npx agentready scan .` 输出清楚
- 有 `.env` secret 的仓库输出清楚
- 有 GitHub Actions 风险的仓库输出清楚
- 有大量 findings 的仓库输出不会淹没用户
- baseline 后 CI 只阻断新增风险
- config 写错时错误可定位
- Windows PowerShell 命令可用
- macOS/Linux shell 命令可用
- README 首屏 30 行内能跑起来
- npm dry-run 包内容不缺文档
- `--format json` 输出可被直接解析
- stderr/stdout 行为符合约定
- 退出码能区分 findings、参数错误和配置错误
- README 明确不上传代码和 findings
- 报告、baseline、SARIF 的敏感性说明清楚

## 下一步建议

建议先按第一轮必须做项推进。第一轮完成后，再用三个 fixture 仓库验证体验：

- clean project：无风险新项目
- messy legacy project：有历史 findings 的老项目
- ci-risk project：有 GitHub Actions 和 MCP 风险的项目

只有当这三个路径都顺畅，再推进 `onboard`、baseline 生命周期和 GitHub Action 产品化。
