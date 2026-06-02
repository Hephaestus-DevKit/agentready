# AgentReady 项目推进文档

## 项目定位

AgentReady 是一个面向开发者和小团队的 AI Agent 安全体检 CLI。

它解决的问题很具体：在把 Claude Code、Codex、Cursor、MCP server 或其他 AI 编程代理接入仓库之前，开发者可以运行一个命令，检查项目是否暴露了 secrets、危险脚本、过宽的 MCP 权限、CI 权限风险和缺失的 agent 操作边界。

目标不是做一个企业级大平台，而是做一个轻量、开源、容易传播、能直接进入日常开发流程的小工具。

## 目标用户

- 正在使用 Claude Code、Codex、Cursor、Continue、Cline 等 AI 编程工具的个人开发者
- 开源项目维护者
- 小团队的技术负责人
- 想把 MCP 工具接入本地项目，但担心权限边界的开发者
- 想在 CI 里加入 AI agent readiness 检查的团队

## 核心价值

- 给 AI agent 进入仓库之前做 preflight check
- 把安全建议翻译成开发者能直接执行的修复动作
- 输出终端、JSON、Markdown、SARIF 报告，方便本地、CI 和 GitHub code scanning 使用
- 生成 `AGENTS.md`、`.agentignore` 与 `.agentready.json`，帮助项目建立 agent 操作边界和扫描配置
- 未来支持 GitHub Action、SARIF、MCP 专项审计和安全自动修复

## MVP 范围

第一版只做三条命令：

```bash
agentready scan
agentready init
agentready doctor
```

`scan` 负责检查仓库风险。

`init` 负责生成 `AGENTS.md`、`.agentignore` 和 `.agentready.json`。

`doctor` 负责检查本地运行环境，并附带一次扫描。

## 第一版扫描规则

- 检查 `.env`、私钥、credential、secret 等敏感文件名
- 检查 GitHub token、OpenAI key、Anthropic key、AWS access key、private key 等内容痕迹
- 检查敏感文件中的通用 secret assignment
- 检查 shell 脚本中的危险命令，例如 `rm -rf /`、远程脚本 pipe shell、`sudo`、`chmod -R 777`
- 检查 `package.json` 中的危险 scripts 和 lifecycle scripts
- 检查 GitHub Actions 中的 `pull_request_target`、写权限、`secrets: inherit`、危险 `run` 命令、`persist-credentials: true`
- 检查 MCP 配置中的 shell-capable server、过宽文件系统路径、inline secret-like 字段
- 检查 Python 项目的未固定依赖和缺失 `requires-python`
- 检查是否缺失 `AGENTS.md` 和 `.agentignore`
- 支持配置文件、路径忽略、规则忽略、严重级别覆盖和 CI 失败阈值
- 支持 baseline，让老项目可以先记录既有风险，再只阻断新增风险

## 技术路线

当前 MVP 使用纯 Node.js ESM，避免早期引入过多依赖，保证工具可以快速运行和测试。

后续成熟后迁移到 TypeScript，增加更强的规则类型、配置 schema、插件式规则和包发布流程。

暂定结构：

```text
agentready/
  bin/agentready.js
  src/
    cli.js
    scanner.js
    reporters.js
    init.js
    doctor.js
  test/
  docs/
```

## 30 天推进安排

第 1 阶段：可运行 MVP

- 创建 CLI 项目骨架
- 实现 `scan`、`init`、`doctor`
- 实现基础扫描规则
- 支持 text、json、markdown、sarif 输出
- 支持 finding fingerprint 和 baseline
- 增加 Node 内置测试
- 写 README 和项目规划文档

第 2 阶段：开源可发布

- 支持忽略规则和自定义严重级别
- 增加 GitHub Action 示例
- 补充真实项目示例报告
- 完善 README、截图、贡献指南和发布流程

第 3 阶段：MCP 专项增强

- 识别 Claude Desktop、Claude Code、Cursor、VS Code 等常见 MCP 配置路径
- 分析 filesystem、shell、browser、database 类工具权限
- 给出最小权限建议
- 支持生成安全版 MCP 配置建议

第 4 阶段：传播和增长

- 发布 npm 包
- 写一篇面向开发者的文章：Before You Give an AI Agent Your Repo
- 做 GitHub Action marketplace 页面
- 收集真实仓库扫描案例
- 邀请 AI coding 工具用户试用并提 issue

## 成功指标

短期：

- 能在任意仓库运行并输出可读报告
- 能在 CI 里以 JSON 或 Markdown 方式使用
- 能生成安全边界文件

中期：

- npm 包可安装
- GitHub Action 可用
- 规则配置可扩展
- README 足够清楚，开发者 3 分钟内能跑起来

长期：

- 成为 AI coding agent 接入项目前的常用检查工具
- 被 Claude Code、Codex、Cursor、MCP 用户自然引用
- 形成一套开源的 agent readiness 安全规则

## 当前决策

- 项目名：AgentReady
- 第一版语言：Node.js ESM
- 第一版分发目标：npm CLI
- 第一版重点：真实可用、低依赖、容易理解
- 不做：聊天 UI、企业 dashboard、复杂策略引擎、泛泛 prompt 集合

## 下一步

当前应优先完成可运行 MVP，然后用一个本地示例项目验证扫描结果。验证通过后，再推进配置文件、SARIF 和 GitHub Action。
