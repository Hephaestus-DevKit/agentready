# 后续事项

这份清单用于本地验证全部通过后，继续完成 GitHub、npm 和真实仓库验证。

## 本地门禁

```bash
npm run market:check
```

创建 GitHub Release 之前必须先通过这条命令。它会覆盖测试、自扫描、配置校验、npm 包 dry-run、打包后安装冒烟、Markdown 本地链接检查、公开面关键词检查和空白 diff 检查。

## GitHub 设置

- 按 [Repository settings](docs/REPOSITORY_SETTINGS.md) 保护 `main` 分支，并启用完整必需检查。
- 启用 code scanning alerts。
- 禁止保护分支和 release tag 被 force push。
- 只给能发布版本的维护者保留必要 bypass 权限。

## npm 设置

- 为 `release.yml` workflow 配置 npm Trusted Publishing。
- 使用 [Repository settings](docs/REPOSITORY_SETTINGS.md) 中约定的 GitHub `npm` environment。
- Trusted Publishing 生效后，保持 environment secrets 为空。
- 除非 Trusted Publishing 暂时不可用，否则不要添加长期 npm automation token。

## 首次发布

- 确认 `package.json` 里的版本号已经最终确定。
- 创建 GitHub Release tag，格式必须等于 `v` 加 package version，例如 `v0.1.0`。
- 通过 GitHub `release` workflow 发布，不从本地工作站发布。
- 发布后确认 npm provenance 可见。
- 发布后运行 `npx agentready version`，确认 npm 包可以正常安装和执行。
- 制造一次可控的 CI finding，确认 AgentReady SARIF 能出现在 GitHub code scanning。

## 真实仓库验证

在继续扩规则之前，先用两到三个真实仓库 dogfood。只记录会影响产品判断的证据：

- 用户确实会处理的高价值 findings
- 需要降低噪音的误报
- 当前漏掉但应该覆盖的风险
- baseline diff、prune、debt 是否容易解释
- Markdown 和 SARIF 报告是否适合 PR review

## 暂时不要做

- 没有真实仓库证据之前，不要继续加宽泛规则。
- 没有重复配置需求之前，不要做复杂 policy DSL。
- GitHub release workflow 可用时，不要从本地工作站发布。
