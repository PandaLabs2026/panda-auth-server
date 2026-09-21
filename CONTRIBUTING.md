# 贡献指南 / Contributing

遵循本仓贡献规则：Bug 提供环境与脱敏复现，功能建议说明场景与维护成本，Question 说明已尝试的步骤。路线图由实际需求驱动，不承诺请求交付时间；漏洞走 [SECURITY.md](SECURITY.md)。

本仓采用 main、短期工作分支与发布 tag，贡献遵循[本仓许可范围](LICENSING.md)，不新增 CLA 或改变历史授权。PR 说明问题、结果、验证和限制；中英文 README 同步维护，遵循现有代码格式，不夹带无关重排或品牌资产修改。

## 本仓验证

从本仓根目录开始；前置条件与已知限制见 [README](README.md)。代码或依赖变更按范围执行：

```bash
dotnet build PandaAuth.Server.slnx
dotnet test tests/PandaAuth.Tests/PandaAuth.Tests.csproj
```

纯文档变更检查路径、命令和中英文一致性，并在本仓根目录运行 `git diff --check`，不启动服务、发布或运行迁移。不能将未执行的构建、测试或集成验证记为通过。

Follow this repository's contribution policy for feedback and PRs. Describe the use case and maintenance cost for requests; no delivery date is promised. Use [SECURITY.md](SECURITY.md) for vulnerabilities. Work on short-lived branches from main and use release tags. Contributions follow [license scope](LICENSING.md); no CLA or retroactive license change is introduced. Keep PRs focused, preserve conventions and update both READMEs.

Run the commands above for relevant code/dependency changes after satisfying README prerequisites. Tests currently cover hashing and rate limiting only. Do not run startup or migrations for documentation checks. For documentation-only changes, check paths, commands and translation consistency, then run git diff --check from the repository root. Do not start services, deploy or migrate to check documentation. Report checks not run.
