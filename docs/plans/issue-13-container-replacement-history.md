# Issue #13：验证被替换容器的历史 Evidence

## 目标与边界

证明同一 Investigation 中先后观测到的两个不同容器 ID 会各自保留原始时间区间、启动时间和 incarnation 标识；重放各自查询不产生重复记录。用户按容器 ID 查询时间线时，替换前后两段历史都可独立核验。

本切片只补持久化集成验收，不增加运行时查询、状态推断、API、迁移、依赖或外部操作。它不证明任一容器健康、不推断重启原因，也不把 OOM 窗口归属于某个 incarnation。

## 验证设计

1. 使用隔离的 PostgreSQL 测试 schema 为同一 Investigation 构造两个不同容器 ID 和不同启动时间的 runtime 观测。
2. 分别通过 `FromRuntimeResult` 规范化并持久化，重复持久化同一观测，要求 Evidence ID 稳定且不新增记录。
3. 按旧、新容器 ID 分别读取时间线，断言原查询区间、`InstanceID` 和 start-time Evidence 均保留，且其他指标 Evidence 不携带 `StartTime`。

## 风险与回滚

风险 `high`：历史身份串联错误会让替换前后的运行证据混淆。本次只增加数据库集成测试和验证记录，不改变生产路径。回滚为删除本测试及本计划文件，无数据库迁移或持久化数据影响。

## 执行记录

- 定向 `go test ./internal/store -run '^TestRuntimeContainerReplacementHistorySurvivesPersistenceAndTimeline$' -count=1 -v` 可编译，但本机因未设置 `RELYTHRA_TEST_DATABASE_URL` 跳过隔离 PostgreSQL 集成场景；需要最终 PR Backend CI 在配置的 PostgreSQL 上实际执行。
- `make fmt-check vet test build web-check case-check dev-script-check`：通过。`internal/store` 包在本机通过，但该集成测试因相同环境限制被跳过。
- `gitleaks detect --source . --no-git --redact` 与 `git diff --check`：通过。
- 本切片验证已有持久化与时间线行为；未将测试通过描述为完整 Issue #13 验收，Issue 继续开放。
