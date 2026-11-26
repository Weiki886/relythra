# Issue #16：采集任务并发领取与租约恢复

## 目标与边界

为迁移 000010 中的持久化任务定义安全的多 Worker 领取和终态更新契约：领取使用 `FOR UPDATE SKIP LOCKED`，同一任务只能由一个有效租约持有者更新；Worker 崩溃后租约到期可再次领取；失败按有限次数重试，过期租约耗尽次数后进入终态。此切片只交付数据库仓储协议，不启动生产消费循环，也不声称已执行任何来源采集。

## 实施计划

1. 先写 PostgreSQL 集成测试，覆盖两个并发消费者领取不同任务、重复完成幂等/拒绝、旧租约 token 不能覆盖新领取、租约过期重领、重试延迟和最大尝试次数终止；先运行确认失败。
2. 新增 migration `000011` 为任务增加仅 RUNNING 状态持有的 UUID lease token，并按仓库迁移测试验证约束和 Down。
3. 新增 `internal/store/collection_jobs.go`：有界批量领取、数据库锁跳过、租约 token、完成、失败重试/终止；验证参数并只接受稳定错误码，不持久化任意错误文本。
4. 新增/调整 `internal/store` 集成与迁移测试，保持现有 worker heartbeat 行为不变；更新 ADR 0010 与本计划，清楚标记执行循环和采集器未完成。
5. 运行聚焦 PostgreSQL 测试、迁移测试、`make check`、Gitleaks、gofmt 和 diff 检查；自审完整差异，提交并创建 `Refs #16` PR。

## 影响文件

- `internal/store/collection_jobs.go`
- `internal/store/collection_jobs_integration_test.go`
- `migrations/000011_collection_job_leases.sql`
- `migrations/domain_model_test.go`
- `internal/store/grafana_evidence_integration_test.go`（仅如迁移版本断言需调整）
- `docs/adr/0010-investigation-collection-dispatch.md`
- `docs/plans/issue-16-worker-collection-claim.md`

## 风险与回滚

风险为 `high`：新增持久化租约状态并改变队列状态迁移。migration 只新增 nullable token 与一致性约束；代码回滚保留任务表和可恢复状态。生产不执行 Down；Down 仅在隔离 schema 验证。租约 token 不写日志、不出现在 API 响应。

## 裁决

本轮不将任务标记完成来伪装采集，也不在缺少可执行来源采集器的情况下接入一个会耗尽队列的空处理器。生产 Worker 消费循环、固定查询计划装配及真实证据持久化留待后续可验收切片。

## 执行记录

- 红阶段：先加入调用尚不存在的 claim/complete/retry 仓储方法的 PostgreSQL 集成用例；构建按预期因方法和类型缺失失败。
- `GOCACHE=/private/tmp/relythra-issue16-go-cache RELYTHRA_TEST_DATABASE_URL='postgres:///relythra?host=/tmp&sslmode=disable' go test ./internal/store -run '^TestCollectionJobs' -count=1 -v`：通过，覆盖租约过期重领、token 轮换、过期 token no-op、完成后幂等、重试延迟、并发消费者领取唯一性和五次尝试后终止。
- `GOCACHE=/private/tmp/relythra-issue16-go-cache RELYTHRA_TEST_DATABASE_URL='postgres:///relythra?host=/tmp&sslmode=disable' go test ./migrations -run '^TestDomainSchemaMigratesAndRollsBack$' -count=1 -v`：通过，在隔离 schema 验证全量 migration 11 up/down 与重复 up。
- 生产消费循环、外部采集器、Compose 故障注入尚未实现；本 PR 不声称端到端采集或自动诊断已完成。
