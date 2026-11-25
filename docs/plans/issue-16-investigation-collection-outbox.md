# Issue #16：新 Investigation 的持久化采集排队

## 目标与边界

当已映射的 `FIRING` 告警创建 Investigation 时，在同一个 PostgreSQL 事务中写入唯一采集任务，避免 webhook 成功但内存任务丢失。重复投递复用 Investigation 和任务；未映射告警在人工重映射成功创建 Investigation 前不排队；`RESOLVED` 不创建新的调查和任务。

本切片只实现可靠排队，不消费任务、不查询 Prometheus/Loki/GitHub/运行状态、不推进诊断状态机，也不执行外部写操作。后续 Worker 切片必须通过有界租约与重试领取任务，并只使用注册的只读采集器。

## 实施计划

1. 先增加 PostgreSQL 集成测试，验证首次 FIRING 入队、重复投递幂等、未映射与 RESOLVED 不入队、重映射首次创建调查后入队，以及事务回滚不留下任务；先运行并确认失败。
2. 新增 `000010_investigation_collection_jobs.sql`，为状态、重试计数、时间字段和 Investigation 唯一性建立约束与索引；按迁移规范补充 schema 验证。
3. 在 `internal/store/grafana.go` 加事务内 helper，并在 webhook 入队和人工重映射创建 Investigation 的两个入口调用。任务只携带 Investigation ID，不复制告警正文、查询文本、密钥或故障注入元数据。
4. 新增 ADR 0010，明确持久化任务触发与 Agent 执行的边界，并记录其如何调整 ADR 0008 的旧约束；本计划记录范围、验证证据与未完成项。
5. 运行聚焦 PostgreSQL 集成测试、`make check`、Gitleaks、gofmt 和 diff 检查；确认未执行任何共享数据库迁移 Down，再创建使用 `Refs #16` 的 PR，因为任务消费与真实 Compose 诊断仍未完成。

## 影响文件

- `internal/store/grafana.go`
- `internal/store/grafana_evidence_integration_test.go`
- `migrations/000010_investigation_collection_jobs.sql`
- `migrations/domain_model_test.go`（仅在需要直接验证 schema 约束时）
- `docs/adr/0010-investigation-collection-dispatch.md`
- `docs/plans/issue-16-investigation-collection-outbox.md`

## 风险与回滚

风险为 `high`：新增持久化表并改变告警与重映射事务。回滚先部署兼容的代码回退；`Down` 只用于隔离环境，生产采用评审后的前向迁移，且不得隐式丢弃排队任务。本次不会对共享或生产数据库执行迁移回退。

## 裁决

告警登记只生成持久化采集请求，不直接启动 Agent。当前 Worker 只有心跳，缺少有界任务执行契约，因此 Worker 消费不纳入本切片。

## Execution record

- 红阶段：新增 PostgreSQL 用例先于生产代码运行，因 `investigation_collection_jobs` 尚不存在而按预期失败。
- 聚焦验证：`GOCACHE=/private/tmp/relythra-issue16-go-cache RELYTHRA_TEST_DATABASE_URL='postgres:///relythra?host=/tmp&sslmode=disable' go test ./internal/store -run '^TestGrafanaFiringEnqueuesCollectionJobOnceAndAfterMapping$' -count=1 -v` 通过；覆盖 mapped FIRING、重放、RESOLVED、NEEDS_MAPPING 后 remap 和批次回滚。
- 并发验证：`GOCACHE=/private/tmp/relythra-issue16-go-cache RELYTHRA_TEST_DATABASE_URL='postgres:///relythra?host=/tmp&sslmode=disable' go test ./internal/store -run '^TestIngestGrafanaAlertDeduplicatesConcurrentFingerprints$' -count=1` 通过，8 个并发相同 fingerprint 的投递只保留一条调查和一条采集任务。
- 迁移验证：`GOCACHE=/private/tmp/relythra-issue16-go-cache RELYTHRA_TEST_DATABASE_URL='postgres:///relythra?host=/tmp&sslmode=disable' go test ./migrations -run '^TestDomainSchemaMigratesAndRollsBack$' -count=1 -v` 通过，验证全新 schema、重复 up、migration 10 down 与其余既有迁移回滚。
- 完整本地检查：`RELYTHRA_TEST_DATABASE_URL='postgres:///relythra?host=/tmp&sslmode=disable' RELYTHRA_MANAGEMENT_TOKEN_FILE=/dev/null RELYTHRA_POSTGRES_PASSWORD_FILE=/dev/null make check` 通过，包含 Go vet/test/build、前端 lint/typecheck/57 项 Vitest/生产构建、案例校验、16 项 demo artifact 测试、Compose 配置渲染和本地启动脚本检查。前端构建仍报告既有 MetricTrend chunk 超过 500 kB 的提示。
- `gitleaks detect --no-git --source . --redact --no-banner`、`gofmt` 和 `git diff --check` 通过。
- 未运行 Compose 启动/故障注入，也未运行 Worker 消费；本 PR 不声称端到端采集完成。
