# Issue #16 Worker Loki 自动采集切片

## 目标与范围

接通已映射 Loki 固定模板到 Worker、Evidence 和调查时间线的只读链路。沿用现有查询注册表、出站策略、SecretRef、租约重试与持久化入口。Issue #16 的完整演示链仍有发布、GitHub、Runtime、诊断和重复运行验收，本次使用 `Refs #16`。

## 文件与实现步骤

1. `internal/worker/collection_loki_test.go` 与现有测试 fake 增加 Loki 行为测试。先验证缺少自动采集时失败，覆盖映射身份、固定查询、空结果、部分结果、长窗口、日志体积、凭据脱敏、错误分级、独立模板继续和持久化失败禁止完成。
2. `internal/worker/collection.go` 与 `collection_loki.go` 增加可选 Loki 连接器和受限采集。已映射但连接器未装配时保留明确缺口。每个模板最多一页、20 条，查询窗口最长两小时，截断时间窗或日志时标记 `PARTIAL` 并给出警告。序列化原始和脱敏结果均限制为 32 KiB，保留能装入预算的日志前缀，保证 Evidence 64 KiB 边界。单条日志超预算时保留部分采集的空快照与警告。
3. `internal/connector/loki/client.go` 和测试增加已解析凭据输入，Worker 使用同一凭据快照进行请求和 Evidence 脱敏，避免 SecretRef 轮换期间二次读取。原有调用仍可按引用解析。
4. `cmd/relythra-worker/main.go` 使用同一出站策略装配 Loki。`internal/worker/collection_loki_integration_test.go` 验证受控 Loki 结果经真实 PostgreSQL 保存后在时间线可见，重试重复结果保持幂等。
5. README 和 AGENTS.md 更新已交付范围、只读凭据与采集预算。使用现有配置和迁移。

## 验证方式

- 定向测试先红后绿，执行 Worker、Loki 连接器单元测试与 PostgreSQL 集成测试。
- `make check`、`make demo-artifact-check`、`gitleaks dir --no-banner --redact .` 和 `git diff --check`。
- 检查最终 diff 的身份约束、脱敏、窗口、采集上限和失败重试。按 code-review skill 独立评审。
- 新 PR 使用 M2 v0 证据链、`type:feature`、`high`、`area:backend`、`area:connector`。等待最终 HEAD 的 Backend、Frontend、Compose smoke，回读远端元数据。

## 风险与回滚

风险为 high，因为 Worker 新增自动访问带凭据的外部日志源。请求受原有策略、固定模板和超时约束，日志经统一脱敏与不可信标记入库。查询失败先落缺口再重试，已有独立模板结果继续保存，保存失败不得完成租约。回滚本次应用提交即可停止自动 Loki 采集，无 schema 变更。

## 执行记录

- 完成现有 Loki 连接器、Evidence normalizer 和持久化入口核对，直接复用其服务所有权与幂等校验。

- 回归测试先观察到 Loki Evidence 数量为 0，接通后定向测试通过。新增凭据回显用例先复现已解析凭据进入连接器输出，再通过每次查询独立的脱敏 Filter 修复。
- 测试边界裁决。出站策略拒绝回环地址，保持该约束。连接器 HTTP 行为通过既有包内受控服务器测试，Worker 与 PostgreSQL 集成通过可控连接器结果验证，分别取证。
- PostgreSQL 集成使用 Kiri 临时 PostgreSQL 17 容器、临时内存文件系统和专用测试 schema，验证独立来源失败时 Loki 仍保存、恢复重试后仅有一条相同 Loki 快照、最终租约完成。

- 最终本地验证通过。`make check` 使用隔离 PostgreSQL，包含 Go 检查、集成测试、前端 lint/typecheck/57 项 Vitest 测试/生产构建、25 项 Python 测试与 Compose 静态配置检查。
- `go test -race ./internal/worker ./internal/connector/loki -count=1` 使用同一隔离 PostgreSQL 通过。`make demo-artifact-check`、`make fmt-check`、`git diff --check` 与 `gitleaks dir --no-banner --redact .` 通过。
- `RELYTHRA_POSTGRES_PASSWORD=ci-only-not-secret make demo-smoke` 在 Kiri 隔离项目通过，覆盖真实遥测、签名告警触发和恢复、Worker Prometheus Evidence、慢 SQL 遥测恢复、只读权限、数据库隔离、连接恢复与重启。脚本自动清理专用容器、网络和卷。本次脚本仍只创建 Prometheus 自动采集映射，Loki 完整演示链后续验收。
- code-review 独立评审覆盖全部交付文件，未发现 blocking 或 question。人工 Review 与新 PR 最终 HEAD 的远端 CI 待提交后验证。
- 现有 Vite 大于 500 kB 的 chunk 提示仍出现，生产构建成功。
