# Issue #14：Grafana 告警 Evidence 快照

## 范围与取舍

Maintained / full，基线 9ad09ef（PR #61 已合并），顺序执行。复用现有 Normalize、脱敏、不可变 Evidence、事务和时间线，不新增依赖。补齐告警来源的明确身份与安全持久化入口；本 PR 使用 Refs #14，不关闭完整 Issue。

- 新增 `GRAFANA` 来源与 migration 000009；时间线 API 接受该来源。
- `GrafanaAlertEvidence(Alert, GrafanaAlertEvidenceContext, Filter)` 仅转换 allowlist，保留原始时间、时区、引用、状态、映射信息；不复制 labels、annotations、payload 或幂等键。
- `PersistGrafanaAlertEvidence(ctx, alertID, meta, filter)` 在事务内锁定并校验 Investigation、incident 和告警。必须是 incident 实际关联的告警，project/service/environment 一致；从数据库读取规范对象，不信任外部构造的 Alert。
- 触发未恢复的告警使用 StartsAt 点事件，恢复使用 EndsAt。不同状态追加，同一告警共享 `grafana:alert:<id>`；采集时间不影响 hash。
- 未映射使用 ALERT 实体及 PARTIAL；缺来源链接、恢复缺结束时间、事件晚于采集时间标 PARTIAL。非法 UUID、状态、版本、时间范围、FIRING 携带结束时间拒绝。不设置无依据的 freshness。
- 不接入 Webhook/Worker 自动编排，不生成根因、置信度或健康判断。

## 文件与红绿步骤

1. `internal/store/grafana_evidence_test.go`：先覆盖触发/恢复、UTC、脱敏、allowlist、幂等 hash、缺口和无效输入；`internal/api/handler_test.go` 加 GRAFANA 过滤契约，运行确认失败。
2. `internal/evidence/normalize.go`、`internal/store/timeline.go`、`internal/store/grafana_evidence.go`：实现来源、adapter、安全事务持久化。
3. `internal/store/grafana_evidence_integration_test.go`：真实 PostgreSQL 验证重复返回原行/采集时间、状态变化追加、原行不变、归属/ToolCall 拒绝及时间线筛选。先运行失败再实现 persistence。
4. `migrations/000009_grafana_evidence_source.sql`、`migrations/domain_model_test.go`：新增来源约束，空表升级/降级/重升；有 GRAFANA 行则 Down 明确拒绝且保留数据。调整原有 latest 回退步骤，不改已合并 SQL。
5. 定向集成测试后执行 `make fmt-check vet test build web-check case-check dev-script-check`、gitleaks 与 diff 自审。Compose 本地能力不足则记录限制，核实最终 PR HEAD 的三个必需 CI。

## 例子与兼容/回滚

- FIRING 08:00+08:00 -> UTC 00:00 点事件；次次采集同一内容返回同一 ID。
- RESOLVED 08:05+08:00 -> UTC 00:00–00:05 新记录，独立性分组与前一记录相同。
- 其他项目/服务/环境或 incident 的 Alert ID -> ErrInvalidInput，零写入；未知 Investigation -> ErrNotFound。
- 迁移仅扩展 check，历史数据保持不变；先升级数据库再部署新二进制。回滚应用可保留扩展 schema；存在 GRAFANA 历史时数据库 Down 拒绝，须另行评审数据保留方案，禁止删除证据解除门禁。
- 风险 high（公开枚举与数据库约束迁移）；不自动调用新入口，因此尚无端到端自动采集能力。

## Ledger / Ruling

- 红：adapter/API 测试最初因新类型/来源未定义、GRAFANA 筛选返回 400 失败；真实 PostgreSQL 测试在迁移前因 evidence_source_type_check 不接受 GRAFANA 失败。
- 绿：adapter/API 定向测试、真实 PostgreSQL 快照/归属/迁移定向测试通过。补测覆盖同项目同服务同环境的另一告警、跨调查 ToolCall、incident 与 investigation 的映射不一致；确认拒绝且未写入证据。
- 测试夹具修正：另一告警必须使用不同 fingerprint，不能只更换幂等键，否则现有告警去重会返回原告警；显式断言两个 Alert ID 不同。
- 完整本地验证：独立临时 PostgreSQL 17 下 `make fmt-check vet test build case-check` 通过；`make web-check dev-script-check` 通过（前端 3 项测试、lint/typecheck/build、启动脚本检查）。未访问用户现有数据库。
- 本地 Docker CLI 不支持现有 `docker compose --file`，未声称 `make check` 或本地 Compose smoke 通过；交由最终 PR HEAD 的 CI 验证。
- 固定基线 9ad09ef 的独立审查轮次：轴 A 检查允许字段、脱敏、事务归属、不可变幂等、来源约束与降级保留；轴 B 核对 Issue #14 的告警分组/时间/来源引用/筛选切片，未发现阻塞项。完整 Issue 验收尚未全部实现，保留 Refs #14；需人工 Review，不以自审代替批准。
- 风险 high；迁移采用事务内替换约束，数据量大时部署需安排 ALTER TABLE 锁与约束验证窗口。应用可回退并保留扩展 schema；存在 GRAFANA 行时 Down 拒绝，禁止通过删除证据解除门禁。
- 保留用户现有 `internal/connector/runtime/collector_test.go` 修改及 `.codebase-memory/`，不纳入 PR。

- 提交前范围验证：用 `git checkout-index` 导出仅含暂存内容的独立目录，在临时 PostgreSQL 下再次执行后端完整检查，通过；避免本地保留的其他改动影响交付证据。暂存 diff 的 `gitleaks stdin --redact --no-banner` 扫描通过，未发现泄漏。
