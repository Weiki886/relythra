# Issue #14：Grafana 告警接入时自动追加证据

## 范围与选择

- maintained / full；基于 main `0712a31`，承接 PR #62 的不可变 Grafana 快照。
- 复用现有告警事务及归一化、持久化函数即可实现，不新增调度器、队列或数据库表。
- 已匹配且关联 Investigation 的告警，每条输入处理后立即追加快照；同批 FIRING → RESOLVED 保留两个状态。重复快照复用已有 Evidence 和采集时间。
- 未映射或只有恢复消息且没有 Investigation 时不创建证据，也不虚构 Investigation；人工映射 FIRING 成功时同步采集；RESOLVED 只复用已有 Investigation 采集并校验归属，不创建新调查。
- API 将配置好的 `*redact.Filter` 显式传入仓库接入/重映射方法；nil 立即拒绝，避免默认过滤器漏掉运行时注册的密钥。HTTP 请求、响应格式保持不变。
- 公共 `PersistGrafanaAlertEvidence` 与接入流程共享接受 `*sql.Tx` 的内部函数，统一校验告警、Incident、Investigation 的精确归属与映射。
- 自动采集失败回滚整批告警、投递记录、调查及证据；重映射失败同样回滚。已有 Investigation 的映射与新映射冲突时拒绝，不移动历史证据。
- 不推进 Agent 状态、不查询外部数据、不生成根因与置信度、不补采历史数据；Issue #14 保持开放并使用 Refs。

## 实现步骤与验收

1. 新建 `internal/store/grafana_collection_integration_test.go`，先验证当前未接入采集的实现会失败：
   - 首次接入产生 Grafana 时间线证据，重复接入不增加证据、不改变原采集时间。
   - 同批 FIRING/RESOLVED 保留两个不可变快照，独立性分组一致；恢复未知结束时间保留 partial。
   - 未映射及仅恢复告警没有调查和证据，人工映射 FIRING 后创建证据。
   - 通过测试 schema 内的触发器强制证据插入失败，整批告警及映射更新回滚；不影响其他测试或本地数据库。
2. 修改 `internal/store/grafana_evidence.go` 抽取事务内 helper；修改 `internal/store/grafana.go` 在每条接入及人工映射提交前调用。保持 alert → incident/investigation 锁顺序。
3. 更新 `internal/api/grafana_webhook.go`、fake repository 和既有调用测试，显式传递配置过滤器。补齐 nil 拒绝、运行时密钥脱敏、映射不一致回滚与 API 过滤器传递的测试。
4. 更新本文记录红绿证据、审查及边界；执行针对性 PG 集成测试、全量后端检查、前端/本地脚本检查、gitleaks；固定 base 自审后创建中文描述 PR。

## 验证命令

- 临时 PostgreSQL 17：`python3 /tmp/relythra-alert-evidence-pg.py go test ./internal/store -run 'TestGrafanaCollection' -count=1`。
- 全量后端（同一临时 PostgreSQL）：`make fmt-check vet test build case-check`。
- 前端和脚本：`make web-check dev-script-check`。
- `make compose-config`；若本机 Docker CLI 不支持 Compose，记录限制并跟踪 PR 的 Compose smoke CI。
- staged diff 与提交范围的 `gitleaks`。用户原有 `internal/connector/runtime/collector_test.go` 改动及 `.codebase-memory/` 不纳入提交。

## 风险与回滚

- 无迁移、无新依赖、无外部写入。已有 Grafana Evidence schema 由 migration 000009 提供。
- 告警请求增加有界的本地 Evidence 写入和锁持有时间（已有批次上限 100）；接入成功以告警和证据同时持久化为准。
- 证据失败会使接入/映射请求失败；Webhook 签名领取仍沿用既有独立事务，同一签名重放会被拒绝，重试必须重新签名。
- 回滚本 PR 提交即可恢复原有接入行为；已有不可变证据保留，不执行 down 或删除数据。

## 执行记录

- 计划已确认：优先事务内逐项采集，显式传递运行时过滤器，不引入 Worker 调度。

- 首轮 RED：`go test ./internal/store -run TestGrafanaCollection -count=1` 在 PostgreSQL 17 中按预期失败：首次/状态转换/人工映射的时间线为空，强制证据失败未回滚业务。
- 首轮 GREEN：接入事务内 helper 后，Grafana store/API 定向套件通过；运行时注册密钥脱敏、八并发投递仅一份证据、过滤器显式传递、nil 拒绝、FIRING 映射冲突回滚均通过。
- 审查补充：RESOLVED 人工映射原本只修改 Alert/Incident，不校验已有 Investigation。新增回归在 `resolved ownership error=<nil>` 处失败；修正为复用已有调查、验证归属并追加快照，仍不为 resolved-only 创建调查。

- 最终验证（2026-11-13）：暂存的九个文件导出到独立目录，排除用户原有 runtime 测试和本地索引缓存；在独立临时 PostgreSQL 17 中执行 `make fmt-check vet test build case-check` 全部通过，包含证据插入失败后各业务表恢复原行数的回归断言。
- `make web-check dev-script-check` 通过：ESLint、TypeScript、Vitest（3 个用例）、生产构建和本地启动脚本检查。`git diff --cached --check` 与暂存差异的 `gitleaks stdin --redact --no-banner` 通过。
- 本地 Compose 限制：`make compose-config` 因已安装 Docker CLI 报 `unknown flag: --file` 失败，未执行本地 Compose smoke；提交后跟踪最终 HEAD 的 Backend、Frontend、Compose smoke 三项 CI，不把本地测试等同于远程验证。

## 提交前审查

- 固定基线：`0712a31c696d9256f2c6d66fd66ae9290bf22cda`，提交前已重新 fetch 并确认 `origin/main` 未前进；范围为本文所列九个文件。
- 规范轴：作者自检未发现剩余阻塞项。复用现有 Evidence 归一化与幂等写入，锁顺序沿用 alert → incident/investigation；无新迁移、依赖或公开 HTTP 格式变更。证据写入使用运行时脱敏过滤器，缺过滤器立即拒绝。审查中发现的 RESOLVED 归属绕过已由先失败后通过的回归测试覆盖。
- 需求轴：完成 Issue #14 中 Grafana 告警进入不可变证据时间线的接入切片；跨来源自动采集、结构化查询缺口与完整演示验收不在本次范围，继续 `Refs #14`，不关闭 Issue。
- 风险级别沿用 Issue 的 `high`：修改 Webhook 事务边界与脱敏过滤器传递，采集失败现在会拒绝并回滚整批业务写入。人工 Review 尚待 PR 评审；作者自检不代表批准合并。
