# ADR 0010：Investigation 证据采集任务持久化与调度边界

- 状态：Accepted
- 日期：2026-11-25
- 关联：Issue #16、Proposal #1、ADR 0002、ADR 0008
- 风险：high（持久化 schema 与告警事务边界）

## 背景

Issue #16 要求告警到达后自动收集告警窗口附近的证据。当前 Grafana 接入在一个 PostgreSQL 事务内登记 Alert、Incident、Investigation、投递历史和部署候选，但 ADR 0008 明确禁止把告警登记作为 Agent 启动信号。Worker 当前只有心跳，没有可恢复的后台任务来源。若 Webhook 直接启动 goroutine，进程重启会丢失任务；若在 Web 请求内同步查询外部数据源，响应延迟和外部故障会耦合到告警接收。

## 决策

- 将 ADR 0008 中“告警登记不是 Agent 启动信号”保留为 Agent 执行边界；在该边界之下，新增“持久化证据采集任务”作为独立 Worker 调度信号。Webhook 只负责原子登记任务，不直接启动 Agent、外部查询或通知。
- 仅当一个 Project、Service 和 Environment 已精确匹配，且 `FIRING` 告警创建或复用一个 Investigation 时，保证存在一条 `investigation_collection_jobs` 记录。`UNIQUE (investigation_id)` 使同一 Investigation attempt 最多有一个采集任务；重复告警投递使用 `ON CONFLICT DO NOTHING`。
- 将新任务写入与 Investigation 创建处于同一数据库事务。事务失败时 Investigation 和任务一起回滚，避免任务指向不存在的调查或出现成功接收但没有任务的状态。
- `NEEDS_MAPPING` 告警不创建 Investigation 或采集任务。若告警仍为 `FIRING`，管理员通过版本受控 remap 首次创建 Investigation 时，在同一事务内补建任务。`RESOLVED` 不创建新 Investigation 或任务。
- 每个任务只通过外键关联 Investigation，不复制 Alert 正文、注释、日志、指标结果、查询文本、SecretRef、凭据、源码 Diff 或故障注入元数据。采集器在执行时通过 Investigation 读取已持久化且脱敏的领域上下文，并使用已注册的固定查询计划。
- 后续 Worker 使用 PostgreSQL 队列领取任务，支持并发安全 claim、有限批量、有限租约和有限重试；回收过期 lease 后可安全重试。到达重试上限时以稳定错误码标记任务失败并保留调查，不能删除证据或触发外部写操作。
- Worker 消费任务不等同于启动 LLM Agent。采集器仅执行允许的只读连接器调用；任意 PromQL/LogQL 文本、部署、回滚、重启、扩缩容、配置修改及通知仍不在本 ADR 授权范围内。
- 任务状态只能在创建事务后由 Worker 更新。终态任务不得被 webhook 重投复活；需要新的调查尝试时，按 ADR 0002 创建新的 Investigation attempt 和独立任务。

## 考虑过的方案

- **Webhook 内同步采集：** 请求耗时受多个外部服务影响，超时和重试会让告警接收不稳定；拒绝。
- **进程内 goroutine/channel：** 服务退出会丢任务，多个 Worker 间不能可靠协调；拒绝。
- **独立消息队列：** 当前单仓库演示系统仅依赖 PostgreSQL，另增消息基础设施会增加本地部署与运维负担；拒绝。
- **直接把告警当作 Agent 启动信号：** 会越过 ADR 0008 的 Agent 边界，也使采集不完整时难以解释状态；拒绝。

## 迁移与回滚

迁移 `000010` 新增 `investigation_collection_jobs`，包含状态、尝试次数、可领取时间、租约截止时间及稳定错误码；唯一约束保证每个 Investigation 只有一条任务。代码回退必须先停止 Worker 消费，再保留任务表；生产环境不通过 `Down` 删除未完成任务。需要调整结构时使用兼容的前向迁移。隔离测试环境可验证 `Down`。

## 实施阶段

- 首个切片实现与 Investigation 同事务的任务持久化、幂等约束和 remap 入队。
- 第二个切片实现 `FOR UPDATE SKIP LOCKED` 有界领取、UUID 租约 token、过期重领、受限退避重试和最大尝试次数终止；仓储契约本身不启动生产消费循环。
- 后续切片仍需将 Worker 消费循环装配到固定模板只读采集器，写入已验证的 Evidence，并完成 Compose 慢 SQL 故障 E2E。不得在来源采集尚未实现时将任务标记成功。

Issue #16 在完整链路验收前保持开放。
