# Issue #13：OOM 窗口观测摘要

## 需求与边界

为 Runtime 连接器的容器结果增加可追溯的 OOM 窗口摘要，继续保留原始 `OOMEvents` Measurement。数据来自固定模板 `prometheus.runtime.container.oom_events.v1` 的 `increase(container_oom_events_total[5m])`，每个正样本只说明求值时间之前五分钟内的估算增量。重叠窗口不得求和、逐点相减或当作独立事件；估算值可为小数，求值时间不是故障发生时间。

本切片属于 maintained code，仅依赖标准库和现有固定查询，不新增数据源调用、权限、数据库迁移或依赖。它不证明容器重启、退出、根因或健康状态，也不把窗口绑定到某个 incarnation（窗口可能跨越开始时间）。Issue #13 继续开放。

## 实现与验证计划

1. 新建 `internal/connector/runtime/oom_test.go`：先验证当前模型缺少摘要而失败；覆盖相邻重叠窗口保留原值、小数、零值、实例隔离、UTC、异常输入与原始样本保留。已有未提交 `collector_test.go` 原样保留，不纳入提交。
2. 修改 `internal/connector/runtime/collector.go` 并新增 `oom.go`：定义 `OOMWindowObservation`，每个容器输出稳定的空数组；只为有来源、时间在请求区间内且有限正值的样本生成窗口摘要。负值、非有限值、非法时间及正值缺少来源时标记 gap/partial，原始 Measurement 保留。摘要按求值时间排序。
3. 使用现有 Evidence 归一化测试验证原始 OOM Measurement 仍可追溯。此次派生摘要只存在于连接器结果，不新增持久化契约或 API/Agent/UI 能力；未来接入须以原始证据为准。
4. 更新本计划记录红绿证据；运行相关包测试与 race、`make check`、Gitleaks、`git diff --check`。环境不能执行的检查明确记录，远程最终 HEAD 的 Backend / Frontend / Compose smoke 单独核验。
5. 按 code-review skill 固定基线自查，再交给人类 Reviewer 独立审查；英文 PR 标题、中文正文，使用 `Refs #13` 表明尚未满足完整 Issue 验收，附相同 milestone 和标签。用户审查后决定合并。

## 兼容性、风险与回滚

风险 high，原因是基础设施证据可信度。仅增加连接器 JSON 字段，不改旧 Measurement、查询、状态判断或数据库；缺少摘要不等于没有发生 OOM。回滚为 revert 本 PR，无数据迁移或外部写操作。

## 执行记录

- 基线：`origin/main` = `dda05e087cb2f712a811c6c94bdbd220e74ff23e`，PR #59 已合并。
- 分支：`feat/13-oom-window-summary`。保留已有未提交测试及 `.codebase-memory/`。

- 红：新增 `TestOOMSummary*` 后，先因模型缺少摘要而编译失败；补齐模型后，重叠窗口摘要、无效样本 gap 和空数组 JSON 等行为断言仍失败。
- 绿：实现逐样本归一化与校验后，`go test ./internal/connector/runtime ./internal/evidence -count=1` 通过。
- `go test -race ./internal/connector/runtime ./internal/evidence ./internal/connector/prometheus -count=1` 通过。
- `RELYTHRA_POSTGRES_PASSWORD_FILE=/dev/null RELYTHRA_MANAGEMENT_TOKEN_FILE=/dev/null make check`：格式、vet、Go 单测、Go 构建、前端 ESLint/TypeScript/Vitest（3 个测试）/生产构建、case-check 通过；在 `compose-config` 失败，本机 Docker 不支持 `compose --file`。因此不声称完整 `make check` 通过；其后的 `make dev-script-check` 已单独执行并通过。
- `gitleaks detect --source . --no-git --redact` 与 `git diff --check` 通过。
- 本机未设置 `RELYTHRA_TEST_DATABASE_URL`，未验证 PostgreSQL 集成场景；本次无数据库模型或迁移变更。真实 cAdvisor OOM 故障实验和 Compose smoke 未在本机执行。

## 提交前自查与交接

- 审查基线固定为 `dda05e087cb2f712a811c6c94bdbd220e74ff23e`，范围只包含本计划、`collector.go`、`oom.go` 和 `oom_test.go`。
- 规范轴：只增加派生结果，保留原始 Measurement；沿用现有采集请求、身份映射、数据缺口与状态判断，不添加权限、依赖、迁移或外部调用。无本次已发现且未解决的代码阻塞项。
- 需求轴：覆盖重叠窗口、有限正值、小数、零值、时间边界、UTC、来源缺失和容器隔离；窗口下界可早于请求起点，求值点必须在请求区间内。新字段不包含 InstanceID，避免把跨生命周期的窗口估算归属某次容器启动。
- Ruling：本次进行作者自查，独立审查交给 PR 的人类 Reviewer；不得把作者自查称为独立批准。Issue #13 的完整运行时、历史证据、健康 peer 和故障演示验收仍需后续切片。
- 合并前需在最终 PR HEAD 核验 Backend、Frontend、Compose smoke，并完成人类 Review；本地结果不替代上述门禁。
