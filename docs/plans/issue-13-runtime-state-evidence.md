# Issue #13：保留运行时采集状态到 Evidence

## 目标与边界

在 Runtime collector 已计算的 Host/Container 最近观测时间、时钟偏差和 Container 采集状态，从连接器结果写入规范化 Evidence。这样持久化时间线可以还原采集器当时观测到的数据覆盖状态。`observed` 仅表示 CPU 与内存指标在该查询窗口内可观测且未被标记 stale/clock-skew；它不是健康、就绪或根因判断。

不新增查询、API、数据库字段、依赖或外部操作；不改变指标样本、生命周期日志分类、peer 关系、置信度或根因规则。既有 `StartTime` 仍只出现在 start-time Evidence。

## 实现步骤

1. 在 `internal/evidence/runtime_test.go` 增加失败用例，验证 Host/Container 元数据在各自指标 Evidence 中完整保留、时间统一为 UTC，状态为 false 时也显式序列化，并拒绝未知或矛盾的 Container 状态组合。
2. 在 `internal/evidence/runtime.go` 增加 `last_observed_at`、`clock_skew` 和容器 `state`/`stale` 序列化；复制并 UTC 规范化时间，不改变 connector 输入。
3. 验证状态枚举为 `observed`、`stale`、`unknown`；`observed` 不得伴随 stale 或 clock-skew，`stale` 必须有 stale 标记且不能伴随 clock-skew。未知状态拒绝生成 Evidence。未来的最近观测时间必须显式标记时钟偏差。
4. 运行 Evidence/runtime 定向测试、相关包 race 测试、仓库检查、密钥扫描和 diff 检查，并记录实际结果。

## 风险与回滚

风险 `high`：运行时状态若丢失可能让下游误读数据缺口。新增字段只保留现有 collector 输出；无迁移且消费者可忽略未知 JSON 字段。通过枚举与组合校验避免将无效输入固化。回滚为 revert 本 PR，不修改既有记录。

## 验收

- Host 的 `last_observed_at` 与 `clock_skew` 保存在三个 Host 指标 Evidence 中。
- Container 的 `last_observed_at`、`state`、`stale` 与 `clock_skew` 保存在四个 Container 指标 Evidence 中。
- 所有保存时间为 UTC；开始时间保持在既有 start-time Evidence 范围。
- 非法或矛盾状态及未标记的未来观测时间被拒绝；时间规范化不修改连接器传入的源时间值。
- 字段只描述采集覆盖状态，不引入健康 peer 或根因语义；Issue #13 保持开放。

## 执行记录

- 红：实现前，`go test ./internal/evidence -run 'TestFromRuntime(PreservesRuntimeStateMetadata|RejectsUnknownContainerState)$' -count=1` 失败：Host 的观测时间/时钟偏差未出现在 Evidence，且非法的 `healthy` 状态被接受。
- 绿：新增状态/时间校验后，`go test ./internal/evidence -run 'TestFromRuntime(PreservesRuntimeStateMetadata|PreservesFalseStaleState|RejectsInvalidContainerStateAndObservationTime)$' -count=1` 通过。
- `go test -race ./internal/evidence ./internal/connector/runtime -count=1`：通过。
- `make fmt-check vet test build web-check case-check dev-script-check`：通过，包含 Go、前端 lint/typecheck/Vitest/生产构建、评测用例和本地启动脚本检查。
- `gitleaks detect --source . --no-git --redact` 与 `git diff --check`：通过。
- `make check` 在最后的 `compose-config` 阶段失败：本机 Docker CLI 没有 Compose 子命令，且未安装 `docker-compose`。因此本地 Compose 配置/启动未验证；由 PR 最终 HEAD 的必需 CI 单独验证。
- 首轮 PR Backend CI 暴露 `internal/store/runtime_oom_test.go` 的手工结果夹具缺少 Container `State`；已将空 CPU/Memory 夹具标记为 `unknown`，等待更新 HEAD 的 CI 回归确认。该本地数据库集成测试因未配置 `RELYTHRA_TEST_DATABASE_URL` 无法在本机完整执行。
