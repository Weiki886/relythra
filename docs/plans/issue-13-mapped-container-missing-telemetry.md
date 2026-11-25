# Issue #13：显式映射容器无遥测时保留实例级缺口

## 目标与边界

当运行时查询使用了当前版本的管理员显式容器映射，但某个映射 cgroup 在本次 Prometheus 窗口完全没有容器序列时，结果仍返回该映射的匿名容器 ID、映射版本、`unknown` 采集状态及空指标，避免同服务其他副本有数据时把这个副本静默隐藏。

这只说明“当前查询窗口没有该映射的容器遥测”。不代表容器退出、已被替换、健康或不健康，也不使用 Docker Socket、容器管理 API 或日志文本补造状态。缺失遥测不生成零值或 start-time/instance ID。未提供显式版本映射时保持现有行为。

## 实现步骤

1. 在 `internal/connector/runtime/collector_test.go` 添加失败测试：一个显式映射容器有指标、另一个没有任何容器序列；要求两者按实例返回，缺失者为 `unknown`、四类测量为空、无启动时间/实例 ID，并有稳定缺口。另覆盖无映射时不合成实例，以及只收到 start-time 序列时仍保留该观察。
2. 在 `internal/connector/runtime/collector.go` 仅为四类容器模板均无序列的当前显式映射创建匿名缺口记录；复用每个已返回模板的来源引用和 partial 状态，继续应用现有输出实体预算与确定性排序。仅有 start-time 序列时输出该实际观察并保持状态 `unknown`。
3. 增加无映射基线回归，确保 raw cgroup-only 场景不会合成期望实体；运行 Runtime、Evidence 和相关 store 测试。
4. 更新本计划的实际验证记录，执行完整 `make check`、gitleaks 与 diff 检查。

## 风险与回滚

风险 `high`：把未观测实例误呈现为真实容器会误导故障排查。限制为管理员已提供的当前版本映射；输出只使用匿名映射 ID、空测量与 `unknown` 状态，不声称生命周期事实。无 schema、迁移、依赖或外部副作用；回滚为 revert 本 PR。

## 交付边界

本 PR 是 Issue #13 的部分交付，使用 `Refs #13`。它不完成经认证的服务/容器映射、可验证退出/重启事实、健康 peer 对照或完整故障注入验收。

## 执行记录

- 红：新增 `TestQueryPreservesMappedContainersWithNoTelemetryAsUnknown` 后，修复前失败，显式映射但没有 Prometheus 序列的第二个副本从结果中消失。
- 绿：实现后 `go test ./internal/connector/runtime -count=1` 通过；回归还确认生命周期日志只通过精确的 host/cgroup 映射关联，单独 `container_id` 标签不关联。
- `go test ./internal/connector/runtime ./internal/evidence ./internal/store ./internal/api -count=1`：通过。
- `go test -race ./internal/connector/runtime ./internal/evidence ./internal/store -count=1`：通过；Race 命令不依赖数据库集成场景。
- PostgreSQL 17 上完整 `make check`：通过，包含 PostgreSQL 集成测试、Go vet/test/build、前端 lint/typecheck/57 项测试/生产构建、案例校验、16 项脱敏测试、Compose 配置和本地启动脚本检查。
- `make fmt-check`、`gitleaks detect --no-git --source . --redact --no-banner` 与 `git diff --check`：通过。
- 本轮只验证配置和应用启动脚本检查，未运行完整 Compose smoke 或真实 Docker 故障注入。
