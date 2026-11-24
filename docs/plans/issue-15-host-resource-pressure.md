# Issue #15 宿主机资源压力信号规则

## 背景与目标

Issue #15 包含机器和容器资源压力的基础规则。Runtime Collector 与 Evidence 持久化已经提供宿主机 CPU、可用内存和 Load 三类固定观测。本次将这些已持久化数据用于 v0 固定规则，向只读诊断 API 输出低置信度的宿主机资源压力信号。

## 范围

- 规则 ID 为 `host-resource-pressure-signal.v1`，故障类型为 `HOST_RESOURCE_PRESSURE_SIGNAL`。
- 仅消费 `RUNTIME` 来源、`HOST` 实体的 `prometheus.runtime.host.cpu.v1`、`prometheus.runtime.host.memory_available.v1` 和 `prometheus.runtime.host.load.v1` Evidence，模板版本固定为 1。
- 三类证据必须属于同一宿主机，并有相互重叠的有效观测窗口。
- 每类指标至少存在三个时间严格递增的样本。CPU 与 Load 值严格递增，可用内存值严格递减。
- 必须使用各模板固定的 `prometheus:<template_id>:v1` independence group（Runtime Evidence 的底层 Prometheus 来源分组）。分组不匹配时不生成该宿主机候选。
- 候选置信等级固定为 `LOW`，支持证据引用三类 Evidence ID，且返回 `independent_resource_corroboration` 与 `host_pressure_causality_unproven` 缺口。非 `COMPLETE` 的支持证据额外返回完整度缺口。
- 缺少、过期、趋势不成立、时间窗不重叠或独立性组不匹配时不生成宿主机候选，并返回相应缺口。
- 规则集版本升至 `v0.4.0`。Web 诊断测试夹具与 README 同步版本和规则描述。

## 非目标

- 不新增 Prometheus/Runtime 查询、任意查询文本、Docker Socket 或 Kubernetes 查询。
- 不把 CPU 增长、Load 增长或可用内存下降解释为已发生机器故障、资源耗尽、OOM 或应用故障。
- 不确定资源阈值，不判断机器容量是否足够，也不推断发布导致压力。
- 不自动重启、扩容、修改配置、回滚或执行其他外部写操作。
- 不关闭 Issue #15，也不声称实现了其全部范围。

## 证据与边界

宿主机 Runtime Evidence 的顶层 Entity ID 可以是受限字符集的宿主机标识，而不是数据库 UUID。规则只接受 1 至 128 个 ASCII 字母、数字、下划线、点、冒号或连字符组成且首字符为字母或数字的标识，并校验摘要中的 `entity_type`、`entity_id`、`host_id` 与 Evidence 顶层实体一致。

趋势仅在该 Evidence 的观测区间内验证，且候选生成时再次限制到三种指标共同覆盖的时间区间。样本时间为零、超出 Evidence 区间、数值为负数或非有限数均视为无效输入。缺少趋势属于证据缺口，不属于输入损坏。

## 验收

- 三个固定模板、正确独立性组、同一宿主机和共同时间窗内符合趋势的完整 Evidence 生成一个低置信候选。
- 缺任意指标、任意指标不满足趋势、Evidence 缺失或过期、独立性组不匹配、宿主机不一致或观测区间不重叠时不生成候选。
- 候选支持 Evidence ID 稳定排序，反证数组为空数组，因果和独立佐证缺口明确。
- 诊断 API 集成测试验证持久化 Runtime Evidence 到候选的链路，并确保响应不包含原始来源引用、查询身份或实例标签。
- API 不触发外部采集或产生写操作，其他已有规则输出行为保持兼容。

## 风险、兼容与回滚

- 风险级别为 `high`，因为扩展公开只读诊断 API 的候选类型和规则集版本。
- API JSON 字段保持不变，只增加候选规则类型并更新 `rule_set_version`。旧客户端可忽略未知规则 ID；版本消费者需接受 `v0.4.0`。
- 若发现误报，可在后续代码变更中移除本规则或回退到上一规则集版本。回滚不需要数据库迁移，也不需要更改已有 Evidence。

## 验证

- `go test ./internal/diagnosis -count=1`
- `go test ./internal/api -run TestDiagnosisFromPersistedHostResourceEvidence -count=1`，需配置独立 PostgreSQL 测试库，否则测试会跳过。
- `make check`
- `go run ./cmd/relythra-casecheck test/evaluation/cases`
- `gitleaks dir --no-banner --redact`
- `git diff --check`
