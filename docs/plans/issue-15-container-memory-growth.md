# Issue #15：容器内存增长信号规则

**目标**：基于已持久化的 Prometheus 容器工作集序列，生成可追溯、低置信度的内存增长信号候选。

**架构**：扩展既有纯函数 `diagnosis.Analyze`，仅消费同一 Investigation、服务实体和固定模板 `prometheus.container.memory.v1` 的 Evidence，不访问外部数据源。候选基于同一条容器序列内至少三个采样点的严格递增趋势；不跨容器/系列拼点，不把增长解释为泄漏、OOM、发布原因或服务故障。

**需求依据**：Issue #15 要求实现内存增长/重启类固定规则、输出规则 ID/证据/缺失项/定性置信度，且根因不能超出证据。

## 规则契约

- Rule ID：`container-memory-growth-trend.v1`。
- Fault type：`CONTAINER_MEMORY_GROWTH_SIGNAL`；作用实体保持已映射的 SERVICE ID，支持证据跳转到原始序列查看具体容器标签。
- 匹配来源：PROMETHEUS，模板 `prometheus.container.memory.v1` v1，独立组必须为 `prometheus:prometheus.container.memory.v1:v1`。
- 趋势：至少 3 个有效样本来自同一条 `Series`；时间戳必须落在 Evidence 观测窗口内且严格递增，值必须有限、非负并逐点严格增加。相邻序列不得合并。
- 证据状态：`MISSING` / `EXPIRED` 不支持候选；`PARTIAL` 可以支持但始终为 `LOW`，并列出完整数据缺失。
- 置信度：始终为 `LOW`，不按趋势幅度伪造概率或提升等级。
- 证明缺口：候选始终声明 `independent_memory_corroboration` 与 `memory_leak_causality_unproven`；不绑定部署，不声称内存泄漏、容器重启或根因。
- 无趋势、样本不足或无来源时不生成候选并保留结构化缺失项；坏 JSON、负值、非有限值或窗口外采样视为无效存储证据，返回 `ErrInvalidInput`。`MISSING` / `EXPIRED` 来源标为 `container_memory_metric_unavailable`，有效但无增长趋势标为 `container_memory_growth_trend`。
- 新增规则后 `RuleSetVersion` 从 `v0.1.1` 升至 `v0.2.0`，供后续评测基线区分。

## Task 1：规则测试（RED）

**文件**：新增 `memoryEvidence` fixture helper，并修改 `internal/diagnosis/rules_test.go`。

先测试以下行为，再实现：

- 三个同系列、同服务、同窗内严格递增的完整样本生成一个 LOW 候选，且支持 Evidence ID 精确匹配。
- 三点不递增、只有两点、两个系列各有两点递增但不可合并时均不生成候选。
- `PARTIAL` 只产生 LOW 候选并记录完整性缺口；`MISSING` / `EXPIRED` 不可支持。
- 非法独立组不支持候选并记录 `approved_independence_groups`。
- 窗口外样本、负数样本、同一 Evidence 的错误 Investigation 归属不能支持候选；坏摘要返回 `ErrInvalidInput`。
- 同一服务有多个匹配 Evidence 时，候选和支持 ID 排序稳定、ID 不重复。

执行 `go test ./internal/diagnosis -run ContainerMemory -count=1`，确认新行为因规则缺失而失败；修正测试夹具错误后再实现。

## Task 2：最小规则实现（GREEN）

**文件**：修改 `internal/diagnosis/rules.go`。

- 增加模板常量和规则 ID，在固定注册模板识别逻辑中加入该模板。
- 扩展 `Analyze` 采集容器内存 Evidence，并校验来源、服务实体、模板版本、完整度和独立组。
- 新增纯 helper `hasIncreasingMemoryTrend(summary prometheusSummary, start, end time.Time) (bool, error)`：先验证每条样本时间、有限非负值和窗口边界，再对每条 series 单独按时间排序；只检查相邻三个样本时间严格递增且值严格递增的片段。
- 按服务聚合匹配 Evidence ID，生成固定 `LOW` 候选并附加上述证明缺口；与慢 SQL 候选一起按 Rule ID 和 Entity ID 排序。
- 在 `MISSING` / `EXPIRED`、无样本、样本不足、平坦或波动序列下保持无候选与 `INCONCLUSIVE`（若无其他规则候选）。

重跑定向测试，再执行整个 `go test ./internal/diagnosis -count=1`；禁止改变既有慢 SQL 的证据门槛与置信度。

## Task 3：接口、文档与交付

**文件**：修改 `README.md`、本计划执行记录；如 API 集成测试需要，再修改 `internal/api/diagnosis_integration_test.go`。

- 已在 README 明确 `v0.2.0` 包含慢 SQL 与内存增长信号，且内存候选不是泄漏或根因判定；已更新前端诊断版本夹具。
- 已新增只读诊断 API 数据库集成测试，验证固定 Rule ID、LOW 置信度、准确 Evidence ID、缺失义务、无反证/发布归因，并断言不泄露查询、引用和容器标签。
- `go test ./internal/diagnosis -count=1`：通过。
- 使用独立 schema 的本机 PostgreSQL 执行 `make check`：通过，包含 Go vet/test/build、ESLint、TypeScript、54 个 Vitest 用例、生产构建、case-check、Compose 配置和开发脚本检查。构建有既存的 ECharts chunk 大小警告。
- `gitleaks dir --no-banner --redact`、`git diff --check`：通过。
- PR #86 已合并，`feat/15-evidence-metric-trend` 远端来源分支已不存在；本地 `origin/main` 与工作分支基线均为 `3131adcc6f87446ece602251da5217de1f16cdff`。
- 待完成：最终 diff 审查、提交、推送和创建引用 #15 的 PR；验证远程 Backend、Frontend、Compose smoke 状态。不合并。

## 风险、兼容与回滚

- 风险：`high`，扩展对外诊断 API 的候选语义；兼容字段不变，仅新增候选类型与 RuleSetVersion。
- 不新增依赖、schema、运行配置或外部写操作；规则只读取已有 Evidence。
- 回滚为 revert 本 PR 并重新部署应用，无迁移或持久化数据需回退。

## 执行记录

- 基线：`3131adcc6f87446ece602251da5217de1f16cdff`（PR #86 合并后的 `main`）。
- 分支：`feat/15-container-memory-growth`；本会话顺序执行，不委派。
- 当前状态：RED/GREEN、数据库集成测试和本地全量检查已完成；待差异审查及 PR 交付。
