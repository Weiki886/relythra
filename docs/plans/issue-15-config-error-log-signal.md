# Issue #15：配置错误日志信号规则

**目标**：使用已经持久化的固定 Loki 配置错误日志 Evidence，生成可追溯、低置信度的服务级配置错误信号候选。

**边界**：规则只根据注册模板返回的时间窗内日志记录是否存在来报告信号，不解析或回显不可信日志正文，不声称配置错误已导致告警、服务故障或发布回归。`MISSING` / `EXPIRED` 不支持候选；`PARTIAL` 允许形成信号但置信度固定为 `LOW`。

**需求依据**：Issue #15 范围包含配置错误基础规则，并要求候选保留规则 ID、Evidence 引用、缺失证据和定性置信等级，不能输出未经证据支持的根因。

## 规则契约

- Rule ID：`configuration-error-log-signal.v1`。
- Fault type：`CONFIGURATION_ERROR_LOG_SIGNAL`；实体为已映射的 SERVICE UUID。
- 唯一支持来源：`LOKI`，模板 `loki.service.config_errors.v1` v1，独立组 `loki:loki.service.config_errors.v1:v1`。
- 仅接纳 `ObservedStart` 与 `ObservedEnd` 范围内、未标记 `OutsideTimeWindow` 的日志条目；不跨 Evidence、服务或 Investigation 拼接。
- 候选置信度固定 `LOW`，不生成反证或 `TriggerChange`；明确保留 `independent_configuration_corroboration` 与 `configuration_error_causality_unproven` 缺口。
- `PARTIAL` 候选额外声明 `complete_configuration_log_evidence`；`MISSING` / `EXPIRED` 标记 `configuration_error_log_unavailable`，无时间窗内条目标记 `configuration_error_log_in_window`。
- 不调用 Loki，不添加任意查询入口，不改变既有慢 SQL 或内存规则语义。
- 规则集版本由 `v0.2.0` 升至 `v0.3.0`。

## Task 1：规则测试（RED）

**文件**：修改 `internal/diagnosis/rules_test.go`。

先添加失败测试，至少覆盖：

- 完整模板、批准独立组及一条有效窗口内记录产生固定 `LOW` 候选，且只引用该 Evidence ID。
- `PARTIAL` 有匹配记录时仍为 `LOW` 并保留完整性缺口。
- `MISSING` / `EXPIRED`、无条目、窗口外条目、错误独立组不产生候选并报告结构化缺口。
- 错误 Investigation、非 SERVICE 实体、未知模板版本不支持候选；损坏的注册模板摘要返回 `ErrInvalidInput`。
- 多个同服务 Evidence 的 ID 排序稳定、去重；输出无反证、无发布触发归因，且始终不高于 `LOW`。

运行 `go test ./internal/diagnosis -run ConfigurationError -count=1` 并确认先因规则缺失而失败。

## Task 2：最小规则实现（GREEN）

**文件**：修改 `internal/diagnosis/rules.go`。

- 增加固定模板与规则 ID，并将其加入注册模板白名单和版本处理。
- 使用 `loki.Entry.Timestamp`、`OutsideTimeWindow` 检查 Evidence 窗口内是否存在记录；禁止解读日志正文。
- 按 SERVICE ID 聚合候选和支持 Evidence ID，排序输出并声明固定证明缺口。
- 保持其他规则的候选、置信度和缺失项行为不变。

重跑配置错误定向测试及 `go test ./internal/diagnosis -count=1`。

## Task 3：API、文档与交付

**文件**：修改 `internal/api/diagnosis_integration_test.go`、`README.md`、`web/src/test/investigationFixture.ts`，更新本计划执行记录。

- 通过已有只读 API 集成测试，从已持久化 Loki Evidence 验证新候选、Evidence ID、缺失义务和敏感正文不泄露；不新增 API、迁移或外部查询。
- README 准确说明 `v0.3.0` 的三类固定信号及配置候选只代表日志信号、不证明根因。
- 更新前端测试夹具中的规则集版本。
- 执行带隔离本机 PostgreSQL 的 `make check`、`gitleaks dir --no-banner --redact` 与 `git diff --check`。
- 对固定 `origin/main` 与最终 HEAD 自审；创建标记 `Refs #15` 的 PR，标签使用 `type:feature`、`high`、`area:backend`、`area:frontend`，Milestone 为 M2；不自行合并。
- 在最终 HEAD 核验 Backend、Frontend、Compose smoke 远程 CI。

## 风险、兼容与回滚

- 风险：`high`，新增公开只读诊断候选语义。
- 不新增依赖、迁移、配置或外部副作用；已有响应字段不变，只增加候选类型及规则版本。
- 回滚方式：revert PR 并重新部署应用，无数据库回滚。

## 执行记录

- 基线：`710ea9ad12473002c29e52adc6660df517a20216`（PR #87 合并后的 `main`）。
- 分支：`feat/15-config-error-log-signal`。
- RED/GREEN：配置错误规则测试先因模板未识别失败；实现后通过，覆盖完整/部分、缺失/过期、无窗口条目、窗口外条目、独立组、未知模板版本、错误实体、坏摘要、错误 Investigation 和多条支持 Evidence 排序。
- 已新增 PostgreSQL API 集成测试，从持久化 Loki Evidence 验证规则版本、候选 ID、LOW 等级、因果缺口和查询/来源/正文不泄露。
- `go test ./internal/diagnosis -count=1`：通过。
- `RELYTHRA_TEST_DATABASE_URL=<本机隔离测试库> RELYTHRA_MANAGEMENT_TOKEN_FILE=/dev/null RELYTHRA_POSTGRES_PASSWORD_FILE=/dev/null make check`：通过，包含 Go vet/test/build、54 个 Vitest 用例、ESLint、TypeScript、Web build、case-check、Compose 配置与开发脚本检查。Web build 有已存在的 ECharts chunk 大小警告。
- `gitleaks dir --no-banner --redact`、`git diff --check`：通过。
- 待完成：最终 diff 自审、提交、推送、创建并标记 `Refs #15` 的 PR，验证远程 Backend/Frontend/Compose smoke。
