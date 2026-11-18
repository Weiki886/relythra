# Issue #15：调查与告警上下文

## 范围与取舍

依据 Issue #15、Proposal #1、ADR 0002/0003/0008。基线为 PR #84 合并提交
`e472ff8d6f836365416e6a7869d9898b0991ac17`。本会话顺序执行，不委派。

在已有只读工作台增加调查摘要：项目、服务、环境、调查生命周期、关联告警及映射状态。
复用 PostgreSQL、API 脱敏器、React、unknown 解码和独立请求 Hook，不新增依赖。
不从 Evidence 推测当前告警，不返回整个领域对象或配置，不查外部平台。
本 PR 是 Issue #15 的部分交付，使用 `Refs #15`；部署候选独立视图、趋势和其余规则另行交付。

## 读取契约

`GET /api/v1/investigations/{id}`；仅 GET，不接受 query（含空 `?`）。
UUID 非法返回 400，缺失调查返回 404，数据库错误返回通用 500。
响应遵循既有 `{data, request_id}` 并统一脱敏，沿用本地/受信网络访问边界。

`store.InvestigationContext` 字段：

- `investigation_id`、`incident_id`、`status`、`started_at`、`completed_at`。
- `project: {id, slug, name}`；`service: {id, slug, name} | null`；`environment: string | null`。
- `alert: {id, status, severity, summary, starts_at, ends_at, source_reference} | null`。
- `mapping_status: MATCHED | NEEDS_MAPPING | CONFLICT`，仅表示实体服务/环境关联，不能证明数据源配置就绪。
- `context_gaps: string[]`，无告警为 `alert_not_linked`；缺服务/环境为
  `service_mapping_missing`/`environment_mapping_missing`；不一致为 `mapping_conflict`。

一次 SELECT 读取 Investigation → Incident → Project，LEFT JOIN 限定同项目的 Service 和 Alert，
所有字段处于同一数据库语句快照。无关联告警返回 null，不以空告警对象表示正常。
调查、Incident、关联 Alert 的服务/环境只要不一致（含 null 不一致），或服务不属于项目，返回 CONFLICT，
同时隐藏服务与环境，避免展示错误归属；一致但缺字段为 NEEDS_MAPPING；其余为 MATCHED。
不从 labels 读取或相信自报 mapping_status，不返回 labels/annotations/payload/SecretRef/连接串/内部错误。
该摘要是当前登记状态，不是不可变证据快照；告警 RESOLVED 不等于根因已确认或调查已结束。

## Task 1：只读 API 与持久化读取

文件：新增 `internal/store/investigation_context.go`、`internal/api/investigation_handler.go`、
`internal/api/investigation_context_test.go`、`internal/api/investigation_context_integration_test.go`；
修改 `internal/api/handler.go` 与 `internal/api/handler_test.go`。

接口：`(*store.Postgres).GetInvestigationContext(context.Context, string) (store.InvestigationContext, error)`，
加入既有 `api.Reader`，由 `getInvestigationContext` 路由消费。

1. 先编写 API 契约测试、SQL 真实集成测试：正常关联/当前告警恢复、无告警、缺映射、错服务/跨项目、
   缺失调查、UUID/方法/query 拒绝、稳定错误与秘密输出边界。
   核心断言：`if result.MappingStatus != "CONFLICT" || result.Service != nil { t.Fatal(result) }`。
2. `RELYTHRA_TEST_DATABASE_URL=<隔离测试库入口> go test ./internal/api -run InvestigationContext -count=1`
   确认缺方法/路由而失败，再实现单 SELECT 与受控字段 DTO。
3. 定向测试通过后执行 `go test -race ./internal/api ./internal/store`（含测试库）。

## Task 2：摘要界面与安全降级

文件：修改 `web/src/investigation.ts`、`web/src/investigation.test.ts`、
`web/src/test/investigationFixture.ts`、`web/src/InvestigationWorkbench.tsx`、
`web/src/App.test.tsx`、`web/src/styles.css`。

接口：`parseInvestigationContext(value: unknown)` 校验 UUID、时间/枚举、可空嵌套对象，
沿用 `useReadResource` 对响应调查归属进行校验。

1. 测试先行：摘要字段、告警安全外链、无告警、待映射/冲突、独立失败重试、跨调查响应拒绝。
   例：`expect(await screen.findByText("尚未关联告警")).toBeInTheDocument()`。
2. `npm --prefix web test -- --run` 确认失败；实现 `InvestigationContext` 展示组件，顶部全宽摘要，
   未映射/冲突为琥珀提示，生命周期和告警状态分开呈现，危险链接不生成 anchor。
3. `make web-check`，使用 Playwright 在 1440/390/320 宽验证正常、长字段、部分失败、无告警/冲突。
   页面摘要失败不得遮蔽时间线/诊断；文本用 React 渲染，不使用 HTML 注入。

## Task 3：入口、文档与交付

文件：修改 `README.md`、`scripts/smoke.sh` 和本计划执行记录。

在 smoke 通过 Web 入口验证摘要 JSON 404，数据库为空不应落入 SPA HTML。
运行 `make check`、`make smoke`、Gitleaks 和 diff 检查，固定 base/head 进行 code-review 自检并创建 PR。
核对最终 HEAD Backend、Frontend、Compose smoke；保留人工 Review，不自行合并。

风险 high（新增只读 API、不可信告警文本与实体归属）。无迁移或新配置，回滚整个 PR 并重建 API/Web 即可。
未验证生产认证、真实告警到浏览器的完整链路或其他浏览器时，必须在 PR 如实注明。

## 执行记录

- 已核对 Issue #15 与 PR #84；远端分支已自动删除。本地 `git branch -d` 因 squash ancestry 拒绝，未强删。
- 图索引停留在 2026-11-16，相关新/变更文件已直接读取，以当前源码为准。
- Task 1：完成。API 契约与 PostgreSQL 集成测试覆盖 UUID/方法/query 边界、缺失调查、无告警、映射缺失/冲突、已恢复告警、错误脱敏与跨项目服务隐藏。`RELYTHRA_TEST_DATABASE_URL='postgres:///relythra?host=/tmp&sslmode=disable' go test -race ./internal/api ./internal/store -count=1` 通过，连接真实本地 PostgreSQL，各测试使用并清理独立 schema。
- Task 2：完成。前端对摘要独立解码、加载、错误和重试；测试覆盖安全外链、无告警、映射状态、跨调查响应拒绝和其他工作区内容不受摘要失败影响。`make web-check` 通过，40 个测试通过。Playwright 验证 1440/390/320 宽度、长字段、冲突、无告警、独立重试和 Evidence 导航，无横向溢出或页面错误。
- Task 3：完成本地范围。最终代码执行 `RELYTHRA_MANAGEMENT_TOKEN_FILE=/dev/null RELYTHRA_POSTGRES_PASSWORD_FILE=/dev/null make check` 通过，覆盖 Go 静态检查、单测和构建、前端检查、40 个前端测试、生产构建、夹具校验及配置/启动脚本检查。首次未提供两个 Secret 文件路径时止于 Compose 配置，提供仅用于静态配置渲染的占位路径后完整复验通过；数据库集成测试以 Task 1 的独立命令为准。`RELYTHRA_POSTGRES_PASSWORD=ci-only-not-secret make smoke` 通过，覆盖实际迁移、Web 代理后的摘要 404/成功 JSON/字段边界与数据库故障语义，专用容器、网络及卷已清理。`gitleaks dir --no-banner --redact`、`git diff --check` 和 `bash -n scripts/smoke.sh` 通过。
- 本次交付仅为 Issue #15 的部分实现：调查/告警上下文摘要，不新增其余固定规则、部署候选独立视图、趋势图或完整场景验收；保留既有慢 SQL 规则候选，PR 使用 `Refs #15`，不关闭 Issue。Playwright 使用受控合成 API 响应验证渲染，不代表真实采集至浏览器全链路验收。
- 风险：`high`。新增只读 API 并展示不可信告警文本；无迁移、新配置、依赖或外部写操作。回滚整个 PR 并重建 API/Web。未验证生产认证、真实告警至浏览器全链路及其他浏览器。
- 创建 PR 前需再次确认 `origin/main` 基线未变化。PR 必需 CI、Reviewer 和 Issue 后续完整验收仍待完成；不由本次操作合并。
