# Issue #15：只读调查工作台实现计划

## 目标与范围

需求依据：Issue #15、Proposal #1、ADR 0003，以及已合入的诊断和时间线读取契约。
交付按 Investigation UUID 打开的只读详情页，展示固定规则候选、缺口、分页时间线和 Evidence 核验。
本次是 Issue #15 的部分交付，PR 使用 `Refs #15`：告警摘要/映射状态/服务环境名称的读取接口、指标趋势图及其余故障规则仍未交付。

沿用 React、TypeScript strict、原生 fetch 和现有测试工具，不新增依赖。
视觉采用紧凑的白底运维工作台，绿色表示可用状态、琥珀表示证据不足，ID/UTC 时间用等宽字体。
没有 Investigation 时显示查询入口；不自动创建调查、不触发采集、不填充演示结论。

## 接口与安全

- `GET /api/v1/investigations/{id}/diagnosis`：不带查询参数，独立加载与重试。
- `GET /api/v1/investigations/{id}/timeline?limit=50&offset=0`：可追加已有的 `source_type`、`completeness`；筛选切换重置 offset，最大 offset 10000。
- `GET /api/v1/evidence/{id}`：点击候选或时间线后独立读取；校验 ID 与 Investigation 归属。
- 响应作为 unknown 解码，校验必要字段、枚举、分页和归属；Go 的 nullable 切片按契约归一化为空数组。
- 每次请求 15 秒超时、卸载/切换时取消；失败信息使用本地固定文案，不直接展示远端错误正文。
- 所有远端文本仅通过 React 文本节点展示；原始引用只允许无 userinfo 的绝对 HTTP(S) 外链，其他 scheme 作为文本。
- 诊断与时间线是不同快照，不把页面筛选结果当作诊断完整输入；Evidence 详情始终重新读取。
- 浏览器仅使用既有只读路由，不存储或索取管理 Token。沿用本地/受信网络边界。

## Task 1：契约与页面行为（红绿循环）

文件：新增 `web/src/investigation.ts`、`web/src/useReadResource.ts`、`web/src/InvestigationWorkbench.tsx`、`web/src/investigation.test.ts`、`web/src/test/investigationFixture.ts`；修改 `web/src/App.tsx`、`web/src/App.test.tsx`、`web/src/styles.css`。

1. 先写解码及组件测试：UUID 拒绝、独立失败/重试、INCONCLUSIVE、支持/反证跳转、缺口、筛选分页、跨调查隔离、危险链接与 HTML 文本。
2. `cd web && npm test -- --run` 确认新测试因缺实现失败，保留 readiness 回归断言。
3. 实现解码函数 `parseDiagnosis(value: unknown)`、`parseTimeline(value: unknown)`、`parseEvidence(value: unknown)`，以及只读组件；无需路由库，查询参数 `investigation` 保存可分享入口。
4. 重跑测试、lint、typecheck、build，修复至通过。

核心行为例：

```tsx
fireEvent.change(screen.getByLabelText("Investigation ID"), { target: { value: investigationID } });
fireEvent.click(screen.getByRole("button", { name: "打开调查" }));
expect(await screen.findByText("候选方向")).toBeInTheDocument();
```

## Task 2：实际入口与交付验证

文件：修改 `web/vite.config.ts`、`web/nginx.conf`、`scripts/smoke.sh`、`README.md`。

1. Vite 与 Nginx 固定转发 `/api/` 至已有 API；Compose smoke 通过 Web 入口查询不存在调查，断言 JSON 404，避免 SPA HTML 假成功。
2. 用受控合成响应实际渲染桌面和窄屏，验证候选、筛选、Evidence、部分失败和空态，检查溢出及控制台错误。此验证不能替代真实数据链验收。
3. 运行 `make check`（宿主机测试 PostgreSQL）及 Gitleaks；固定 base/head 按 code-review 审阅 diff，再创建 PR 并检查最终 HEAD 的三项必需 CI。
4. 不合并；人工 Review 与合并留给用户。

## 风险、兼容与回滚

风险 `high`：新增浏览器对只读数据 API 的可达路径和不可信证据展示。
不新增 API、迁移、依赖、采集或外部写行为。已有 `/health/` 检查保留。
回滚整个 PR 并重新构建 Web 镜像即可；数据库无需回滚。

## 执行记录

- 基线：`381c54f58394f731b5f67a93fbce0bca60353f94`（PR #83）。
- 本会话顺序执行，先测试后实现；不委派子代理。
- 文件命名裁决：组件使用 `InvestigationWorkbench.tsx`，避免大小写不敏感文件系统将 `Investigation.tsx` 与 `investigation.ts` 错配。
- 浏览器首轮发现来源 select 的名称匹配问题；增加精确可访问名称。证据跳转聚焦详情标题，覆盖窄屏与键盘使用。
- 红绿证据：新增首批测试在骨架上失败（缺查询入口/解码模块）；焦点跳转与 Evidence 404 提示各自新增回归后确认失败，再实现修正。
- 最终本地验证：`make check`（含宿主机 PostgreSQL 测试）、23 个 Vitest 用例、`bash -n scripts/smoke.sh`、Gitleaks 与 diff whitespace 检查通过。
- `RELYTHRA_POSTGRES_PASSWORD=ci-only-not-secret make smoke` 通过，包括 Web 到诊断 API 的 JSON 404 转发，专用容器、网络与卷已清理。随后只修改了前端焦点和错误文案，已重跑完整前端验证；最终镜像验证交由最终 HEAD 的远程 CI。
- Playwright 合成 API 验证：1440×1000、390×844、320×740；支持证据跳转、长查询/HTML 文本、来源筛选、独立失败重试、INCONCLUSIVE 与空态通过；无页面错误或横向溢出。截图位于本机 `/tmp/relythra-ui-84/`，未验证真实采集到浏览器的完整数据链、其他浏览器或生产认证。
- 容器 `npm ci` 提示既有依赖有 12 条 high 审计项；本 PR 未改依赖或锁文件。单独 `npm audit --omit=dev` 因本机 registry DNS 失败未完成，不能据此确认生产依赖是否受影响。
