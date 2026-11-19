# Issue #15：Prometheus Evidence 趋势图

**目标**：在已选中的 Prometheus Evidence 详情中展示其结构化指标序列，帮助值班人员核对观测窗口内的变化。

**架构**：只消费现有 `GET /api/v1/evidence/{id}` 返回的 `value_summary.series[].samples[]`，不新增采集、API 或持久化。前端边界解码器限制系列、标签和样本，ECharts 仅绘制有效时间和值；同一 Evidence 内的每条 Prometheus series 独立成线，不跨 Evidence、实体或快照聚合。ECharts 通过动态 import 延迟加载，避免增加工作台初始包体。

**视觉方向**：工作台继续保持低噪声运维界面；趋势图作为 Evidence 详情中的一个明确分区，横轴统一 UTC、纵轴使用序列声明的单位，强调可读数值和异常窗口，不添加装饰性渐变或额外指标解释。

**依赖**：Apache ECharts，按需导入 core、line chart、grid、tooltip、legend 和 canvas renderer。该依赖用于补足产品设计明确要求的 ECharts 趋势图；不引入 React 包装器。

**需求依据**：Issue #15 的只读故障详情页；PR #84 说明中记录“指标趋势图”仍未完成；Proposal #1 的 React/ECharts 工作台。

## 全局约束

- 远端 Evidence 与指标标签是非可信输入，只按文本处理。
- 仅绘制当前已选中的 Prometheus Evidence，不把不同快照或实体聚合。
- 缺失、过期或不完整 Evidence 不显示为健康；图表标注完整度。
- 趋势展示是观测，不推断根因，不显示阈值或健康结论。
- 结构化数据无法完整解码时隐藏图表并保留原始摘要供核验。
- 图表包含可访问名称和可读数据表，不仅依赖颜色或 Canvas。

## Task 1：趋势数据解码与测试

**文件**
- 修改：`web/src/investigation.ts`
- 修改：`web/src/investigation.test.ts`
- 修改：`web/src/test/investigationFixture.ts`

1. 增加 `parseMetricTrend(value: unknown, unit: unknown, observedStart: string, observedEnd: string)`，只接受对象中的 `series` 数组；每条序列必须有字符串标签和有限数值、有效时间戳的样本，且样本不得超出 Evidence 观测区间。
2. 限制最多 10 条序列、每条最多 240 点、标签条目最多 16 个、标签文本最多 128 字符；任一违反契约时拒绝整份趋势数据。
3. 样本按 UTC 时间稳定升序排列但不改变数值；输出规范化 UTC 时间戳、稳定系列名和单位文本，缺失或空序列返回空列表。
4. 先增加有效序列、边界上限、无效时间、NaN/Infinity、错误类型、过量序列/样本与空数据测试，运行 `npm --prefix web test -- --run` 确认失败，再实现并确认通过。

## Task 2：详情中的 ECharts 图表

**文件**
- 新增：`web/src/MetricTrend.tsx`
- 修改：`web/src/InvestigationWorkbench.tsx`
- 修改：`web/src/styles.css`
- 修改：`web/package.json`、`web/package-lock.json`
- 修改：`web/src/App.test.tsx`

1. 安装并锁定 `echarts`，使用 core 按需注册 `LineChart`、`GridComponent`、`TooltipComponent`、`LegendComponent` 与 `CanvasRenderer`。
2. 仅当 Evidence 来源为 `PROMETHEUS` 且模板身份可识别、趋势数据解码成功并至少有一个样本时显示图表。
3. ECharts 以 UTC 时间轴绘制每条原始序列；显示来源单位、系列名与 Evidence 完整度，不生成阈值、聚合值或健康判断。
4. 对空样本、非法/超限数据、非 Prometheus、非序列摘要不显示图表；摘要 JSON 和原始来源仍保持可见。
5. 使用 resize observer 更新尺寸，组件卸载时移除 observer 并 dispose；限制稳定图表高度并适配窄屏。
6. 同步测试图表显示、完整度提示、非指标/空数据降级、序列分离和屏幕阅读器可读的数据表；先验证 UI 测试失败再实现。

## Task 3：验证与交付

1. 运行 `npm --prefix web test -- --run`、`make web-check`、`make check`、`gitleaks dir --no-banner --redact` 和 `git diff --check`。
2. 用受控合成 API 在 1440、390、320 像素宽度渲染工作台，检查正常图表、长标签、部分数据、空数据、键盘焦点、横向溢出和浏览器错误。
3. 按 `origin/main...HEAD` 自审，更新本计划执行记录，提交并创建 PR，PR 使用 `Refs #15`，同步 Issue #15 的 Milestone/标签；不合并。
4. 在最终 HEAD 上核对 Backend、Frontend、Compose smoke 远程检查。

## 风险、兼容与回滚

- 风险：`standard`，只增加单个已有 Evidence 详情的前端可视化，不改变后端或数据格式。
- 兼容：API 不变；不支持序列摘要时继续展示原始 Evidence 数据。
- 回滚：revert 本 PR 并重建 Web；无数据库迁移或持久化数据影响。

## 执行记录

- 基线：`c32aeea4dbe84cda28827a1a0f3af2e0f1479615`（PR #85 合并后的 `main`）。
- 本会话顺序执行；分支：`feat/15-evidence-metric-trend`。
- 当前状态：本地实现与验证完成，已准备创建 PR 并等待远程 CI。
- RED：趋势解码测试先因缺少 `parseMetricTrend` 失败；工作台集成测试先因未渲染 Prometheus 趋势图失败。
- GREEN：解码器按时间排序、限制 10 条序列/每序列 240 点/16 个标签/128 字符，拒绝非有限值、无效时间、越界样本和未知模板；图表按需加载 ECharts，仅绘制模板白名单内且有样本的 Prometheus Evidence，保留原始摘要与来源。
- 前端定向检查：最终 `make web-check` 通过，54 tests，包含 lint、typecheck 和 production build。ECharts 形成独立 516.67 kB（174.64 kB gzip）动态 chunk，主入口 242.51 kB（75.99 kB gzip）。
- 全仓检查：`RELYTHRA_TEST_DATABASE_URL='postgres:///relythra?host=/tmp&sslmode=disable' RELYTHRA_MANAGEMENT_TOKEN_FILE=/dev/null RELYTHRA_POSTGRES_PASSWORD_FILE=/dev/null make check` 通过，含 Go 测试/构建、前端 53 tests、case-check、Compose 配置和开发脚本检查；`gitleaks dir --no-banner --redact`、`git diff --check` 通过。`npm install echarts --save-exact` 锁定 `6.1.0`，安装审计报告 0 vulnerabilities。
- Playwright 实际 Chrome 合成 API 验证：1440×1000、390×844、320×740；两条独立指标线正确绘制，Canvas 非空像素为真、无页面错误、文档无横向溢出；320px 下绘图区域宽 288px，完整样本摘要可展开。截图保存于 `/tmp/relythra-metric-trend-desktop.png` 与 `/tmp/relythra-metric-trend-mobile.png`。未连接真实 Prometheus。
- 自审：base 固定为 `origin/main`（`c32aeea4dbe84cda28827a1a0f3af2e0f1479615`）；只允许 7 个注册模板绘图，所有外部标签以文本处理，tooltip 使用 rich-text 渲染，不将系列聚合或解释为健康/根因。
