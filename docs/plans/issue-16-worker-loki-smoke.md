# Issue #16 真实 Loki 自动采集演示验证

## 目标与范围

在现有隔离 Compose 演示中，通过管理 API 为 Inventory 创建 Loki 固定模板映射。Grafana 触发 Investigation 后，验证 Worker 自动采集的日志经 Evidence 持久化进入该调查的时间线，并可通过 Evidence ID 回读。

本切片使用 `Refs #16`。完整慢 SQL 发布、DeploymentEvent、GitHub、Runtime、规则候选，以及三次运行和空卷/已有卷验收仍需后续完成。

## 实现步骤

1. 在 `scripts/demo_artifacts_test.py` 中新增 Loki 映射与时间线断言测试，先复现断言尚不存在的失败。覆盖错误调查、服务归属、模板、缺失日志、错误标签、未标注不可信数据、非业务日志，以及真实业务日志的成功与 PARTIAL 情况。
2. 在 `scripts/demo_assertions.py` 增加固定 Loki 映射载荷和纯时间线断言。验证精确服务、环境、模板、真实 `/stock` 请求日志和有限的 duration_ms。
3. 在 `scripts/demo-assert.py` 复用管理 API 创建逻辑，增加 Loki 映射与 Evidence 检查命令。通过查询公开时间线和 Evidence 读取 API 验证日志结果，使用现有有界轮询。
4. 在 `scripts/demo-smoke.sh` 中，告警触发前创建 Loki 映射，触发后检查同一调查的 Loki Evidence。保留现有告警恢复、Prometheus、只读权限和隔离验证。
5. 更新 `docs/demo.md` 与 README 的实际验收范围。

## 验证与回滚

- 定向 Python 回归测试先红后绿，完整执行 `make demo-artifact-check`。
- 执行 `make check`、`git diff --check`、gitleaks，并在 Kiri 执行 `make demo-smoke`，确认专用资源清理。
- 独立代码评审后提交 PR，核对最终 HEAD 的 Backend、Frontend 和 Compose smoke。
- 风险为 high，类型为 type:test、type:fix，范围为 area:qa、area:infra、area:security。改动限于隔离演示编排、断言和说明，使用既有只读采集与映射接口。回滚应用提交即可恢复原冒烟流程，无迁移。

## CI 发现与方案修订

首轮远端演示在 Worker Loki 采集时产生 `loki_permission_denied`。失败产物确认连接器使用 POST 表单查询，演示网关只接受 GET，返回 403。复用连接器的既有请求契约，为精确 `/loki/api/v1/query_range` 路径开放带 Token 的 POST，限制请求体 16 KiB，其余方法和路径保持白名单约束。新增 ADR 0011、非空 POST 查询探针及未认证/其他 POST/DELETE 拒绝验证。因涉及观测网关安全边界，本轮风险调整为 high，并增加 type:fix、area:security 标签。回滚整份 PR 可恢复原网关策略与 smoke。
