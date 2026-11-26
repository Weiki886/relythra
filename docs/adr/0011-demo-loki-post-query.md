# ADR 0011：演示网关的 Loki POST 查询

- 状态：Accepted，待本 PR 人工评审
- 关联：Issue #16、ADR 0003、0005、0010

## 背景与决策

Worker 复用 Loki 连接器，以 POST 表单提交固定模板到 `/loki/api/v1/query_range`。ADR 0005 定义的演示网关只接受 GET，真实采集因此收到 403，并持久化缺失证据。

在 Loki 监听端口保留 Token 与路径校验，为精确 `/loki/api/v1/query_range` 额外接受 POST。请求体限制为 16 KiB，满足现有固定模板参数。其他 Loki 路径的 POST 和其他方法均拒绝。Prometheus 监听端口继续使用原有 GET 方法白名单。

此决策更新 ADR 0005 的 Loki 查询方法约束。POST 在此路径承担只读查询，网关无法调用 push、delete、admin 或配置接口。连接器继续使用固定模板、有界窗口、超时与结果上限，演示网关继续作为本地可信边界。

## 验证

Compose 演示先验证带 Token 的 POST 返回非空 Inventory 日志，再触发 Grafana 告警并验证 Worker 自动 Evidence。额外断言未认证 POST 被拒绝，其他 Loki 查询/标签/健康路径的 POST、DELETE 和写入路径被拒绝。Python 回归测试验证 POST 探针的参数和失败行为。

## 风险与回滚

风险为 high，涉及网关方法白名单。原始 Loki 仍位于隔离存储网络。回滚本 PR 恢复 GET 白名单及原有演示流程，无数据库迁移。
