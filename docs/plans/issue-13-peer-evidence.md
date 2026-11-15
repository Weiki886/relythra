# Issue #13：将容器 peer 关系保留到运行时 Evidence

## 目标与边界

将运行时连接器为显式映射容器生成的匿名 peer ID 列表保留在对应 Prometheus Evidence observation 中，使后续时间线读取者能够复核同服务候选实例关系。

Evidence 边界只接受同一查询结果内、同一宿主机/服务/映射版本下已观测显式映射容器之间的完整 peer 集合。拒绝自引用、重复、未知/未映射 peer、不完整集合及歧义身份，并按 ID 稳定排序。关系不表示 peer 健康，不改变容器状态、事件、置信度或根因结论；不添加 API、schema、依赖、数据源查询或外部副作用。

## 实现步骤

1. 在 `internal/evidence/runtime_test.go` 建立三个显式映射容器的 peer 关系，断言四类容器指标 Evidence 均保留排序后的 peer ID，并为 raw cgroup、自引用、重复、未知、不对称和对称但不完整关系添加拒绝用例。
2. 先运行定向测试，确认 peer 关系丢失或非法关系未拒绝。
3. 在 `internal/evidence/runtime.go` 为容器 observation 增加可选 peer ID 字段；基于同一结果的显式映射身份校验 peer 集合，排序副本而不修改调用方输入。
4. 运行 Evidence/runtime 定向测试、Go race 相关包和仓库快速检查，复核序列化大小、脱敏、回放哈希与只读边界。

## 风险与回滚

风险 high：映射错误可能污染运行时证据中的实例关联。通过同次查询的显式映射、host/service/mapping version 已有校验，以及完整集合、唯一身份、无重复/无自引用校验限制边界。无迁移，回滚为 revert 本 PR；既有 Evidence 不需重写。

## 验收

- 显式映射容器的 peer ID 在 CPU、memory、OOM 和 start-time Evidence 中可追溯，且输出顺序稳定、集合完整。
- raw cgroup、未知 peer、自引用、重复 peer、非对称关系和不完整集合使规范化失败。
- 规范化不改变输入结果；peer 关系不产生健康或根因语义。
- Issue #13 保持开放；宿主机/容器健康判断、生命周期持久化和真实故障注入仍属未完成范围。
