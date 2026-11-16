# Issue #13 生命周期日志数据缺口语义

## 范围与取舍

本切片补齐 Runtime Collector 对 Loki 生命周期日志结果的结构化缺口表达。当前日志结果已经会让 Runtime 结果进入 partial，并保留 `unverified_log_match`；本切片仅把截断、时间偏差和窗口外条目分别记录为稳定 gap，帮助下游区分“日志不完整”的具体原因。

选择在 `internal/connector/runtime/collector.go` 归一化结果时追加 gap，而不是在 Loki connector 中直接生成 Runtime 专属名称，原因是 gap 描述的是跨数据源的 Runtime 证据边界，Loki connector 仍只负责通用查询结果。保留现有 Loki Evidence 的 partial 规则，不新增生命周期事实分类。

## 验收标准

- `loki.Result.Partial` 或存在 `NextCursor` 时，Runtime 结果包含 `container_lifecycle_events_truncated`。
- `loki.Result.TimeSkew` 时，Runtime 结果包含 `container_lifecycle_events_time_skewed`。
- 至少一个归一化事件的 `OutsideTimeWindow` 为 true 时，Runtime 结果包含 `container_lifecycle_events_outside_window`。
- 所有上述情况继续保留 `container_lifecycle_events_unverified` 和 partial 状态。
- 事件分类仍为 `unverified_log_match`，不新增 `restart`、`exit`、`oom` 或健康状态断言。
- gap 为空时不增加对应条目；最终 gap 列表仍按现有排序和去重规则输出。

## 非目标

- 不修改 Loki 查询模板、分页协议或响应字段。
- 不根据日志文本推断容器重启、退出、OOM、健康或根因。
- 不新增数据库迁移、API 字段、Agent 工具或外部写操作。

## 验证与回滚

先在生产代码前增加 Runtime Collector 失败测试，确认新 gap 尚不存在；再实现最小归一化逻辑，运行 Runtime 定向测试与 race 测试。交付前执行仓库规定的格式、vet、测试、构建、前端检查、密钥扫描和 diff 检查。回滚方式为 revert 本切片提交，无数据或配置回滚。

## 执行记录

- 2026-11-15：基于 Issue #13 和 `docs/plans/issue-14-runtime-evidence.md` 确认只扩展 partial/gap 语义，保留未验证日志边界。
