# Issue #13：显式映射容器的 peer 关联

## 目标与边界

为当前查询结果中的显式映射容器提供同服务 peer 身份，支持后续逐实例对照。peer 定义为同一查询 Host、同一 Service、同一 MappingVersion 下的其他显式映射 cgroup。结果仅提供候选 peer ID，不声称 peer 健康，也不基于 peer 关系生成根因、事件或状态判断。

保留每个容器独立结果；raw cgroup、仅有 exporter service label 的容器、其他宿主机或不同映射版本不能成为 peer。无 peer 时继续返回空数组。无数据库、API schema、权限或依赖变化。

## 实现步骤

1. 在 `internal/connector/runtime/collector_test.go` 增加回归测试：三个同服务显式映射容器相互引用且顺序稳定；未映射但带伪造 Compose service label 的同机 cgroup 不进入关系；配置的其他主机映射不泄漏进结果；单容器映射没有 peer。
2. 先在主干基线运行新测试，确认它因空 peer 列表而失败。
3. 在 `internal/connector/runtime/collector.go` 按 `(host_id, service, mapping_version)` 对已映射容器分组，为每个容器生成排除自身、排序稳定的 peer ID 列表；不接触 `State`。
4. 运行 runtime 包测试、Go race 相关包测试和仓库全量检查；记录本地 Compose 环境限制以及 CI 实际结果。

## 风险与回滚

风险 high，来源于基础设施身份关联可能被下游误读。限制为使用管理映射和当前版本作为 peer 依据，不信任 exporter labels。回滚为 revert 本 PR；无数据迁移。

## 验收与剩余范围

- 多个显式同服务映射的副本在彼此结果中出现其他匿名 ID，顺序确定且自身不出现。
- 未映射身份和伪造 label 不进入 peer 集合；容器仍分别返回。
- peer 关系不赋予健康语义、不改变状态与事件。
- Issue #13 的实际 OOM/退出时间、健康判定、被替换容器的历史持久化和真实故障注入仍未在此切片实现，Issue 保持开放。

## 执行记录

- 基线：`origin/main` = `0712a31c696d9256f2c6d66fd66ae9290bf22cda`。
- 红：`go test ./internal/connector/runtime -run '^TestQueryLinksOnlyExplicitlyMappedContainersAsPeers$' -count=1` 在实现前失败，显示 peer 列表为空。
- 绿：相同定向测试在实现后通过；测试另验证三个副本的 peer ID 顺序稳定、无自身引用、exporter label 不能建立映射、外部 host 的序列被当前查询排除，且 peer 关联不改变 `observed` 状态。单个显式映射副本仍返回空 peer 列表。
- `go test -race ./internal/connector/runtime ./internal/evidence ./internal/connector/prometheus -count=1`：通过。
- 首次 `make check` 在隔离工作树中因缺少 Web 依赖而在 ESLint 失败；执行 `make web-install`（234 包，0 漏洞）后重跑，Go fmt/vet/test/build、Web lint/typecheck/Vitest（3 项）/build 和 case-check 全通过，在 `compose-config` 因本机 Docker 不支持 `docker compose --file` 失败。`make dev-script-check` 单独通过。
- `gitleaks detect --source . --no-git --redact`：未发现泄漏；`git diff --check`：通过。
- `make fmt-check vet test build web-check case-check dev-script-check`：通过；Web Vitest 1 个文件、3 个测试通过。
- 本次风险自查：分组规模受映射上限 1000 限制；每个副本比较同组候选并排序，最多约一百万次 ID 比较。只增添候选身份关系，不生成任何健康、事件或根因结论。
- 最终远程 CI 在 PR 创建后回填；Compose 配置与 smoke 仍依赖远程 CI 验证。
