# ADR 0005：隔离的 Compose 示例业务与只读观测入口

- 状态：Accepted（Issue #6 的实现边界，待 PR 人工评审）
- 关联：Issue #1、#6；ADR 0001、0003、0004

## 问题与选择

M1 需要可重复的真实业务和观测数据，不能让演示故障损坏诊断数据库，也不能通过监控取得容器控制权限。

选择在基础 Compose 之上叠加 `demo.yaml`，保留无 Docker 开发方式和现有 smoke。orders 与 inventory 是独立构建的 Go 程序，共享最小 HTTP/telemetry 实现，调用链为 orders → inventory → demo PostgreSQL。业务数据库使用独立实例、卷和只读角色，诊断数据库不创建演示角色。示例请求只读库存，避免为基础观测演示加入业务写权限。

日志通过独立的命名卷保存有限轮转文件；Alloy 只读采集并向内网 Loki 写入。与直接读取 Docker JSON 日志相比，不需要宿主机 Docker 数据目录和 Docker Socket，Docker Desktop 上也能采集。只采集示例业务日志，不声称已经采集任意容器/控制面日志。缺失 service/host/container 的记录被显式丢弃并记录 Alloy drop counter，其余关联标签在源端固定。

Prometheus 与 Loki 原始接口不发布到宿主机，存储网络与诊断网络隔离。Nginx 网关校验独立只读 Bearer Token，仅转发 GET 白名单路径，拒绝 Push、Delete、Admin、Reload 等路径；Grafana 用此 Token 读取。Grafana 默认匿名 Viewer，仅在本地回环端口提供 UI；管理员密码单独注入，不能作为数据源凭据。网关和 Grafana 是本地可信演示边界，不构成公网多租户权限。

node_exporter 只读挂载 proc/sys，不启用额外 collectors。cAdvisor 不挂 Socket、不 privileged，使用只读 sys 和宿主机 cgroup namespace，输出原始 cgroup 指标。没有 Docker 元数据时，无法保证名称、镜像、Compose 标签和退出/OOM 事件，统一标记 `mapping_status=raw_cgroup_only`。宿主机标签 `demo-host` 是管理员声明的逻辑主机标识；Docker Desktop 采到的是 Linux VM，不能将它当作 macOS 宿主机。未来 #13 必须在映射与时效验证后才把 cgroup 证据关联服务；Kubernetes 不在范围内。

### Issue #13：显式容器身份映射

容器归属只接受管理员在版本化 Runtime 数据源映射中维护的精确 `(host_id, cgroup_id)` 项；项目、服务和环境继承该数据源映射的作用域。映射更新使用现有 `expected_version` 乐观并发契约，采集结果和 Evidence 查询参数记录实际使用的映射版本。未配置、未命中或超出所选 host 的 cgroup 继续保持 `raw_cgroup_only` 并产生数据缺口；日志中的容器 ID 不用于补全映射。该规则不证明容器健康，也不提供 Docker 实例列表、退出状态或经验证的健康 peer。

## 取舍

- 不引入 Docker API 或 privileged 来换取完整的容器身份信息；保留证据缺口，避免越权和错误关联。
- 示例日志文件保留当前及前一份（各 4 MiB），容器 stdout 各 2×5 MiB；Prometheus 24h/256 MB，Loki 24h。Loki 保留时间不是磁盘硬配额，Docker 数据盘仍需监控与人工容量管理。
- Grafana 预配置数据源、面板和 target-down 告警。部署回调、通知 Webhook 仅提供独立配置占位，告警推送和诊断创建留给后续 Issue。
- 版本固定到明确镜像版本/摘要，探针通过轻量派生镜像加入，保持无 shell 原镜像可运行。
- 不自动更新现有 demo 卷的 schema；缺失版本/种子时 inventory readiness 返回 503。保留卷后人工迁移/重建，禁止脚本静默清库。

## 风险与回滚

此改动为 high：只读宿主机目录仍包含敏感元数据，部署者必须信任镜像，不能把监控接口发布公网。Grafana 初始化脚本以 root 读取挂载 Secret 并准备数据卷，然后以 UID 472 启动。业务进程 UID 10001，诊断 Token 与演示读 Token 分离。

回滚只需停止 demo 叠加环境，继续基础 Compose 或无 Docker 入口；没有生产迁移变更。`demo.sh down` 保留全部卷，删除卷必须人工确认。专用 `demo-smoke.sh` 只销毁它自己创建的随机命名项目。

## 官方资料

- [Alloy 文件采集](https://grafana.com/docs/alloy/latest/reference/components/loki/loki.source.file/)
- [Grafana provisioning](https://grafana.com/docs/grafana/latest/administration/provisioning/)
- [Grafana 告警文件配置](https://grafana.com/docs/grafana/latest/alerting/set-up/provision-alerting-resources/file-provisioning/)
- [node_exporter 容器约束](https://github.com/prometheus/node_exporter#docker)
- [cAdvisor runtime flags](https://github.com/google/cadvisor/blob/master/docs/runtime_options.md)

## 安全复核补充

禁止整个宿主机 `/` bind 到容器，即使标记只读也可能间接暴露 Unix Socket；文件系统只读不等于 Socket API 只读。node_exporter 只挂 `/proc`、`/sys`，启用 CPU/meminfo/loadavg/time，禁用 filesystem collector；cAdvisor 仅挂 `/sys`。因此本轮不提供宿主机磁盘容量证据。未来若增加磁盘观测，须单独设计不会暴露运行时控制入口的限定挂载/外部 exporter，不得将缺失当作磁盘健康。
