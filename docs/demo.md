# Compose 业务与观测演示

这是 Issue #6 的本地可信环境：orders → inventory → 独立 demo PostgreSQL；Prometheus 采集业务/Worker/node/cgroup 指标；Alloy 采集业务 JSON 日志到 Loki；Grafana 提供 Viewer 面板和初始告警。真实诊断、部署回调、告警接收与通知仍由后续 Issue 实现。

## 启动

基础 API/Worker/Web 的无 Docker 入口仍是 `./scripts/dev.sh`。下面的完整演示需要 Docker Compose v2、约 4 GiB 可用内存与 Linux cgroup。Docker Desktop 指标代表其 Linux VM，不能代表 macOS/Windows 物理宿主机。

先按 README 创建 `secrets/postgres_password`、`secrets/management_token` 并复制 `.env.example` 为 `.env`，再创建四份独立随机演示凭据。重复启动不要重新生成已有凭据：数据库与 Grafana 初始化密码保存在卷内，覆盖文件不会自动修改已有账号。

```bash
mkdir -p secrets
chmod 700 secrets
for name in demo_owner_password demo_reader_password observability_token grafana_admin_password; do
  if [ ! -e "secrets/$name" ]; then
    (umask 077; openssl rand -hex 32 | tr -d '\n' > "secrets/$name")
  fi
done
./scripts/demo.sh up
./scripts/demo.sh status
```

旧 `.env` 需从 `.env.example` 补充 `DEMO_*_FILE`。Secret 路径相对于 `deploy/compose/`；不要提交 `.env`、`secrets/` 或含 Token 的截图/命令历史。只读 Token 限制为至少 32 个字母、数字、下划线或连字符。

| 入口 | 默认地址 | 权限/用途 |
| --- | --- | --- |
| Relythra Web | http://127.0.0.1:3000 | 当前健康工作台 |
| API | http://127.0.0.1:8080/health/ready | 领域读取/管理需独立管理 Token |
| Worker | http://127.0.0.1:8081/metrics | 心跳指标 |
| orders | http://127.0.0.1:18090/orders | 真实请求 inventory 的库存只读请求 |
| Grafana | http://127.0.0.1:13001/d/relythra-demo | 默认匿名 Viewer |
| Prometheus 网关 | http://127.0.0.1:19090 | 独立只读 Bearer Token |
| Loki 网关 | http://127.0.0.1:13100 | 同一演示只读 Bearer Token |

所有发布端口仅绑定回环。inventory、演示数据库、Alloy、node_exporter、cAdvisor 和原始存储不发布端口。控制面 PostgreSQL 仍在 15432；演示数据库使用不同实例、网络、卷、账号和凭据。

Grafana 管理员用户名为 `admin`，密码来自 `secrets/grafana_admin_password`，仅用于人工管理。数据源和面板由文件配置且不可在 UI 修改。初始告警 `Demo target unavailable` 检查每个示例服务的抓取可用性；它不表示数据库 readiness，也不向 Relythra 创建 Incident。查看/编辑告警需要管理员，Viewer 用于浏览面板。

## 产生与核验观测数据

```bash
curl --fail http://127.0.0.1:18090/orders
# 返回 available=42，来自独立 demo 数据库的固定种子。

curl --fail --get \
  --header "Authorization: Bearer $(cat secrets/observability_token)" \
  --data-urlencode 'query=demo_http_request_duration_seconds_count' \
  http://127.0.0.1:19090/api/v1/query

curl --fail --get \
  --header "Authorization: Bearer $(cat secrets/observability_token)" \
  --data-urlencode 'query={project="relythra-demo",env="demo"}' \
  --data-urlencode 'limit=20' \
  http://127.0.0.1:13100/loki/api/v1/query_range
```

业务日志包含 `project/service/env/host/container/runtime_type/release`，container 来自容器 hostname，host 是明确配置的 `demo-host`。它们是示例环境的显式身份，并非从 Docker 名称推测。采集器缺少 service/host/container 时丢弃该记录，计入 Alloy `loki_process_dropped_lines_total` 及对应 missing_* reason；可以通过 Prometheus 查询 Alloy 的采集器指标，或查看容器日志排查。

Prometheus 每 5 秒抓取两个示例服务、Worker、node_exporter、cAdvisor 和 Alloy，共 6 个 targets。业务请求指标只有固定路由和状态标签；`demo_service_info` 单独提供与日志一致的实例、版本与环境标签，探活/任意路径不会引入高基数。P95 需要多次业务请求与至少两个抓取点；没有数据不是健康零值。工作台 API 的真实业务指标尚未实现，当前只抓 Worker 心跳。

node_exporter 只读挂载 `/proc` 与 `/sys`，采集 CPU、内存、负载与时间；不挂整个宿主机根目录，宿主机磁盘容量当前不可用，不能输出磁盘根因证据。cAdvisor 仅挂只读 `/sys`，在无 Socket/无 privileged 条件下提供原始 cgroup 内存/CPU；连接器额外尝试查询 OOM 计数和启动时间，但这些指标在当前环境中可能缺失；Prometheus 用 `host_id` 标识逻辑宿主机，并加入 `mapping_status=raw_cgroup_only`。Runtime Connector 会按逻辑主机和原始 cgroup 的摘要区分资源实体，无法可靠映射时保留缺口，不会返回明文 cgroup 路径或推断 Compose 服务名。Loki 中匹配 restart/OOM 关键词的应用日志只作为未验证日志证据，不代表 Docker 生命周期事件；缺少日志或指标不会解释为零或健康。Docker Desktop 的 node_exporter 观测对象是 Linux VM，不是 macOS 宿主机。系统不支持 Kubernetes Pod/Node/Eviction。这次仅提供连接器库与固定模板，尚未接入 API、Agent 或工作台。默认每模板最多 10 条序列、240 个点，七个模板合计不得超过 20,000 点；最终宿主机和 cgroup 结果各不超过请求的 MaxSeries。宿主机筛选在上游截断之后进行，可能遗漏目标主机，不能据此判定其没有运行实例；数据源必须由调用方预先授权，本库不提供项目隔离。存在服务映射、健康 peer 和生命周期事件缺口时始终返回 partial。Delay、Stale 和 LastObservedAt 只描述范围查询返回的求值时间覆盖，不代表 exporter 实际采集延迟或机器健康；实际 scrape 新鲜度未验证，返回 `exporter_scrape_freshness_unavailable`。未来时间戳的启动证据会保留原始样本并标记 clock skew，不生成实例身份。

环境若无法提供非根 cgroup 指标，smoke 会失败，需检查 cgroup 权限、rootless 限制和 Docker Desktop 设置，不能用根 cgroup冒充业务容器。

诊断进程只加入 control/diagnosis 网络，Loki 原始写入只在 observation-backend；读网关仅允许明确 GET 路径，写请求与未登记路径返回 403。只读 Token 与控制面管理 Token 分开；部署发送 Token 与通知通道只在 `.env.example` 留独立 SecretRef 占位，当前不消费。

## 发布、故障与恢复边界

两个程序分别使用 `cmd/demo-orders` 和 `cmd/demo-inventory` 构建，可单独构建/替换镜像并修改 `DEMO_ORDERS_RELEASE` / `DEMO_INVENTORY_RELEASE` 标签。标签不等于已接入 DeploymentEvent，不能作为真实发布事实。更新单个服务示例：

```bash
docker compose -p relythra-demo -f deploy/compose/compose.yaml -f deploy/compose/demo.yaml up -d --build --no-deps inventory
```

所有故障测试默认关闭。只有显式设置 `DEMO_ENABLE_FAULTS=true` 并重建 inventory 容器时，容器内 `GET /internal/test/slow-query` 才执行固定 `SELECT pg_sleep(0.2)`，上下文最多 1 秒；无任意 SQL/命令、无公开管理端口。这只验证测试入口边界，不是已经完成慢 SQL 发布回归或评测案例。完整故障注入与恢复将在后续 Issue 实现，不能把控制元数据写进观测日志当根因答案。

数据库断开：inventory/orders 的 `/health/ready` 返回 503，业务请求 503，`/health/live` 保持 200；控制面数据库独立，Relythra readiness 不受演示数据库影响。恢复 demo 数据库后自动重连，不自动执行重启、扩容、回滚。

首次空卷创建 `demo_stock` schema 版本 1 与 SKU 种子。旧卷缺表、缺 SKU 或版本不匹配会 readiness 503；检查 inventory 日志/数据库，再人工迁移。不要通过自动删卷掩盖版本问题。基础 goose 迁移仍只修改控制库。

## 持久化与资源

| 卷 | 内容 | 保留/限制 |
| --- | --- | --- |
| postgres-data | 控制面领域/审计数据 | down 保留 |
| demo-postgres-data | demo_stock 与只读业务角色 | down 保留，与控制面隔离 |
| orders-logs / inventory-logs | 当前与上一份 JSON 日志 | 各文件 4 MiB，总计各 8 MiB |
| prometheus-data | TSDB | 24 小时 / 256 MB 保留策略 |
| loki-data | 日志、索引、压缩状态 | 24 小时，非磁盘硬配额 |
| alloy-data | 采集游标 | down 保留 |
| grafana-data | SQLite、用户与告警状态 | down 保留 |

每个服务有 CPU、内存、PID 限制；stdout 日志 2×5 MiB。内存限额不是磁盘配额，需确保 Docker 数据盘容量。所有宿主机 bind 挂载只读，业务日志/数据库/观测数据是各自的命名卷。没有 privileged、Docker Socket、宿主机可写挂载或容器写 API。

```bash
./scripts/demo.sh down
```

此命令停止完整演示并保留卷。重置需要先备份并人工确认项目名和卷列表，之后只删除选定的演示卷；不要删除控制库 `postgres-data`。不提供一键清空用户数据的脚本。

## 自动验收与排错

```bash
make demo-smoke
```

需要 Python 3；脚本创建独立随机项目、随机 Secret、专用端口 28080/28081/23000/25432/28090/29090/23100/23001。验收结束只删除该项目的容器、网络、卷和临时 Secret。不要把这个脚本改成连接共享/生产数据库。

检查项包括真实业务请求、6 个 targets、业务/宿主机/非根 cgroup/Worker 样本、两种服务日志与标签、Viewer 面板、只读拒写、数据库权限、演示数据库中断/恢复、重启保留数据。任何组件没就绪都会失败并报告具体服务/缺失样本。首次下载镜像超时可在网络恢复后重新执行；不把重跑当作解决 flaky。

`demo.sh up` 失败后不会清空数据；用 `status` 定位不健康组件，再用相同项目名和两个 compose 文件执行 `logs <service>`。不要输出 Secret、网关渲染文件或完整环境变量。Grafana 初始密码仅在空卷生效，修改 Secret 文件后应通过受控账号管理更新已有密码。
