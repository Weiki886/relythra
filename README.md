# Relythra

Relythra 是一个面向发布后异常排查的只读诊断系统：关联发布与代码变更、指标、日志和运行状态，组织可追溯的根因假设与处理建议。

当前仓库已完成 Issue #2 的工程骨架、Issue #3 的领域持久化契约、Issue #5 的安全数据边界、Issue #4 的数据源映射管理、Issue #7 的诊断评测案例契约、Issue #8 的部署事件接入，以及 Issue #9 的 Grafana 告警接入：Go API 与 Worker、React 健康状态页、PostgreSQL 领域与不可变审计迁移、受签名保护的部署与告警 Webhook、告警去重/Incident/Investigation 创建、人工告警重映射、部署候选查询、只读追溯 API、SecretRef、脱敏、Prompt allowlist、固定查询模板、受限连接测试、Docker Compose 和 CI。真实 Prometheus/LogQL 业务查询、Agent、完整工作台与通知能力尚未实现；本项目不是生产部署方案。

## 工具链

| 组件 | 最低版本 |
| --- | --- |
| Go | 1.26 |
| Node.js | 24 |
| PostgreSQL | 17 |
| Docker Compose | v2（含 BuildKit，仅 Compose 方式需要） |

其他依赖由 `go.mod`、`web/package-lock.json` 和容器镜像固定。

## 本地启动（不使用 Docker）

本地已启动 PostgreSQL 时，可以从仓库根目录一次启动 API、Worker 和前端开发服务器：

```bash
./scripts/dev.sh
```

脚本会检查本机依赖，按需创建 `relythra` 数据库，执行数据库迁移，安装缺失的前端依赖，并等待三个服务通过健康检查。服务地址如下：

- Web：<http://127.0.0.1:5173>
- API readiness：<http://127.0.0.1:8080/health/ready>
- API 只读领域端点：`/api/v1/reports/{id}`、`/api/v1/evidence/{id}`、`/api/v1/investigations/{id}/timeline`、`/api/v1/deployments/{id}`

`GET /api/v1/investigations/{id}/timeline` 返回该 Investigation 已持久化的 Evidence，支持 `source_type`、`entity_id`、`completeness`、`stance`、`limit` 和 `offset`。`stance=SUPPORTS` 或 `stance=CONTRADICTS` 筛选与该调查中任意假设存在对应立场关联的证据；多次关联仅返回一次，当前不支持指定假设筛选。每个时间线项的 `relations` 返回所有关联假设 ID 与立场，包括筛选条件相反的关系；无关系时为空数组。关联本身不代表根因已确定。完整度包括 `COMPLETE`、`PARTIAL`、`MISSING` 和 `EXPIRED`；Evidence 会分别保留 UTC 事件区间、来源原始时间/时区和采集时间，无法追溯的历史记录 `collected_at` 为空；新采集记录还保存经过脱敏的查询文本、参数快照与来源引用。默认 `limit=50`，最大 `100`，`offset` 最大 `10000`；按事件开始/结束时间及来源、实体、内容摘要和 ID 稳定排序，计数与当前页在同一只读数据库快照中读取。不存在的 Investigation 返回 `404`，存在但没有匹配证据时返回空 `items`。此端点不合成尚未持久化的查询失败或缺口。

时间线支持 `source_type=GRAFANA`。后端提供 `PersistGrafanaAlertEvidence`，将数据库中与调查所属事件关联的规范告警保存为不可变、脱敏的证据快照；持续触发的告警以触发时间为点事件，恢复后追加结束时间已知的区间快照，同一告警的状态快照共享独立性分组。未映射、缺来源引用或恢复时间未知时标记为 `PARTIAL`。Webhook 接收已映射且关联 Investigation 的告警时会自动采集快照；同批触发/恢复逐项追加，重复投递复用已有证据及采集时间。人工映射 FIRING 告警时同步采集，RESOLVED 只复用已有 Investigation 采集并校验归属；未映射或仅收到恢复消息且没有 Investigation 时不创建证据。快照与告警、事件、调查在同一事务提交，采集失败会回滚整批业务写入或人工映射。该流程尚不启动 Agent 或 Worker 外部查询。部署该能力前先执行迁移 `000009`；存在 `GRAFANA` 历史证据时，该迁移拒绝降级以保留数据，回滚应用可以保留扩展后的数据库约束。

- Worker metrics：<http://127.0.0.1:8081/metrics>

按 `Ctrl+C` 会停止脚本启动的全部进程。默认连接 `postgres://$USER@127.0.0.1:5432/relythra?sslmode=disable`。连接凭据也可以从绝对路径文件注入，避免把密码写进仓库或命令行：

```bash
RELYTHRA_DATABASE_URL_REF='file:/run/secrets/relythra-database-url' \
  ./scripts/dev.sh
```

`RELYTHRA_DATABASE_URL_REF` 指向包含完整 PostgreSQL DSN 的文件。直接运行 API 或迁移命令时，也可使用 `RELYTHRA_DATABASE_PASSWORD_REF` 配合 `RELYTHRA_DATABASE_HOST`、`RELYTHRA_DATABASE_PORT`、`RELYTHRA_DATABASE_NAME`、`RELYTHRA_DATABASE_USER` 和 `RELYTHRA_DATABASE_SSL_MODE`。SecretRef 只接受 `env:NAME` 或 `file:/absolute/path`。

只检查环境、准备本地数据库并查看脚本将使用的地址，不启动服务：

```bash
./scripts/dev.sh --check
```

管理 API 默认关闭。需要在本地启用时，同时提供管理 Token 和数据源 allowlist，例如：

```bash
mkdir -p secrets
chmod 700 secrets
printf '%s' 'local-only-management-token' > secrets/management_token
chmod 600 secrets/management_token

RELYTHRA_ADMIN_TOKEN_REF="file:${PWD}/secrets/management_token" \
RELYTHRA_DATASOURCE_ALLOWED_HOSTS=metrics.example.com \
RELYTHRA_DATASOURCE_ALLOWED_PORTS=443 \
  ./scripts/dev.sh
```

示例 allowlist 只用于本地配置和固定模板查询计划。实际连接测试会解析主机，并且在没有显式开启 `RELYTHRA_DATASOURCE_ALLOW_HTTP` 或 `RELYTHRA_DATASOURCE_ALLOW_PRIVATE` 时拒绝 HTTP 或私有地址。

## 使用 Compose 启动

要求 Docker daemon 已启动。先创建一个不进入 Git 的本地密码文件，再复制非敏感路径配置：

```bash
mkdir -p secrets
chmod 700 secrets
read -rsp 'PostgreSQL password: ' DB_PASSWORD
printf '%s' "$DB_PASSWORD" > secrets/postgres_password
unset DB_PASSWORD
chmod 600 secrets/postgres_password

read -rsp 'Management API token: ' ADMIN_TOKEN
printf '%s' "$ADMIN_TOKEN" > secrets/management_token
unset ADMIN_TOKEN
chmod 600 secrets/management_token

cp .env.example .env
docker compose --file deploy/compose/compose.yaml up --build
```

`.env.example` 只保存 PostgreSQL 密码文件、管理 Token 文件和演示数据源策略，不包含凭据值。Compose 把两个 Secret 只读挂载给需要的进程；API 入口再以 UID 10001 可读的权限复制到运行时目录。Compose 会等待 PostgreSQL 健康、执行迁移，再启动 API、Worker 和 Web。首次启动需要拉取镜像并安装依赖，耗时会随网络变化。

- Web：<http://localhost:3000>
- API liveness：<http://localhost:8080/health/live>
- API readiness：<http://localhost:8080/health/ready>
- API 只读领域端点：`/api/v1/reports/{id}`、`/api/v1/evidence/{id}`、`/api/v1/investigations/{id}/timeline`、`/api/v1/deployments/{id}`
- API 数据源映射：<http://localhost:8080/api/v1/data-source-mappings>
- Worker metrics：<http://localhost:8081/metrics>

所有演示端口只绑定回环地址，数据库映射到本机 `15432` 端口。停止服务：

```bash
docker compose --file deploy/compose/compose.yaml down
```

下面的命令会同时删除演示数据库卷及其数据：

```bash
docker compose --file deploy/compose/compose.yaml down --volumes
```

## 示例业务与观测环境

完整演示作为 Compose 叠加环境提供，保留上面的基础启动方式。按 [演示说明](docs/demo.md) 创建独立凭据后运行：

```bash
./scripts/demo.sh up
```

访问 orders `http://127.0.0.1:18090/orders` 与 Grafana `http://127.0.0.1:13001/d/relythra-demo`。包含 orders → inventory → 独立业务 PostgreSQL、Prometheus、Loki、Alloy、node_exporter 和 cAdvisor；观测查询使用独立只读 Token。`make demo-smoke` 在专用项目验证真实指标/日志、权限、数据库故障隔离和重启恢复。完整端口、卷、资源限制、cgroup 身份缺口及安全清理见 [docs/demo.md](docs/demo.md)。

## 数据库迁移

迁移通过独立命令执行，API 启动时不会自动修改 schema：

```bash
docker compose --file deploy/compose/compose.yaml run --rm migrate status
docker compose --file deploy/compose/compose.yaml run --rm migrate up
docker compose --file deploy/compose/compose.yaml run --rm migrate down
```

`000001_baseline.sql` 建立迁移基线，`000002_domain_model.sql` 创建核心领域表，`000003_security_audit.sql` 创建只允许追加的安全审计表，`000004_datasource_mapping_constraints.sql` 增加映射乐观锁和唯一约束，`000005_diagnosis_case_evaluation_separation.sql` 将评测真值与运行时数据隔离，`000006_deployment_event_ingestion.sql` 增加部署状态版本/来源一致性、不可变变更历史和短期签名重放登记，`000007_grafana_alert_ingestion.sql` 增加告警指纹版本、Alert-Incident 关联、投递历史和重映射版本。迁移共同提供 UUID 主键、UTC 时间、幂等唯一约束、外键、索引、状态机和历史保护。

`down` 会回滚一个版本，执行前应确认影响。领域迁移的 `down` 会删除领域表和其中的数据，只允许用于隔离的本地或测试环境。API 启动不会自动迁移。

三个领域端点只读，并返回统一请求 ID 和错误包络。数据库为空或资源不存在时返回 `404`，路径 ID 非法时在查询数据库前返回 `400`。当前没有创建这些资源的公开写接口。

## 数据源映射管理 API

管理 API 使用单个 Bearer Token，必须在启动时同时配置：

- `RELYTHRA_ADMIN_TOKEN_REF`：只接受 `env:NAME` 或 `file:/absolute/path`。
- `RELYTHRA_DATASOURCE_ALLOWED_HOSTS`：逗号分隔的精确主机 allowlist。
- `RELYTHRA_DATASOURCE_ALLOWED_PORTS`：逗号分隔的端口 allowlist。
- `RELYTHRA_DATASOURCE_ALLOW_HTTP`：显式允许明文 HTTP，默认 `false`。
- `RELYTHRA_DATASOURCE_ALLOW_PRIVATE`：显式允许私有 DNS 地址，默认 `false`。

Token 或 allowlist 缺失时管理路由返回 `503 management_unavailable`。该 Token 是可信内网的单管理员能力，不是 RBAC、SSO 或多租户授权；演示端口只绑定回环地址，不能据此公网部署。

管理端点：

| 方法与路径 | 行为 |
| --- | --- |
| `GET /api/v1/data-source-mappings` | 游标分页列出活动映射，可按 Project、Service 和 Environment 过滤 |
| `POST /api/v1/data-source-mappings` | 创建映射；不完整 Compose 标签或模板可作为草稿保存 |
| `GET /api/v1/data-source-mappings/{id}` | 读取映射，只返回 Secret 配置状态 |
| `PUT /api/v1/data-source-mappings/{id}` | 使用 `expected_version` 乐观更新 |
| `DELETE /api/v1/data-source-mappings/{id}?expected_version=N` | 软删除映射 |
| `POST /api/v1/data-source-mappings/{id}/validate` | 返回结构化配置问题 |
| `POST /api/v1/data-source-mappings/{id}/queries` | 解析固定模板并返回有界查询计划 |
| `POST /api/v1/data-source-mappings/{id}/connection-test` | 执行固定路径、只读连接测试 |

创建 Prometheus 映射示例：

```bash
curl --fail \
  --header "Authorization: Bearer $(cat secrets/management_token)" \
  --header 'Content-Type: application/json' \
  --data '{
    "project_id": "10000000-0000-4000-8000-000000000001",
    "service_id": "10000000-0000-4000-8000-000000000002",
    "environment": "prod",
    "source_type": "PROMETHEUS",
    "public_settings": {"endpoint": "https://metrics.example.com"},
    "template_ids": ["prometheus.service.latency.v1"],
    "secret_ref": "env:PROMETHEUS_READ_TOKEN"
  }' \
  http://127.0.0.1:8080/api/v1/data-source-mappings
```

API 不接受原始 PromQL、LogQL、SQL、shell、任意 Header 或任意 HTTP method。连接测试使用固定路径：GitHub `/repos/{owner}/{repo}`、Grafana `/api/health`、Prometheus `/api/v1/status/buildinfo`、Loki `/loki/api/v1/status/buildinfo` 和 Compose 运行时 `/-/ready`。Kubernetes 映射可以保存，但 v1 校验和连接测试返回 `unsupported_runtime`。

主要错误语义：

- `401 unauthorized`：Bearer Token 缺失或错误。
- `503 management_unavailable`：管理 Token 或 allowlist 未配置，或连接测试依赖不可用。
- `422 validation_failed` / `invalid_request`：字段、模板、时间窗、标签或请求体无效。
- `409 stale_version`：映射已被其他请求更新或删除。
- `422 policy_rejected`：协议、主机、端口、DNS/IP 或重定向策略拒绝。
- `504 connection_timeout`、`502 network_error` / `tls_error` / `remote_unavailable` / `invalid_response`：连接测试失败类别。

所有管理拒绝和操作都写入不可变审计。审计只记录来源类型、模板 ID、错误码、耗时和对象 ID，不记录 Endpoint、SecretRef、Authorization 或响应正文。CRUD 数据库写与最终审计写不在同一事务中；若数据写已提交而审计写失败，API 返回 `internal_error`，部署方需通过请求 ID 和数据库记录核查。

## DeploymentEvent 接入

部署回调使用独立的 `RELYTHRA_DEPLOYMENT_WEBHOOK_SECRET_REF` 和 `RELYTHRA_DEPLOYMENT_WEBHOOK_SOURCE`，签名头为 `X-Relythra-Timestamp` 与 `X-Relythra-Signature`。签名采用 HMAC-SHA256，覆盖 Unix 秒时间戳和原始 JSON body；服务端只接受与当前时间相差不超过 5 分钟的签名。同一签名只接受一次，数据库仅暂存其 SHA-256 摘要至签名过期；部署来源 ID 的事件幂等仍允许 CI 对同一部署使用新时间戳重签重试。

| 方法与路径 | 行为 |
| --- | --- |
| `POST /api/v1/deployment-events/webhook` | 验证签名与来源后接收 CI/CD 事件；重复签名返回 `409 replayed_signature` |
| `POST /api/v1/deployment-events` | 使用管理 Bearer Token 人工登记部署事实 |
| `PATCH /api/v1/deployment-events/{id}` | 使用期望版本和修正理由登记人工修正，并追加变更历史 |
| `GET /api/v1/deployment-events/candidates` | 在限定时间窗内返回全部匹配部署候选，不会含糊选择“最近一次” |

人工路由使用已配置的单管理员 Token；management actor 是受信任配置标识，不构成多用户身份认证。部署来源回调不会触发部署、回滚或其他运维写操作。Webhook SecretRef 必须由 API 进程通过 `env:NAME` 或 `file:/absolute/path` 读取；不得写入 `.env`、请求体或日志。完整签名、状态转移、审计和回滚边界见 [Issue #8 实施计划](docs/plans/issue-8-deployment-events.md) 与 [ADR 0007](docs/adr/0007-deployment-event-ingestion.md)。

## Grafana 告警接入

配置专用 `RELYTHRA_GRAFANA_WEBHOOK_SECRET_REF` 后，Grafana 通用 Webhook contact point 向 `POST /api/v1/alerts/grafana` 发送 JSON，并附带 `X-Relythra-Timestamp`、`X-Relythra-Signature` 两个由发送端按 HMAC-SHA256 规则生成的 Header。签名覆盖 Unix 秒时间戳和原始 body，验证窗口为 ±5 分钟；重复签名、超大 body、非法 schema 均在业务写入前拒绝。Webhook 支持最多 100 条 alert，标签、annotation、`values` 数量与字段长度均有限制。告警时间统一按 UTC 比较，同时保留来源 RFC3339 时间文本和时区偏移。

告警通过 `project`、`service`、`env` 标签精确匹配 Project slug、Service slug 和环境。缺少/不匹配 Service 或环境时会记录待映射 Alert/Incident，不猜测服务、不创建 Investigation，也不启动 Agent。缺少有效 Project slug 时返回 `422 needs_mapping`，不写入业务对象。缺失 fingerprint 时使用排序标签和告警开始时间派生版本化 SHA-256 指纹。

已映射并关联 Investigation 的每条输入会在事务内追加 Grafana Evidence 快照，时间线可立即读取；同一批次的 FIRING → RESOLVED 保留两个状态。相同快照重复投递不会新增 Evidence。采集失败时整批业务写入回滚；签名领取仍是独立事务，重试必须生成新的有效签名。已有 Investigation 与新映射冲突时拒绝并回滚，避免移动历史证据。

相同 fingerprint 在 ±5 分钟窗口中复用 Alert、Incident 和 Investigation；每次接收仍会保留一条经过脱敏的 `alert_deliveries`。resolved 通知更新既有 Alert/Incident，不重新开启诊断。人工映射使用 `POST /api/v1/alerts/{id}/remap`，必须提供 `expected_version`、`service_id` 和 `environment`，并写入管理审计。服务名只接受精确 slug，不能按展示名模糊推断。更详细的边界见 [Issue #9 实施计划](docs/plans/issue-9-grafana-webhook.md) 与 [ADR 0008](docs/adr/0008-grafana-alert-ingestion.md)。

## 本地检查

安装依赖并运行与 CI 相同的检查：

```bash
make web-install
make fmt-check vet test build web-check
```

也可以分别使用 `make fmt`、`make test`、`make build` 和 `make web-check`。前端开发服务器通过以下命令启动，默认监听 Vite 输出中的地址，并将 `/health` 代理到本机 `8080`：

```bash
npm --prefix web run dev
```

前端开发页需要可访问的 API；直接运行 Go API 时，必须通过 `RELYTHRA_DATABASE_URL`、`RELYTHRA_DATABASE_URL_REF` 或 `RELYTHRA_DATABASE_PASSWORD_REF` 提供 PostgreSQL 连接配置。不要把包含真实凭据的连接串写入仓库。

`make test` 在没有测试数据库时会跳过真实 PostgreSQL 用例。需要验证迁移和事务仓储时，显式提供隔离测试库：

```bash
RELYTHRA_TEST_DATABASE_URL='postgres://user@127.0.0.1:5432/relythra?sslmode=disable' \
  go test ./internal/store ./internal/security/audit ./migrations -count=1
```

## 完整冒烟

冒烟使用独立 Compose 项目与端口 `18080`、`18081`、`13000`、`15432`，会构建镜像、从空卷迁移、重复执行迁移，并检查领域表、索引、幂等约束、非法状态回滚、数据源映射版本与软删除、SecretRef、管理认证、固定模板计划、审计脱敏、报告关联、只读 API、Worker 和 Web：

```bash
RELYTHRA_POSTGRES_PASSWORD_FILE=/absolute/path/to/local-password ./scripts/smoke.sh
```

脚本退出时自动删除其容器和数据库卷。CI 兼容入口 `RELYTHRA_POSTGRES_PASSWORD=ci-only-not-secret ./scripts/smoke.sh` 会创建临时只读密码文件和管理 Token 文件，并在退出时删除。若已有服务占用上述端口，可通过 `RELYTHRA_API_PORT`、`RELYTHRA_WORKER_PORT`、`RELYTHRA_WEB_PORT` 和 `RELYTHRA_POSTGRES_PORT` 覆盖。

仅校验 Compose 渲染结果时运行：

```bash
RELYTHRA_POSTGRES_PASSWORD_FILE=/absolute/path/to/local-password \
  RELYTHRA_MANAGEMENT_TOKEN_FILE=/absolute/path/to/local-management-token \
  docker compose --file deploy/compose/compose.yaml config --quiet
```

## 故障排查

- Web 显示 `API is not ready`：检查 API 容器日志与 PostgreSQL 健康状态。readiness 失败时 liveness 仍应成功。
- 迁移失败：查看一次性 `migrate` 容器日志；依赖未满足时 API 不会启动。
- 端口冲突：在 `.env` 中修改对应的 `RELYTHRA_*_PORT`。
- 依赖或镜像下载失败：先恢复网络，再重新执行相同命令；缓存不是构建成功的必要条件。

## 仓库边界

- `cmd/`：API、Worker 和迁移进程入口。
- `internal/`：Go 领域模型、事务仓储、HTTP 契约、配置、健康检查与 Worker 能力。
- `web/`：React/TypeScript 工作台与前端测试。
- `migrations/`：嵌入式、版本化 PostgreSQL 迁移。
- `deploy/`：Compose 和镜像构建配置。
- `test/fixtures/`：后续跨服务测试夹具及其说明。
- `docs/adr/`：架构决策，见 [ADR 0001](docs/adr/0001-repository-baseline.md)、[ADR 0002](docs/adr/0002-domain-persistence.md)、[ADR 0003](docs/adr/0003-security-data-boundary.md)、[ADR 0004](docs/adr/0004-datasource-mapping-boundary.md) 和 [ADR 0007](docs/adr/0007-deployment-event-ingestion.md)。
- `docs/security/`：威胁模型、控制与剩余风险，见 [安全威胁模型](docs/security/threat-model.md)。
- `scripts/smoke.sh`：真实服务端到端冒烟；领域夹具与断言位于 `scripts/smoke_domain.sql`。

## 配置与数据边界

`.env.example` 只包含本地端口、未跟踪 Secret 文件路径和演示 allowlist，`.env`、`secrets/` 被 Git 忽略。数据库、管理 API 和后续连接器通过 SecretRef 或 Secret 文件注入；不得提交真实密码、Token、私钥或含凭据的连接串。日志、API、审计和模型 Prompt 使用统一脱敏，无法安全处理时拒绝外发。

凭据轮换时先撤销旧值，再替换 Secret 文件或环境变量并重启使用它的进程；仅替换文件但保留旧凭据有效不构成完成处置。安全问题请按 [SECURITY.md](SECURITY.md) 的私密流程报告。

诊断系统不自动回滚、重启或扩容。当前已实现单管理员 Token、部署与 Grafana Webhook 签名/重放防护、数据源 allowlist、DNS/IP 锁定、零重定向和固定路径连接测试；尚未实现多租户 RBAC、真实 Prometheus/LogQL 业务查询、Kubernetes 诊断、通知、模型调用和公网访问控制。生产数据库角色隔离、通用数据保留期和外部审计留存仍需后续设计。健康检查只反映进程与数据库连通性，不代表业务诊断已经可用。
