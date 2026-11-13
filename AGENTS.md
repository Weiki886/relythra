# Relythra 仓库开发规范

本文件适用于整个仓库，是开发、评审、CI 和仓库操作的项目级契约。更靠近目标文件的 `AGENTS.md` 可以补充或覆盖本文件；用户在当前任务中的明确要求优先。若规范之间冲突，以能同时满足安全、可验证性和仓库现状的最严格规则为准。

## 1. 项目边界

Relythra 面向发布后异常排查，关联发布、代码变更、指标、日志和运行状态，生成可追溯、带证据与置信度的根因假设。

- 系统以只读诊断为主。不得自动执行回滚、重启、扩容、配置修改或其他外部写操作。
- Agent 输出是根因假设，不是未经证据支持的绝对结论。无法证明时必须显式返回证据不足或 `inconclusive`。
- 证据必须能回到原始来源核验；区分事实、推断、反证和未知项。
- 当前仓库处于 `M1 契约与夹具` 阶段，已有 Go/React/PostgreSQL/Compose 骨架、数据源映射管理、固定查询计划、固定路径连接测试和可选 Compose 示例业务/观测拓扑；真实 Prometheus/LogQL 业务查询、Agent、完整工作台和通知能力尚未实现。文档和 PR 不得把规划能力写成已交付能力。
- 仓库是公开仓库。Issue、PR、Commit、测试夹具、日志、截图和 AI Prompt 都按公开数据处理。

产品范围和阶段目标以 Issue #1 的 Proposal、Milestone 和对应 Issue 为准；已接受的技术边界记录在 `docs/adr/`。

## 2. 开始工作前

1. 检查工作区与分支：`git status --short --branch`。不得覆盖、回退或顺手整理用户及其他协作者尚未提交的改动。
2. 读取与任务相关的 Issue、Milestone、ADR、README、目标目录中的 `AGENTS.md` 和现有测试。
3. 从最新 `origin/main` 创建短生命周期分支。不要直接在 `main` 提交或推送。
4. 代码发现优先使用可用的 codebase-memory MCP 图工具；不可用时使用 `rg` 和精确文件读取。禁止无目标地扫描依赖目录、构建产物或整个工作区。
5. 确认需求、非目标、验收标准、风险、兼容性和回滚方式。关键选择未决时先通过 Issue 解决，不带着 `status:needs-info` 开始实现。

对于多文件、跨模块、数据模型、接口契约或高风险变更，先写出可执行的实现计划。计划必须包含受影响文件、验证方式和回滚点；不得使用“适当处理”“补一下测试”等占位描述。

## 3. 开发原则

- 一次变更只解决一个明确问题，保持 diff 小而可独立回滚。
- 优先使用现有实现、标准库、已安装依赖和仓库已有模式；新增抽象、依赖或基础设施必须有当前需求支撑。
- 行为变更按 maintained code 处理：先写能失败的测试，再写最小实现，最后重构。
- 缺陷必须先复现并定位根因。修复共享层根因，不在多个调用方叠加症状补丁。
- 文档、配置和纯机械改动可以不先写失败测试，但必须有可复查的静态检查、配置渲染或实际运行证据。
- 不提交调试输出、注释掉的代码、临时文件、生成缓存或与 Issue 无关的格式化噪音。
- 禁止使用 `--no-verify`、跳过 lint/test/typecheck 或通过无依据的忽略标记掩盖问题。
- 没有本轮实际执行的验证证据，不得声称“完成”“通过”或“可以合并”。

## 4. 当前架构与目录职责

| 路径 | 职责与约束 |
| --- | --- |
| `cmd/` | API、Worker 和迁移进程入口；入口只负责配置、装配、启动和优雅关闭。 |
| `internal/` | Go 共享业务与基础设施代码；单元测试与实现放在同一包。 |
| `web/` | React、TypeScript、Vite 工作台；TypeScript 保持 `strict`。 |
| `migrations/` | 嵌入式、版本化 goose 迁移；API 启动时不得自动迁移。 |
| `deploy/compose/` | 本地演示拓扑；演示端口默认只绑定回环地址。 |
| `deploy/docker/` | 容器镜像构建定义；构建上下文不得包含凭据或依赖产物。 |
| `test/fixtures/` | 跨服务测试夹具；不得放入真实账号、Token、用户日志或评测答案泄漏。 |
| `docs/adr/` | 已接受架构决策；改变模块边界、迁移所有权、进程拓扑或工具链基线时新增 ADR。 |
| `scripts/` | 本地启动与端到端验证入口；脚本必须可重复、失败可定位并清理资源。 |

关键运行约束：

- API 的 liveness 只表示进程存活，不访问数据库；readiness 才检查 PostgreSQL 等必要依赖。
- API 与 Worker 是独立生命周期，各自支持信号触发的优雅关闭。
- Worker 暴露的 Prometheus 指标必须保持可解析、稳定命名，并能被冒烟或监控验证。
- PostgreSQL 迁移由独立命令执行。Compose 按数据库健康、迁移成功、API 健康的顺序启动。
- 面向浏览器的错误响应不得泄露连接串、内部地址、堆栈或凭据；详细错误写入脱敏后的服务端日志。
- 前端通过严格类型、ESLint、Vitest 和生产构建验证；不得用 `any`、禁用 Hook 规则或关闭类型检查来绕过问题。

## 5. 外部数据与只读安全

连接 GitHub、Grafana、Prometheus、Loki、容器和机器状态时，必须遵守以下规则：

- 所有连接器默认只读，使用最小权限凭据；禁止通过连接器触发回滚、部署、重启、扩容或配置写入。
- 当前只实现固定路径、固定响应上限的连接测试；真实业务查询必须复用同一出站策略、模板注册表和 Evidence 边界，未实现前不得由 API 接受任意查询文本。
- 外部请求必须有超时、重试上限、结果大小/分页上限和明确的失败降级，不进行无界查询。
- 数据源地址必须经过配置与白名单校验，防止 SSRF；不得允许用户直接提交任意 URL 或任意 PromQL/LogQL 执行入口。
- Webhook 必须校验来源、大小、格式和重复投递；错误信息保持稳定且不泄露内部实现。
- 告警标签、日志正文、Commit/PR 内容和远端响应都视为不可信输入。
- Prompt 中不得包含评测预期答案、故障注入元数据、密钥或无关个人信息；工具调用必须走注册表并校验 Evidence ID。
- 日志、异常、审计记录和前端展示都要脱敏。不得记录完整 Token、密码、私钥、Cookie 或含凭据的连接串。
- 新增写能力、外部副作用或生产权限必须单独立项，完成威胁建模、ADR、人工安全评审和回滚设计。

## 6. 配置、迁移与依赖

### 配置

- 运行时配置通过环境变量注入，默认值必须适合本地开发，且不得包含真实凭据。
- `.env.example` 只能放占位值；`.env` 仅用于本地并保持被 Git 和 Docker 忽略。
- 新配置需要同步更新 README、Compose、CI、测试和错误提示。

### PostgreSQL

- 新 schema 变更使用递增编号的 goose migration，并同时提供可执行的 `Up` 与 `Down`。
- 已合入或已应用的迁移视为不可变；修正问题应新增迁移。
- 迁移必须可从空库执行，重复 `up` 应为成功空操作；破坏性操作必须明确数据影响和回滚方式。
- API 启动不得隐式修改 schema。执行 `down`、删除卷或删除数据前必须有明确授权。

### 依赖与工具链

- Go 依赖由 `go.mod`/`go.sum` 固定；前端依赖由 `package-lock.json` 固定，使用 `npm ci` 安装。
- 不进行与 Issue 无关的批量依赖升级。新增依赖需说明标准库或现有依赖为何不足、维护状态和安全影响。
- GitHub Actions 第三方 Action 固定完整提交 SHA，并遵循最小 `permissions`。
- 工具链最低版本以 README 和 ADR 为准：Go 1.26、Node.js 24、PostgreSQL 17、Docker Compose v2。

## 7. GitHub 交付流程

采用团队、多迭代交付模式。标准链路为：

`Proposal → ADR（需要时）→ Milestone → Issue → 分支 → Commit → PR → Review/CI → Merge → 删除合并分支 → Release`

### Issue

非机械性的新增、修复、重构、测试和基础设施变更必须先有关联 Issue。Issue 标题和说明正文必须使用中文，并至少包含：

- 背景、目标、非目标和明确的范围边界。
- 可验证的验收标准与验证计划。
- 风险级别、兼容性和回滚方式。
- 关联 Proposal、ADR、依赖 Issue 和适用 Milestone。

风险标签使用仓库现有标签：

- `low`：文档、测试或不改变运行行为的可逆机械性改动。
- `standard`：边界清晰、可独立回滚的一般功能或缺陷修复。
- `high`：涉及凭据、安全、数据迁移、公开 API、基础设施、供应链或较大影响面。

每个 Issue/PR 必须同时满足以下标签要求：

- 至少一个 `type:*` 标签、恰好一个风险标签（`low`、`standard`、`high`）和至少一个与实际改动有关的 `area:*` 标签。
- 复用现有标签，不使用近义标签重复表达同一含义。当前类型包括 `type:feature`、`type:fix`、`type:test`、`type:infra`、`type:docs`、`type:proposal`；范围包括 backend、frontend、data、connector、agent、infra、security、qa、docs、workflow。其中 `type:fix` 用于缺陷修复，`area:workflow` 用于仓库协作与交付流程。
- 新的工作类别或影响范围确实无法由现有标签表达时，可以创建有明确用途的标签。标签名使用稳定的英文标识，描述使用中文；不得为凑数量添加不相关标签。
- 正文中列出的标签、风险级别及其依据必须与 GitHub 实际标签一致。PR 按本次实际变更评估风险；若与关联 Issue 不同，在 PR 正文解释范围差异与分级依据，不机械降低风险。
- 需要用户或维护者决策时添加 `status:needs-info`。

### 分支与 Commit

- 分支名使用英文：`<type>/<issue>-<slug>`，例如 `feat/42-alert-ingestion`、`docs/31-agents-guide`。
- 允许的常用 type：`feat`、`fix`、`docs`、`test`、`refactor`、`build`、`ci`、`chore`。
- 从最新 `origin/main` 创建；长任务定期同步 `main`，避免把无关历史带入 PR。
- Commit 使用 Conventional Commits，标题使用英文：`<type>(<scope>): <summary>`。正文可使用中文。
- 每个 Commit 表达一个完整意图并保持可构建。提交前检查暂存范围，避免 `git add -A` 带入无关文件。
- 不重写已共享分支历史；确需 force-push 时先确认没有协作者依赖，且不得 force-push `main`。

### Pull Request

PR 标题必须使用英文，说明正文必须使用中文。Issue/PR 中的产品名称、技术术语、代码标识、文件路径、代码块、命令、原始输出及 GitHub 关联关键字（如 `Closes`、`Refs`）可以保留原文；章节标题、问题说明和验收描述使用中文。分支名和 Commit 标题继续使用英文。

PR 必须：

- 明确本次交付的范围与关联 Issue。满足该 Issue 全部验收标准时使用 `Closes #<issue>`；部分交付使用 `Refs #<issue>`，写明本次完成项与剩余验收范围，保留 Issue 开放。不得用关闭关键字提前关闭未完成的 Issue。
- 说明问题、关键改动、范围与风险、兼容性、验证证据、部署影响和回滚方式。
- 链接或说明需要 Reviewer 重点检查的边界与未覆盖项。
- 沿用关联 Issue 的适用里程碑，并按实际范围设置类型、风险和范围标签。跨里程碑的仓库维护任务可以不设置里程碑，但需写明原因。
- 保持小而可审；出现无关改动时先拆分。
- 创建或修改 Issue/PR 后、最终交付前，回读 GitHub 远端的标题、正文、标签、里程碑和关联关系，核对语言、标签完整性、正文与风险的一致性，以及 `Closes`/`Refs` 的使用。批量修正历史内容时保留修改前清单，不改变验收事实、未完成项或合并状态。

合并门禁：

- PR 基于最新 `main`，且 `Backend`、`Frontend`、`Compose smoke` 三项严格必需检查全部通过。
- 本地验证与远程 CI 分开表述；本地通过不能代替远程结果。
- 至少一名合适的人类 Reviewer 完成评审，所有 `blocking` 意见关闭。AI Review 只作补充，不能冒充人工 Review。
- 不因等待或时间压力降低测试、安全或人工评审门禁。
- Agent 只有收到用户明确指令后才能合并 PR、创建 Tag/Release、关闭 Milestone 或执行其他不可逆仓库操作。
- PR 合并后必须立即删除对应的来源分支，避免远端和本地积累已失效的短生命周期分支。
- 当前阶段只保留 `main`。已合并 PR 的 `feat/*`、`fix/*`、`docs/*`、`test/*`、`refactor/*`、`build/*`、`ci/*` 和 `chore/*` 分支均不保留；在发布分支策略正式确定前，不创建 `release/*`、`develop` 或其他长期维护分支。
- 优先启用 GitHub 的 `Automatically delete head branches`。若远端分支仍然存在，合并负责人在确认合并提交已进入 `main` 后执行 `git push origin --delete <branch>`。
- 切回并更新 `main` 后，使用 `git branch -d <branch>` 删除本地分支；不得使用 `-D` 跳过“已合并”检查。
- 只有分支仍被其他未合并 PR 引用、受保护规则阻止删除或审计要求保留时，才可暂缓清理；PR 必须记录原因、清理责任人和期限。
- `main`、发布 Tag 和明确声明的长期维护分支不属于删除范围；不得移动已发布 Tag。

## 8. Definition of Ready 与 Definition of Done

开始实现前应满足 Ready：

- 有可执行 Issue、明确验收标准和范围外事项。
- 关键产品/架构选择已决，不存在阻塞实现的 `status:needs-info`。
- 风险、依赖、测试路径和回滚方式已明确。
- 所需外部凭据、环境和权限可安全获得。

关闭 Issue/PR 前应满足 Done：

- 验收标准逐项满足，行为变更具备有效测试。
- 本地适用检查通过，远程必需 CI 在最终 HEAD 上通过。
- 文档、配置、迁移、Compose 和工具链影响已同步。
- 没有真实凭据、敏感数据、调试残留或无关 diff。
- PR 已记录实际命令、结果和未覆盖项；人工 Review 已完成。
- PR 合并后，来源分支已从远端和本地删除；存在记录在案的例外时除外。
- 关联 Issue、Milestone 和标签状态准确，回滚或后续风险有明确入口。

## 9. 测试与验证

本地启动 API、Worker 和 Web（宿主机 PostgreSQL 已启动）：

```bash
./scripts/dev.sh --check
./scripts/dev.sh
```

常用验证命令：

```bash
make fmt-check vet test build
make web-install
make web-check
RELYTHRA_POSTGRES_PASSWORD_FILE=/absolute/path/to/local-password make compose-config
RELYTHRA_POSTGRES_PASSWORD_FILE=/absolute/path/to/local-password make check
RELYTHRA_POSTGRES_PASSWORD=ci-only-not-secret make smoke
```

验证分层：

- 快速层：`gofmt`、`go vet`、Go 单元测试、ESLint、TypeScript、Vitest 和生产构建。
- 集成层：PostgreSQL 连接、迁移、健康检查、连接器解析与失败降级。
- 端到端层：`make smoke` 使用独立 Compose 项目、端口和数据卷，验证迁移、服务健康、数据库故障语义及 Web/API 连通性；不得指向生产或共享环境。
- 数据源管理层：单元测试覆盖管理 Token、CRUD、固定模板、SecretRef 脱敏、审计和出站策略；`make smoke` 额外验证管理 API 的未认证拒绝、映射创建与查询计划、版本冲突、审计对象 ID 和运行时草稿。
- 安全层：凭据泄漏、SSRF、Webhook、只读权限、Prompt 数据隔离和深链授权按高风险变更专项验证。

补充规则：

- 新行为至少有一个能在实现被破坏时失败的测试；测试断言业务结果，不复制实现细节。
- Bug fix 应包含回归测试；难以自动化时记录复现步骤、失败证据和人工验证结果。
- 外部依赖测试使用固定夹具或受控 fake，不依赖公网波动、真实账号或当前时间。
- flaky test 视为缺陷，不通过重跑掩盖。
- 示例观测环境见 `docs/demo.md`，`make demo-smoke` 使用独立随机项目、Secret 与卷验证真实调用链、Prometheus/Loki/Grafana、只读权限和演示数据库故障隔离。无 Docker 入口继续保留。cAdvisor 无 Socket，仅有 raw cgroup 指标，不能声称已验证 Docker 身份、退出/OOM 事件或 Kubernetes。
- `make smoke` 会创建并删除专用容器、网络和数据库卷；执行前确认没有使用生产配置或共享数据。

## 10. Review 规范

评审前固定 base 和 head，使用 `git diff <base>...HEAD`、提交列表和未跟踪文件确认完整范围。评审同时检查：

- 规范符合度：仓库契约、正确性、边界、安全、可维护性、测试和可部署性。
- 需求符合度：需求缺失、需求多做或实现方式与验收标准不符。

意见必须包含严重度、位置、依据和下一步行动：

- `blocking`：正确性、安全、需求缺失、兼容性或回滚问题，修复后才能合并。
- `question`：信息不足，回答后重新定级。
- `nit`：局部可读性或命名建议，非阻塞。
- `fyi`：背景或后续改进，可转 Issue。

只有 `blocking` 阻塞合并。作者必须对意见明确回复“已改 / 延后 / 不改”及证据；不得因社交压力接受无依据意见。处理 `blocking` 后复查新增 delta、受影响调用点和测试。作者不得批准自己的 PR。

## 11. Agent 仓库操作底线

- 始终先检查 `git status`、当前分支、远端基线和相关 Issue。
- 只在授权范围内编辑；不擅自提交用户改动，不切换分支丢弃工作，不重置、清理或覆盖他人文件。
- 不直接修改 `main`，不自行合并、发布、创建 Release、关闭 Issue/Milestone 或修改仓库权限。
- 获得明确合并授权后，同时完成对应来源分支清理；当前阶段不保留已合并 PR 的来源分支。不得删除 `main`、Tag 或其他未合并分支。
- 删除数据卷、执行数据库 `down`、force-push、重写历史或触发外部写操作前，必须得到用户明确授权。
- 遇到失败先复现、读取完整错误并定位根因；不通过反复重跑或关闭检查制造“通过”。
- 完成时报告：改动文件、关联 Issue/PR、实际执行命令与结果、风险级别、远程 CI 状态、未验证项和下一项最小动作。
- 远程 CI、人工 Review、部署和发布状态必须分别取证，不得相互推断。

工具链、目录边界、交付门禁或安全策略发生变化时，同步更新本文件及对应 README/ADR，并在 PR 中说明变更理由。
