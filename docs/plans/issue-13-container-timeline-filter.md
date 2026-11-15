# Issue #13：按容器身份筛选运行时 Evidence 时间线

## 目标与边界

允许工作台按原始 container ID 读取该容器对应的运行时 Evidence，避免容器替换后必须下载并扫描 Investigation 的完整时间线。该筛选匹配 `value_summary.measurements` 中 `entity_type=CONTAINER` 且 `entity_id` 精确相等的记录；既有顶层 `entity_id` 筛选语义保持不变。

本切片只扩展现有只读时间线查询参数，不新增 Evidence 字段、迁移、查询语言、外部访问或健康/根因推断。容器 ID 作为不透明的精确标识处理，最多 256 字节；超长、空白包边和重复参数按无效请求拒绝。

## 实现步骤

1. 扩展 API 与 store 时间线过滤契约，新增 `container_id` 参数及长度/格式校验。
2. 使用参数化 JSONB containment 条件匹配嵌套容器 measurement；查询仍受 Investigation ID、既有分页上限和只读事务约束。
3. 在 API 测试覆盖解析、重复与超长参数拒绝；在 PostgreSQL 集成测试中验证替换前后的容器 ID 各自只返回自己的时间区间。
4. 执行定向测试、仓库 Backend 检查、密钥扫描和 diff 检查；最终依赖 PR CI 实际执行 PostgreSQL 集成测试。

## 风险与回滚

风险 `high`：时间线是面向客户端的查询 API，筛选错配会隐藏或串联错误证据。过滤器只读取现有 Evidence JSON、使用绑定参数精确匹配，不改变存储和返回结构。回滚为 revert 本 PR，无 schema 或数据回滚。

## 验收

- `GET /api/v1/investigations/{id}/timeline?container_id=<id>` 只返回包含该 container ID 的容器运行时 Evidence。
- 容器替换前后的不同 ID 分别返回其自身观测时间段，不互相混入。
- 顶层 `entity_id` 可继续独立使用；既有 Source、completeness、stance 与分页过滤可组合。
- 空白、重复和超过 256 字节的 `container_id` 被 API 拒绝，store 也拒绝超长输入。
- 未匹配容器返回空结果；不推断容器是否健康、是否已退出或根因。

## 执行记录

- 先写 API 与 PostgreSQL 集成回归用例；实现前测试因过滤器字段尚不存在而编译失败。
- 定向 API/store 测试在本地通过；PostgreSQL 集成用例因本机未配置 `RELYTHRA_TEST_DATABASE_URL` 跳过，须由最终 PR Backend CI 验证。
