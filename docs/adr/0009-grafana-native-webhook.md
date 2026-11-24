# ADR 0009 Grafana 原生签名与本地告警来源链接

- 状态为 Proposed，待 PR 人工评审
- 日期为 2026-11-24
- 关联 Issue #95、Issue #16、ADR 0008

## 背景

Grafana 13.3 原生 Webhook 使用 `timestamp:body` 计算 HMAC-SHA256，签名 Header 为十六进制摘要。已有接收端使用 `timestamp.body` 和 `sha256=` 前缀。Grafana 默认 envelope 还包含 `title`、`message`、`state`。本地 HTTP Grafana 会生成 HTTP 来源链接，ADR 0008 的 HTTPS 限制会拒绝该载荷。

## 决策

接收端兼容两种 HMAC 消息格式，复用独立密钥、常量时间比较、五分钟时间窗与数据库签名重放登记。可选前缀归一化后，对解码的 MAC 计算重放键，避免同一签名用不同大小写或前缀重复投递。部署 Webhook 保持其已有格式。

严格 JSON 解码中显式加入默认 envelope 的 title/message/state/appVersion 以及逐条 alert 的 ruleUID/orgId。title/message 最大各 4096 字节，state 最大 32 字节，appVersion/ruleUID 最大各 128 字节。其他未知字段继续拒绝，总 body 上限保持 1 MiB。

来源链接继续要求无凭据 HTTPS URL，额外允许主机名严格为 `127.0.0.1` 或 `::1` 的 HTTP URL。本地演示的 Grafana root URL 配置为实际回环端口。这些链接作为原始来源引用持久化，接收端不会发起请求。这个例外仅作用于告警来源字段，出站连接器继续遵循独立地址策略。

演示环境通过独立随机 Secret 文件向 API 与 Grafana 提供共享 HMAC 密钥。Grafana bootstrap 读取文件，导出供 provisioning 使用的变量，随后降低进程用户权限。失败产物沿用临时凭据目录的精确值脱敏。

## 验证与回滚

单元测试覆盖原生与历史签名、篡改、错误密钥、时钟边界、重放，以及默认 envelope 和来源 URL 边界。隔离 Compose smoke 触发 target-down，验证 FIRING 与 RESOLVED、同一 Investigation 的 Grafana Evidence 和公开读取链接。

回滚本次代码、overlay 与 provisioning 文件即可，数据库 schema 没有变化。已有演示 `.env` 必须补充 `DEMO_GRAFANA_WEBHOOK_SECRET_FILE`。从 overlay 移除 contact point 文件后，已有 Grafana 卷内的配置可能继续保留，需要管理员按 Grafana 配置管理流程处理。
