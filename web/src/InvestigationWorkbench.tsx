import { Suspense, lazy, useRef, useState } from "react";
import {
  completenessStates,
  parseDiagnosis,
  parseEvidence,
  parseInvestigationContext,
  parseTimeline,
  safeSourceURL,
  sources,
  parseMetricTrend,
} from "./investigation";
import type { Evidence } from "./investigation";
import { useReadResource } from "./useReadResource";

const MetricTrend = lazy(() => import("./MetricTrend"));

const metricTemplates = new Set([
  "prometheus.service.latency.v1",
  "prometheus.service.error_ratio.v1",
  "prometheus.service.request_rate.v1",
  "prometheus.container.memory.v1",
  "prometheus.container.cpu.v1",
  "prometheus.database.query_latency.v1",
  "prometheus.node.capacity.v1",
]);

function Failure({
  status,
  name,
  retry,
}: {
  status: number;
  name: string;
  retry: () => void;
}) {
  return (
    <div className="failure" role="alert">
      <p>
        {status === 404
          ? name === "证据"
            ? "证据不存在或已不可用，请重新选择。"
            : "调查不存在或已不可用，请检查 ID。"
          : `${name}加载失败，请重试。`}
      </p>
      <button onClick={retry}>重试{name}</button>
    </div>
  );
}

function Gaps({ items }: { items: string[] }) {
  return items.length > 0 ? (
    <ul className="gaps">
      {items.map((item, index) => (
        <li key={`${index}:${item}`}>{item}</li>
      ))}
    </ul>
  ) : (
    <p className="muted">未记录缺失项；不代表已排除其他原因。</p>
  );
}

function ContextSummary({ id }: { id: string }) {
  const { resource, retry } = useReadResource(
    `/api/v1/investigations/${id}`,
    parseInvestigationContext,
    id,
  );
  const data = resource.state === "ready" ? resource.data : null;
  const alert = data?.alert;
  const href = alert ? safeSourceURL(alert.source_reference) : null;
  return (
    <section className="context-section" aria-labelledby="context-heading">
      <div className="section-heading">
        <h2 id="context-heading">调查摘要</h2>
        {data && <span className="badge">{data.status}</span>}
      </div>
      {resource.state === "loading" && <p role="status">正在读取调查摘要…</p>}
      {resource.state === "error" && (
        <Failure status={resource.status} name="调查摘要" retry={retry} />
      )}
      {data && (
        <>
          <div className="context-layout">
            <dl>
              <dt>项目</dt>
              <dd>
                {data.project.name}
                <span className="mono muted context-id">
                  {data.project.slug} · {data.project.id}
                </span>
              </dd>
              <dt>服务</dt>
              <dd>
                {data.service ? (
                  <>
                    {data.service.name}
                    <span className="mono muted context-id">
                      {data.service.slug} · {data.service.id}
                    </span>
                  </>
                ) : (
                  "待核对"
                )}
              </dd>
              <dt>环境</dt>
              <dd>{data.environment ?? "待核对"}</dd>
              <dt>实体映射</dt>
              <dd>{data.mapping_status}</dd>
              <dt>调查开始 UTC</dt>
              <dd className="mono">
                {new Date(data.started_at).toISOString()}
              </dd>
              <dt>调查结束 UTC</dt>
              <dd className="mono">
                {data.completed_at
                  ? new Date(data.completed_at).toISOString()
                  : "尚未结束"}
              </dd>
              <dt>Incident</dt>
              <dd className="mono">{data.incident_id}</dd>
            </dl>
            <div className="alert-summary">
              <h3>关联告警</h3>
              {alert ? (
                <>
                  <span className="badge warning">
                    {alert.severity} · {alert.status}
                  </span>
                  <p className="alert-title">{alert.summary}</p>
                  <dl>
                    <dt>告警 ID</dt>
                    <dd className="mono">{alert.id}</dd>
                    <dt>开始 UTC</dt>
                    <dd className="mono">
                      {new Date(alert.starts_at).toISOString()}
                    </dd>
                    <dt>结束 UTC</dt>
                    <dd className="mono">
                      {alert.ends_at
                        ? new Date(alert.ends_at).toISOString()
                        : "未记录"}
                    </dd>
                  </dl>
                  {href && (
                    <a href={href} target="_blank" rel="noopener noreferrer">
                      打开告警来源
                    </a>
                  )}
                  {!href && <p className="muted">未记录可打开的告警来源</p>}
                </>
              ) : (
                <p className="muted">尚未关联告警</p>
              )}
            </div>
          </div>
          {data.mapping_status === "NEEDS_MAPPING" && (
            <p className="notice">服务或环境尚未完成映射。</p>
          )}
          {data.mapping_status === "CONFLICT" && (
            <p className="notice">
              关联记录的服务或环境不一致，当前归属待核对。
            </p>
          )}
          {data.context_gaps.length > 0 && <Gaps items={data.context_gaps} />}
          <p className="muted">
            当前登记状态 ·
            实体映射不代表数据源就绪；告警恢复不代表根因已确认或调查已结束。
          </p>
        </>
      )}
    </section>
  );
}

function EvidenceButtons({
  ids,
  label,
  onSelect,
}: {
  ids: string[];
  label: string;
  onSelect: (id: string) => void;
}) {
  return (
    <div className="evidence-links">
      <span>{label}</span>
      {ids.length ? (
        ids.map((id) => (
          <button
            className="text-button mono"
            key={id}
            aria-label={`${label} ${id}`}
            onClick={() => onSelect(id)}
          >
            {id}
          </button>
        ))
      ) : (
        <span className="muted">未记录</span>
      )}
    </div>
  );
}

function Diagnosis({
  id,
  onSelect,
}: {
  id: string;
  onSelect: (id: string) => void;
}) {
  const { resource, retry } = useReadResource(
    `/api/v1/investigations/${id}/diagnosis`,
    parseDiagnosis,
    id,
  );
  return (
    <section className="diagnosis-section" aria-labelledby="diagnosis-heading">
      <div className="section-heading">
        <h2 id="diagnosis-heading">候选方向</h2>
        {resource.state === "ready" && (
          <span className="mono muted">{resource.data.rule_set_version}</span>
        )}
      </div>
      {resource.state === "loading" && <p role="status">正在读取诊断…</p>}
      {resource.state === "error" && (
        <Failure status={resource.status} name="诊断" retry={retry} />
      )}
      {resource.state === "ready" && (
        <>
          <div className="diagnosis-summary">
            <span className="badge warning">
              {resource.data.status === "INCONCLUSIVE"
                ? "证据不足 · INCONCLUSIVE"
                : `${resource.data.candidates.length} 个候选假设`}
            </span>
            <span className="muted">
              证据总量 {resource.data.evidence_total} · 读取上限{" "}
              {resource.data.evidence_limit}
            </span>
          </div>
          <p className="muted">
            候选仅表示证据关联，不证明发布或 SQL 导致故障；置信等级不是概率。
          </p>
          {resource.data.evidence_truncated && (
            <p className="notice">
              诊断证据超过读取上限，未基于截断子集生成结论。
            </p>
          )}
          {resource.data.missing_requirements.length > 0 && (
            <>
              <h3>诊断缺口</h3>
              <Gaps items={resource.data.missing_requirements} />
            </>
          )}
          {resource.data.candidates.map((candidate, index) => (
            <article
              className="candidate"
              key={`${candidate.rule_id}:${candidate.entity_type}:${candidate.entity_id}:${index}`}
            >
              <div className="section-heading">
                <h3>{candidate.fault_type}</h3>
                <span className="badge warning">
                  {candidate.confidence} · 定性等级
                </span>
              </div>
              <p className="mono">{candidate.rule_id}</p>
              <p className="muted mono">{candidate.entity_type} · {candidate.entity_id}</p>
              <EvidenceButtons
                ids={candidate.support_evidence_ids}
                label="支持证据"
                onSelect={onSelect}
              />
              <EvidenceButtons
                ids={candidate.contradict_evidence_ids}
                label="反证"
                onSelect={onSelect}
              />
              <h4>缺失证据与证明义务</h4>
              <Gaps items={candidate.missing_requirements} />
              {candidate.trigger_change && (
                <p>触发变化：{candidate.trigger_change}</p>
              )}
            </article>
          ))}
        </>
      )}
    </section>
  );
}

function Timeline({
  id,
  selected,
  onSelect,
}: {
  id: string;
  selected: string;
  onSelect: (id: string) => void;
}) {
  const [source, setSource] = useState("");
  const [completeness, setCompleteness] = useState("");
  const [offset, setOffset] = useState(0);
  const query = new URLSearchParams({ limit: "50", offset: String(offset) });
  if (source) query.set("source_type", source);
  if (completeness) query.set("completeness", completeness);
  const { resource, retry } = useReadResource(
    `/api/v1/investigations/${id}/timeline?${query}`,
    parseTimeline,
    id,
  );
  return (
    <section className="timeline-section" aria-labelledby="timeline-heading">
      <div className="section-heading">
        <h2 id="timeline-heading">证据时间线</h2>
        <span className="muted">UTC</span>
      </div>
      <div className="filters">
        <label>
          来源
          <select
            aria-label="来源"
            value={source}
            onChange={(event) => {
              setSource(event.target.value);
              setOffset(0);
            }}
          >
            <option value="">全部来源</option>
            {sources.map((item) => (
              <option key={item}>{item}</option>
            ))}
          </select>
        </label>
        <label>
          完整度
          <select
            aria-label="完整度"
            value={completeness}
            onChange={(event) => {
              setCompleteness(event.target.value);
              setOffset(0);
            }}
          >
            <option value="">全部完整度</option>
            {completenessStates.map((item) => (
              <option key={item}>{item}</option>
            ))}
          </select>
        </label>
      </div>
      {resource.state === "loading" && <p role="status">正在读取时间线…</p>}
      {resource.state === "error" && (
        <Failure status={resource.status} name="时间线" retry={retry} />
      )}
      {resource.state === "ready" && (
        <>
          <p className="muted">
            共 {resource.data.total} 条 · 本页 {resource.data.items.length} 条 ·
            独立读取快照
          </p>
          {!resource.data.items.length && (
            <p className="empty-state">
              当前筛选下没有证据，不能据此判断服务健康。
            </p>
          )}
          <ol className="timeline">
            {resource.data.items.map((item) => (
              <li key={item.id}>
                <button
                  className={`timeline-item ${selected === item.id ? "selected" : ""}`}
                  aria-label={`查看证据 ${item.id}`}
                  aria-pressed={selected === item.id}
                  onClick={() => onSelect(item.id)}
                >
                  <span className="item-heading">
                    <strong>{item.source_type}</strong>
                    <span
                      className={`badge ${item.completeness === "COMPLETE" ? "" : "warning"}`}
                    >
                      {item.completeness}
                    </span>
                  </span>
                  <time className="mono" dateTime={item.observed_start}>
                    {utc(item.observed_start)}
                  </time>
                  <span className="mono muted">
                    {item.entity_type} · {item.entity_id ?? "未映射"}
                  </span>
                  <span className="mono item-id">{item.id}</span>
                  {item.relations.map((relation) => (
                    <span
                      className="mono muted"
                      key={`${relation.hypothesis_id}:${relation.stance}`}
                    >
                      {relation.stance} · {relation.hypothesis_id}
                    </span>
                  ))}
                </button>
              </li>
            ))}
          </ol>
          <div className="pagination">
            <button
              disabled={offset === 0}
              onClick={() => setOffset(Math.max(0, offset - 50))}
            >
              上一页
            </button>
            <span className="mono">第 {Math.floor(offset / 50) + 1} 页</span>
            <button
              disabled={!resource.data.has_more || offset >= 10000}
              onClick={() => setOffset(offset + 50)}
            >
              下一页
            </button>
          </div>
          {resource.data.has_more && offset >= 10000 && (
            <p className="notice">已到分页上限，请缩小筛选范围。</p>
          )}
        </>
      )}
    </section>
  );
}

function utc(value: string) {
  return new Date(value).toISOString().replace("T", " ").replace(".000Z", "Z");
}

function EvidenceContent({ item }: { item: Evidence }) {
  const href = safeSourceURL(item.raw_reference);
  const templateID = item.query_parameters.template_id;
  let trend = null;
  if (
    item.source_type === "PROMETHEUS" &&
    typeof templateID === "string" &&
    metricTemplates.has(templateID)
  ) {
    try {
      const parsed = parseMetricTrend(
        item.value_summary,
        item.query_parameters.unit,
        item.observed_start,
        item.observed_end,
      );
      if (parsed.series.some((series) => series.samples.length > 0))
        trend = parsed;
    } catch {
      trend = null;
    }
  }
  return (
    <>
      <div className="section-heading">
        <strong>{item.source_type}</strong>
        <span
          className={`badge ${item.completeness === "COMPLETE" ? "" : "warning"}`}
        >
          {item.completeness}
        </span>
      </div>
      {item.completeness !== "COMPLETE" && (
        <p className="notice">
          此证据不完整、缺失或已过期；保留观测不代表当前状态。
        </p>
      )}
      <dl>
        <dt>Evidence ID</dt>
        <dd className="mono">{item.id}</dd>
        <dt>实体</dt>
        <dd className="mono">
          {item.entity_type} · {item.entity_id ?? "未映射"}
        </dd>
        <dt>事件区间 · UTC</dt>
        <dd className="mono">
          {utc(item.observed_start)}
          <br />
          {utc(item.observed_end)}
        </dd>
        <dt>采集时间 · UTC</dt>
        <dd className="mono">
          {item.collected_at ? utc(item.collected_at) : "未记录"}
        </dd>
        <dt>来源时间 / 时区</dt>
        <dd>
          {item.source_time_text || "未记录"} /{" "}
          {item.source_timezone || "未记录"}
        </dd>
        <dt>独立证据组</dt>
        <dd className="mono">{item.independence_group || "未记录"}</dd>
        <dt>时效秒数</dt>
        <dd>{item.freshness_seconds ?? "未记录"}</dd>
      </dl>
      <h3>查询</h3>
      <pre>{item.query_text || "未记录"}</pre>
      <h3>查询参数</h3>
      <pre>{JSON.stringify(item.query_parameters, null, 2)}</pre>
      {trend && (
        <Suspense fallback={<p role="status">正在加载指标图表…</p>}>
          <MetricTrend trend={trend} completeness={item.completeness} />
        </Suspense>
      )}
      <h3>观测摘要与缺口</h3>
      <pre>{JSON.stringify(item.value_summary, null, 2)}</pre>
      <h3>原始来源</h3>
      <p className="mono source-reference">{item.raw_reference || "未记录"}</p>
      {href && (
        <a href={href} target="_blank" rel="noopener noreferrer">
          打开原始来源
        </a>
      )}
    </>
  );
}

function EvidenceDetail({
  id,
  investigationID,
}: {
  id: string;
  investigationID: string;
}) {
  const { resource, retry } = useReadResource(
    `/api/v1/evidence/${id}`,
    parseEvidence,
    investigationID,
    id,
  );
  return (
    <>
      {resource.state === "loading" && <p role="status">正在读取证据…</p>}
      {resource.state === "error" && (
        <Failure status={resource.status} name="证据" retry={retry} />
      )}
      {resource.state === "ready" && <EvidenceContent item={resource.data} />}
    </>
  );
}

export default function InvestigationWorkbench({ id }: { id: string }) {
  const [selected, setSelected] = useState("");
  const detailHeading = useRef<HTMLHeadingElement>(null);
  function selectEvidence(evidenceID: string) {
    setSelected(evidenceID);
    detailHeading.current?.focus();
  }
  return (
    <>
      <p className="investigation-reference mono">INVESTIGATION · {id}</p>
      <ContextSummary id={id} />
      <Diagnosis id={id} onSelect={selectEvidence} />
      <div className="evidence-layout">
        <Timeline id={id} selected={selected} onSelect={selectEvidence} />
        <section className="evidence-detail" aria-labelledby="evidence-heading">
          <div className="section-heading">
            <h2 id="evidence-heading" ref={detailHeading} tabIndex={-1}>
              Evidence 详情
            </h2>
          </div>
          {selected ? (
            <EvidenceDetail key={selected} id={selected} investigationID={id} />
          ) : (
            <p className="muted">尚未选择证据</p>
          )}
        </section>
      </div>
    </>
  );
}
