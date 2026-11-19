export const sources = [
  "DEPLOYMENT",
  "GRAFANA",
  "GITHUB",
  "PROMETHEUS",
  "LOKI",
  "RUNTIME",
  "MAPPING",
  "SYSTEM",
] as const;
export const completenessStates = [
  "COMPLETE",
  "PARTIAL",
  "MISSING",
  "EXPIRED",
] as const;
export const isID = (value: string) =>
  /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/i.test(value);

function invalid(): never {
  throw new Error("Invalid API response");
}
function object(value: unknown): Record<string, unknown> {
  if (!value || typeof value !== "object" || Array.isArray(value))
    return invalid();
  return value as Record<string, unknown>;
}
function text(value: unknown): string {
  return typeof value === "string" ? value : invalid();
}
function id(value: unknown): string {
  const result = text(value);
  return isID(result) ? result.toLowerCase() : invalid();
}
function integer(value: unknown): number {
  return typeof value === "number" && Number.isSafeInteger(value) && value >= 0
    ? value
    : invalid();
}
function boolean(value: unknown): boolean {
  return typeof value === "boolean" ? value : invalid();
}
function list<T>(value: unknown, decode: (item: unknown) => T): T[] {
  if (value === null) return [];
  return Array.isArray(value) ? value.map(decode) : invalid();
}
function choice<T extends string>(value: unknown, options: readonly T[]): T {
  for (const option of options) if (value === option) return option;
  return invalid();
}
function timestamp(value: unknown): string {
  const result = text(value);
  return /^\d{4}-\d{2}-\d{2}T/.test(result) &&
    Number.isFinite(Date.parse(result))
    ? result
    : invalid();
}

const maxMetricSeries = 10;
const maxMetricSamples = 240;
const maxMetricLabels = 16;
const maxMetricLabelLength = 128;

export type MetricTrend = {
  unit: string;
  series: {
    name: string;
    samples: { timestamp: number; value: number }[];
  }[];
};

export function parseMetricTrend(
  value: unknown,
  unitValue: unknown,
  observedStart: string,
  observedEnd: string,
): MetricTrend {
  const summary = object(value);
  if (!Array.isArray(summary.series) || summary.series.length > maxMetricSeries)
    return invalid();
  const unit = text(unitValue);
  if (unit.length > 32) return invalid();
  const start = Date.parse(timestamp(observedStart));
  const end = Date.parse(timestamp(observedEnd));
  if (end < start) return invalid();

  const usedNames = new Map<string, number>();
  const series = summary.series.map((value, index) => {
    const item = object(value);
    const labels = object(item.labels);
    const entries = Object.entries(labels);
    if (entries.length > maxMetricLabels) return invalid();
    for (const [key, label] of entries) {
      if (
        key.length === 0 ||
        key.length > maxMetricLabelLength ||
        typeof label !== "string" ||
        label.length > maxMetricLabelLength
      )
        return invalid();
    }
    if (!Array.isArray(item.samples) || item.samples.length > maxMetricSamples)
      return invalid();

    const baseName = entries.length
      ? entries
          .sort(([left], [right]) => (left < right ? -1 : left > right ? 1 : 0))
          .map(([key, label]) => `${key}=${label}`)
          .join(", ")
      : `序列 ${index + 1}`;
    const nameCount = (usedNames.get(baseName) ?? 0) + 1;
    usedNames.set(baseName, nameCount);
    const name = nameCount === 1 ? baseName : `${baseName} (${nameCount})`;

    const samples = item.samples.map((sampleValue) => {
      const sample = object(sampleValue);
      const sampleTime = Date.parse(timestamp(sample.timestamp));
      if (
        sampleTime < start ||
        sampleTime > end ||
        typeof sample.value !== "number" ||
        !Number.isFinite(sample.value)
      )
        return invalid();
      return { timestamp: sampleTime, value: sample.value };
    });
    samples.sort((left, right) => left.timestamp - right.timestamp);

    return {
      name,
      samples,
    };
  });
  return { unit, series };
}

function contextEntity(value: unknown) {
  const entity = object(value);
  return {
    id: id(entity.id),
    slug: text(entity.slug),
    name: text(entity.name),
  };
}

export function parseInvestigationContext(value: unknown) {
  const item = object(value);
  const service = item.service === null ? null : contextEntity(item.service);
  const environment = item.environment === null ? null : text(item.environment);
  const mapping_status = choice(item.mapping_status, [
    "MATCHED",
    "NEEDS_MAPPING",
    "CONFLICT",
  ] as const);
  if (
    (mapping_status === "MATCHED" && (!service || !environment)) ||
    (mapping_status === "CONFLICT" &&
      (service !== null || environment !== null)) ||
    (mapping_status === "NEEDS_MAPPING" && service !== null && !!environment)
  )
    return invalid();
  const alert =
    item.alert === null
      ? null
      : (() => {
          const alert = object(item.alert);
          const starts_at = timestamp(alert.starts_at);
          const ends_at =
            alert.ends_at === null ? null : timestamp(alert.ends_at);
          if (ends_at && Date.parse(ends_at) < Date.parse(starts_at))
            return invalid();
          return {
            id: id(alert.id),
            status: choice(alert.status, [
              "FIRING",
              "RESOLVED",
              "UNKNOWN",
            ] as const),
            severity: choice(alert.severity, [
              "INFO",
              "WARNING",
              "ERROR",
              "CRITICAL",
              "UNKNOWN",
            ] as const),
            summary: text(alert.summary),
            starts_at,
            ends_at,
            source_reference: text(alert.source_reference),
          };
        })();
  const started_at = timestamp(item.started_at);
  const completed_at =
    item.completed_at === null ? null : timestamp(item.completed_at);
  if (completed_at && Date.parse(completed_at) < Date.parse(started_at))
    return invalid();
  return {
    investigation_id: id(item.investigation_id),
    incident_id: id(item.incident_id),
    status: choice(item.status, [
      "RECEIVED",
      "MATCHED",
      "COLLECTING",
      "HYPOTHESIZING",
      "VERIFYING",
      "COMPLETED",
      "INSUFFICIENT_EVIDENCE",
      "FAILED",
    ] as const),
    started_at,
    completed_at,
    project: contextEntity(item.project),
    service,
    environment,
    mapping_status,
    context_gaps: list(item.context_gaps, text),
    alert,
  };
}

export function parseEvidence(value: unknown) {
  const item = object(value);
  const observed_start = timestamp(item.observed_start);
  const observed_end = timestamp(item.observed_end);
  if (Date.parse(observed_end) < Date.parse(observed_start)) return invalid();
  return {
    id: id(item.id),
    investigation_id: id(item.investigation_id),
    source_type: choice(item.source_type, sources),
    entity_type: text(item.entity_type),
    entity_id: item.entity_id === null ? null : text(item.entity_id),
    observed_start,
    observed_end,
    collected_at:
      item.collected_at === null ? null : timestamp(item.collected_at),
    completeness: choice(item.completeness, completenessStates),
    query_text: text(item.query_text),
    raw_reference: text(item.raw_reference),
    query_parameters: object(item.query_parameters),
    value_summary: object(item.value_summary),
    source_timezone: text(item.source_timezone),
    source_time_text: text(item.source_time_text),
    independence_group: text(item.independence_group),
    freshness_seconds:
      item.freshness_seconds === null ? null : integer(item.freshness_seconds),
  };
}
export type Evidence = ReturnType<typeof parseEvidence>;

export function parseTimeline(value: unknown) {
  const page = object(value);
  const investigation_id = id(page.investigation_id);
  const items = list(page.items, (value) => {
    const item = parseEvidence(value);
    if (item.investigation_id !== investigation_id) return invalid();
    return {
      ...item,
      relations: list(object(value).relations, (value) => {
        const relation = object(value);
        return {
          hypothesis_id: id(relation.hypothesis_id),
          stance: choice(relation.stance, ["SUPPORTS", "CONTRADICTS"] as const),
        };
      }),
    };
  });
  const limit = integer(page.limit);
  const offset = integer(page.offset);
  const total = integer(page.total);
  const has_more = boolean(page.has_more);
  if (
    limit < 1 ||
    limit > 100 ||
    offset > 10000 ||
    items.length > limit ||
    items.length > total
  )
    return invalid();
  return { investigation_id, items, total, limit, offset, has_more };
}

export function parseDiagnosis(value: unknown) {
  const result = object(value);
  return {
    investigation_id: id(result.investigation_id),
    rule_set_version: text(result.rule_set_version),
    status: choice(result.status, [
      "INCONCLUSIVE",
      "CANDIDATES_FOUND",
    ] as const),
    evidence_total: integer(result.evidence_total),
    evidence_limit: integer(result.evidence_limit),
    evidence_truncated: boolean(result.evidence_truncated),
    missing_requirements: list(result.missing_requirements, text),
    candidates: list(result.candidates, (value) => {
      const candidate = object(value);
      return {
        rule_id: text(candidate.rule_id),
        fault_type: text(candidate.fault_type),
        entity_id: id(candidate.entity_id),
        confidence: choice(candidate.confidence, ["LOW", "MEDIUM"] as const),
        support_evidence_ids: list(candidate.support_evidence_ids, id),
        contradict_evidence_ids: list(candidate.contradict_evidence_ids, id),
        missing_requirements: list(candidate.missing_requirements, text),
        trigger_change:
          candidate.trigger_change === undefined
            ? ""
            : text(candidate.trigger_change),
      };
    }),
  };
}

export class APIError extends Error {
  constructor(public readonly status: number) {
    super("Read request failed");
  }
}

export async function readAPI<T>(
  url: string,
  decode: (value: unknown) => T,
  signal: AbortSignal,
): Promise<T> {
  const response = await fetch(url, { signal });
  if (!response.ok) throw new APIError(response.status);
  const envelope: unknown = await response.json();
  return decode(object(envelope).data);
}

export function safeSourceURL(reference: string): string | null {
  try {
    const url = new URL(reference);
    if (
      !/^https?:\/\//i.test(reference) ||
      !["http:", "https:"].includes(url.protocol) ||
      url.username ||
      url.password
    )
      return null;
    return url.href;
  } catch {
    return null;
  }
}
