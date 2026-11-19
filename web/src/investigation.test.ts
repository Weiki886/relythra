import { describe, expect, it } from "vitest";
import {
  parseDiagnosis,
  parseEvidence,
  parseTimeline,
  parseInvestigationContext,
  parseMetricTrend,
  safeSourceURL,
} from "./investigation";
import {
  diagnosis,
  evidence,
  investigationContext,
  timeline,
} from "./test/investigationFixture";

describe("read-only API contracts", () => {
  it("decodes current investigation context and explicit absent alert/mapping", () => {
    expect(parseInvestigationContext(investigationContext)).toEqual(
      investigationContext,
    );
    expect(
      parseInvestigationContext({
        ...investigationContext,
        alert: null,
        service: null,
        environment: null,
        mapping_status: "NEEDS_MAPPING",
        context_gaps: ["alert_not_linked", "service_mapping_missing"],
      }).alert,
    ).toBeNull();
    expect(
      parseInvestigationContext({
        ...investigationContext,
        service: null,
        environment: null,
        mapping_status: "CONFLICT",
        context_gaps: ["mapping_conflict"],
      }).mapping_status,
    ).toBe("CONFLICT");
  });
  it.each([
    { ...investigationContext, investigation_id: "other" },
    { ...investigationContext, status: "HEALTHY" },
    { ...investigationContext, mapping_status: "GUESS" },
    { ...investigationContext, service: null },
    { ...investigationContext, mapping_status: "CONFLICT" },
    { ...investigationContext, environment: 42 },
    { ...investigationContext, started_at: "yesterday" },
    { ...investigationContext, alert: {} },
    {
      ...investigationContext,
      alert: { ...investigationContext.alert, severity: "HIGH" },
    },
    {
      ...investigationContext,
      alert: { ...investigationContext.alert, ends_at: "2026-01-01T00:00:00Z" },
    },
  ])("rejects malformed investigation context", (input) => {
    expect(() => parseInvestigationContext(input)).toThrow();
  });
  it("normalizes nullable Go slices", () => {
    expect(parseDiagnosis(diagnosis).missing_requirements).toEqual([]);
    expect(
      parseDiagnosis(diagnosis).candidates[0].contradict_evidence_ids,
    ).toEqual([]);
    expect(parseTimeline({ ...timeline, items: null }).items).toEqual([]);
    expect(parseEvidence(evidence).collected_at).toBeNull();
  });
  it.each([
    { ...diagnosis, status: "HEALTHY" },
    { ...diagnosis, evidence_truncated: "false" },
    {
      ...diagnosis,
      candidates: [{ ...diagnosis.candidates[0], confidence: "99%" }],
    },
  ])("rejects malformed diagnosis instead of inferring success", (input) => {
    expect(() => parseDiagnosis(input)).toThrow();
  });
  it("rejects malformed timeline and Evidence", () => {
    expect(() => parseTimeline({ ...timeline, has_more: "false" })).toThrow();
    expect(() => parseTimeline({ ...timeline, offset: -1 })).toThrow();
    expect(() =>
      parseEvidence({ ...evidence, completeness: "HEALTHY" }),
    ).toThrow("Invalid API response");
    expect(() =>
      parseEvidence({ ...evidence, observed_start: "invalid" }),
    ).toThrow("Invalid API response");
  });
  it.each([
    "javascript:alert(1)",
    "data:text/html,hi",
    "//example.test",
    "https://user:pass@example.test",
    "not-a-url",
  ])("does not make %s clickable", (url) => {
    expect(safeSourceURL(url)).toBeNull();
  });
  it("permits absolute HTTP(S) source links", () => {
    expect(safeSourceURL("https://example.test/explore?q=1")).toBe(
      "https://example.test/explore?q=1",
    );
  });
});

describe("Prometheus Evidence metric trends", () => {
  const summary = {
    series: [
      {
        labels: { service: "checkout-api", instance: "app-1" },
        samples: [
          { timestamp: "2026-11-18T01:00:00Z", value: 12.5 },
          { timestamp: "2026-11-18T01:01:00Z", value: 14 },
        ],
      },
      {
        labels: { instance: "app-2", service: "checkout-api" },
        samples: [{ timestamp: "2026-11-18T01:00:00Z", value: 9 }],
      },
    ],
  };

  it("preserves independent series, stable label names, UTC times and units", () => {
    expect(
      parseMetricTrend(
        summary,
        "milliseconds",
        "2026-11-18T01:00:00Z",
        "2026-11-18T01:05:00Z",
      ),
    ).toEqual({
      unit: "milliseconds",
      series: [
        {
          name: "instance=app-1, service=checkout-api",
          samples: [
            { timestamp: Date.parse("2026-11-18T01:00:00Z"), value: 12.5 },
            { timestamp: Date.parse("2026-11-18T01:01:00Z"), value: 14 },
          ],
        },
        {
          name: "instance=app-2, service=checkout-api",
          samples: [
            { timestamp: Date.parse("2026-11-18T01:00:00Z"), value: 9 },
          ],
        },
      ],
    });
  });

  it("sorts samples by time without combining or changing their values", () => {
    const trend = parseMetricTrend(
      {
        series: [
          {
            labels: {},
            samples: [
              { timestamp: "2026-11-18T01:02:00Z", value: 2 },
              { timestamp: "2026-11-18T01:01:00Z", value: 1 },
            ],
          },
        ],
      },
      "bytes",
      "2026-11-18T01:00:00Z",
      "2026-11-18T01:05:00Z",
    );
    expect(trend.series[0].samples.map((sample) => sample.value)).toEqual([
      1, 2,
    ]);
  });

  it("returns an empty trend for an empty series list", () => {
    expect(
      parseMetricTrend(
        { series: [] },
        "bytes",
        "2026-11-18T01:00:00Z",
        "2026-11-18T01:05:00Z",
      ),
    ).toEqual({
      unit: "bytes",
      series: [],
    });
  });

  it.each([
    { series: "not-an-array" },
    { series: [{ labels: {}, samples: [{ timestamp: "invalid", value: 1 }] }] },
    { series: [{ labels: {}, samples: [{ timestamp: "2026-11-18T01:00:00Z", value: Number.NaN }] }] },
    { series: [{ labels: {}, samples: [{ timestamp: "2026-11-18T01:00:00Z", value: Number.POSITIVE_INFINITY }] }] },
    { series: [{ labels: { service: 1 }, samples: [] }] },
    { series: [{ labels: {}, samples: "not-an-array" }] },
  ])("rejects malformed metric series", (value) => {
    expect(() =>
      parseMetricTrend(
        value,
        "bytes",
        "2026-11-18T01:00:00Z",
        "2026-11-18T01:05:00Z",
      ),
    ).toThrow("Invalid API response");
  });

  it("rejects data that exceeds the bounded chart size", () => {
    expect(() =>
      parseMetricTrend(
        {
          series: Array.from({ length: 11 }, () => ({ labels: {}, samples: [] })),
        },
        "bytes",
        "2026-11-18T01:00:00Z",
        "2026-11-18T01:05:00Z",
      ),
    ).toThrow("Invalid API response");
    expect(() =>
      parseMetricTrend(
        {
          series: [
            {
              labels: {},
              samples: Array.from({ length: 241 }, (_, index) => ({
                timestamp: new Date(Date.UTC(2026, 10, 18, 1, index)).toISOString(),
                value: index,
              })),
            },
          ],
        },
        "bytes",
        "2026-11-18T01:00:00Z",
        "2026-11-18T01:05:00Z",
      ),
    ).toThrow("Invalid API response");
  });

  it("rejects samples outside the Evidence observation interval", () => {
    expect(() =>
      parseMetricTrend(
        {
          series: [
            {
              labels: {},
              samples: [{ timestamp: "2026-11-18T00:59:59Z", value: 1 }],
            },
          ],
        },
        "bytes",
        "2026-11-18T01:00:00Z",
        "2026-11-18T01:05:00Z",
      ),
    ).toThrow("Invalid API response");
  });
});
