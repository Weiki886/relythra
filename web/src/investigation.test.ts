import { describe, expect, it } from "vitest";
import {
  parseDiagnosis,
  parseEvidence,
  parseTimeline,
  safeSourceURL,
} from "./investigation";
import { diagnosis, evidence, timeline } from "./test/investigationFixture";

describe("read-only API contracts", () => {
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
    ).toThrow();
    expect(() =>
      parseEvidence({ ...evidence, observed_start: "invalid" }),
    ).toThrow();
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
