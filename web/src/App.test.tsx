import {
  act,
  cleanup,
  fireEvent,
  render,
  screen,
  waitFor,
} from "@testing-library/react";
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import App from "./App";
import {
  diagnosis,
  evidence,
  investigationID,
  investigationContext,
  timeline,
} from "./test/investigationFixture";

function response(data: unknown, status = 200) {
  return new Response(JSON.stringify({ data }), {
    status,
    headers: { "Content-Type": "application/json" },
  });
}
function mockAPI(overrides: Record<string, () => Promise<Response>> = {}) {
  const fetchMock = vi.fn((input: string) => {
    if (overrides[input]) return overrides[input]();
    if (input === "/health/ready")
      return Promise.resolve(response({ status: "ready" }));
    if (input === `/api/v1/investigations/${investigationID}`)
      return Promise.resolve(response(investigationContext));
    if (input.endsWith("/diagnosis"))
      return Promise.resolve(response(diagnosis));
    if (input.includes("/timeline?"))
      return Promise.resolve(response(timeline));
    if (input === `/api/v1/evidence/${evidence.id}`)
      return Promise.resolve(response(evidence));
    return Promise.resolve(response({}, 404));
  });
  vi.stubGlobal("fetch", fetchMock);
  return fetchMock;
}
function openInvestigation() {
  fireEvent.change(screen.getByLabelText("Investigation ID"), {
    target: { value: investigationID },
  });
  fireEvent.click(screen.getByRole("button", { name: "打开调查" }));
}
beforeEach(() => {
  window.history.replaceState(null, "", "/");
});
afterEach(() => {
  cleanup();
  vi.unstubAllGlobals();
  vi.useRealTimers();
});

describe("investigation workbench", () => {
  it("normalizes context times with offsets to the displayed UTC zone", async () => {
    mockAPI({
      [`/api/v1/investigations/${investigationID}`]: async () =>
        response({
          ...investigationContext,
          started_at: "2026-11-18T10:11:12+08:00",
          completed_at: "2026-11-18T10:13:14+08:00",
          alert: {
            ...investigationContext.alert,
            status: "RESOLVED",
            starts_at: "2026-11-18T10:09:10+08:00",
            ends_at: "2026-11-18T10:12:13+08:00",
          },
        }),
    });
    render(<App />);
    openInvestigation();
    expect(
      await screen.findByText("2026-11-18T02:11:12.000Z"),
    ).toBeInTheDocument();
    for (const value of [
      "2026-11-18T02:13:14.000Z",
      "2026-11-18T02:09:10.000Z",
      "2026-11-18T02:12:13.000Z",
    ])
      expect(screen.getByText(value)).toBeInTheDocument();
  });
  it("shows canonical alert and service context separately from diagnosis", async () => {
    mockAPI();
    render(<App />);
    openInvestigation();
    expect(await screen.findByText("Checkout API")).toBeInTheDocument();
    expect(screen.getByText("Synthetic Shop")).toBeInTheDocument();
    expect(screen.getByText("prod")).toBeInTheDocument();
    expect(screen.getByText("Checkout latency rose")).toBeInTheDocument();
    expect(screen.getByText("ERROR · FIRING")).toBeInTheDocument();
    expect(screen.getByText("RECEIVED")).toBeInTheDocument();
    expect(screen.getByRole("link", { name: "打开告警来源" })).toHaveAttribute(
      "rel",
      "noopener noreferrer",
    );
  });
  it.each([
    {
      mapping_status: "NEEDS_MAPPING",
      context_gaps: ["service_mapping_missing"],
      message: "服务或环境尚未完成映射。",
    },
    {
      mapping_status: "CONFLICT",
      context_gaps: ["mapping_conflict"],
      message: "关联记录的服务或环境不一致，当前归属待核对。",
    },
  ])(
    "shows $mapping_status and an absent alert without implying health",
    async (input) => {
      mockAPI({
        [`/api/v1/investigations/${investigationID}`]: async () =>
          response({
            ...investigationContext,
            ...input,
            service: null,
            environment: null,
            alert: null,
          }),
      });
      render(<App />);
      openInvestigation();
      expect(await screen.findByText(input.message)).toBeInTheDocument();
      expect(screen.getByText("尚未关联告警")).toBeInTheDocument();
      expect(screen.queryByText("Checkout API")).not.toBeInTheDocument();
      expect(
        screen.queryByRole("link", { name: "打开告警来源" }),
      ).not.toBeInTheDocument();
    },
  );
  it("retries context independently while retaining diagnosis and never displays another investigation", async () => {
    let failed = true;
    const fetchMock = mockAPI({
      [`/api/v1/investigations/${investigationID}`]: async () =>
        response(
          failed
            ? {
                ...investigationContext,
                investigation_id: evidence.id,
                alert: {
                  ...investigationContext.alert,
                  summary: "other-investigation-context",
                },
              }
            : investigationContext,
        ),
    });
    render(<App />);
    openInvestigation();
    expect(
      await screen.findByText("调查摘要加载失败，请重试。"),
    ).toBeInTheDocument();
    expect(
      await screen.findByText("slow-query-latency-correlation.v1"),
    ).toBeInTheDocument();
    expect(
      screen.queryByText("other-investigation-context"),
    ).not.toBeInTheDocument();
    failed = false;
    fireEvent.click(screen.getByRole("button", { name: "重试调查摘要" }));
    expect(await screen.findByText("Checkout API")).toBeInTheDocument();
    expect(
      fetchMock.mock.calls.filter(([url]) => url.endsWith("/diagnosis")),
    ).toHaveLength(1);
  });
  it("renders alert HTML as text and rejects unsafe alert links", async () => {
    mockAPI({
      [`/api/v1/investigations/${investigationID}`]: async () =>
        response({
          ...investigationContext,
          alert: {
            ...investigationContext.alert,
            summary: "<img src=x onerror=untrusted()>",
            source_reference: "javascript:alert(1)",
          },
        }),
    });
    render(<App />);
    openInvestigation();
    expect(
      await screen.findByText("<img src=x onerror=untrusted()>"),
    ).toBeInTheDocument();
    expect(document.querySelector("img")).toBeNull();
    expect(
      screen.queryByRole("link", { name: "打开告警来源" }),
    ).not.toBeInTheDocument();
  });
  it("retains readiness and rejects invalid IDs without data requests", async () => {
    const fetchMock = mockAPI();
    render(<App />);
    expect(await screen.findByText("API is ready")).toBeInTheDocument();
    fireEvent.change(screen.getByLabelText("Investigation ID"), {
      target: { value: "../../admin" },
    });
    fireEvent.click(screen.getByRole("button", { name: "打开调查" }));
    expect(screen.getByRole("alert")).toHaveTextContent("有效的 UUID");
    expect(fetchMock).toHaveBeenCalledTimes(1);
  });
  it("opens a shareable investigation and follows candidate Evidence references", async () => {
    const fetchMock = mockAPI();
    render(<App />);
    openInvestigation();
    expect(
      await screen.findByText("slow-query-latency-correlation.v1"),
    ).toBeInTheDocument();
    expect(screen.getByText("MEDIUM · 定性等级")).toBeInTheDocument();
    expect(window.location.search).toBe(`?investigation=${investigationID}`);
    fireEvent.click(
      screen.getByRole("button", { name: `支持证据 ${evidence.id}` }),
    );
    expect(
      await screen.findByRole("heading", { name: "Evidence 详情" }),
    ).toBeInTheDocument();
    expect(
      screen.getByRole("heading", { name: "Evidence 详情" }),
    ).toHaveFocus();
    expect(
      await screen.findByText("select duration from queries"),
    ).toBeInTheDocument();
    expect(screen.getByRole("link", { name: "打开原始来源" })).toHaveAttribute(
      "rel",
      "noopener noreferrer",
    );
    expect(fetchMock).toHaveBeenCalledWith(
      `/api/v1/evidence/${evidence.id}`,
      expect.objectContaining({ signal: expect.any(AbortSignal) }),
    );
  });
  it("shows a bounded Prometheus trend for the selected Evidence", async () => {
    const metricEvidence = {
      ...evidence,
      query_parameters: {
        template_id: "prometheus.service.request_rate.v1",
        template_version: 1,
        unit: "requests/second",
      },
      value_summary: {
        series: [
          {
            labels: { service: "checkout-api" },
            samples: [
              { timestamp: "2026-11-18T01:01:00Z", value: 12 },
              { timestamp: "2026-11-18T01:02:00Z", value: 14 },
            ],
          },
        ],
      },
    };
    mockAPI({
      [`/api/v1/evidence/${evidence.id}`]: async () =>
        response(metricEvidence),
    });
    render(<App />);
    openInvestigation();
    await screen.findByText("slow-query-latency-correlation.v1");
    fireEvent.click(
      screen.getByRole("button", { name: `支持证据 ${evidence.id}` }),
    );
    expect(
      await screen.findByRole("img", { name: "Prometheus 指标趋势图" }),
    ).toBeInTheDocument();
    expect(screen.getAllByText("PARTIAL").length).toBeGreaterThanOrEqual(2);
    fireEvent.click(screen.getByText(/查看序列数据/));
    expect(screen.getByText("service=checkout-api")).toBeInTheDocument();
    expect(screen.getByText(/单位：requests\/second/)).toBeInTheDocument();
  });
  it.each([
    {
      name: "unknown template",
      evidence: {
        ...evidence,
        query_parameters: { template_id: "prometheus.unknown.v1", unit: "bytes" },
        value_summary: { series: [{ labels: {}, samples: [] }] },
      },
    },
    {
      name: "empty series",
      evidence: {
        ...evidence,
        query_parameters: {
          template_id: "prometheus.service.request_rate.v1",
          unit: "requests_per_second",
        },
        value_summary: { series: [] },
      },
    },
  ])("keeps raw evidence without charting $name", async ({ evidence: item }) => {
    mockAPI({
      [`/api/v1/evidence/${evidence.id}`]: async () => response(item),
    });
    render(<App />);
    openInvestigation();
    await screen.findByText("slow-query-latency-correlation.v1");
    fireEvent.click(
      screen.getByRole("button", { name: `支持证据 ${evidence.id}` }),
    );
    expect(await screen.findByText("select duration from queries")).toBeInTheDocument();
    expect(
      screen.queryByRole("img", { name: "Prometheus 指标趋势图" }),
    ).not.toBeInTheDocument();
  });
  it("loads a deep link, retains timeline on diagnosis failure and retries independently", async () => {
    window.history.replaceState(null, "", `/?investigation=${investigationID}`);
    let failed = true;
    mockAPI({
      [`/api/v1/investigations/${investigationID}/diagnosis`]: async () =>
        failed
          ? response({ secret: "must-not-display" }, 503)
          : response(diagnosis),
    });
    render(<App />);
    expect(
      await screen.findByRole("button", { name: `查看证据 ${evidence.id}` }),
    ).toBeInTheDocument();
    expect(
      await screen.findByText("诊断加载失败，请重试。"),
    ).toBeInTheDocument();
    expect(screen.queryByText("must-not-display")).not.toBeInTheDocument();
    failed = false;
    fireEvent.click(screen.getByRole("button", { name: "重试诊断" }));
    expect(
      await screen.findByText("slow-query-latency-correlation.v1"),
    ).toBeInTheDocument();
  });
  it("filters server-side, resets pagination and keeps diagnosis unfiltered", async () => {
    const fetchMock = mockAPI({
      [`/api/v1/investigations/${investigationID}/timeline?limit=50&offset=0`]:
        async () => response({ ...timeline, total: 51, has_more: true }),
    });
    render(<App />);
    openInvestigation();
    fireEvent.click(await screen.findByRole("button", { name: "下一页" }));
    await waitFor(() =>
      expect(fetchMock).toHaveBeenCalledWith(
        expect.stringContaining("offset=50"),
        expect.anything(),
      ),
    );
    fireEvent.change(screen.getByLabelText("来源"), {
      target: { value: "LOKI" },
    });
    await waitFor(() =>
      expect(fetchMock).toHaveBeenCalledWith(
        `/api/v1/investigations/${investigationID}/timeline?limit=50&offset=0&source_type=LOKI`,
        expect.anything(),
      ),
    );
    expect(
      fetchMock.mock.calls.filter(([url]) => url.endsWith("/diagnosis")),
    ).toHaveLength(1);
  });
  it("shows inconclusive and truncation without implying health", async () => {
    mockAPI({
      [`/api/v1/investigations/${investigationID}/diagnosis`]: async () =>
        response({
          ...diagnosis,
          status: "INCONCLUSIVE",
          candidates: [],
          evidence_total: 101,
          evidence_truncated: true,
          missing_requirements: ["complete_evidence_snapshot"],
        }),
    });
    render(<App />);
    openInvestigation();
    expect(
      await screen.findByText("证据不足 · INCONCLUSIVE"),
    ).toBeInTheDocument();
    expect(screen.getByText("complete_evidence_snapshot")).toBeInTheDocument();
    expect(screen.getByText(/诊断证据超过读取上限/)).toBeInTheDocument();
  });
  it("renders untrusted text safely and does not link unsafe source references", async () => {
    mockAPI({
      [`/api/v1/evidence/${evidence.id}`]: async () =>
        response({
          ...evidence,
          completeness: "MISSING",
          raw_reference: "javascript:alert(1)",
          query_text: "<script>untrusted()</script>",
        }),
    });
    render(<App />);
    openInvestigation();
    fireEvent.click(
      await screen.findByRole("button", { name: `查看证据 ${evidence.id}` }),
    );
    expect(
      await screen.findByText("<script>untrusted()</script>"),
    ).toBeInTheDocument();
    expect(
      screen.queryByRole("link", { name: "打开原始来源" }),
    ).not.toBeInTheDocument();
    expect(document.querySelector("script")).toBeNull();
  });
  it("rejects Evidence owned by another investigation", async () => {
    mockAPI({
      [`/api/v1/evidence/${evidence.id}`]: async () =>
        response({
          ...evidence,
          investigation_id: "22222222-2222-4222-8222-222222222222",
          query_text: "other-investigation",
        }),
    });
    render(<App />);
    openInvestigation();
    fireEvent.click(
      await screen.findByRole("button", { name: `查看证据 ${evidence.id}` }),
    );
    expect(
      await screen.findByText("证据加载失败，请重试。"),
    ).toBeInTheDocument();
    expect(screen.queryByText("other-investigation")).not.toBeInTheDocument();
  });
  it("shows empty, not-found and readiness failure states", async () => {
    mockAPI({
      "/health/ready": async () => response({}, 503),
      [`/api/v1/investigations/${investigationID}/timeline?limit=50&offset=0`]:
        async () => response({ ...timeline, items: [], total: 0 }),
      [`/api/v1/investigations/${investigationID}/diagnosis`]: async () =>
        response({}, 404),
    });
    render(<App />);
    openInvestigation();
    expect(
      await screen.findByText("当前筛选下没有证据，不能据此判断服务健康。"),
    ).toBeInTheDocument();
    expect(
      await screen.findByText("调查不存在或已不可用，请检查 ID。"),
    ).toBeInTheDocument();
    expect(await screen.findByText("API is not ready")).toBeInTheDocument();
  });

  it("ends loading after a bounded timeout", async () => {
    vi.useFakeTimers();
    mockAPI({
      [`/api/v1/investigations/${investigationID}/diagnosis`]: () =>
        new Promise<Response>(() => {}),
    });
    render(<App />);
    openInvestigation();
    expect(screen.getByText("正在读取诊断…")).toBeInTheDocument();
    await act(async () => {
      vi.advanceTimersByTime(15000);
    });
    expect(screen.getByText("诊断加载失败，请重试。")).toBeInTheDocument();
  });

  it("distinguishes a missing Evidence record from a missing investigation", async () => {
    mockAPI({
      [`/api/v1/evidence/${evidence.id}`]: async () => response({}, 404),
    });
    render(<App />);
    openInvestigation();
    fireEvent.click(
      await screen.findByRole("button", { name: `查看证据 ${evidence.id}` }),
    );
    expect(
      await screen.findByText("证据不存在或已不可用，请重新选择。"),
    ).toBeInTheDocument();
    expect(
      screen.getByText("slow-query-latency-correlation.v1"),
    ).toBeInTheDocument();
  });

  it("does not display a late response from a previously opened investigation", async () => {
    const otherID = "22222222-2222-4222-8222-222222222222";
    let resolveOld: (value: Response) => void = () => {};
    mockAPI({
      [`/api/v1/investigations/${investigationID}/diagnosis`]: () =>
        new Promise<Response>((resolve) => {
          resolveOld = resolve;
        }),
      [`/api/v1/investigations/${otherID}/diagnosis`]: async () =>
        response({
          ...diagnosis,
          investigation_id: otherID,
          status: "INCONCLUSIVE",
          candidates: null,
        }),
      [`/api/v1/investigations/${otherID}/timeline?limit=50&offset=0`]:
        async () =>
          response({
            ...timeline,
            investigation_id: otherID,
            items: [],
            total: 0,
          }),
    });
    render(<App />);
    openInvestigation();
    fireEvent.change(screen.getByLabelText("Investigation ID"), {
      target: { value: otherID },
    });
    fireEvent.click(screen.getByRole("button", { name: "打开调查" }));
    expect(
      await screen.findByText("证据不足 · INCONCLUSIVE"),
    ).toBeInTheDocument();
    await act(async () => {
      resolveOld(response(diagnosis));
    });
    expect(
      screen.queryByText("slow-query-latency-correlation.v1"),
    ).not.toBeInTheDocument();
    expect(
      screen.queryByRole("button", { name: `查看证据 ${evidence.id}` }),
    ).not.toBeInTheDocument();
  });

  it("can inspect counterevidence outside the visible timeline page", async () => {
    mockAPI({
      [`/api/v1/investigations/${investigationID}/diagnosis`]: async () =>
        response({
          ...diagnosis,
          candidates: [
            {
              ...diagnosis.candidates[0],
              support_evidence_ids: [],
              contradict_evidence_ids: [evidence.id],
            },
          ],
        }),
      [`/api/v1/investigations/${investigationID}/timeline?limit=50&offset=0`]:
        async () => response({ ...timeline, items: [], total: 0 }),
    });
    render(<App />);
    openInvestigation();
    fireEvent.click(
      await screen.findByRole("button", { name: `反证 ${evidence.id}` }),
    );
    expect(
      await screen.findByText("select duration from queries"),
    ).toBeInTheDocument();
  });
});
