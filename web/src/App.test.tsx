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
