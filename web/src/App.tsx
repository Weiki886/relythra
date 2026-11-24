import { useEffect, useState } from "react";
import { isID } from "./investigation";
import InvestigationWorkbench from "./InvestigationWorkbench";

function Readiness() {
  const [readiness, setReadiness] = useState("checking");
  useEffect(() => {
    const controller = new AbortController();
    const timeout = window.setTimeout(() => {
      controller.abort();
      setReadiness("error");
    }, 15000);
    void fetch("/health/ready", { signal: controller.signal })
      .then((response) => {
        if (!controller.signal.aborted)
          setReadiness(response.ok ? "ready" : "error");
      })
      .catch(() => {
        if (!controller.signal.aborted) setReadiness("error");
      })
      .finally(() => window.clearTimeout(timeout));
    return () => {
      window.clearTimeout(timeout);
      controller.abort();
    };
  }, []);
  return (
    <span className={`health health-${readiness}`} role="status">
      {readiness === "checking"
        ? "Checking API readiness…"
        : readiness === "ready"
          ? "API is ready"
          : "API is not ready"}
    </span>
  );
}

function initialID() {
  return new URLSearchParams(window.location.search).get("investigation") ?? "";
}

export default function App() {
  const [input, setInput] = useState(initialID);
  const [investigationID, setInvestigationID] = useState(() =>
    isID(initialID()) ? initialID().toLowerCase() : "",
  );
  const [error, setError] = useState(() =>
    initialID() && !isID(initialID()) ? "请输入有效的 UUID。" : "",
  );
  useEffect(() => {
    function navigate() {
      const value = initialID();
      setInput(value);
      setInvestigationID(isID(value) ? value.toLowerCase() : "");
      setError(value && !isID(value) ? "请输入有效的 UUID。" : "");
    }
    window.addEventListener("popstate", navigate);
    return () => window.removeEventListener("popstate", navigate);
  }, []);

  return (
    <>
      <header className="topbar">
        <div className="brand">
          Relythra <span>发布风险诊断</span>
        </div>
        <Readiness />
      </header>
      <main className="shell">
        <div className="page-heading">
          <div>
            <p className="eyebrow">INVESTIGATION / v0</p>
            <h1>故障调查</h1>
          </div>
          <span className="badge">只读</span>
        </div>
        <form
          className="lookup"
          onSubmit={(event) => {
            event.preventDefault();
            const value = input.trim().toLowerCase();
            if (!isID(value)) {
              setError("请输入有效的 UUID。");
              return;
            }
            setError("");
            setInput(value);
            setInvestigationID(value);
            const url = new URL(window.location.href);
            url.searchParams.set("investigation", value);
            window.history.pushState(null, "", url);
          }}
        >
          <label htmlFor="investigation-id">Investigation ID</label>
          <div className="lookup-controls">
            <input
              id="investigation-id"
              value={input}
              onChange={(event) => setInput(event.target.value)}
              autoComplete="off"
              spellCheck={false}
              aria-invalid={Boolean(error)}
              aria-describedby={error ? "id-error" : undefined}
            />
            <button className="primary" type="submit">
              打开调查
            </button>
          </div>
          {error && (
            <p id="id-error" role="alert">
              {error}
            </p>
          )}
        </form>
        {investigationID ? (
          <InvestigationWorkbench key={investigationID} id={investigationID} />
        ) : (
          <section className="empty-state">
            <h2>尚未选择调查</h2>
            <p>Investigation ID 暂无记录。</p>
          </section>
        )}
      </main>
    </>
  );
}
