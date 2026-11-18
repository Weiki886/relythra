import { useEffect, useState } from "react";
import { APIError, readAPI } from "./investigation";

type Resource<T> =
  | { state: "loading" }
  | { state: "ready"; data: T }
  | { state: "error"; status: number };

// A key mismatch immediately hides stale results, even before effect cleanup.
export function useReadResource<T extends { investigation_id: string }>(
  url: string,
  decode: (value: unknown) => T,
  investigationID: string,
  expectedEvidenceID?: string,
) {
  const [attempt, setAttempt] = useState(0);
  const key = `${url}:${attempt}`;
  const [result, setResult] = useState<{
    key: string;
    resource: Resource<T>;
  }>();
  useEffect(() => {
    const controller = new AbortController();
    let active = true;
    const timeout = window.setTimeout(() => {
      controller.abort();
      if (active) setResult({ key, resource: { state: "error", status: 0 } });
    }, 15000);
    void readAPI(url, decode, controller.signal)
      .then((data) => {
        if (
          data.investigation_id !== investigationID ||
          (expectedEvidenceID &&
            (!("id" in data) || data.id !== expectedEvidenceID))
        ) {
          throw new Error("Mismatched evidence owner");
        }
        if (active && !controller.signal.aborted)
          setResult({ key, resource: { state: "ready", data } });
      })
      .catch((error: unknown) => {
        if (active && !controller.signal.aborted)
          setResult({
            key,
            resource: {
              state: "error",
              status: error instanceof APIError ? error.status : 0,
            },
          });
      })
      .finally(() => window.clearTimeout(timeout));
    return () => {
      active = false;
      window.clearTimeout(timeout);
      controller.abort();
    };
  }, [url, decode, investigationID, expectedEvidenceID, key]);
  const resource: Resource<T> =
    result?.key === key ? result.resource : { state: "loading" };
  return { resource, retry: () => setAttempt((value) => value + 1) };
}
