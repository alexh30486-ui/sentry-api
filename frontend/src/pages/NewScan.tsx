import { useState, type FormEvent } from "react";
import { useNavigate } from "react-router-dom";
import { api, ApiError } from "../api/client";
import { ALL_MODULES, type ScanModule } from "../types";

export function NewScan() {
  const navigate = useNavigate();
  const [targetUrl, setTargetUrl] = useState("http://localhost:8000");
  const [endpointsRaw, setEndpointsRaw] = useState(
    "/api/users/{id}\n/api/orders/{order_id}"
  );
  const [authHeader, setAuthHeader] = useState("");
  const [modules, setModules] = useState<Set<ScanModule>>(
    new Set(ALL_MODULES.map((m) => m.key))
  );
  const [error, setError] = useState<string | null>(null);
  const [submitting, setSubmitting] = useState(false);

  function toggleModule(key: ScanModule) {
    setModules((prev) => {
      const next = new Set(prev);
      if (next.has(key)) next.delete(key);
      else next.add(key);
      return next;
    });
  }

  async function handleSubmit(e: FormEvent) {
    e.preventDefault();
    setError(null);
    setSubmitting(true);
    try {
      const endpoints = endpointsRaw
        .split("\n")
        .map((l) => l.trim())
        .filter(Boolean);

      const scan = await api.createScan({
        target_base_url: targetUrl,
        modules: Array.from(modules),
        endpoints,
        auth_header: authHeader || undefined,
      });
      navigate(`/scans/${(scan as { id: string }).id}`);
    } catch (err) {
      setError(err instanceof ApiError ? err.message : "Could not start scan");
    } finally {
      setSubmitting(false);
    }
  }

  return (
    <div className="main">
      <div className="page-header">
        <div>
          <h1>New scan</h1>
          <p>
            Only scan APIs you own or are explicitly authorized to test. The
            target host must be on the server's allow-list.
          </p>
        </div>
      </div>

      {error && <div className="error-banner">{error}</div>}

      <div className="card">
        <form className="form-grid" onSubmit={handleSubmit}>
          <div className="field">
            <label>Target base URL</label>
            <input
              value={targetUrl}
              onChange={(e) => setTargetUrl(e.target.value)}
              placeholder="http://localhost:8000"
              required
            />
            <small>
              e.g. http://localhost:8000 for an API running alongside this
              scanner in Docker.
            </small>
          </div>

          <div className="field">
            <label>Endpoints to test (one per line)</label>
            <textarea
              rows={4}
              value={endpointsRaw}
              onChange={(e) => setEndpointsRaw(e.target.value)}
              placeholder="/api/users/{id}"
            />
            <small>
              Use curly braces for path params, e.g. /api/orders/{"{"}
              order_id{"}"}. The IDOR and SQLi modules substitute values into
              these placeholders.
            </small>
          </div>

          <div className="field">
            <label>Modules</label>
            <div className="checkbox-row">
              {ALL_MODULES.map((m) => (
                <div
                  key={m.key}
                  className={`checkbox-pill ${
                    modules.has(m.key) ? "checkbox-pill--active" : ""
                  }`}
                  onClick={() => toggleModule(m.key)}
                >
                  {m.label}
                </div>
              ))}
            </div>
          </div>

          <div className="field">
            <label>Authorization header (optional)</label>
            <input
              value={authHeader}
              onChange={(e) => setAuthHeader(e.target.value)}
              placeholder="Bearer eyJhbGciOi..."
            />
            <small>
              A valid session token for the target API, used to test IDOR and
              JWT alg-confusion from an authenticated caller's perspective.
            </small>
          </div>

          <button
            className="btn btn--primary"
            type="submit"
            disabled={submitting || modules.size === 0}
          >
            {submitting ? "Starting scan..." : "Start scan"}
          </button>
        </form>
      </div>
    </div>
  );
}
