import { useEffect, useState } from "react";
import { useNavigate, useParams } from "react-router-dom";
import { api } from "../api/client";
import { SeverityTag, StatusDot } from "../components/Badges";
import type { Finding, Scan } from "../types";

const SEVERITY_ORDER: Record<string, number> = {
  critical: 0,
  high: 1,
  medium: 2,
  low: 3,
  info: 4,
};

export function ScanDetail() {
  const { scanId } = useParams<{ scanId: string }>();
  const navigate = useNavigate();
  const [scan, setScan] = useState<Scan | null>(null);
  const [findings, setFindings] = useState<Finding[]>([]);
  const [error, setError] = useState<string | null>(null);

  async function load() {
    if (!scanId) return;
    try {
      const [scanData, findingsData] = await Promise.all([
        api.getScan(scanId),
        api.listFindings(scanId),
      ]);
      setScan(scanData as Scan);
      const sorted = [...(findingsData as Finding[])].sort(
        (a, b) => SEVERITY_ORDER[a.severity] - SEVERITY_ORDER[b.severity]
      );
      setFindings(sorted);
    } catch (err) {
      setError("Could not load scan.");
    }
  }

  useEffect(() => {
    load();
    const interval = setInterval(() => {
      if (scan?.status === "pending" || scan?.status === "running") {
        load();
      }
    }, 2500);
    return () => clearInterval(interval);
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [scanId, scan?.status]);

  async function handleDelete() {
    if (!scanId) return;
    await api.deleteScan(scanId);
    navigate("/");
  }

  if (error) {
    return (
      <div className="main">
        <div className="error-banner">{error}</div>
      </div>
    );
  }

  if (!scan) {
    return (
      <div className="main">
        <div className="empty-state">Loading...</div>
      </div>
    );
  }

  return (
    <div className="main">
      <div className="page-header">
        <div>
          <h1 style={{ display: "flex", alignItems: "center", gap: 10 }}>
            <StatusDot status={scan.status} />
            {scan.target_base_url}
          </h1>
          <p>
            {scan.modules.join(", ")} &middot; started{" "}
            {scan.started_at ? new Date(scan.started_at).toLocaleString() : "—"}
          </p>
        </div>
        <button className="btn btn--ghost" onClick={handleDelete}>
          Delete scan
        </button>
      </div>

      {scan.status === "failed" && scan.error_message && (
        <div className="error-banner">{scan.error_message}</div>
      )}

      {(scan.status === "pending" || scan.status === "running") && (
        <div className="card" style={{ marginBottom: 20 }}>
          Scan in progress — this view refreshes automatically.
        </div>
      )}

      {scan.status === "completed" && findings.length === 0 && (
        <div className="empty-state card">
          <h3>No findings</h3>
          <p>None of the selected modules flagged an issue on this target.</p>
        </div>
      )}

      {findings.map((f) => (
        <div className="finding" key={f.id}>
          <div className="finding__header">
            <SeverityTag severity={f.severity} />
            <span className="finding__title">{f.title}</span>
            <span className="finding__category">{f.owasp_category}</span>
          </div>
          <div className="finding__body">
            <div className="finding__meta-row">
              <span>
                {f.method} {f.endpoint}
              </span>
              <span>module: {f.module}</span>
            </div>
            <p>{f.description}</p>
            <p>
              <strong>Remediation:</strong> {f.remediation}
            </p>
            {Object.keys(f.evidence).length > 0 && (
              <pre className="finding__evidence">
                {JSON.stringify(f.evidence, null, 2)}
              </pre>
            )}
          </div>
        </div>
      ))}
    </div>
  );
}
