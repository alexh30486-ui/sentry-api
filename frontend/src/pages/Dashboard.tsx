import { useEffect, useState } from "react";
import { Link } from "react-router-dom";
import { api } from "../api/client";
import { SeverityTag, StatusDot } from "../components/Badges";
import type { ScanSummary } from "../types";

function timeAgo(iso: string): string {
  const diffMs = Date.now() - new Date(iso).getTime();
  const mins = Math.floor(diffMs / 60000);
  if (mins < 1) return "just now";
  if (mins < 60) return `${mins}m ago`;
  const hrs = Math.floor(mins / 60);
  if (hrs < 24) return `${hrs}h ago`;
  return `${Math.floor(hrs / 24)}d ago`;
}

export function Dashboard() {
  const [scans, setScans] = useState<ScanSummary[] | null>(null);
  const [error, setError] = useState<string | null>(null);

  async function load() {
    try {
      const data = await api.listScans();
      setScans(data as ScanSummary[]);
    } catch (err) {
      setError("Could not load scans.");
    }
  }

  useEffect(() => {
    load();
    const interval = setInterval(load, 4000);
    return () => clearInterval(interval);
  }, []);

  return (
    <div className="main">
      <div className="page-header">
        <div>
          <h1>Scans</h1>
          <p>Vulnerability scans against your registered API targets.</p>
        </div>
        <Link to="/scans/new" className="btn btn--primary">
          + New scan
        </Link>
      </div>

      {error && <div className="error-banner">{error}</div>}

      {scans === null && !error && (
        <div className="empty-state">Loading...</div>
      )}

      {scans && scans.length === 0 && (
        <div className="empty-state card">
          <h3>No scans yet</h3>
          <p>Kick off your first scan to see OWASP API Top 10 findings here.</p>
        </div>
      )}

      {scans && scans.length > 0 && (
        <div className="scan-list">
          {scans.map((scan) => (
            <Link to={`/scans/${scan.id}`} key={scan.id} className="scan-row">
              <StatusDot status={scan.status} />
              <span className="scan-row__target">{scan.target_base_url}</span>
              {scan.critical_count > 0 && (
                <SeverityTag severity="critical" />
              )}
              {scan.high_count > 0 && <SeverityTag severity="high" />}
              <span className="finding-count-pill">
                {scan.finding_count} finding{scan.finding_count === 1 ? "" : "s"}
              </span>
              <span className="scan-row__meta">{timeAgo(scan.created_at)}</span>
            </Link>
          ))}
        </div>
      )}
    </div>
  );
}
