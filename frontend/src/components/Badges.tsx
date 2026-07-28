import type { ScanStatus, Severity } from "../types";

export function SeverityTag({ severity }: { severity: Severity }) {
  return (
    <span className={`severity-tag severity-tag--${severity}`}>
      {severity.toUpperCase()}
    </span>
  );
}

const STATUS_LABEL: Record<ScanStatus, string> = {
  pending: "Queued",
  running: "Running",
  completed: "Completed",
  failed: "Failed",
};

export function StatusDot({ status }: { status: ScanStatus }) {
  return (
    <span
      className={`status-dot status-dot--${status}`}
      title={STATUS_LABEL[status]}
    />
  );
}
