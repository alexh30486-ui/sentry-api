export type ScanModule = "rate_limit" | "auth_bypass" | "sqli" | "idor";

export const ALL_MODULES: { key: ScanModule; label: string }[] = [
  { key: "rate_limit", label: "Rate Limiting" },
  { key: "auth_bypass", label: "Auth Bypass" },
  { key: "sqli", label: "SQL Injection" },
  { key: "idor", label: "IDOR" },
];

export type ScanStatus = "pending" | "running" | "completed" | "failed";

export interface Scan {
  id: string;
  target_base_url: string;
  status: ScanStatus;
  modules: ScanModule[];
  created_at: string;
  started_at: string | null;
  completed_at: string | null;
  error_message: string | null;
}

export interface ScanSummary extends Scan {
  finding_count: number;
  critical_count: number;
  high_count: number;
}

export type Severity = "info" | "low" | "medium" | "high" | "critical";

export interface Finding {
  id: string;
  scan_id: string;
  module: string;
  owasp_category: string;
  title: string;
  severity: Severity;
  endpoint: string;
  method: string;
  description: string;
  evidence: Record<string, unknown>;
  remediation: string;
  created_at: string;
}

export interface User {
  id: string;
  email: string;
  full_name: string | null;
  is_active: boolean;
}
