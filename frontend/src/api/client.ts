const TOKEN_KEY = "scanner_token";

export function getToken(): string | null {
  return sessionStorage.getItem(TOKEN_KEY);
}

export function setToken(token: string): void {
  sessionStorage.setItem(TOKEN_KEY, token);
}

export function clearToken(): void {
  sessionStorage.removeItem(TOKEN_KEY);
}

class ApiError extends Error {
  status: number;
  constructor(status: number, message: string) {
    super(message);
    this.status = status;
  }
}

async function request<T>(
  path: string,
  options: RequestInit = {}
): Promise<T> {
  const token = getToken();
  const headers: Record<string, string> = {
    "Content-Type": "application/json",
    ...(options.headers as Record<string, string>),
  };
  if (token) {
    headers["Authorization"] = `Bearer ${token}`;
  }

  const res = await fetch(`/api${path}`, { ...options, headers });

  if (res.status === 204) {
    return undefined as T;
  }

  const data = await res.json().catch(() => ({}));

  if (!res.ok) {
    const message =
      typeof data.detail === "string" ? data.detail : "Request failed";
    throw new ApiError(res.status, message);
  }

  return data as T;
}

export const api = {
  register: (email: string, password: string, full_name?: string) =>
    request("/auth/register", {
      method: "POST",
      body: JSON.stringify({ email, password, full_name }),
    }),

  login: (email: string, password: string) =>
    request<{ access_token: string; token_type: string }>("/auth/login", {
      method: "POST",
      body: JSON.stringify({ email, password }),
    }),

  me: () => request("/auth/me"),

  listScans: () => request("/scans"),

  createScan: (payload: {
    target_base_url: string;
    modules: string[];
    endpoints: string[];
    auth_header?: string;
  }) =>
    request("/scans", {
      method: "POST",
      body: JSON.stringify(payload),
    }),

  getScan: (id: string) => request(`/scans/${id}`),

  deleteScan: (id: string) => request(`/scans/${id}`, { method: "DELETE" }),

  listFindings: (scanId: string) => request(`/scans/${scanId}/findings`),
};

export { ApiError };
