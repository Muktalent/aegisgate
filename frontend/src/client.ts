// Typed client for the AegisGate API. The session lives in an HttpOnly cookie;
// the CSRF token is kept in memory only and sent on every state-changing call.

export type Role = "security_admin" | "soc_analyst" | "viewer" | "ingestor";
export type Level = "critical" | "high" | "medium" | "low" | "informational";
export type Severity = "critical" | "high" | "medium" | "low";

export interface Session { username: string; role: Role; csrf_token: string | null }

export interface Overview {
  academic_mode: boolean;
  generated_at: string;
  counts: {
    monitored_assets: number; unidentified_sources: number; events: number;
    current_detections: number; current_findings: number; open_investigations: number;
    response_actions: number | null;
  };
  findings_by_level: Record<Level, number>;
  highest_risk: { group_id: string; risk_score: number; risk_level: Level; finding: string; source_ip: string } | null;
  attention: {
    high_severity_detections: number; findings_awaiting_review: number;
    unidentified_sources: number; restrictive_recommendations: number;
  };
  detection_trend: Array<{ hour: string } & Record<Severity, number>>;
  recent_events: EventRow[];
  assets_by_status: Record<AssetStatus, number>;
  system: { api: string; database: string; last_analysis_at: string | null };
}

export interface EventRow {
  event_id: string; timestamp: string; source: string; event_type: string; source_ip: string;
  destination_ip: string | null; destination_port: number | null; signature: string | null;
  asset_name: string | null;
}

export type AssetStatus = "normal" | "under_review" | "at_risk" | "unknown";

export interface Asset {
  asset_id: string | null; ip_address: string; device_name: string | null; user_id: string | null;
  location: string | null; criticality: string | null; identified: boolean; status: AssetStatus;
  event_count: number; detection_count: number; finding_count: number;
  highest_risk: number | null; last_seen: string | null;
}

export interface FindingSummary {
  group_id: string; finding: string; source_ip: string; asset_id: string | null; scope: string;
  window_start: string; window_end: string; risk_score: number; risk_level: Level;
  detection_confidence: number; decision: string; categories: string[]; explanation: string;
  is_current: boolean;
}

export interface Detection {
  detection_id: string; rule_id: string; rule_version: string; category: string; source_ip: string;
  severity: Severity; confidence: number; window_start: string; window_end: string;
  supporting_events: string[]; observations: Record<string, unknown>; explanation: string;
  limitations: string[]; group_id: string | null; scope?: string;
}

export interface FindingDetail extends FindingSummary {
  baseline: { status: string; metric: string; explanation: string; deviation: number | null } | null;
  risk_assessment: {
    risk_score: number; risk_level: Level; detection_confidence: number; max_severity: string | null;
    asset_criticality: string | null; asset_identified: boolean; corroborating_categories: number;
    factors: Array<{ factor: string; contribution: number; detail: string }>;
    missing_context: string[]; explanation: string; model_version: string;
  };
  policy_decision: {
    decision: string; recommended_actions: string[]; requires_human_approval: boolean;
    conditions: string[]; explanation: string; policy_version: string;
  };
  versions: Record<string, string>;
  detections: Detection[];
}

export interface StoredEvent {
  event_id: string | null; status: string;
  telemetry: {
    source: string; event_type: string; timestamp: string; source_ip: string;
    destination_ip?: string | null; destination_port?: number | null; protocol?: string | null;
    signature?: string | null;
  };
}

export type CaseStatus = "open" | "acknowledged" | "resolved" | "false_positive";

export interface IncidentCase {
  case_id: string; alert_event_id: string; status: CaseStatus; title: string;
  analyst_note: string | null; created_at: string; updated_at: string;
  created_by: string; updated_by: string;
}

export interface AnalysisSummary {
  events_analysed: number; detection_count: number; finding_count: number; completed_at: string;
  suppressed_count?: number;
  suppressed?: Array<{ detection_id: string; rule_id: string; category: string; source_ip: string; entry_id: string; reason: string }>;
}

interface Page<T> { total: number; items: T[] }

export type ActionState = "proposed" | "pending_approval" | "approved" | "rejected"
  | "executed_in_simulation" | "rolled_back" | "failed";
export type Operation = "approve" | "reject" | "execute" | "rollback";

export interface CatalogueItem {
  action_type: string; impact: "low" | "high"; effect: string; target_state: string; requires_approval: boolean;
}

export interface ResponseAction {
  action_id: string; group_id: string; source_ip: string; asset_id: string | null; action_type: string;
  impact: "low" | "high"; state: ActionState; reason: string; requested_by: string; requested_at: string;
  updated_at: string; simulated: boolean;
  outcome: { simulated: boolean; adapter: string; effect: string; target_state: string;
    real_infrastructure_changed: boolean } | null;
  history: Array<{ at: string; by: string; role: string; operation: string; state: string; note: string | null }>;
}

export interface AuditEntry {
  audit_id: number; occurred_at: string; actor: string; action: string; target_type: string;
  target_id: string; details: Record<string, unknown>;
}

export interface AuditVerification {
  valid: boolean; checked: number; first_invalid_audit_id: number | null; reason: string | null;
  latest_hash?: string | null; algorithm: string; total_entries: number; sealed_entries: number;
  entries_not_covered: number; first_sealed_audit_id: number | null; limitation: string; verified_at: string;
}

export interface Scenario {
  scenario_id: string; title: string; description: string; ground_truth: "malicious" | "benign";
  source_ip: string; notes: string;
  expected: { rules: string[]; finding: string | null; decision: string | null };
  last_run: ScenarioRun | null;
}

export interface ScenarioRun {
  run_id: string; scenario_id: string; started_by: string; started_at: string;
  events_ingested: number; baseline_events: number; detection_count: number; finding_count: number;
  finding: { group_id: string; finding: string; risk_score: number; risk_level: Level; decision: string } | null;
  comparison: {
    matches_expected: boolean; checks: { rules: boolean; finding: boolean; decision: boolean };
    expected: { rules: string[]; finding: string | null; decision: string | null };
    actual: { rules: string[]; finding: string | null; decision: string | null };
  };
  ground_truth: string;
}

export interface Metric {
  approach: "rule_based" | "anomaly_based" | "combined";
  true_positives: number; false_positives: number; true_negatives: number; false_negatives: number;
  precision: number | null; recall: number | null; false_positive_rate: number | null; f1: number | null;
  median_latency_seconds: number | null; max_latency_seconds: number | null;
}

export interface Evaluation {
  run_id: string; started_by: string; started_at: string; evaluation_version: string;
  data_provenance: string; case_count: number; malicious_cases: number; benign_cases: number;
  variants_per_family: number; definitions: Record<string, string>; metrics: Metric[];
  by_family: Array<{ family: string; label: string; description: string; cases: number;
    rule_based: number; anomaly_based: number; combined: number }>;
  limitations: string[];
  allowlist_comparison?: {
    description: string; entries: AllowEntryCore[]; metrics: Metric[];
    by_family: Evaluation["by_family"];
    changed_cases: Array<{ case_id: string; family: string; label: string; suppressed_by: string[] } &
      Record<"rule_based" | "anomaly_based" | "combined", { before: boolean; after: boolean }>>;
  };
}

export interface AllowEntryCore {
  entry_id: string; source_ip: string; destinations: string[]; ports: number[]; categories: string[]; reason: string;
}

export interface AllowEntry extends AllowEntryCore {
  active: boolean; created_by: string; created_at: string | null;
  disabled_by: string | null; disabled_at: string | null; disabled_note: string | null;
}

export interface UserRow {
  username: string; role: Role; is_active: boolean; created_at: string | null; last_login_at: string | null;
}

export interface ImportResult {
  import_id: string; filename: string; sha256: string; size_bytes: number; imported_by: string;
  imported_at: string; records_read: number; stored: number; duplicates_skipped: number; rejected: number;
  unresolved_sources: number; by_sensor: Record<string, number>;
  errors: Array<{ line: number; reason: string }>; errors_truncated: boolean;
  analysis: AnalysisSummary | null;
}

export class ApiError extends Error {
  status: number;
  constructor(status: number, message: string) {
    super(message);
    this.status = status;
  }
}

let csrfToken: string | null = null;
let onUnauthorised: (() => void) | null = null;

export function setUnauthorisedHandler(handler: (() => void) | null): void {
  onUnauthorised = handler;
}

function describe(detail: unknown, status: number): string {
  if (typeof detail === "string") return detail;
  if (Array.isArray(detail)) {
    return detail
      .map((item: { loc?: unknown[]; msg?: string }) => `${item.loc?.slice(1).join(".") ?? "request"}: ${item.msg ?? "invalid"}`)
      .join("; ");
  }
  return `The request failed (HTTP ${status}).`;
}

async function request<T>(method: string, path: string, body?: unknown, signOutOn401 = true): Promise<T> {
  const headers: Record<string, string> = {};
  const isForm = body instanceof FormData;
  if (body !== undefined && !isForm) headers["Content-Type"] = "application/json";
  if (method !== "GET" && csrfToken) headers["X-CSRF-Token"] = csrfToken;

  let response: Response;
  try {
    response = await fetch(path, {
      method, headers, credentials: "same-origin",
      body: body === undefined ? undefined : isForm ? body : JSON.stringify(body),
    });
  } catch {
    throw new ApiError(0, "The AegisGate API cannot be reached. Check that the backend is running.");
  }

  if (!response.ok) {
    const payload = (await response.json().catch(() => null)) as { detail?: unknown } | null;
    if (response.status === 401 && signOutOn401) onUnauthorised?.();
    throw new ApiError(response.status, describe(payload?.detail, response.status));
  }
  return (await response.json()) as T;
}

export const api = {
  async login(username: string, password: string): Promise<Session> {
    const session = await request<Session>("POST", "/api/v1/auth/login", { username, password }, false);
    csrfToken = session.csrf_token;
    return session;
  },
  async me(): Promise<Session> {
    const session = await request<Session>("GET", "/api/v1/auth/me", undefined, false);
    csrfToken = session.csrf_token;
    return session;
  },
  async logout(): Promise<void> {
    try {
      await request<unknown>("POST", "/api/v1/auth/logout", undefined, false);
    } finally {
      csrfToken = null;
    }
  },
  overview: () => request<Overview>("GET", "/api/v1/dashboard/overview"),
  assets: () => request<Page<Asset>>("GET", "/api/v1/assets"),
  findings: () => request<Page<FindingSummary>>("GET", "/api/v1/findings"),
  finding: (id: string) => request<FindingDetail>("GET", `/api/v1/findings/${encodeURIComponent(id)}`),
  detections: () => request<Page<Detection>>("GET", "/api/v1/detections"),
  runAnalysis: () => request<AnalysisSummary>("POST", "/api/v1/analysis/run"),
  events: () => request<StoredEvent[]>("GET", "/v1/events"),
  cases: () => request<IncidentCase[]>("GET", "/v1/cases"),
  createCase: (eventId: string, title: string, note: string) =>
    request<IncidentCase>("POST", `/v1/events/${encodeURIComponent(eventId)}/case`,
      { title, analyst_note: note || undefined }),
  updateCase: (caseId: string, status: CaseStatus, note: string) =>
    request<IncidentCase>("PATCH", `/v1/cases/${encodeURIComponent(caseId)}`,
      { status, analyst_note: note }),

  catalogue: () => request<{ simulated_only: boolean; items: CatalogueItem[] }>("GET", "/api/v1/responses/catalogue"),
  responses: (filter: { state?: string; groupId?: string } = {}) => {
    const params = new URLSearchParams();
    if (filter.state) params.set("state", filter.state);
    if (filter.groupId) params.set("group_id", filter.groupId);
    const query = params.toString();
    return request<Page<ResponseAction>>("GET", `/api/v1/responses${query ? `?${query}` : ""}`);
  },
  requestResponse: (groupId: string, actionType: string, reason: string) =>
    request<ResponseAction>("POST", "/api/v1/responses", { group_id: groupId, action_type: actionType, reason }),
  operateResponse: (actionId: string, operation: Operation, note?: string) =>
    request<ResponseAction>("POST", `/api/v1/responses/${encodeURIComponent(actionId)}/${operation}`,
      { note: note || null }),

  audit: (filter: { action?: string; actor?: string; limit?: number } = {}) => {
    const params = new URLSearchParams({ limit: String(filter.limit ?? 200) });
    if (filter.action) params.set("action", filter.action);
    if (filter.actor) params.set("actor", filter.actor);
    return request<Page<AuditEntry> & { actions: string[] }>("GET", `/api/v1/audit?${params.toString()}`);
  },
  verifyAudit: () => request<AuditVerification>("GET", "/api/v1/audit/verify"),

  scenarios: () => request<{ data_provenance: string; items: Scenario[] }>("GET", "/api/v1/demo/scenarios"),
  runScenario: (id: string) => request<ScenarioRun>("POST", `/api/v1/demo/scenarios/${encodeURIComponent(id)}/run`),
  runEvaluation: () => request<Evaluation>("POST", "/api/v1/demo/evaluation"),
  async latestEvaluation(): Promise<Evaluation | null> {
    try {
      return await request<Evaluation>("GET", "/api/v1/demo/evaluation/latest");
    } catch (error) {
      if (error instanceof ApiError && error.status === 404) return null;
      throw error;
    }
  },

  users: () => request<Page<UserRow>>("GET", "/api/v1/users"),
  allowlist: () => request<{ items: AllowEntry[]; categories: string[] }>("GET", "/api/v1/allowlist"),
  createAllowEntry: (entry: { source_ip: string; destinations: string[]; ports: number[]; categories: string[]; reason: string }) =>
    request<AllowEntry>("POST", "/api/v1/allowlist", entry),
  disableAllowEntry: (entryId: string, note: string) =>
    request<AllowEntry>("POST", `/api/v1/allowlist/${encodeURIComponent(entryId)}/disable`, { note }),
  createUser: (username: string, password: string, role: Role) =>
    request<UserRow>("POST", "/api/v1/users", { username, password, role }),
  updateUser: (username: string, change: { role?: Role; is_active?: boolean; password?: string }) =>
    request<UserRow>("PATCH", `/api/v1/users/${encodeURIComponent(username)}`, change),

  importTelemetry: (file: File, analyse: boolean) => {
    const form = new FormData();
    form.append("file", file);
    form.append("analyse", analyse ? "true" : "false");
    return request<ImportResult>("POST", "/api/v1/ingest/upload", form);
  },
  imports: () => request<Page<ImportResult>>("GET", "/api/v1/ingest/imports"),
};

export function canImport(role: Role): boolean {
  return role === "security_admin" || role === "ingestor";
}

export function percent(value: number | null): string {
  return value === null ? "—" : `${Math.round(value * 1000) / 10}%`;
}

export function canAct(role: Role): boolean {
  return role === "security_admin" || role === "soc_analyst";
}

export function titleCase(value: string): string {
  const text = value.replaceAll("_", " ").replace(/\bids\b/gi, "IDS");
  return text.charAt(0).toUpperCase() + text.slice(1);
}

export function clock(iso: string | null | undefined): string {
  if (!iso) return "—";
  const date = new Date(iso);
  if (Number.isNaN(date.getTime())) return "—";
  return date.toISOString().slice(11, 19);
}

export function dateTime(iso: string | null | undefined): string {
  if (!iso) return "—";
  const date = new Date(iso);
  if (Number.isNaN(date.getTime())) return "—";
  return `${date.toISOString().slice(0, 10)} ${date.toISOString().slice(11, 19)} UTC`;
}
