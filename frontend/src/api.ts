export type CaseStatus =
  | "open"
  | "acknowledged"
  | "resolved"
  | "false_positive";

export interface DashboardSummary {
  total_alerts: number;
  open_cases: number;
  critical_alerts: number;
  denied_events: number;
  unresolved_assets: number;
  alerts_by_source: Record<string, number>;
  cases_by_status: Record<CaseStatus, number>;
}

export async function getDashboardSummary(
  accessToken: string,
): Promise<DashboardSummary> {
  const response = await fetch("/v1/dashboard/summary", {
    headers: {
      Authorization: `Bearer ${accessToken}`,
    },
  });

  if (!response.ok) {
    const body = await response.json().catch(() => null);

    throw new Error(
      body?.detail ??
        `The dashboard request failed with HTTP ${response.status}.`,
    );
  }

  return response.json() as Promise<DashboardSummary>;
}

export interface AlertTelemetry {
  source: string;
  source_ip: string;
  destination_ip?: string | null;
  signature?: string | null;
  timestamp?: string | null;
  severity?: number | null;
}

export interface RiskAssessment {
  score: number;
  severity: number;
  reason?: string | null;
}

export interface AccessDecision {
  action: string;
  reason?: string | null;
}

export interface AlertRecord {
  event_id: string;
  status: string;
  telemetry: AlertTelemetry;
  risk_assessment: RiskAssessment | null;
  access_decision: AccessDecision | null;
  error?: string | null;
}

export interface CreateCaseRequest {
  title: string;
  analyst_note?: string;
}

export interface IncidentCase {
  case_id: string;
  alert_event_id: string;
  title: string;
  status: CaseStatus;
  analyst_note?: string | null;
  created_by: string;
  updated_by: string;
}

async function getErrorDetail(response: Response): Promise<string> {
  const body = await response.json().catch(() => null);

  return (
    body?.detail ??
    `The request failed with HTTP ${response.status}.`
  );
}

export async function getAlerts(
  accessToken: string,
): Promise<AlertRecord[]> {
  const response = await fetch("/v1/events", {
    headers: {
      Authorization: `Bearer ${accessToken}`,
    },
  });

  if (!response.ok) {
    throw new Error(await getErrorDetail(response));
  }

  return response.json() as Promise<AlertRecord[]>;
}

export async function createCase(
  accessToken: string,
  eventId: string,
  payload: CreateCaseRequest,
): Promise<IncidentCase> {
  const response = await fetch(`/v1/events/${eventId}/case`, {
    method: "POST",
    headers: {
      Authorization: `Bearer ${accessToken}`,
      "Content-Type": "application/json",
    },
    body: JSON.stringify(payload),
  });

  if (!response.ok) {
    throw new Error(await getErrorDetail(response));
  }

  return response.json() as Promise<IncidentCase>;
}

export interface BehaviorAnalysis {
  analysis_type: string;
  source_ip: string;
  window_start: string;
  window_end: string;
  destination_threshold: number;
  unique_destination_count: number;
  observed_destinations: string[];
  matching_record_count: number;
  evidence_event_ids: string[];
  skipped_invalid_timestamps: number;
  triggered: boolean;
  interpretation: string;
  limitations: string[];
  scope: string;
  source_record_count: number;
  analysis_version: string;
}

export interface BehaviorAnalysisRequest {
  sourceIp: string;
  windowEnd: string;
  windowMinutes: number;
  destinationThreshold: number;
}

export async function getBehaviorAnalysis(
  accessToken: string,
  request: BehaviorAnalysisRequest,
): Promise<BehaviorAnalysis> {
  const params = new URLSearchParams({
    source_ip: request.sourceIp.trim(),
    window_end: request.windowEnd.trim(),
    window_minutes: String(request.windowMinutes),
    destination_threshold: String(request.destinationThreshold),
  });

  const response = await fetch(
    `/v1/behavior/destination-diversity?${params.toString()}`,
    {
      headers: {
        Authorization: `Bearer ${accessToken}`,
      },
    },
  );

  if (!response.ok) {
    const body = await response.json().catch(() => null);
    const detail: unknown = body?.detail;

    let message = `Analysis failed with HTTP ${response.status}.`;

    if (typeof detail === "string") {
      message = detail;
    } else if (Array.isArray(detail)) {
      message = detail
        .map((item: { loc?: unknown[]; msg?: string }) =>
          `${item.loc?.join(".") ?? "request"}: ${
            item.msg ?? "Invalid value"
          }`,
        )
        .join("; ");
    }

    throw new Error(message);
  }

  return response.json() as Promise<BehaviorAnalysis>;
}

export interface PortBehaviorAnalysis {
  analysis_type: string;
  source_ip: string;
  destination_filter: string | null;
  window_start: string;
  window_end: string;
  port_threshold: number;
  unique_port_count: number;
  observed_ports: number[];
  ports_by_destination: Record<string, number[]>;
  matching_record_count: number;
  evidence_event_ids: string[];
  skipped_invalid_timestamps: number;
  skipped_invalid_ports: number;
  triggered: boolean;
  interpretation: string;
  limitations: string[];
  scope: string;
  source_record_count: number;
  analysis_version: string;
}

export interface PortBehaviorAnalysisRequest {
  sourceIp: string;
  windowEnd: string;
  windowMinutes: number;
  portThreshold: number;
  destinationIp?: string;
}

export async function getPortBehaviorAnalysis(
  accessToken: string,
  request: PortBehaviorAnalysisRequest,
): Promise<PortBehaviorAnalysis> {
  const params = new URLSearchParams({
    source_ip: request.sourceIp.trim(),
    window_end: request.windowEnd.trim(),
    window_minutes: String(request.windowMinutes),
    port_threshold: String(request.portThreshold),
  });

  const destinationIp = request.destinationIp?.trim();

  if (destinationIp) {
    params.set("destination_ip", destinationIp);
  }

  const response = await fetch(
    `/v1/behavior/port-diversity?${params.toString()}`,
    {
      headers: {
        Authorization: `Bearer ${accessToken}`,
      },
    },
  );

  if (!response.ok) {
    const body = await response.json().catch(() => null);
    const detail: unknown = body?.detail;

    let message = `Port analysis failed with HTTP ${response.status}.`;

    if (typeof detail === "string") {
      message = detail;
    } else if (Array.isArray(detail)) {
      message = detail
        .map((item: { loc?: unknown[]; msg?: string }) =>
          `${item.loc?.join(".") ?? "request"}: ${
            item.msg ?? "Invalid value"
          }`,
        )
        .join("; ");
    }

    throw new Error(message);
  }

  return response.json() as Promise<PortBehaviorAnalysis>;
}

export type NetworkBehaviorPattern =
  | "neither_threshold_reached"
  | "destination_threshold_only"
  | "port_threshold_only"
  | "both_thresholds_reached";

export interface NetworkBehaviorSummary {
  analysis_type: string;
  source_ip: string;
  window_start: string;
  window_end: string;
  window_minutes: number;
  pattern: NetworkBehaviorPattern;
  triggered: boolean;
  interpretation: string;
  destination_analysis: Omit<
    BehaviorAnalysis,
    "scope" | "source_record_count" | "analysis_version"
  >;
  port_analysis: Omit<
    PortBehaviorAnalysis,
    "scope" | "source_record_count" | "analysis_version"
  >;
  evidence_event_ids: string[];
  shared_evidence_event_ids: string[];
  destination_only_evidence_event_ids: string[];
  port_only_evidence_event_ids: string[];
  limitations: string[];
  scope: string;
  source_record_count: number;
  analysis_version: string;
}

export interface NetworkBehaviorSummaryRequest {
  sourceIp: string;
  windowEnd: string;
  windowMinutes: number;
  destinationThreshold: number;
  portThreshold: number;
}

export async function getNetworkBehaviorSummary(
  accessToken: string,
  request: NetworkBehaviorSummaryRequest,
): Promise<NetworkBehaviorSummary> {
  const params = new URLSearchParams({
    source_ip: request.sourceIp.trim(),
    window_end: request.windowEnd.trim(),
    window_minutes: String(request.windowMinutes),
    destination_threshold: String(request.destinationThreshold),
    port_threshold: String(request.portThreshold),
  });

  const response = await fetch(
    `/v1/behavior/network-summary?${params.toString()}`,
    {
      headers: {
        Authorization: `Bearer ${accessToken}`,
      },
    },
  );

  if (!response.ok) {
    const body = await response.json().catch(() => null);
    const detail: unknown = body?.detail;

    let message = `Network summary failed with HTTP ${response.status}.`;

    if (typeof detail === "string") {
      message = detail;
    } else if (Array.isArray(detail)) {
      message = detail
        .map((item: { loc?: unknown[]; msg?: string }) =>
          `${item.loc?.join(".") ?? "request"}: ${
            item.msg ?? "Invalid value"
          }`,
        )
        .join("; ");
    }

    throw new Error(message);
  }

  return response.json() as Promise<NetworkBehaviorSummary>;
}