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