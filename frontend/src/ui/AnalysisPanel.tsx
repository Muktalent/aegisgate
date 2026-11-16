import { useState } from "react";

import { api, canAct, dateTime, titleCase, type Detection, type Role } from "../client";
import { ActionControls, RequestAction, StateBadge } from "./responses";
import { DecisionBadge, ErrorNotice, Icon, LevelBadge, State } from "./parts";
import { useLoad } from "./pages";

interface Props {
  role: Role;
  groupId: string | null;
  version: number;
  onChanged: () => void;
}

function observation(detection: Detection): string {
  const o = detection.observations;
  const pick = (key: string) => (typeof o[key] === "number" || typeof o[key] === "string" ? String(o[key]) : null);
  switch (detection.category) {
    case "port_scan": return `${pick("distinct_port_count")} different ports contacted within ${pick("window_seconds")} seconds`;
    case "destination_scan": return `${pick("distinct_destination_count")} different hosts contacted within ${pick("window_seconds")} seconds`;
    case "suspicious_outbound": return `${pick("connection_count")} connections to ${pick("destination_ip")} about every ${pick("mean_interval_seconds")} seconds`;
    case "potential_exfiltration": return `${pick("outbound_bytes")} bytes sent to external destinations`;
    case "ids_alert": return `Suricata alert: ${pick("signature") ?? "signature not reported"} (${pick("alert_count")}×)`;
    default: return detection.explanation;
  }
}

/** Right-hand contextual analysis: assessment, evidence, risk, policy, actions. */
export function AnalysisPanel({ role, groupId, version, onChanged }: Props) {
  const { data, error, loading, retry } = useLoad(
    () => (groupId ? api.finding(groupId) : Promise.resolve(null)), `${version}:${groupId ?? ""}`,
  );
  const responses = useLoad(
    () => (groupId ? api.responses({ groupId }) : Promise.resolve(null)), `${version}:${groupId ?? ""}:responses`,
  );
  const catalogue = useLoad(api.catalogue, "catalogue");
  const [busy, setBusy] = useState(false);
  const [message, setMessage] = useState<{ tone: "ok" | "error"; text: string } | null>(null);

  const header = <div className="panel-tabs"><span>Security analysis</span></div>;

  if (!groupId) {
    return <aside className="panel" aria-label="Security analysis">{header}
      <State title="No finding selected">Select a finding in Threat Detection, or run the analysis, to see its evidence and the resulting decision.</State>
    </aside>;
  }
  if (error) return <aside className="panel" aria-label="Security analysis">{header}<ErrorNotice message={error} onRetry={retry} /></aside>;
  if (!data || data.group_id !== groupId) {
    return <aside className="panel" aria-label="Security analysis">{header}<State title={loading ? "Loading analysis…" : "No data"} /></aside>;
  }

  const risk = data.risk_assessment;
  const policy = data.policy_decision;
  const firstEvent = data.detections[0]?.supporting_events[0];
  const mayAct = canAct(role);

  async function openInvestigation() {
    if (!firstEvent || !data) return;
    setBusy(true); setMessage(null);
    try {
      const created = await api.createCase(firstEvent, `${titleCase(data.finding)} — ${data.source_ip}`,
        `Opened from finding ${data.group_id}. Risk ${risk.risk_score}/100, decision ${policy.decision}.`);
      setMessage({ tone: "ok", text: `Investigation ${created.case_id.slice(0, 8)} opened.` });
      onChanged();
    } catch (reason) {
      setMessage({ tone: "error", text: reason instanceof Error ? reason.message : "Unable to open the investigation." });
    } finally { setBusy(false); }
  }

  return (
    <aside className="panel" aria-label="Security analysis">
      {header}
      <div className={`alert-head ${data.risk_level}`}>
        <Icon name="target" size={20} />
        <div><b>{titleCase(data.finding)}</b>
          <span className="small muted">{data.asset_id ?? "Source not in inventory"} · {data.source_ip} · {dateTime(data.window_start)}</span></div>
        <LevelBadge level={data.risk_level} />
      </div>
      {!data.is_current && (
        <div className="notice warn" style={{ marginTop: 10 }}><Icon name="info" />
          <div><b>Superseded</b>A later analysis replaced this finding. It is kept for the record.</div></div>
      )}

      <section><h3>Threat assessment</h3><p>{data.explanation}</p></section>

      <section>
        <h3>Supporting evidence</h3>
        <ul className="evidence-list">
          {data.detections.map((detection) => (
            <li key={detection.detection_id}>{observation(detection)}{" "}
              <span className="muted small">({detection.rule_id}, {detection.supporting_events.length} event{detection.supporting_events.length === 1 ? "" : "s"})</span></li>
          ))}
          {data.baseline && <li>{data.baseline.status === "insufficient_baseline_data"
            ? "Behavioural baseline: insufficient baseline data" : data.baseline.explanation}</li>}
        </ul>
        <details className="small" style={{ marginTop: 6 }}>
          <summary>Limits of this evidence</summary>
          <ul style={{ paddingLeft: 18, margin: "6px 0 0" }}>
            {Array.from(new Set(data.detections.flatMap((d) => d.limitations))).map((line) => <li key={line}>{line}</li>)}
          </ul>
        </details>
      </section>

      <section>
        <h3>Risk evaluation</h3>
        <div className="triple">
          <div><span>Risk score</span><strong>{risk.risk_score}<small> / 100</small></strong></div>
          <div><span>Confidence</span><strong>{Math.round(risk.detection_confidence * 100)}<small> %</small></strong></div>
          <div><span>Asset criticality</span>{risk.asset_criticality
            ? <LevelBadge level={risk.asset_criticality} /> : <span className="badge">Unknown</span>}</div>
        </div>
        <ul className="factors">
          {risk.factors.map((factor) => (
            <li key={factor.factor}><span>{titleCase(factor.factor)}</span>
              <b>{factor.contribution > 0 ? "+" : ""}{factor.contribution}</b><em>{factor.detail}</em></li>
          ))}
        </ul>
        {risk.missing_context.length > 0 && (
          <p className="small muted" style={{ marginTop: 8 }}>Not available: {risk.missing_context.map(titleCase).join(", ").toLowerCase()}.</p>
        )}
      </section>

      <section>
        <h3>Policy decision</h3>
        <div className="notice"><Icon name="shield" />
          <div><b><DecisionBadge decision={policy.decision} /></b>{policy.explanation}
            <div className="muted" style={{ marginTop: 4 }}>{policy.policy_version} · {risk.model_version}</div></div></div>
      </section>

      <section>
        <h3>Recommended actions</h3>
        {policy.recommended_actions.length > 0
          ? <p className="small" style={{ marginBottom: 8 }}>Policy recommends: {policy.recommended_actions.map(titleCase).join(", ")}.</p>
          : <p className="small muted" style={{ marginBottom: 8 }}>The policy recommends no action.</p>}
        {(responses.data?.items ?? []).length > 0 && (
          <ul className="action-list">
            {responses.data!.items.map((action) => (
              <li key={action.action_id}>
                <div><b>{titleCase(action.action_type)}</b> <StateBadge state={action.state} />
                  <div className="muted small">{action.requested_by} · {dateTime(action.updated_at)}</div></div>
                <ActionControls action={action} role={role} onChanged={onChanged} />
              </li>
            ))}
          </ul>
        )}
        <div className="stack" style={{ gap: 8 }}>
          {mayAct && data.is_current && catalogue.data && (
            <RequestAction groupId={data.group_id} catalogue={catalogue.data.items}
              recommended={policy.recommended_actions} onCreated={onChanged} />
          )}
          <button className="btn block" type="button" onClick={openInvestigation} disabled={!mayAct || busy || !firstEvent}>
            <Icon name="folder" size={16} />{busy ? "Opening…" : "Open investigation"}</button>
        </div>
        {!mayAct && <p className="small muted" style={{ marginTop: 6 }}>Your role can view findings but not act on them.</p>}
        {message && <p role={message.tone === "error" ? "alert" : "status"} className="small"
          style={{ marginTop: 8, color: message.tone === "error" ? "var(--critical)" : "var(--ink-2)" }}>{message.text}</p>}
      </section>

      <section>
        <div className="notice"><Icon name="info" />
          <div><b>Academic mode</b>Decisions are recommendations. No real network block is applied.</div></div>
      </section>
    </aside>
  );
}
