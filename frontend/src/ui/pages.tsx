import { useCallback, useEffect, useMemo, useState, type FormEvent } from "react";

import {
  api, canAct, canImport, clock, dateTime, titleCase, type ImportResult,
  type Asset, type CaseStatus, type FindingSummary, type IncidentCase, type Overview,
  type Role, type StoredEvent,
} from "../client";
import {
  AssetStatusBreakdown, DecisionBadge, ErrorNotice, Icon, LevelBadge, RiskGauge, State,
  TrendChart, statusLabel,
} from "./parts";

/** Load data on mount and whenever ``key`` changes. */
export function useLoad<T>(loader: () => Promise<T>, key: string | number) {
  const [data, setData] = useState<T | null>(null);
  const [error, setError] = useState<string | null>(null);
  const [loading, setLoading] = useState(true);
  const [attempt, setAttempt] = useState(0);

  useEffect(() => {
    let ignore = false;
    setLoading(true);
    loader()
      .then((value) => { if (!ignore) { setData(value); setError(null); } })
      .catch((reason: unknown) => {
        if (!ignore) setError(reason instanceof Error ? reason.message : "Unable to load data.");
      })
      .finally(() => { if (!ignore) setLoading(false); });
    return () => { ignore = true; };
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [key, attempt]);

  const retry = useCallback(() => setAttempt((n) => n + 1), []);
  return { data, error, loading, retry };
}

export interface PageProps {
  role: Role;
  version: number;                       // bumps after an analysis run or a change
  selected: string | null;               // selected finding (group_id)
  onSelect: (groupId: string | null) => void;
  onChanged: () => void;
}

function Kpi({ icon, tone, value, label, note }: {
  icon: string; tone?: string; value: number | string; label: string; note: string;
}) {
  return (
    <div className="card kpi-card">
      <div className={`kpi-icon ${tone ?? ""}`}><Icon name={icon} size={20} /></div>
      <div><strong>{value}</strong><span>{label}</span><small>{note}</small></div>
    </div>
  );
}

function EventsTable({ rows }: { rows: Overview["recent_events"] }) {
  return (
    <div className="table-wrap">
      <table>
        <thead><tr><th>Time (UTC)</th><th>Event</th><th>Source</th><th>Destination</th><th>Sensor</th></tr></thead>
        <tbody>
          {rows.map((row) => (
            <tr key={row.event_id}>
              <td className="mono">{clock(row.timestamp)}</td>
              <td className="nowrap">{row.signature ?? titleCase(row.event_type)}</td>
              <td>{row.asset_name ?? <span className="muted">Not in inventory</span>} <span className="mono muted">{row.source_ip}</span></td>
              <td className="mono">{row.destination_ip ?? "—"}{row.destination_port ? `:${row.destination_port}` : ""}</td>
              <td>{titleCase(row.source)}</td>
            </tr>
          ))}
        </tbody>
      </table>
    </div>
  );
}

/* ------------------------------ Overview ------------------------------ */
export function OverviewPage({ version, selected, onSelect }: PageProps) {
  const { data, error, loading, retry } = useLoad(api.overview, version);

  useEffect(() => {
    if (data?.highest_risk && selected === null) onSelect(data.highest_risk.group_id);
  }, [data, selected, onSelect]);

  if (error) return <ErrorNotice message={error} onRetry={retry} />;
  if (!data) return <State title={loading ? "Loading the security overview…" : "No data"} />;

  const { counts, attention } = data;
  const attentionRows: Array<[string, string, number]> = [
    ["target", "High-severity detections", attention.high_severity_detections],
    ["folder", "Findings awaiting manual review", attention.findings_awaiting_review],
    ["monitor", "Sources not in the inventory", attention.unidentified_sources],
    ["shield", "Restrictive policy recommendations", attention.restrictive_recommendations],
  ];

  return (
    <div className="stack">
      <div className="grid kpi">
        <Kpi icon="shield" value={counts.monitored_assets} label="Monitored assets"
          note={`${counts.unidentified_sources} source(s) not in inventory`} />
        <Kpi icon="target" tone="risk" value={counts.current_findings} label="Current findings"
          note={`${counts.current_detections} detection(s) · ${counts.events} events stored`} />
        <Kpi icon="folder" value={counts.open_investigations} label="Open investigations" note="Open or acknowledged cases" />
        <Kpi icon="bolt" tone="warn" value={counts.response_actions ?? "—"} label="Response actions"
          note={counts.response_actions === null ? "Response engine not built yet" : "Simulated actions"} />
      </div>

      <div className="grid two">
        <div className="card">
          <h2>Highest current risk</h2>
          <div className="posture">
            <RiskGauge score={data.highest_risk?.risk_score ?? null} level={data.highest_risk?.risk_level ?? null} />
            <div style={{ flex: 1 }}>
              <h3 style={{ marginBottom: 8 }}>Needs attention</h3>
              <ul className="attention">
                {attentionRows.map(([icon, label, value]) => (
                  <li key={label} className={value > 0 ? "on" : ""}><Icon name={icon} size={16} />{label}<b>{value}</b></li>
                ))}
              </ul>
            </div>
          </div>
          <p className="muted small" style={{ marginTop: 10 }}>
            The score is the highest risk among current findings. It is not a measure of overall protection.
          </p>
        </div>
        <div className="card">
          <h2>Detection trend</h2>
          {data.detection_trend.length === 0
            ? <State title="No detections yet">Run the analysis after telemetry has been ingested.</State>
            : <TrendChart data={data.detection_trend} />}
        </div>
      </div>

      <div className="grid wide">
        <div className="card">
          <h2>Recent security events</h2>
          {data.recent_events.length === 0
            ? <State title="No events stored">Ingest Suricata or Zeek telemetry to see activity here.</State>
            : <EventsTable rows={data.recent_events} />}
        </div>
        <div className="card">
          <h2>Assets by status</h2>
          <AssetStatusBreakdown counts={data.assets_by_status} />
        </div>
      </div>
    </div>
  );
}

/* ------------------------------ Live events ------------------------------ */
function ImportPanel({ onImported }: { onImported: () => void }) {
  const [file, setFile] = useState<File | null>(null);
  const [analyse, setAnalyse] = useState(true);
  const [busy, setBusy] = useState(false);
  const [result, setResult] = useState<ImportResult | null>(null);
  const [error, setError] = useState<string | null>(null);

  async function submit(event: FormEvent<HTMLFormElement>) {
    event.preventDefault();
    if (!file) return;
    setBusy(true); setError(null); setResult(null);
    try {
      setResult(await api.importTelemetry(file, analyse));
      onImported();
    } catch (reason) {
      setError(reason instanceof Error ? reason.message : "The import failed.");
    } finally { setBusy(false); }
  }

  return (
    <div className="card">
      <h2>Import telemetry</h2>
      <p className="small muted" style={{ marginBottom: 10 }}>Suricata <code>eve.json</code>, Zeek JSON logs (one JSON
        object per line) or Zeek tab-separated logs such as <code>conn.log</code>, up to 10 MB. Records already imported are skipped.</p>
      <form className="toolbar" onSubmit={submit} style={{ marginBottom: 0 }}>
        <input className="input" type="file" accept=".json,.log,.jsonl,.ndjson,application/json,text/plain"
          aria-label="Telemetry file" disabled={busy} onChange={(e) => setFile(e.target.files?.[0] ?? null)} />
        <label className="small" style={{ display: "inline-flex", gap: 6, alignItems: "center" }}>
          <input type="checkbox" checked={analyse} onChange={(e) => setAnalyse(e.target.checked)} disabled={busy} />
          Run the analysis afterwards</label>
        <button className="btn primary" type="submit" disabled={!file || busy}>{busy ? "Importing…" : "Import"}</button>
      </form>
      {error && <div style={{ marginTop: 10 }}><ErrorNotice message={error} /></div>}
      {result && (
        <div className={`notice ${result.rejected ? "warn" : ""}`} role="status" style={{ marginTop: 10 }}>
          <Icon name={result.rejected ? "info" : "check"} />
          <div><b>{result.filename}: {result.stored} stored, {result.duplicates_skipped} duplicate(s) skipped,{" "}
            {result.rejected} rejected</b>
            {Object.entries(result.by_sensor).map(([k, v]) => `${titleCase(k)} ${v}`).join(" · ")}
            {result.unresolved_sources > 0 && ` · ${result.unresolved_sources} from sources not in the inventory`}
            {result.analysis && <div>Analysis: {result.analysis.detection_count} detection(s), {result.analysis.finding_count} finding(s)
              {result.analysis.suppressed_count ? `, ${result.analysis.suppressed_count} suppressed by the allowlist` : ""}.</div>}
            {result.errors.length > 0 && (
              <details style={{ marginTop: 4 }}><summary>Rejected records</summary>
                <ul style={{ margin: "4px 0 0", paddingLeft: 18 }}>
                  {result.errors.map((e, i) => <li key={i}>Line {e.line}: {e.reason}</li>)}
                  {result.errors_truncated && <li>Only the first {result.errors.length} errors are shown.</li>}
                </ul></details>
            )}
          </div>
        </div>
      )}
    </div>
  );
}

export function EventsPage({ role, version, onChanged }: PageProps) {
  const ingestOnly = role === "ingestor";        // ingestors import telemetry but cannot read it
  const { data, error, loading, retry } = useLoad(
    () => (ingestOnly ? Promise.resolve([] as StoredEvent[]) : api.events()), version);
  const [query, setQuery] = useState("");
  const [source, setSource] = useState("all");

  const rows = useMemo(() => {
    const text = query.trim().toLowerCase();
    return (data ?? []).filter((event: StoredEvent) => {
      const t = event.telemetry;
      if (source !== "all" && t.source !== source) return false;
      if (!text) return true;
      return [event.event_id ?? "", t.source_ip, t.destination_ip ?? "", t.signature ?? "", t.event_type]
        .some((value) => value.toLowerCase().includes(text));
    }).slice(0, 300);
  }, [data, query, source]);

  if (ingestOnly) return <ImportPanel onImported={onChanged} />;
  if (error) return <ErrorNotice message={error} onRetry={retry} />;
  if (!data) return <State title={loading ? "Loading events…" : "No data"} />;

  return (
    <div className="stack">
    {canImport(role) && <ImportPanel onImported={onChanged} />}
    <div className="card">
      <div className="toolbar">
        <input className="input search" placeholder="Search by address, signature, type or event ID"
          value={query} onChange={(e) => setQuery(e.target.value)} aria-label="Search events" />
        <select className="input" value={source} onChange={(e) => setSource(e.target.value)} aria-label="Sensor">
          <option value="all">All sensors</option><option value="suricata">Suricata</option><option value="zeek">Zeek</option>
        </select>
        <span className="muted small num">{rows.length} of {data.length} events</span>
      </div>
      {rows.length === 0 ? <State title="No events match">Change the search or the sensor filter.</State> : (
        <div className="table-wrap">
          <table>
            <thead><tr><th>Event time (UTC)</th><th>Sensor</th><th>Type</th><th>Source</th><th>Destination</th><th>Signature</th><th>Asset</th></tr></thead>
            <tbody>
              {rows.map((event) => (
                <tr key={event.event_id}>
                  <td className="mono">{dateTime(event.telemetry.timestamp)}</td>
                  <td>{titleCase(event.telemetry.source)}</td>
                  <td>{titleCase(event.telemetry.event_type)}</td>
                  <td className="mono">{event.telemetry.source_ip}</td>
                  <td className="mono">{event.telemetry.destination_ip ?? "—"}{event.telemetry.destination_port ? `:${event.telemetry.destination_port}` : ""}</td>
                  <td>{event.telemetry.event_type === "alert" ? event.telemetry.signature ?? "—" : "—"}</td>
                  <td>{event.status === "unresolved_asset" ? <span className="badge">Not in inventory</span> : <span className="badge good">Identified</span>}</td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      )}
    </div>
    </div>
  );
}

/* ------------------------------ Assets ------------------------------ */
export function AssetsPage({ version }: PageProps) {
  const { data, error, loading, retry } = useLoad(api.assets, version);
  const [query, setQuery] = useState("");
  const [status, setStatus] = useState("all");

  if (error) return <ErrorNotice message={error} onRetry={retry} />;
  if (!data) return <State title={loading ? "Loading assets…" : "No data"} />;

  const text = query.trim().toLowerCase();
  const rows = data.items.filter((asset: Asset) =>
    (status === "all" || asset.status === status) &&
    (!text || [asset.ip_address, asset.device_name ?? "", asset.user_id ?? "", asset.asset_id ?? ""]
      .some((value) => value.toLowerCase().includes(text))));

  return (
    <div className="card">
      <div className="toolbar">
        <input className="input search" placeholder="Search by name, address, user or asset ID"
          value={query} onChange={(e) => setQuery(e.target.value)} aria-label="Search assets" />
        <select className="input" value={status} onChange={(e) => setStatus(e.target.value)} aria-label="Status">
          <option value="all">All statuses</option><option value="normal">Normal</option>
          <option value="under_review">Under review</option><option value="at_risk">At risk</option>
          <option value="unknown">Not in inventory</option>
        </select>
      </div>
      {rows.length === 0 ? <State title="No assets match" /> : (
        <div className="table-wrap">
          <table>
            <thead><tr><th>Asset</th><th>Address</th><th>Criticality</th><th>Status</th>
              <th className="right">Events</th><th className="right">Detections</th><th className="right">Highest risk</th><th>Last seen</th></tr></thead>
            <tbody>
              {rows.map((asset) => (
                <tr key={asset.ip_address}>
                  <td><b>{asset.device_name ?? "Unidentified device"}</b>
                    <div className="muted small">{asset.user_id ?? "No inventory record"}</div></td>
                  <td className="mono">{asset.ip_address}</td>
                  <td>{asset.criticality ? <LevelBadge level={asset.criticality} /> : <span className="muted">Unknown</span>}</td>
                  <td><span className={`badge ${asset.status === "at_risk" ? "critical" : asset.status === "under_review" ? "medium" : asset.status === "normal" ? "good" : ""}`}>{statusLabel(asset.status)}</span></td>
                  <td className="right num">{asset.event_count}</td>
                  <td className="right num">{asset.detection_count}</td>
                  <td className="right num">{asset.highest_risk ?? "—"}</td>
                  <td className="mono">{dateTime(asset.last_seen)}</td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      )}
    </div>
  );
}

/* ------------------------------ Threat detection ------------------------------ */
export function DetectionPage({ version, selected, onSelect }: PageProps) {
  const { data, error, loading, retry } = useLoad(api.findings, version);
  const [query, setQuery] = useState("");
  const [level, setLevel] = useState("all");

  if (error) return <ErrorNotice message={error} onRetry={retry} />;
  if (!data) return <State title={loading ? "Loading findings…" : "No data"} />;

  const text = query.trim().toLowerCase();
  const rows = data.items.filter((item: FindingSummary) =>
    (level === "all" || item.risk_level === level) &&
    (!text || [item.finding, item.source_ip, item.asset_id ?? "", ...item.categories]
      .some((value) => value.toLowerCase().includes(text))));

  return (
    <div className="card">
      <div className="toolbar">
        <input className="input search" placeholder="Search by finding, address or asset"
          value={query} onChange={(e) => setQuery(e.target.value)} aria-label="Search findings" />
        <select className="input" value={level} onChange={(e) => setLevel(e.target.value)} aria-label="Risk level">
          <option value="all">All risk levels</option><option value="critical">Critical</option>
          <option value="high">High</option><option value="medium">Medium</option><option value="low">Low</option>
        </select>
        <span className="muted small num">{rows.length} of {data.total} findings</span>
      </div>
      {data.total === 0 ? (
        <State title="No findings yet">Use “Run analysis” to evaluate the stored telemetry.</State>
      ) : rows.length === 0 ? <State title="No findings match" /> : (
        <div className="table-wrap">
          <table>
            <thead><tr><th>Finding</th><th>Source</th><th>Indicators</th><th className="right">Risk</th><th>Level</th><th>Policy decision</th><th>Observed (UTC)</th></tr></thead>
            <tbody>
              {rows.map((item) => (
                <tr key={item.group_id} className="selectable" aria-selected={selected === item.group_id}
                  tabIndex={0} onClick={() => onSelect(item.group_id)}
                  onKeyDown={(e) => { if (e.key === "Enter" || e.key === " ") { e.preventDefault(); onSelect(item.group_id); } }}>
                  <td><b>{titleCase(item.finding)}</b>{item.scope !== "all-events" && <div><span className="badge">Demo Lab</span></div>}</td>
                  <td className="nowrap">{item.source_ip}<div className="muted small">{item.asset_id ?? "Not in inventory"}</div></td>
                  <td>{item.categories.map(titleCase).join(", ")}</td>
                  <td className="right num"><b>{item.risk_score}</b></td>
                  <td><LevelBadge level={item.risk_level} /></td>
                  <td><DecisionBadge decision={item.decision} /></td>
                  <td className="mono">{dateTime(item.window_start)}</td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      )}
      <p className="muted small" style={{ marginTop: 10 }}>Select a finding to see its evidence, risk factors and policy decision in the analysis panel.</p>
    </div>
  );
}

/* ------------------------------ Investigations ------------------------------ */
const NEXT_STATUS: CaseStatus[] = ["acknowledged", "resolved", "false_positive"];

function CaseRow({ item, editable, onSaved }: { item: IncidentCase; editable: boolean; onSaved: () => void }) {
  const [open, setOpen] = useState(false);
  const [busy, setBusy] = useState(false);
  const [message, setMessage] = useState<string | null>(null);

  async function submit(event: FormEvent<HTMLFormElement>) {
    event.preventDefault();
    const form = new FormData(event.currentTarget);
    const note = String(form.get("note") ?? "").trim();
    if (note.length < 3) { setMessage("Add a note of at least three characters."); return; }
    setBusy(true);
    try {
      await api.updateCase(item.case_id, String(form.get("status")) as CaseStatus, note);
      setOpen(false); setMessage(null); onSaved();
    } catch (reason) {
      setMessage(reason instanceof Error ? reason.message : "Unable to update the case.");
    } finally { setBusy(false); }
  }

  const tone = item.status === "open" ? "medium" : item.status === "resolved" ? "good" : "";
  return (
    <>
      <tr>
        <td><b>{item.title}</b><div className="muted small mono">{item.case_id.slice(0, 8)}</div></td>
        <td><span className={`badge ${tone}`}>{titleCase(item.status)}</span></td>
        <td>{item.analyst_note ?? <span className="muted">No note</span>}</td>
        <td>{item.updated_by}<div className="muted small mono">{dateTime(item.updated_at)}</div></td>
        <td className="right">{editable && <button className="btn" type="button" onClick={() => setOpen((v) => !v)}>{open ? "Cancel" : "Update"}</button>}</td>
      </tr>
      {open && (
        <tr><td colSpan={5} style={{ background: "var(--surface-2)" }}>
          <form onSubmit={submit} className="toolbar" style={{ margin: 0 }}>
            <select className="input" name="status" defaultValue="acknowledged" aria-label="New status" disabled={busy}>
              {NEXT_STATUS.map((s) => <option key={s} value={s}>{titleCase(s)}</option>)}
            </select>
            <input className="input search" name="note" placeholder="Analyst note (required)" aria-label="Analyst note" disabled={busy} />
            <button className="btn primary" type="submit" disabled={busy}>{busy ? "Saving…" : "Save"}</button>
            {message && <span role="alert" style={{ color: "var(--critical)" }}>{message}</span>}
          </form>
        </td></tr>
      )}
    </>
  );
}

export function InvestigationsPage({ role, version, onChanged }: PageProps) {
  const { data, error, loading, retry } = useLoad(api.cases, version);
  const [status, setStatus] = useState("all");

  if (error) return <ErrorNotice message={error} onRetry={retry} />;
  if (!data) return <State title={loading ? "Loading investigations…" : "No data"} />;
  const rows = data.filter((item) => status === "all" || item.status === status);

  return (
    <div className="card">
      <div className="toolbar">
        <select className="input" value={status} onChange={(e) => setStatus(e.target.value)} aria-label="Status">
          <option value="all">All statuses</option><option value="open">Open</option>
          <option value="acknowledged">Acknowledged</option><option value="resolved">Resolved</option>
          <option value="false_positive">False positive</option>
        </select>
        <span className="muted small num">{rows.length} of {data.length} investigations</span>
      </div>
      {data.length === 0 ? (
        <State title="No investigations yet">Open one from a finding in the analysis panel.</State>
      ) : rows.length === 0 ? <State title="No investigations match" /> : (
        <div className="table-wrap">
          <table>
            <thead><tr><th>Investigation</th><th>Status</th><th>Latest note</th><th>Last update</th><th /></tr></thead>
            <tbody>{rows.map((item) => <CaseRow key={item.case_id} item={item} editable={canAct(role)} onSaved={onChanged} />)}</tbody>
          </table>
        </div>
      )}
    </div>
  );
}
