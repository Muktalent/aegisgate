import { Fragment, useMemo, useState, type FormEvent } from "react";

import {
  api, canAct, dateTime, percent, titleCase,
  type AllowEntry, type Evaluation, type Level, type Metric, type Role, type Scenario, type ScenarioRun, type UserRow,
} from "../client";
import { ActionControls, ActionHistory, StateBadge } from "./responses";
import { DecisionBadge, ErrorNotice, Icon, LevelBadge, State } from "./parts";
import { useLoad, type PageProps } from "./pages";

/* ------------------------------ Response Center ------------------------------ */
const CATEGORY_NAME: Record<string, string> = {
  port_scan: "Port scan", destination_scan: "Destination scan",
  suspicious_outbound: "Regular outbound", potential_exfiltration: "Potential exfiltration",
};

export function ResponsePage({ role, version, onChanged, onSelect }: PageProps) {
  const [state, setState] = useState("active");
  const [refresh, setRefresh] = useState(0);
  const { data, error, loading, retry } = useLoad(() => api.responses(), `${version}:${refresh}`);
  const [open, setOpen] = useState<string | null>(null);

  if (error) return <ErrorNotice message={error} onRetry={retry} />;
  if (!data) return <State title={loading ? "Loading response actions…" : "No data"} />;

  const active = ["proposed", "pending_approval", "approved", "executed_in_simulation"];
  const rows = data.items.filter((item) =>
    state === "all" || (state === "active" ? active.includes(item.state) : item.state === state));
  const changed = () => { setRefresh((n) => n + 1); onChanged(); };

  return (
    <div className="stack">
      <div className="notice"><Icon name="info" />
        <div><b>Simulation only</b>Every action here is recorded and audited, but no firewall, account or host is
          changed. High-impact actions need an administrator's approval and can be rolled back.</div></div>
      <div className="card">
        <div className="toolbar">
          <select className="input" value={state} onChange={(e) => setState(e.target.value)} aria-label="State">
            <option value="active">Active</option><option value="pending_approval">Awaiting approval</option>
            <option value="executed_in_simulation">Applied in simulation</option>
            <option value="rolled_back">Rolled back</option><option value="rejected">Rejected</option>
            <option value="all">All</option>
          </select>
          <span className="muted small num">{rows.length} of {data.total} actions</span>
        </div>
        {data.total === 0 ? (
          <State title="No response actions yet">Request one from a finding in the analysis panel.</State>
        ) : rows.length === 0 ? <State title="No actions in this state" /> : (
          <div className="table-wrap">
            <table>
              <thead><tr><th>Action</th><th>Target</th><th>Impact</th><th>State</th><th>Requested</th><th /></tr></thead>
              <tbody>
                {rows.map((action) => (
                  <Fragment key={action.action_id}>
                    <tr>
                      <td><b>{titleCase(action.action_type)}</b>
                        <div className="muted small">{action.reason}</div></td>
                      <td className="nowrap"><span className="mono">{action.source_ip}</span>
                        <div className="small"><button className="link" type="button" onClick={() => onSelect(action.group_id)}>
                          {action.asset_id ?? "Not in inventory"} · view finding</button></div></td>
                      <td><span className={`badge ${action.impact === "high" ? "high" : ""}`}>{titleCase(action.impact)}</span></td>
                      <td><StateBadge state={action.state} /></td>
                      <td className="nowrap">{action.requested_by}<div className="muted small mono">{dateTime(action.requested_at)}</div></td>
                      <td className="right">
                        <div className="op-row">
                          <ActionControls action={action} role={role} onChanged={changed} />
                          <button className="btn ghost" type="button" aria-expanded={open === action.action_id}
                            onClick={() => setOpen(open === action.action_id ? null : action.action_id)}>History</button>
                        </div>
                      </td>
                    </tr>
                    {open === action.action_id && (
                      <tr><td colSpan={6} style={{ background: "var(--surface-2)" }}>
                        <ActionHistory action={action} />
                        {action.outcome && <p className="small muted">Simulated effect: {action.outcome.effect}
                          {" "}Real infrastructure changed: {action.outcome.real_infrastructure_changed ? "yes" : "no"}.</p>}
                      </td></tr>
                    )}
                  </Fragment>
                ))}
              </tbody>
            </table>
          </div>
        )}
      </div>
    </div>
  );
}

/* ------------------------------ Demo Lab ------------------------------ */
function Check({ ok, label }: { ok: boolean; label: string }) {
  return <span className={`badge ${ok ? "good" : "critical"}`}>{ok ? "✓" : "✗"} {label}</span>;
}

function RunResult({ run, onSelect }: { run: ScenarioRun; onSelect: (id: string) => void }) {
  const { comparison, finding } = run;
  return (
    <div className="run-result">
      <div className="toolbar" style={{ margin: 0 }}>
        <span className={`badge ${comparison.matches_expected ? "good" : "critical"}`}>
          {comparison.matches_expected ? "Matches expectation" : "Differs from expectation"}</span>
        <Check ok={comparison.checks.rules} label="Rules" />
        <Check ok={comparison.checks.finding} label="Finding" />
        <Check ok={comparison.checks.decision} label="Decision" />
      </div>
      <p className="small muted" style={{ marginTop: 6 }}>
        {run.events_ingested} events ingested ({run.baseline_events} history) · rules fired:{" "}
        {comparison.actual.rules.length ? comparison.actual.rules.join(", ") : "none"} · {dateTime(run.started_at)}
      </p>
      {finding && (
        <p className="small" style={{ marginTop: 4 }}>
          {titleCase(finding.finding)} · risk {finding.risk_score} <LevelBadge level={finding.risk_level} />{" "}
          <DecisionBadge decision={finding.decision} />{" "}
          <button className="link" type="button" onClick={() => onSelect(finding.group_id)}>Open analysis</button>
        </p>
      )}
    </div>
  );
}

function MetricsTable({ metrics }: { metrics: Metric[] }) {
  const name: Record<string, string> = { rule_based: "Rule-based", anomaly_based: "Anomaly-based", combined: "Combined" };
  return (
    <div className="table-wrap">
      <table>
        <thead><tr><th>Approach</th><th className="right">TP</th><th className="right">FP</th><th className="right">TN</th>
          <th className="right">FN</th><th className="right">Precision</th><th className="right">Recall</th>
          <th className="right">False-positive rate</th><th className="right">F1</th><th className="right">Median latency</th></tr></thead>
        <tbody>
          {metrics.map((m) => (
            <tr key={m.approach}>
              <td><b>{name[m.approach]}</b></td>
              <td className="right num">{m.true_positives}</td><td className="right num">{m.false_positives}</td>
              <td className="right num">{m.true_negatives}</td><td className="right num">{m.false_negatives}</td>
              <td className="right num">{percent(m.precision)}</td><td className="right num">{percent(m.recall)}</td>
              <td className="right num">{percent(m.false_positive_rate)}</td>
              <td className="right num">{m.f1 ?? "—"}</td>
              <td className="right num">{m.median_latency_seconds === null ? "—" : `${m.median_latency_seconds} s`}</td>
            </tr>
          ))}
        </tbody>
      </table>
    </div>
  );
}

function AllowlistComparison({ data }: { data: NonNullable<Evaluation["allowlist_comparison"]> }) {
  const mark = (v: { before: boolean; after: boolean }) => `${v.before ? "flagged" : "—"} → ${v.after ? "flagged" : "—"}`;
  return (
    <div className="stack">
      <h3 style={{ margin: "8px 0 0" }}>With the approved-activity allowlist</h3>
      <p className="small muted">{data.description}</p>
      <MetricsTable metrics={data.metrics} />
      <details>
        <summary className="small">Entries used and cases whose outcome changed ({data.changed_cases.length})</summary>
        <ul className="small" style={{ paddingLeft: 18 }}>
          {data.entries.map((e) => <li key={e.entry_id}><b>{e.entry_id}</b> {e.source_ip} → {e.destinations.join(", ")}
            {e.ports.length > 0 && ` port ${e.ports.join(", ")}`} · {e.categories.map((c) => CATEGORY_NAME[c] ?? c).join(", ")} · {e.reason}</li>)}
        </ul>
        <div className="table-wrap">
          <table>
            <thead><tr><th>Case</th><th>Truth</th><th>Rule</th><th>Anomaly</th><th>Combined</th><th>Suppressed by</th></tr></thead>
            <tbody>{data.changed_cases.map((c) => (
              <tr key={c.case_id}><td className="mono small">{c.case_id}</td>
                <td><span className={`badge ${c.label === "malicious" ? "high" : "good"}`}>{titleCase(c.label)}</span></td>
                <td className="small">{mark(c.rule_based)}</td><td className="small">{mark(c.anomaly_based)}</td>
                <td className="small">{mark(c.combined)}</td><td className="mono small">{c.suppressed_by.join(", ") || "—"}</td></tr>
            ))}</tbody>
          </table>
        </div>
      </details>
    </div>
  );
}

export function DemoLabPage({ role, version, onChanged, onSelect }: PageProps) {
  const [refresh, setRefresh] = useState(0);
  const scenarios = useLoad(api.scenarios, `${version}:${refresh}`);
  const evaluation = useLoad(api.latestEvaluation, `${version}:${refresh}`);
  const [running, setRunning] = useState<string | null>(null);
  const [error, setError] = useState<string | null>(null);
  const mayRun = canAct(role);

  async function run(id: string) {
    setRunning(id); setError(null);
    try {
      if (id === "__evaluation__") await api.runEvaluation(); else await api.runScenario(id);
      setRefresh((n) => n + 1); onChanged();
    } catch (reason) {
      setError(reason instanceof Error ? reason.message : "The run failed.");
    } finally { setRunning(null); }
  }

  if (scenarios.error) return <ErrorNotice message={scenarios.error} onRetry={scenarios.retry} />;
  if (!scenarios.data) return <State title="Loading scenarios…" />;

  return (
    <div className="stack">
      <div className="notice"><Icon name="flask" />
        <div><b>{scenarios.data.data_provenance}</b>Each scenario writes Suricata-format records and sends them through
          the normal ingestion, detection, correlation, risk and policy code. Nothing is hard-coded: the result is
          compared with what the scenario expects. Lab findings are kept apart from the global analysis.</div></div>
      {error && <ErrorNotice message={error} />}

      <div className="card">
        <h2>Scenarios</h2>
        <div className="table-wrap">
          <table>
            <thead><tr><th>Scenario</th><th>Ground truth</th><th>Expected</th><th>Last run</th><th /></tr></thead>
            <tbody>
              {scenarios.data.items.map((s: Scenario) => (
                <tr key={s.scenario_id}>
                  <td style={{ maxWidth: 300 }}><b>{s.title}</b><div className="muted small">{s.description}</div>
                    {s.notes && <div className="small" style={{ marginTop: 4 }}>{s.notes}</div>}</td>
                  <td><span className={`badge ${s.ground_truth === "malicious" ? "high" : "good"}`}>{titleCase(s.ground_truth)}</span></td>
                  <td className="small">{s.expected.rules.length ? s.expected.rules.join(", ") : "No rule"}
                    <div className="muted">{s.expected.decision ? titleCase(s.expected.decision) : "No finding"}</div></td>
                  <td style={{ minWidth: 260 }}>{s.last_run ? <RunResult run={s.last_run} onSelect={onSelect} /> : <span className="muted">Not run yet</span>}</td>
                  <td className="right">{mayRun && (
                    <button className="btn" type="button" disabled={running !== null} onClick={() => void run(s.scenario_id)}>
                      {running === s.scenario_id ? "Running…" : "Run"}</button>)}</td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      </div>

      <div className="card">
        <div className="page-head" style={{ marginBottom: 10 }}>
          <div><h2>Detection evaluation</h2>
            <p className="small">Rule-based, anomaly-based and combined detection on labelled synthetic cases,
              including benign look-alikes.</p></div>
          <div className="actions">
            {evaluation.data && <a className="btn" href="/api/v1/reports/evaluation.csv">Download cases (CSV)</a>}
            {mayRun && <button className="btn primary" type="button" disabled={running !== null}
              onClick={() => void run("__evaluation__")}>{running === "__evaluation__" ? "Evaluating…" : "Run evaluation"}</button>}
          </div>
        </div>
        {evaluation.error ? <ErrorNotice message={evaluation.error} onRetry={evaluation.retry} />
          : !evaluation.data ? <State title="No evaluation yet">Run the evaluation to compare the three approaches.</State> : (
          <div className="stack">
            <p className="small muted">{evaluation.data.case_count} cases ({evaluation.data.malicious_cases} malicious,{" "}
              {evaluation.data.benign_cases} benign) · {evaluation.data.evaluation_version} · run by{" "}
              {evaluation.data.started_by}, {dateTime(evaluation.data.started_at)}</p>
            <MetricsTable metrics={evaluation.data.metrics} />
            {evaluation.data.allowlist_comparison && <AllowlistComparison data={evaluation.data.allowlist_comparison} />}
            <details>
              <summary className="small">Flagged cases per family</summary>
              <div className="table-wrap" style={{ marginTop: 8 }}>
                <table>
                  <thead><tr><th>Family</th><th>Truth</th><th className="right">Cases</th><th className="right">Rule</th>
                    <th className="right">Anomaly</th><th className="right">Combined</th></tr></thead>
                  <tbody>{evaluation.data.by_family.map((f) => (
                    <tr key={f.family}><td>{titleCase(f.family)}<div className="muted small">{f.description}</div></td>
                      <td><span className={`badge ${f.label === "malicious" ? "high" : "good"}`}>{titleCase(f.label)}</span></td>
                      <td className="right num">{f.cases}</td><td className="right num">{f.rule_based}</td>
                      <td className="right num">{f.anomaly_based}</td><td className="right num">{f.combined}</td></tr>
                  ))}</tbody>
                </table>
              </div>
            </details>
            <details>
              <summary className="small">Definitions and limitations</summary>
              <ul className="small" style={{ paddingLeft: 18 }}>
                {Object.entries(evaluation.data.definitions).map(([k, v]) => <li key={k}><b>{titleCase(k)}:</b> {v}</li>)}
                {evaluation.data.limitations.map((line) => <li key={line}>{line}</li>)}
              </ul>
            </details>
          </div>
        )}
      </div>
    </div>
  );
}

/* ------------------------------ Audit & Reports ------------------------------ */
export function AuditPage({ role, version }: PageProps) {
  const [action, setAction] = useState("");
  const [actor, setActor] = useState("");
  const [applied, setApplied] = useState({ action: "", actor: "" });
  const [check, setCheck] = useState(0);
  const allowed = canAct(role);
  const entries = useLoad(() => (allowed ? api.audit(applied) : Promise.resolve(null)),
    `${version}:${applied.action}:${applied.actor}`);
  const verification = useLoad(() => (allowed ? api.verifyAudit() : Promise.resolve(null)), `${version}:${check}`);
  const [open, setOpen] = useState<number | null>(null);

  if (!allowed) {
    return <div className="card"><h2>Reports</h2>
      <p className="muted" style={{ marginBottom: 10 }}>Your role can download findings but not the audit trail.</p>
      <a className="btn" href="/api/v1/reports/findings.csv">Download current findings (CSV)</a></div>;
  }
  const v = verification.data;

  return (
    <div className="stack">
      <div className="grid two">
        <div className="card">
          <h2>Audit trail integrity</h2>
          {verification.error ? <ErrorNotice message={verification.error} onRetry={verification.retry} />
            : !v ? <State title="Verifying…" /> : (
            <div className="stack" style={{ gap: 10 }}>
              <div className={`alert-head ${v.valid ? "" : "critical"}`} style={v.valid ? { borderColor: "var(--good)", background: "var(--good-soft)" } : undefined}>
                <Icon name={v.valid ? "check" : "info"} size={20} />
                <div><b>{v.valid ? "Hash chain intact" : "Integrity check failed"}</b>
                  <span className="small muted">{v.valid ? `${v.checked} sealed entries verified (${v.algorithm}).`
                    : `${v.reason} First affected entry: #${v.first_invalid_audit_id}.`}</span></div>
              </div>
              <ul className="status-list">
                <li>Entries in the audit log<b>{v.total_entries}</b></li>
                <li>Sealed by the hash chain<b>{v.sealed_entries}</b></li>
                <li>Older entries not covered<b>{v.entries_not_covered}</b></li>
              </ul>
              {v.latest_hash && <p className="small">Latest hash <code style={{ wordBreak: "break-all" }}>{v.latest_hash}</code></p>}
              <p className="small muted">{v.limitation}</p>
              <div><button className="btn" type="button" onClick={() => setCheck((n) => n + 1)}>Verify again</button></div>
            </div>
          )}
        </div>
        <div className="card">
          <h2>Reports</h2>
          <p className="small muted" style={{ marginBottom: 12 }}>CSV files for analysis or for the project write-up.
            Text that could be read as a spreadsheet formula is escaped.</p>
          <div className="stack" style={{ gap: 8 }}>
            <a className="btn" href="/api/v1/reports/findings.csv"><Icon name="doc" size={16} />Current findings</a>
            <a className="btn" href="/api/v1/reports/findings.csv?include_superseded=true"><Icon name="doc" size={16} />All findings, including superseded</a>
            <a className="btn" href="/api/v1/reports/audit.csv"><Icon name="doc" size={16} />Audit trail</a>
            <a className="btn" href="/api/v1/reports/evaluation.csv"><Icon name="doc" size={16} />Latest detection evaluation</a>
          </div>
        </div>
      </div>

      <div className="card">
        <h2>Audit log</h2>
        <form className="toolbar" onSubmit={(e: FormEvent) => { e.preventDefault(); setApplied({ action, actor: actor.trim() }); }}>
          <select className="input" value={action} onChange={(e) => setAction(e.target.value)} aria-label="Action">
            <option value="">All actions</option>
            {(entries.data?.actions ?? []).map((name) => <option key={name} value={name}>{titleCase(name)}</option>)}
          </select>
          <input className="input" value={actor} onChange={(e) => setActor(e.target.value)} placeholder="Actor (exact)" aria-label="Actor" />
          <button className="btn" type="submit">Filter</button>
          {entries.data && <span className="muted small num">Showing {entries.data.items.length} of {entries.data.total}</span>}
        </form>
        {entries.error ? <ErrorNotice message={entries.error} onRetry={entries.retry} />
          : !entries.data ? <State title="Loading audit log…" />
          : entries.data.items.length === 0 ? <State title="No entries match" /> : (
          <div className="table-wrap">
            <table>
              <thead><tr><th>#</th><th>Time (UTC)</th><th>Actor</th><th>Action</th><th>Target</th><th /></tr></thead>
              <tbody>{entries.data.items.map((entry) => (
                <Fragment key={entry.audit_id}>
                  <tr>
                    <td className="num">{entry.audit_id}</td>
                    <td className="mono">{dateTime(entry.occurred_at)}</td>
                    <td>{entry.actor}</td><td>{titleCase(entry.action)}</td>
                    <td className="small">{titleCase(entry.target_type)} <span className="mono muted">{entry.target_id.slice(0, 24)}</span></td>
                    <td className="right"><button className="btn ghost" type="button" aria-expanded={open === entry.audit_id}
                      onClick={() => setOpen(open === entry.audit_id ? null : entry.audit_id)}>Details</button></td>
                  </tr>
                  {open === entry.audit_id && <tr><td colSpan={6} style={{ background: "var(--surface-2)" }}>
                    <pre className="mono small" style={{ margin: 0, whiteSpace: "pre-wrap" }}>{JSON.stringify(entry.details, null, 2)}</pre></td></tr>}
                </Fragment>
              ))}</tbody>
            </table>
          </div>
        )}
      </div>
    </div>
  );
}

/* ------------------------------ Security Analytics ------------------------------ */
function Bars({ rows }: { rows: Array<{ label: string; value: number; tone?: string }> }) {
  const peak = Math.max(1, ...rows.map((r) => r.value));
  return (
    <ul className="bars">
      {rows.map((row) => (
        <li key={row.label}>
          <span>{row.label}</span>
          <i><b style={{ width: `${(row.value / peak) * 100}%`, background: row.tone ?? "var(--accent)" }} /></i>
          <strong className="num">{row.value}</strong>
        </li>
      ))}
    </ul>
  );
}

const LEVEL_TONE: Record<string, string> = {
  critical: "var(--critical)", high: "var(--high)", medium: "var(--medium)", low: "var(--low)", informational: "var(--info)",
};

export function AnalyticsPage({ version }: PageProps) {
  const findings = useLoad(api.findings, version);
  const detections = useLoad(api.detections, version);
  const [scope, setScope] = useState("global");

  const data = useMemo(() => {
    if (!findings.data || !detections.data) return null;
    const inScope = (s: string | undefined) => scope === "all" || (scope === "global" ? s === "all-events" : s !== "all-events");
    const f = findings.data.items.filter((item) => inScope(item.scope));
    const d = detections.data.items.filter((item) => inScope(item.scope));
    const count = <T,>(items: T[], key: (item: T) => string) => {
      const out = new Map<string, number>();
      items.forEach((item) => out.set(key(item), (out.get(key(item)) ?? 0) + 1));
      return [...out.entries()].sort((a, b) => b[1] - a[1]);
    };
    return {
      findings: f.length, detections: d.length,
      levels: (["critical", "high", "medium", "low", "informational"] as Level[])
        .map((level) => ({ label: titleCase(level), value: f.filter((x) => x.risk_level === level).length, tone: LEVEL_TONE[level] })),
      decisions: count(f, (x) => x.decision).map(([k, v]) => ({ label: titleCase(k), value: v })),
      rules: count(d, (x) => `${x.rule_id} ${titleCase(x.category)}`).map(([k, v]) => ({ label: k, value: v })),
      sources: count(f, (x) => x.source_ip).slice(0, 8).map(([k, v]) => ({ label: k, value: v })),
      meanConfidence: d.length ? d.reduce((sum, x) => sum + x.confidence, 0) / d.length : null,
    };
  }, [findings.data, detections.data, scope]);

  if (findings.error || detections.error) return <ErrorNotice message={findings.error ?? detections.error ?? ""} />;
  if (!data) return <State title="Loading analytics…" />;

  return (
    <div className="stack">
      <div className="toolbar" style={{ margin: 0 }}>
        <select className="input" value={scope} onChange={(e) => setScope(e.target.value)} aria-label="Scope">
          <option value="global">Ingested telemetry</option><option value="lab">Demo Lab runs</option><option value="all">Everything</option>
        </select>
        <span className="muted small">{data.findings} current finding(s) · {data.detections} detection(s)
          {data.meanConfidence !== null && ` · mean detection confidence ${Math.round(data.meanConfidence * 100)}%`}</span>
      </div>
      {data.findings === 0 && data.detections === 0 ? (
        <div className="card"><State title="Nothing to analyse in this scope">Import telemetry or run a Demo Lab scenario, then run the analysis.</State></div>
      ) : (
        <>
          <div className="grid two">
            <div className="card"><h2>Findings by risk level</h2><Bars rows={data.levels} /></div>
            <div className="card"><h2>Policy decisions</h2><Bars rows={data.decisions} /></div>
          </div>
          <div className="grid two">
            <div className="card"><h2>Detections by rule</h2><Bars rows={data.rules} /></div>
            <div className="card"><h2>Sources with most findings</h2><Bars rows={data.sources} /></div>
          </div>
        </>
      )}
    </div>
  );
}

/* ------------------------------ Settings ------------------------------ */
const ROLES: Role[] = ["security_admin", "soc_analyst", "viewer", "ingestor"];
const ROLE_NAME: Record<string, string> = {
  security_admin: "Administrator", soc_analyst: "Analyst", viewer: "Viewer", ingestor: "Ingestor",
};

function Allowlist({ admin }: { admin: boolean }) {
  const [refresh, setRefresh] = useState(0);
  const { data, error, loading, retry } = useLoad(api.allowlist, refresh);
  const [message, setMessage] = useState<{ ok: boolean; text: string } | null>(null);
  const [busy, setBusy] = useState(false);

  async function act(task: () => Promise<unknown>, done: string) {
    setBusy(true); setMessage(null);
    try { await task(); setMessage({ ok: true, text: done }); setRefresh((n) => n + 1); }
    catch (reason) { setMessage({ ok: false, text: reason instanceof Error ? reason.message : "The change failed." }); }
    finally { setBusy(false); }
  }

  function create(event: FormEvent<HTMLFormElement>) {
    event.preventDefault();
    const form = event.currentTarget;
    const values = new FormData(form);
    const list = (name: string) => String(values.get(name) ?? "").split(/[\s,]+/).map((v) => v.trim()).filter(Boolean);
    const ports = list("ports").map(Number);
    if (ports.some((p) => !Number.isInteger(p))) { setMessage({ ok: false, text: "Ports must be whole numbers." }); return; }
    void act(async () => {
      await api.createAllowEntry({ source_ip: String(values.get("source_ip") ?? "").trim(), destinations: list("destinations"),
        ports, categories: values.getAll("categories").map(String), reason: String(values.get("reason") ?? "").trim() });
      form.reset();
    }, "Entry created. It applies from the next analysis run.");
  }

  function disable(entry: AllowEntry) {
    const note = window.prompt(`Why is ${entry.entry_id} being disabled?`);
    if (note) void act(() => api.disableAllowEntry(entry.entry_id, note), `${entry.entry_id} disabled.`);
  }

  if (error) return <ErrorNotice message={error} onRetry={retry} />;
  if (!data) return <State title={loading ? "Loading allowlist…" : "No data"} />;

  return (
    <div className="stack">
      <p className="small muted">Approved benign activity that resembles an attack, such as a backup job. A detection is
        suppressed only when every one of its events is covered by an entry; suppressions are reported with each
        analysis run and audited. IDS signature alerts cannot be allowlisted. Entries are disabled, never deleted.</p>
      {message && <div className={`notice ${message.ok ? "" : "error"}`} role={message.ok ? "status" : "alert"}>
        <Icon name={message.ok ? "check" : "info"} /><div>{message.text}</div></div>}
      {data.items.length === 0 ? <State title="No entries">Nothing is suppressed.</State> : (
        <div className="table-wrap">
          <table>
            <thead><tr><th>Entry</th><th>Source</th><th>Destinations and ports</th><th>Covers</th><th>Reason</th><th>Status</th>{admin && <th />}</tr></thead>
            <tbody>{data.items.map((e) => (
              <tr key={e.entry_id}>
                <td className="mono small"><b>{e.entry_id}</b><div className="muted">{e.created_by}, {dateTime(e.created_at)}</div></td>
                <td className="mono small">{e.source_ip}</td>
                <td className="mono small">{e.destinations.join(", ")}{e.ports.length > 0 && <div>port {e.ports.join(", ")}</div>}</td>
                <td className="small">{e.categories.map((c) => CATEGORY_NAME[c] ?? c).join(", ")}</td>
                <td className="small">{e.reason}</td>
                <td><span className={`badge ${e.active ? "good" : ""}`}>{e.active ? "Active" : "Disabled"}</span>
                  {!e.active && e.disabled_note && <div className="muted small">{e.disabled_note}</div>}</td>
                {admin && <td className="right">{e.active && <button className="btn" type="button" disabled={busy}
                  onClick={() => disable(e)}>Disable</button>}</td>}
              </tr>
            ))}</tbody>
          </table>
        </div>
      )}
      {admin && (
        <form className="stack" onSubmit={create}>
          <div className="toolbar" style={{ alignItems: "flex-end", marginBottom: 0 }}>
            <label className="field">Source IP<input className="input mono" name="source_ip" required placeholder="10.10.10.50" disabled={busy} /></label>
            <label className="field">Destinations (IPs or ranges up to /24)<input className="input mono" name="destinations" required
              placeholder="10.10.10.96/27, 198.51.100.90" disabled={busy} /></label>
            <label className="field">Ports (optional)<input className="input mono" name="ports" placeholder="445" disabled={busy} /></label>
          </div>
          <fieldset className="toolbar" style={{ border: 0, padding: 0, margin: 0 }} disabled={busy}>
            <legend className="small muted">Detections it may suppress</legend>
            {data.categories.map((c) => <label key={c} className="small" style={{ display: "inline-flex", gap: 6, alignItems: "center" }}>
              <input type="checkbox" name="categories" value={c} />{CATEGORY_NAME[c] ?? c}</label>)}
          </fieldset>
          <div className="toolbar" style={{ alignItems: "flex-end", marginBottom: 0 }}>
            <label className="field" style={{ flex: 1 }}>Reason<input className="input" name="reason" required minLength={5}
              placeholder="Nightly backup job to the file servers" disabled={busy} /></label>
            <button className="btn primary" type="submit" disabled={busy}>Add entry</button>
          </div>
        </form>
      )}
    </div>
  );
}

function UserAdmin({ self }: { self: string }) {
  const [refresh, setRefresh] = useState(0);
  const { data, error, loading, retry } = useLoad(api.users, refresh);
  const [message, setMessage] = useState<{ ok: boolean; text: string } | null>(null);
  const [busy, setBusy] = useState(false);

  async function act(task: () => Promise<unknown>, done: string) {
    setBusy(true); setMessage(null);
    try { await task(); setMessage({ ok: true, text: done }); setRefresh((n) => n + 1); }
    catch (reason) { setMessage({ ok: false, text: reason instanceof Error ? reason.message : "The change failed." }); }
    finally { setBusy(false); }
  }

  function create(event: FormEvent<HTMLFormElement>) {
    event.preventDefault();
    const form = event.currentTarget;
    const values = new FormData(form);
    const username = String(values.get("username") ?? "").trim().toLowerCase();
    void act(async () => {
      await api.createUser(username, String(values.get("password") ?? ""), String(values.get("role")) as Role);
      form.reset();
    }, `User ${username} created.`);
  }

  function resetPassword(username: string) {
    const password = window.prompt(`New password for ${username} (at least 12 characters):`);
    if (password) void act(() => api.updateUser(username, { password }), `Password for ${username} changed.`);
  }

  if (error) return <ErrorNotice message={error} onRetry={retry} />;
  if (!data) return <State title={loading ? "Loading users…" : "No data"} />;

  return (
    <div className="stack">
      {message && <div className={`notice ${message.ok ? "" : "error"}`} role={message.ok ? "status" : "alert"}>
        <Icon name={message.ok ? "check" : "info"} /><div>{message.text}</div></div>}
      <div className="table-wrap">
        <table>
          <thead><tr><th>User</th><th>Role</th><th>Status</th><th>Last sign-in</th><th /></tr></thead>
          <tbody>{data.items.map((user: UserRow) => {
            const isSelf = user.username === self;
            return (
              <tr key={user.username}>
                <td><b>{user.username}</b>{isSelf && <span className="muted small"> (you)</span>}</td>
                <td><select className="input" value={user.role} disabled={busy || isSelf} aria-label={`Role of ${user.username}`}
                  onChange={(e) => void act(() => api.updateUser(user.username, { role: e.target.value as Role }),
                    `Role of ${user.username} changed. Their open sessions were signed out.`)}>
                  {ROLES.map((r) => <option key={r} value={r}>{ROLE_NAME[r]}</option>)}</select></td>
                <td><span className={`badge ${user.is_active ? "good" : ""}`}>{user.is_active ? "Active" : "Disabled"}</span></td>
                <td className="mono small">{dateTime(user.last_login_at)}</td>
                <td className="right"><div className="op-row">
                  <button className="btn" type="button" disabled={busy} onClick={() => resetPassword(user.username)}>Reset password</button>
                  {!isSelf && <button className="btn" type="button" disabled={busy}
                    onClick={() => void act(() => api.updateUser(user.username, { is_active: !user.is_active }),
                      `${user.username} ${user.is_active ? "disabled" : "enabled"}.`)}>{user.is_active ? "Disable" : "Enable"}</button>}
                </div></td>
              </tr>
            );
          })}</tbody>
        </table>
      </div>
      <form className="toolbar" onSubmit={create} style={{ alignItems: "flex-end" }}>
        <label className="field">Username<input className="input" name="username" required pattern="[a-z0-9][a-z0-9._@\-]{2,63}"
          title="3-64 characters: lowercase letters, digits, . _ @ -" disabled={busy} /></label>
        <label className="field">Password<input className="input" name="password" type="password" minLength={12} required
          autoComplete="new-password" disabled={busy} /></label>
        <label className="field">Role<select className="input" name="role" defaultValue="soc_analyst" disabled={busy}>
          {ROLES.map((r) => <option key={r} value={r}>{ROLE_NAME[r]}</option>)}</select></label>
        <button className="btn primary" type="submit" disabled={busy}>Create user</button>
      </form>
    </div>
  );
}

export function SettingsPage({ role, username, theme, onToggleTheme }: PageProps & {
  username: string; theme: string; onToggleTheme: () => void;
}) {
  return (
    <div className="stack">
      <div className="card">
        <h2>Your account</h2>
        <ul className="status-list">
          <li>Username<b>{username}</b></li>
          <li>Role<b>{ROLE_NAME[role] ?? role}</b></li>
          <li>Theme<b><button className="btn" type="button" onClick={onToggleTheme}>
            <Icon name={theme === "dark" ? "sun" : "moon"} size={16} />{theme === "dark" ? "Use light mode" : "Use dark mode"}</button></b></li>
        </ul>
      </div>
      <div className="card">
        <h2>Users</h2>
        {role === "security_admin" ? <UserAdmin self={username} />
          : <p className="muted">Only an administrator can manage users.</p>}
      </div>
      {role !== "ingestor" && (
        <div className="card">
          <h2>Approved-activity allowlist</h2>
          <Allowlist admin={role === "security_admin"} />
        </div>
      )}
      <div className="card">
        <h2>About this edition</h2>
        <p className="small">AegisGate Academic analyses telemetry you import and synthetic Demo Lab data. Every response
          action is simulated: no firewall, account or host is changed. Decisions are recommendations for an analyst.</p>
      </div>
    </div>
  );
}
