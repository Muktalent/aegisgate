import { useCallback, useEffect, useState, type FormEvent } from "react";

import { ApiError, api, canAct, dateTime, setUnauthorisedHandler, type Session } from "./client";
import { AnalysisPanel } from "./ui/AnalysisPanel";
import {
  AssetsPage, DetectionPage, EventsPage, InvestigationsPage, OverviewPage, type PageProps,
} from "./ui/pages";
import { AnalyticsPage, AuditPage, DemoLabPage, ResponsePage, SettingsPage } from "./ui/more";
import { Icon, Logo } from "./ui/parts";
import "./styles.css";

type PageId = "overview" | "events" | "assets" | "detection" | "investigations" | "responses"
  | "analytics" | "demo" | "audit" | "settings";

interface PageInfo { id: PageId; label: string; icon: string; title: string; subtitle: string; group?: string }

const PAGES: PageInfo[] = [
  { id: "overview", label: "Overview", icon: "home", title: "Security Overview",
    subtitle: "Current findings, key figures and recent activity in the laboratory environment." },
  { id: "events", label: "Live Events", icon: "pulse", title: "Live Events",
    subtitle: "Normalised Suricata and Zeek telemetry stored by AegisGate, and file import." },
  { id: "assets", label: "Assets", icon: "monitor", title: "Assets",
    subtitle: "Inventory assets and sources seen in telemetry that have no inventory record." },
  { id: "detection", label: "Threat Detection", icon: "shield", title: "Threat Detection",
    subtitle: "Correlated findings with their risk score and policy decision." },
  { id: "investigations", label: "Investigations", icon: "folder", title: "Investigations",
    subtitle: "Cases opened by analysts, with status and notes." },
  { id: "responses", label: "Response Center", icon: "bolt", title: "Response Center",
    subtitle: "Simulated response actions: approval, application in simulation and rollback." },
  { id: "analytics", label: "Security Analytics", icon: "chart", title: "Security Analytics",
    subtitle: "How current findings and detections are distributed." },
  { id: "demo", label: "Demo Lab", icon: "flask", group: "Laboratory", title: "Demo Lab",
    subtitle: "Reproducible synthetic scenarios and the comparative detection evaluation." },
  { id: "audit", label: "Audit & Reports", icon: "doc", group: "Management", title: "Audit & Reports",
    subtitle: "Tamper-evident audit trail and CSV reports." },
  { id: "settings", label: "Settings", icon: "gear", group: "Management", title: "Settings",
    subtitle: "Your account, appearance and user administration." },
];

const ROLE_LABEL: Record<string, string> = {
  security_admin: "Administrator", soc_analyst: "Analyst", viewer: "Viewer", ingestor: "Ingestor",
};

function useTheme(): [string, () => void] {
  const [theme, setTheme] = useState(() => {
    try { return localStorage.getItem("aegis_theme") === "dark" ? "dark" : "light"; } catch { return "light"; }
  });
  useEffect(() => {
    document.documentElement.dataset.theme = theme;
    try { localStorage.setItem("aegis_theme", theme); } catch { /* storage unavailable */ }
  }, [theme]);
  return [theme, () => setTheme((t) => (t === "dark" ? "light" : "dark"))];
}

function Login({ onSignedIn }: { onSignedIn: (session: Session) => void }) {
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState<string | null>(null);

  async function submit(event: FormEvent<HTMLFormElement>) {
    event.preventDefault();
    const form = new FormData(event.currentTarget);
    setBusy(true); setError(null);
    try {
      onSignedIn(await api.login(String(form.get("username") ?? ""), String(form.get("password") ?? "")));
    } catch (reason) {
      setError(reason instanceof Error ? reason.message : "Unable to sign in.");
    } finally { setBusy(false); }
  }

  return (
    <main className="login">
      <form className="card" onSubmit={submit}>
        <div className="brand"><Logo /><div><strong>AegisGate</strong><span>Security Operations Platform</span></div></div>
        <div><h1>Sign in</h1><p className="muted">Academic edition — simulated environment.</p></div>
        <label className="field">Username
          <input className="input" name="username" autoComplete="username" required autoFocus disabled={busy} /></label>
        <label className="field">Password
          <input className="input" name="password" type="password" autoComplete="current-password" required disabled={busy} /></label>
        {error && <div className="notice error" role="alert"><Icon name="info" /><div>{error}</div></div>}
        <button className="btn primary block" type="submit" disabled={busy}>{busy ? "Signing in…" : "Sign in"}</button>
        <p className="muted small">Accounts are created by an administrator. The first administrator is created with <code>scripts/create_user.py</code>.</p>
      </form>
    </main>
  );
}

function Workspace({ session, onSignOut }: { session: Session; onSignOut: () => void }) {
  const ingestor = session.role === "ingestor";
  const [page, setPage] = useState<PageId>(ingestor ? "events" : "overview");
  const [selected, setSelected] = useState<string | null>(null);
  const [version, setVersion] = useState(0);
  const [running, setRunning] = useState(false);
  const [notice, setNotice] = useState<{ tone: "ok" | "error"; text: string } | null>(null);
  const [theme, toggleTheme] = useTheme();

  const refresh = useCallback(() => setVersion((n) => n + 1), []);
  const current = PAGES.find((p) => p.id === page) ?? PAGES[0];

  async function runAnalysis() {
    setRunning(true); setNotice(null);
    try {
      const result = await api.runAnalysis();
      setNotice({ tone: "ok", text: `Analysis finished ${dateTime(result.completed_at)}: ${result.events_analysed} events, ${result.detection_count} detection(s), ${result.finding_count} finding(s)${result.suppressed_count ? `, ${result.suppressed_count} detection(s) suppressed by the allowlist` : ""}.` });
      setSelected(null);
      refresh();
    } catch (reason) {
      setNotice({ tone: "error", text: reason instanceof Error ? reason.message : "The analysis could not be run." });
    } finally { setRunning(false); }
  }

  const props: PageProps = { role: session.role, version, selected, onSelect: setSelected, onChanged: refresh };
  const initials = session.username.slice(0, 2).toUpperCase();
  let lastGroup: string | undefined;
  const visible = ingestor ? PAGES.filter((p) => p.id === "events" || p.id === "settings") : PAGES;

  return (
    <div className="shell">
      <header className="topbar">
        <div className="brand"><Logo /><div><strong>AegisGate</strong><span>Security Operations Platform</span></div></div>
        <span className="mode-chip"><Icon name="flask" size={16} />Academic Mode <small>(Simulated environment)</small></span>
        <span className="spacer" />
        <span className="health"><i className="dot good" />API connected</span>
        <button className="btn ghost" type="button" onClick={toggleTheme}
          aria-label={theme === "dark" ? "Switch to light mode" : "Switch to dark mode"}>
          <Icon name={theme === "dark" ? "sun" : "moon"} /></button>
        <div className="user"><span className="avatar">{initials}</span>
          <div><b>{session.username}</b><span>{ROLE_LABEL[session.role] ?? session.role}</span></div></div>
        <button className="btn" type="button" onClick={onSignOut}>Sign out</button>
      </header>

      <div className="workspace">
        <nav className="nav" aria-label="Main navigation">
          {visible.map((item) => {
            const heading = item.group && item.group !== lastGroup ? <h4>{item.group}</h4> : null;
            if (item.group) lastGroup = item.group;
            return (
              <div key={item.id}>{heading}
                <button type="button" aria-current={page === item.id ? "page" : undefined}
                  onClick={() => { setPage(item.id); setNotice(null); }}><Icon name={item.icon} />{item.label}</button>
              </div>
            );
          })}
        </nav>

        <main className="evidence">
          <div className="page-head">
            <div><h1>{current.title}</h1><p>{current.subtitle}</p></div>
            <div className="actions">
              <button className="btn" type="button" onClick={refresh}><Icon name="refresh" size={16} />Refresh</button>
              {canAct(session.role) && (
                <button className="btn primary" type="button" onClick={runAnalysis} disabled={running}>
                  <Icon name="target" size={16} />{running ? "Analysing…" : "Run analysis"}</button>
              )}
            </div>
          </div>
          {notice && (
            <div className={`notice ${notice.tone === "error" ? "error" : ""}`} role={notice.tone === "error" ? "alert" : "status"} style={{ marginBottom: 14 }}>
              <Icon name={notice.tone === "error" ? "info" : "check"} /><div>{notice.text}</div></div>
          )}
          {page === "overview" && <OverviewPage {...props} />}
          {page === "events" && <EventsPage {...props} />}
          {page === "assets" && <AssetsPage {...props} />}
          {page === "detection" && <DetectionPage {...props} />}
          {page === "investigations" && <InvestigationsPage {...props} />}
          {page === "responses" && <ResponsePage {...props} />}
          {page === "analytics" && <AnalyticsPage {...props} />}
          {page === "demo" && <DemoLabPage {...props} />}
          {page === "audit" && <AuditPage {...props} />}
          {page === "settings" && <SettingsPage {...props} username={session.username} theme={theme} onToggleTheme={toggleTheme} />}
        </main>

        {!ingestor && <AnalysisPanel role={session.role} groupId={selected} version={version} onChanged={refresh} />}
      </div>
    </div>
  );
}

export default function App() {
  const [session, setSession] = useState<Session | null>(null);
  const [checking, setChecking] = useState(true);
  const [problem, setProblem] = useState<string | null>(null);

  useEffect(() => {
    let ignore = false;
    api.me()
      .then((value) => { if (!ignore) setSession(value); })
      .catch((reason: unknown) => {
        if (!ignore && !(reason instanceof ApiError && reason.status === 401)) {
          setProblem(reason instanceof Error ? reason.message : "Unable to reach the API.");
        }
      })
      .finally(() => { if (!ignore) setChecking(false); });
    return () => { ignore = true; };
  }, []);

  useEffect(() => {
    setUnauthorisedHandler(() => setSession(null));     // session expired or was revoked
    return () => setUnauthorisedHandler(null);
  }, []);

  async function signOut() {
    try { await api.logout(); } catch { /* the session is dropped locally either way */ }
    setSession(null);
  }

  if (checking) return <main className="login"><p className="muted" role="status">Checking your session…</p></main>;
  if (!session) {
    return (
      <>
        {problem && <div className="notice error" role="alert" style={{ margin: 16 }}><Icon name="info" /><div>{problem}</div></div>}
        <Login onSignedIn={(value) => { setProblem(null); setSession(value); }} />
      </>
    );
  }
  return <Workspace session={session} onSignOut={signOut} />;
}
