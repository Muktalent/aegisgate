import {
  useEffect,
  useState,
  type FormEvent,
} from "react";

import {
  getDashboardSummary,
  type DashboardSummary,
} from "./api";

import AlertsPage from "./AlertsPage";
import BehaviorAnalysisPage from "./BehaviorAnalysisPage";
import "./App.css";

const STORAGE_KEY = "aegisgate_access_token";

interface MetricCardProps {
  label: string;
  value: number;
  tone: "neutral" | "warning" | "critical" | "success";
}

function MetricCard({
  label,
  value,
  tone,
}: MetricCardProps) {
  return (
    <article className={`metric-card metric-card--${tone}`}>
      <p className="metric-card__label">{label}</p>
      <p className="metric-card__value">{value}</p>
    </article>
  );
}

function CountList({
  values,
}: {
  values: Record<string, number>;
}) {
  const entries = Object.entries(values);

  if (entries.length === 0) {
    return <p className="empty-state">No data available.</p>;
  }

  return (
    <ul className="count-list">
      {entries.map(([label, value]) => (
        <li key={label}>
          <span>{label.replaceAll("_", " ")}</span>
          <strong>{value}</strong>
        </li>
      ))}
    </ul>
  );
}

interface DashboardProps {
  accessToken: string;
  onSignOut: () => void;
}

function Dashboard({
  accessToken,
  onSignOut,
}: DashboardProps) {
  const [summary, setSummary] = useState<DashboardSummary | null>(null);
  const [error, setError] = useState<string | null>(null);
  const [isLoading, setIsLoading] = useState(true);
  const [refreshVersion, setRefreshVersion] = useState(0);

  useEffect(() => {
    let ignore = false;

    async function fetchSummary() {
      try {
        const loadedSummary = await getDashboardSummary(accessToken);

        if (!ignore) {
          setSummary(loadedSummary);
          setError(null);
        }
      } catch (requestError) {
        if (!ignore) {
          setSummary(null);
          setError(
            requestError instanceof Error
              ? requestError.message
              : "Unable to load the dashboard.",
          );
        }
      } finally {
        if (!ignore) {
          setIsLoading(false);
        }
      }
    }

    void fetchSummary();

    return () => {
      ignore = true;
    };
  }, [accessToken, refreshVersion]);

  function handleRefresh() {
    setIsLoading(true);
    setError(null);
    setRefreshVersion((version) => version + 1);
  }

  return (
    <main className="dashboard-page">
      <header className="dashboard-header">
        <div>
          <p className="eyebrow">AEGISGATE SOC</p>
          <h1>Security posture overview</h1>
          <p>
            Aggregated metrics for alerts, access decisions, and
            persistent cases.
          </p>
        </div>

        <div className="header-actions">
          <button
            className="secondary-button"
            onClick={handleRefresh}
            disabled={isLoading}
            type="button"
          >
            {isLoading ? "Refreshing…" : "Refresh"}
          </button>

          <button
            className="secondary-button"
            onClick={onSignOut}
            type="button"
          >
            Sign out
          </button>
        </div>
      </header>

      {isLoading && (
        <p className="status-message">
          Loading dashboard metrics…
        </p>
      )}

      {error && (
        <section className="error-panel" role="alert">
          <h2>Unable to load the dashboard</h2>
          <p>{error}</p>
          <p>
            Verify that FastAPI is running and that the token belongs
            to a <code>soc_analyst</code> or{" "}
            <code>security_admin</code> user.
          </p>
        </section>
      )}

      {summary && (
        <>
          <section
            aria-label="Security metrics"
            className="metrics-grid"
          >
            <MetricCard
              label="Total alerts"
              value={summary.total_alerts}
              tone="neutral"
            />
            <MetricCard
              label="Open cases"
              value={summary.open_cases}
              tone="warning"
            />
            <MetricCard
              label="Critical alerts"
              value={summary.critical_alerts}
              tone="critical"
            />
            <MetricCard
              label="Denied events"
              value={summary.denied_events}
              tone="success"
            />
            <MetricCard
              label="Unresolved assets"
              value={summary.unresolved_assets}
              tone="warning"
            />
          </section>

          <section className="breakdown-grid">
            <article className="breakdown-card">
              <h2>Alerts by source</h2>
              <CountList values={summary.alerts_by_source} />
            </article>

            <article className="breakdown-card">
              <h2>Cases by status</h2>
              <CountList values={summary.cases_by_status} />
            </article>
          </section>

          <BehaviorAnalysisPage accessToken={accessToken} />
          <AlertsPage key={accessToken} accessToken={accessToken} />
        </>
      )}
    </main>
  );
}

function App() {
  const [token, setToken] = useState(
    () => localStorage.getItem(STORAGE_KEY) ?? "",
  );
  const [tokenInput, setTokenInput] = useState(token);

  function handleTokenSubmit(event: FormEvent<HTMLFormElement>) {
    event.preventDefault();

    const nextToken = tokenInput.trim();

    if (!nextToken) {
      localStorage.removeItem(STORAGE_KEY);
      setToken("");
      setTokenInput("");
      return;
    }

    localStorage.setItem(STORAGE_KEY, nextToken);
    setToken(nextToken);
  }

  function handleSignOut() {
    localStorage.removeItem(STORAGE_KEY);
    setToken("");
    setTokenInput("");
  }

  if (token) {
    return (
      <Dashboard
        key={token}
        accessToken={token}
        onSignOut={handleSignOut}
      />
    );
  }

  return (
    <main className="authentication-page">
      <section className="login-panel">
        <p className="eyebrow">AEGISGATE SOC</p>
        <h1>Security operations console</h1>
        <p className="login-panel__description">
          Enter a JWT for a user with the{" "}
          <code>soc_analyst</code> or{" "}
          <code>security_admin</code> role.
        </p>

        <form className="token-form" onSubmit={handleTokenSubmit}>
          <label htmlFor="access-token">Access token</label>

          <textarea
            id="access-token"
            value={tokenInput}
            onChange={(event) => setTokenInput(event.target.value)}
            placeholder="eyJhbGciOi..."
            rows={7}
            spellCheck={false}
          />

          <button type="submit">Open dashboard</button>
        </form>
      </section>
    </main>
  );
}

export default App;
