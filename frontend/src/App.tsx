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

function App() {
  const [token, setToken] = useState(
    () => localStorage.getItem(STORAGE_KEY) ?? "",
  );
  const [tokenInput, setTokenInput] = useState(token);
  const [summary, setSummary] = useState<DashboardSummary | null>(
    null,
  );
  const [error, setError] = useState<string | null>(null);
  const [isLoading, setIsLoading] = useState(false);

  async function loadSummary(currentToken: string) {
    if (!currentToken.trim()) {
      setSummary(null);
      setError(null);
      return;
    }

    setIsLoading(true);
    setError(null);

    try {
      const dashboardSummary = await getDashboardSummary(currentToken);

      setSummary(dashboardSummary);
    } catch (requestError) {
      setSummary(null);

      setError(
        requestError instanceof Error
          ? requestError.message
          : "Unable to load the dashboard.",
      );
    } finally {
      setIsLoading(false);
    }
  }

  useEffect(() => {
    void loadSummary(token);
  }, [token]);

  function handleTokenSubmit(event: FormEvent<HTMLFormElement>) {
    event.preventDefault();

    const nextToken = tokenInput.trim();

    if (!nextToken) {
      localStorage.removeItem(STORAGE_KEY);
      setToken("");
      return;
    }

    localStorage.setItem(STORAGE_KEY, nextToken);
    setToken(nextToken);
  }

  function handleSignOut() {
    localStorage.removeItem(STORAGE_KEY);
    setToken("");
    setTokenInput("");
    setSummary(null);
    setError(null);
  }

  if (!token) {
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

          <form
            className="token-form"
            onSubmit={handleTokenSubmit}
          >
            <label htmlFor="access-token">
              Access token
            </label>

            <textarea
              id="access-token"
              value={tokenInput}
              onChange={(event) =>
                setTokenInput(event.target.value)
              }
              placeholder="eyJhbGciOi..."
              rows={7}
              spellCheck={false}
            />

            <button type="submit">
              Open dashboard
            </button>
          </form>
        </section>
      </main>
    );
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
            onClick={() => void loadSummary(token)}
            type="button"
          >
            Refresh
          </button>

          <button
            className="secondary-button"
            onClick={handleSignOut}
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
        <section className="error-panel">
          <h2>Unable to load the dashboard</h2>
          <p>{error}</p>
          <p>
            Verify that FastAPI is running and that the token belongs
            to a <code>soc_analyst</code> or{" "}
            <code>security_admin</code> user.
          </p>
        </section>
      )}

      {summary && !isLoading && (
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

          <AlertsPage accessToken={token} />
        </>
      )}
    </main>
  );
}

export default App;