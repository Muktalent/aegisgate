import {
  useEffect,
  useMemo,
  useState,
  type FormEvent,
} from "react";

import {
  createCase,
  getAlerts,
  type AlertRecord,
} from "./api";

interface AlertsPageProps {
  accessToken: string;
}

function severityLabel(severity: number | undefined): string {
  if (severity === undefined) {
    return "Unknown";
  }

  if (severity <= 1) {
    return "Critical";
  }

  if (severity === 2) {
    return "High";
  }

  if (severity === 3) {
    return "Medium";
  }

  return "Low";
}

function AlertsPage({
  accessToken,
}: AlertsPageProps) {
  const [alerts, setAlerts] = useState<AlertRecord[]>([]);
  const [query, setQuery] = useState("");
  const [isLoading, setIsLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);
  const [caseMessage, setCaseMessage] = useState<string | null>(
    null,
  );
  const [creatingForEventId, setCreatingForEventId] = useState<
    string | null
  >(null);

  async function loadAlerts() {
    setIsLoading(true);
    setError(null);

    try {
      const loadedAlerts = await getAlerts(accessToken);

      setAlerts(loadedAlerts);
    } catch (requestError) {
      setError(
        requestError instanceof Error
          ? requestError.message
          : "Unable to load alerts.",
      );
    } finally {
      setIsLoading(false);
    }
  }

  useEffect(() => {
    void loadAlerts();
  }, [accessToken]);

  const filteredAlerts = useMemo(() => {
    const normalizedQuery = query.trim().toLowerCase();

    if (!normalizedQuery) {
      return alerts;
    }

    return alerts.filter((alert) => {
      const searchableValues = [
        alert.event_id,
        alert.status,
        alert.telemetry.source,
        alert.telemetry.source_ip,
        alert.telemetry.destination_ip ?? "",
        alert.telemetry.signature ?? "",
        alert.access_decision?.action ?? "",
      ];

      return searchableValues.some((value) =>
        value.toLowerCase().includes(normalizedQuery),
      );
    });
  }, [alerts, query]);

  async function handleCreateCase(
    event: FormEvent<HTMLFormElement>,
    alert: AlertRecord,
  ) {
    event.preventDefault();

    const form = new FormData(event.currentTarget);
    const title = String(form.get("title") ?? "").trim();

    if (!title) {
      setCaseMessage("A case title is required.");
      return;
    }

    setCreatingForEventId(alert.event_id);
    setCaseMessage(null);

    try {
      const incidentCase = await createCase(
        accessToken,
        alert.event_id,
        {
          title,
          analyst_note: String(
            form.get("analyst_note") ?? "",
          ).trim(),
        },
      );

      setCaseMessage(
        `Case ${incidentCase.case_id} created for alert ` +
          `${alert.event_id}.`,
      );

      event.currentTarget.reset();
    } catch (requestError) {
      setCaseMessage(
        requestError instanceof Error
          ? requestError.message
          : "Unable to create the case.",
      );
    } finally {
      setCreatingForEventId(null);
    }
  }

  return (
    <section className="alerts-section">
      <div className="section-heading">
        <div>
          <p className="eyebrow">PERSISTED EVIDENCE</p>
          <h2>Alert queue</h2>
          <p className="section-description">
            Search alerts by IP address, source, signature, identifier,
            or access action.
          </p>
        </div>

        <button
          className="secondary-button"
          onClick={() => void loadAlerts()}
          type="button"
        >
          Refresh alerts
        </button>
      </div>

      <label className="search-field" htmlFor="alert-search">
        Search alerts
        <input
          id="alert-search"
          onChange={(event) => setQuery(event.target.value)}
          placeholder="IP address, source, signature, action, or event ID"
          value={query}
        />
      </label>

      {isLoading && (
        <p className="status-message">Loading alerts…</p>
      )}

      {error && (
        <section className="error-panel">
          <h2>Unable to load alerts</h2>
          <p>{error}</p>
        </section>
      )}

      {caseMessage && (
        <p className="case-message">{caseMessage}</p>
      )}

      {!isLoading && !error && (
        <div className="alerts-table-wrapper">
          <table className="alerts-table">
            <thead>
              <tr>
                <th>Severity</th>
                <th>Source</th>
                <th>Source IP</th>
                <th>Signature</th>
                <th>Decision</th>
                <th>Status</th>
                <th>Case</th>
              </tr>
            </thead>

            <tbody>
              {filteredAlerts.map((alert) => {
                const severity = alert.risk_assessment?.severity;

                return (
                  <tr key={alert.event_id}>
                    <td>
                      <span
                        className={
                          "severity severity--" +
                          severityLabel(severity).toLowerCase()
                        }
                      >
                        {severityLabel(severity)}
                      </span>
                    </td>

                    <td>{alert.telemetry.source}</td>
                    <td>
                      <code>{alert.telemetry.source_ip}</code>
                    </td>
                    <td>
                      {alert.telemetry.signature ??
                        "No signature available"}
                    </td>
                    <td>
                      {alert.access_decision?.action ??
                        "Not evaluated"}
                    </td>
                    <td>{alert.status}</td>

                    <td>
                      <details className="case-details">
                        <summary>Open case</summary>

                        <form
                          className="case-form"
                          onSubmit={(event) =>
                            void handleCreateCase(event, alert)
                          }
                        >
                          <label>
                            Case title
                            <input
                              defaultValue={
                                "Investigate " +
                                alert.telemetry.source_ip
                              }
                              name="title"
                            />
                          </label>

                          <label>
                            Analyst note
                            <textarea
                              name="analyst_note"
                              placeholder="Initial investigation note"
                              rows={3}
                            />
                          </label>

                          <button
                            disabled={
                              creatingForEventId === alert.event_id
                            }
                            type="submit"
                          >
                            {creatingForEventId === alert.event_id
                              ? "Creating…"
                              : "Create case"}
                          </button>
                        </form>
                      </details>
                    </td>
                  </tr>
                );
              })}
            </tbody>
          </table>

          {filteredAlerts.length === 0 && (
            <p className="empty-state table-empty-state">
              No alerts match the current search.
            </p>
          )}
        </div>
      )}
    </section>
  );
}

export default AlertsPage;