import { useState, type FormEvent } from "react";

import {
  getNetworkBehaviorSummary,
  type NetworkBehaviorPattern,
  type NetworkBehaviorSummary,
} from "./api";

interface Props {
  accessToken: string;
}

const patternLabels: Record<NetworkBehaviorPattern, string> = {
  neither_threshold_reached: "Neither threshold reached",
  destination_threshold_only: "Destination threshold only",
  port_threshold_only: "Port threshold only",
  both_thresholds_reached: "Both thresholds reached",
};

export default function NetworkBehaviorSummaryPanel({
  accessToken,
}: Props) {
  const [sourceIp, setSourceIp] = useState("");
  const [windowEnd, setWindowEnd] = useState("");
  const [windowMinutes, setWindowMinutes] = useState("5");
  const [destinationThreshold, setDestinationThreshold] = useState("10");
  const [portThreshold, setPortThreshold] = useState("10");

  const [result, setResult] = useState<NetworkBehaviorSummary | null>(null);
  const [error, setError] = useState<string | null>(null);
  const [isLoading, setIsLoading] = useState(false);

  function clearFeedback() {
    setResult(null);
    setError(null);
  }

  function loadDemoValues() {
    setSourceIp("10.10.10.25");
    setWindowEnd("2026-09-27T22:07:20Z");
    setWindowMinutes("5");
    setDestinationThreshold("2");
    setPortThreshold("2");
    clearFeedback();
  }

  async function handleSubmit(event: FormEvent<HTMLFormElement>) {
    event.preventDefault();

    setIsLoading(true);
    setError(null);
    setResult(null);

    try {
      const summary = await getNetworkBehaviorSummary(accessToken, {
        sourceIp,
        windowEnd,
        windowMinutes: Number(windowMinutes),
        destinationThreshold: Number(destinationThreshold),
        portThreshold: Number(portThreshold),
      });

      setResult(summary);
    } catch (requestError) {
      setError(
        requestError instanceof Error
          ? requestError.message
          : "Unable to run the network summary.",
      );
    } finally {
      setIsLoading(false);
    }
  }

  function renderEvidence(label: string, eventIds: string[]) {
    return (
      <details className="behavior-evidence">
        <summary>
          {label} ({eventIds.length} event IDs)
        </summary>
        {eventIds.length > 0 ? (
          <ul>
            {eventIds.map((eventId) => (
              <li key={eventId}>
                <code>{eventId}</code>
              </li>
            ))}
          </ul>
        ) : (
          <p>No event IDs in this group.</p>
        )}
      </details>
    );
  }

  return (
    <section
      className="behavior-section"
      aria-labelledby="network-summary-heading"
    >
      <div className="section-heading">
        <div>
          <p className="eyebrow">COMBINED BEHAVIOUR · V1</p>
          <h2 id="network-summary-heading">Network Behaviour Summary</h2>
          <p className="section-description">
            Compare destination and port diversity for the same source
            and time window. This combines configured heuristics, not
            machine-learning detections.
          </p>
        </div>

        <button
          className="secondary-button"
          type="button"
          disabled={isLoading}
          onClick={loadDemoValues}
        >
          Use demo values
        </button>
      </div>

      <form className="behavior-form" onSubmit={handleSubmit}>
        <fieldset disabled={isLoading}>
          <label htmlFor="summary-source">
            Source IP
            <input
              id="summary-source"
              required
              value={sourceIp}
              onChange={(event) => {
                setSourceIp(event.target.value);
                clearFeedback();
              }}
              placeholder="10.10.10.25"
            />
          </label>

          <label htmlFor="summary-end">
            Window end — include timezone
            <input
              id="summary-end"
              required
              value={windowEnd}
              onChange={(event) => {
                setWindowEnd(event.target.value);
                clearFeedback();
              }}
              placeholder="2026-09-27T22:07:20Z"
            />
          </label>

          <label htmlFor="summary-window">
            Window in minutes
            <input
              id="summary-window"
              type="number"
              required
              min={1}
              max={1440}
              step={1}
              value={windowMinutes}
              onChange={(event) => {
                setWindowMinutes(event.target.value);
                clearFeedback();
              }}
            />
          </label>

          <label htmlFor="summary-destination-threshold">
            Destination threshold
            <input
              id="summary-destination-threshold"
              type="number"
              required
              min={2}
              max={10000}
              step={1}
              value={destinationThreshold}
              onChange={(event) => {
                setDestinationThreshold(event.target.value);
                clearFeedback();
              }}
            />
          </label>

          <label htmlFor="summary-port-threshold">
            Port threshold
            <input
              id="summary-port-threshold"
              type="number"
              required
              min={2}
              max={65535}
              step={1}
              value={portThreshold}
              onChange={(event) => {
                setPortThreshold(event.target.value);
                clearFeedback();
              }}
            />
          </label>
        </fieldset>

        <button
          className="behavior-submit"
          type="submit"
          disabled={isLoading}
        >
          {isLoading ? "Analysing…" : "Run network summary"}
        </button>
      </form>

      <div aria-live="polite">
        {error && (
          <div className="error-panel" role="alert">
            <h3>Network summary unavailable</h3>
            <p>{error}</p>
          </div>
        )}

        {result && (
          <article
            className={`behavior-result ${
              result.triggered ? "behavior-result--triggered" : ""
            }`}
          >
            <h3>{patternLabels[result.pattern]}</h3>
            <p>{result.interpretation}</p>

            <dl className="behavior-metrics">
              <div>
                <dt>Source IP</dt>
                <dd>{result.source_ip}</dd>
              </div>
              <div>
                <dt>Unique destinations / threshold</dt>
                <dd>
                  {result.destination_analysis.unique_destination_count}
                  {" / "}
                  {result.destination_analysis.destination_threshold}
                </dd>
              </div>
              <div>
                <dt>Destination signal</dt>
                <dd>
                  {result.destination_analysis.triggered
                    ? "Threshold reached"
                    : "Threshold not reached"}
                </dd>
              </div>
              <div>
                <dt>Unique ports / threshold</dt>
                <dd>
                  {result.port_analysis.unique_port_count}
                  {" / "}
                  {result.port_analysis.port_threshold}
                </dd>
              </div>
              <div>
                <dt>Port signal</dt>
                <dd>
                  {result.port_analysis.triggered
                    ? "Threshold reached"
                    : "Threshold not reached"}
                </dd>
              </div>
              <div>
                <dt>Destination matching records</dt>
                <dd>{result.destination_analysis.matching_record_count}</dd>
              </div>
              <div>
                <dt>Port matching records</dt>
                <dd>{result.port_analysis.matching_record_count}</dd>
              </div>
            </dl>

            <p>
              Window: <code>{result.window_start}</code>
              {" → "}
              <code>{result.window_end}</code>
            </p>

            <h4>Observed destinations</h4>
            {result.destination_analysis.observed_destinations.length > 0 ? (
              <ul>
                {result.destination_analysis.observed_destinations.map(
                  (destination) => (
                    <li key={destination}>
                      <code>{destination}</code>
                    </li>
                  ),
                )}
              </ul>
            ) : (
              <p>No qualifying destinations observed.</p>
            )}

            <h4>Observed ports</h4>
            <p>
              {result.port_analysis.observed_ports.length > 0
                ? result.port_analysis.observed_ports.join(", ")
                : "No valid destination ports observed."}
            </p>

            <h4>Ports by destination</h4>
            {Object.keys(result.port_analysis.ports_by_destination).length > 0 ? (
              <ul>
                {Object.entries(
                  result.port_analysis.ports_by_destination,
                ).map(([destination, ports]) => (
                  <li key={destination}>
                    <code>{destination}</code>: {ports.join(", ")}
                  </li>
                ))}
              </ul>
            ) : (
              <p>No destination breakdown available.</p>
            )}

            <h4>Evidence groups</h4>
            <p>
              These groups compare event IDs accepted by each signal.
              They are not connection counts.
            </p>

            {renderEvidence("All evidence", result.evidence_event_ids)}
            {renderEvidence(
              "Shared evidence",
              result.shared_evidence_event_ids,
            )}
            {renderEvidence(
              "Destination-only evidence",
              result.destination_only_evidence_event_ids,
            )}
            {renderEvidence(
              "Port-only evidence",
              result.port_only_evidence_event_ids,
            )}

            <h4>Interpretation limits</h4>
            <ul>
              {result.limitations.map((limitation) => (
                <li key={limitation}>{limitation}</li>
              ))}
            </ul>

            <p className="behavior-note">
              Scope: {result.scope}. Version: {result.analysis_version}.
              {" "}Available source records: {result.source_record_count}.
              {" "}Destination-analysis invalid timestamps:
              {" "}{result.destination_analysis.skipped_invalid_timestamps}.
              {" "}Port-analysis invalid timestamps:
              {" "}{result.port_analysis.skipped_invalid_timestamps}.
              {" "}Invalid or missing ports skipped:
              {" "}{result.port_analysis.skipped_invalid_ports}.
            </p>
          </article>
        )}
      </div>
    </section>
  );
}