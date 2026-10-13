import { useState, type FormEvent } from "react";

import {
  getPortBehaviorAnalysis,
  type PortBehaviorAnalysis,
} from "./api";

interface Props {
  accessToken: string;
}

export default function PortBehaviorAnalysisPanel({
  accessToken,
}: Props) {
  const [sourceIp, setSourceIp] = useState("");
  const [destinationIp, setDestinationIp] = useState("");
  const [windowEnd, setWindowEnd] = useState("");
  const [windowMinutes, setWindowMinutes] = useState("5");
  const [threshold, setThreshold] = useState("10");

  const [result, setResult] = useState<PortBehaviorAnalysis | null>(null);
  const [error, setError] = useState<string | null>(null);
  const [isLoading, setIsLoading] = useState(false);

  function clearFeedback() {
    setResult(null);
    setError(null);
  }

  async function handleSubmit(event: FormEvent<HTMLFormElement>) {
    event.preventDefault();

    setIsLoading(true);
    setError(null);
    setResult(null);

    try {
      const analysis = await getPortBehaviorAnalysis(accessToken, {
        sourceIp,
        destinationIp,
        windowEnd,
        windowMinutes: Number(windowMinutes),
        portThreshold: Number(threshold),
      });

      setResult(analysis);
    } catch (requestError) {
      setError(
        requestError instanceof Error
          ? requestError.message
          : "Unable to run the port analysis.",
      );
    } finally {
      setIsLoading(false);
    }
  }

  return (
    <section
      className="behavior-section"
      aria-labelledby="port-behavior-heading"
    >
      <div className="section-heading">
        <div>
          <p className="eyebrow">PORT DIVERSITY · V1</p>
          <h2 id="port-behavior-heading">Destination Port Analysis</h2>
          <p className="section-description">
            Count distinct destination port numbers for a source IP
            within a defined time window. Optionally restrict the
            analysis to one destination.
          </p>
        </div>
      </div>

      <form className="behavior-form" onSubmit={handleSubmit}>
        <fieldset disabled={isLoading}>
          <label htmlFor="port-source">
            Source IP
            <input
              id="port-source"
              required
              value={sourceIp}
              onChange={(event) => {
                setSourceIp(event.target.value);
                clearFeedback();
              }}
              placeholder="10.10.10.25"
            />
          </label>

          <label htmlFor="port-destination">
            Destination IP — optional
            <input
              id="port-destination"
              value={destinationIp}
              onChange={(event) => {
                setDestinationIp(event.target.value);
                clearFeedback();
              }}
              placeholder="Leave empty for all destinations"
            />
          </label>

          <label htmlFor="port-end">
            Window end — include timezone
            <input
              id="port-end"
              required
              value={windowEnd}
              onChange={(event) => {
                setWindowEnd(event.target.value);
                clearFeedback();
              }}
              placeholder="2026-09-27T22:07:20Z"
            />
          </label>

          <label htmlFor="port-window">
            Window in minutes
            <input
              id="port-window"
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

          <label htmlFor="port-threshold">
            Port threshold
            <input
              id="port-threshold"
              type="number"
              required
              min={2}
              max={65535}
              step={1}
              value={threshold}
              onChange={(event) => {
                setThreshold(event.target.value);
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
          {isLoading ? "Analysing…" : "Run port analysis"}
        </button>
      </form>

      <div aria-live="polite">
        {error && (
          <div className="error-panel" role="alert">
            <h3>Port analysis unavailable</h3>
            <p>{error}</p>
          </div>
        )}

        {result && (
          <article
            className={`behavior-result ${
              result.triggered ? "behavior-result--triggered" : ""
            }`}
          >
            <h3>
              {result.triggered
                ? "Threshold reached — review required"
                : "Threshold not reached"}
            </h3>

            <p>{result.interpretation}</p>

            <dl className="behavior-metrics">
              <div>
                <dt>Source IP</dt>
                <dd>{result.source_ip}</dd>
              </div>
              <div>
                <dt>Destination filter</dt>
                <dd>{result.destination_filter ?? "All destinations"}</dd>
              </div>
              <div>
                <dt>Unique destination ports</dt>
                <dd>{result.unique_port_count}</dd>
              </div>
              <div>
                <dt>Threshold</dt>
                <dd>{result.port_threshold}</dd>
              </div>
              <div>
                <dt>Matching records — not connections</dt>
                <dd>{result.matching_record_count}</dd>
              </div>
            </dl>

            <p>
              Window: <code>{result.window_start}</code>
              {" → "}
              <code>{result.window_end}</code>
            </p>

            {result.matching_record_count === 0 && (
              <p>
                No qualifying records were found. This does not
                establish that the device was inactive or safe.
              </p>
            )}

            <h4>Observed ports</h4>
            <p>
              {result.observed_ports.length > 0
                ? result.observed_ports.join(", ")
                : "No valid destination ports observed in this window."}
            </p>

            <h4>Ports by destination</h4>
            {Object.keys(result.ports_by_destination).length > 0 ? (
              <ul>
                {Object.entries(result.ports_by_destination).map(
                  ([destination, ports]) => (
                    <li key={destination}>
                      <code>{destination}</code>: {ports.join(", ")}
                    </li>
                  ),
                )}
              </ul>
            ) : (
              <p>No destination breakdown available.</p>
            )}

            <details className="behavior-evidence">
              <summary>
                Evidence ({result.evidence_event_ids.length} records)
              </summary>
              <ul>
                {result.evidence_event_ids.map((eventId) => (
                  <li key={eventId}>
                    <code>{eventId}</code>
                  </li>
                ))}
              </ul>
            </details>

            <h4>Interpretation limits</h4>
            <ul>
              {result.limitations.map((limitation) => (
                <li key={limitation}>{limitation}</li>
              ))}
            </ul>

            <p className="behavior-note">
              Scope: {result.scope}. Version: {result.analysis_version}.
              {" "}Invalid timestamps skipped:
              {" "}{result.skipped_invalid_timestamps}.
              {" "}Invalid ports skipped:
              {" "}{result.skipped_invalid_ports}.
              {" "}Available source records:
              {" "}{result.source_record_count}.
            </p>
          </article>
        )}
      </div>
    </section>
  );
}