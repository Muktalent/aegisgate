import { useState, type FormEvent } from "react";
import PortBehaviorAnalysisPanel from "./PortBehaviorAnalysisPanel";
import NetworkBehaviorSummaryPanel from "./NetworkBehaviorSummaryPanel";

import {
  getBehaviorAnalysis,
  type BehaviorAnalysis,
} from "./api";

interface Props {
  accessToken: string;
}

export default function BehaviorAnalysisPage({
  accessToken,
}: Props) {
  const [sourceIp, setSourceIp] = useState("");
  const [windowEnd, setWindowEnd] = useState("");
  const [windowMinutes, setWindowMinutes] = useState("5");
  const [threshold, setThreshold] = useState("10");

  const [result, setResult] = useState<BehaviorAnalysis | null>(null);
  const [error, setError] = useState<string | null>(null);
  const [isLoading, setIsLoading] = useState(false);

  function loadDemoValues() {
    setSourceIp("10.10.10.25");
    setWindowEnd("2026-09-27T22:07:20Z");
    setWindowMinutes("5");
    setThreshold("2");
    setResult(null);
    setError(null);
  }

  async function handleSubmit(event: FormEvent<HTMLFormElement>) {
    event.preventDefault();

    setIsLoading(true);
    setError(null);
    setResult(null);

    try {
      const analysis = await getBehaviorAnalysis(accessToken, {
        sourceIp,
        windowEnd,
        windowMinutes: Number(windowMinutes),
        destinationThreshold: Number(threshold),
      });

      setResult(analysis);
    } catch (requestError) {
      setError(
        requestError instanceof Error
          ? requestError.message
          : "Unable to run the analysis.",
      );
    } finally {
      setIsLoading(false);
    }
  }

  return (
    <section
      className="behavior-section"
      aria-labelledby="behavior-heading"
    >
      <div className="section-heading">
        <div>
          <p className="eyebrow">BEHAVIOUR ANALYTICS · V1</p>
          <h2 id="behavior-heading">Network Behaviour Analysis</h2>
          <p className="section-description">
            Count distinct destinations observed for a source IP
            within a defined time window. This is a configurable
            heuristic, not a machine-learning detection.
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
          <label htmlFor="behavior-source">
            Source IP
            <input
              id="behavior-source"
              required
              value={sourceIp}
              onChange={(event) => {
                setSourceIp(event.target.value);
                setResult(null);
              }}
              placeholder="10.10.10.25"
            />
          </label>

          <label htmlFor="behavior-end">
            Window end — include timezone
            <input
              id="behavior-end"
              required
              value={windowEnd}
              onChange={(event) => {
                setWindowEnd(event.target.value);
                setResult(null);
              }}
              placeholder="2026-09-27T22:07:20Z"
            />
          </label>

          <label htmlFor="behavior-window">
            Window in minutes
            <input
              id="behavior-window"
              type="number"
              required
              min={1}
              max={1440}
              step={1}
              value={windowMinutes}
              onChange={(event) => {
                setWindowMinutes(event.target.value);
                setResult(null);
              }}
            />
          </label>

          <label htmlFor="behavior-threshold">
            Destination threshold
            <input
              id="behavior-threshold"
              type="number"
              required
              min={2}
              max={10000}
              step={1}
              value={threshold}
              onChange={(event) => {
                setThreshold(event.target.value);
                setResult(null);
              }}
            />
          </label>
        </fieldset>

        <button
          className="behavior-submit"
          type="submit"
          disabled={isLoading}
        >
          {isLoading ? "Analysing…" : "Run analysis"}
        </button>
      </form>

      <div aria-live="polite">
        {error && (
          <div className="error-panel" role="alert">
            <h3>Analysis unavailable</h3>
            <p>{error}</p>
          </div>
        )}

        {result && (
          <article
            className={`behavior-result ${
              result.triggered
                ? "behavior-result--triggered"
                : ""
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
                <dt>Unique destinations</dt>
                <dd>{result.unique_destination_count}</dd>
              </div>
              <div>
                <dt>Threshold</dt>
                <dd>{result.destination_threshold}</dd>
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

            <h4>Observed destinations</h4>
            {result.observed_destinations.length > 0 ? (
              <ul>
                {result.observed_destinations.map((destination) => (
                  <li key={destination}>
                    <code>{destination}</code>
                  </li>
                ))}
              </ul>
            ) : (
              <p>No destinations observed in this window.</p>
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
              {" "}Available source records:
              {" "}{result.source_record_count}.
            </p>
          </article>
        )}
            </div>

      <PortBehaviorAnalysisPanel accessToken={accessToken} />
      <NetworkBehaviorSummaryPanel accessToken={accessToken} />
    </section>
  );
}