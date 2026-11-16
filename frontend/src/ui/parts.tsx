import type { ReactNode } from "react";

import type { AssetStatus, Level, Overview, Severity } from "../client";
import { titleCase } from "../client";

/* ---------- icons (inline, 18px, currentColor) ---------- */
const PATHS: Record<string, string> = {
  home: "M3 10.5 12 3l9 7.5V20a1 1 0 0 1-1 1h-5v-6H9v6H4a1 1 0 0 1-1-1z",
  pulse: "M3 12h4l2.5-6 4 12 2.5-6H21",
  monitor: "M4 5h16v11H4zM9 20h6M12 16v4",
  shield: "M12 3 4.5 6v5.5c0 4.6 3.1 8 7.5 9.5 4.4-1.5 7.5-4.9 7.5-9.5V6z",
  folder: "M3 7a1 1 0 0 1 1-1h5l2 2h9a1 1 0 0 1 1 1v9a1 1 0 0 1-1 1H4a1 1 0 0 1-1-1z",
  bolt: "M13 2 5 13.5h6L10 22l8-11.5h-6z",
  chart: "M5 20V11M10 20V5M15 20v-7M20 20V8",
  flask: "M9 3h6M10 3v6l-5 9.5A1.5 1.5 0 0 0 6.3 21h11.4a1.5 1.5 0 0 0 1.3-2.5L14 9V3",
  doc: "M7 3h7l4 4v14H7zM14 3v4h4M10 12h5M10 16h5",
  gear: "M12 9a3 3 0 1 0 0 6 3 3 0 0 0 0-6zM12 2v3M12 19v3M2 12h3M19 12h3M5 5l2 2M17 17l2 2M19 5l-2 2M7 17l-2 2",
  target: "M12 21a9 9 0 1 0 0-18 9 9 0 0 0 0 18zM12 16a4 4 0 1 0 0-8 4 4 0 0 0 0 8zM12 12h.01",
  refresh: "M20 11A8 8 0 0 0 6 6.5L4 8.5M4 4v4.5h4.5M4 13a8 8 0 0 0 14 4.5l2-2M20 20v-4.5h-4.5",
  sun: "M12 8a4 4 0 1 0 0 8 4 4 0 0 0 0-8zM12 2v2M12 20v2M2 12h2M20 12h2M5 5l1.5 1.5M17.5 17.5 19 19M19 5l-1.5 1.5M6.5 17.5 5 19",
  moon: "M20 14.5A8 8 0 0 1 9.5 4 8 8 0 1 0 20 14.5z",
  info: "M12 21a9 9 0 1 0 0-18 9 9 0 0 0 0 18zM12 11v6M12 7.5h.01",
  check: "M5 12.5 10 17l9-10",
};

export function Icon({ name, size = 18 }: { name: string; size?: number }) {
  return (
    <svg width={size} height={size} viewBox="0 0 24 24" fill="none" stroke="currentColor"
      strokeWidth="1.8" strokeLinecap="round" strokeLinejoin="round" aria-hidden="true">
      <path d={PATHS[name] ?? PATHS.info} />
    </svg>
  );
}

export function Logo() {
  return (
    <svg width="30" height="30" viewBox="0 0 24 24" aria-hidden="true">
      <path d="M12 2 3.5 5.4v6.1c0 5 3.5 8.8 8.5 10.5 5-1.7 8.5-5.5 8.5-10.5V5.4z" fill="var(--accent)" />
      <path d="M12 6.2 7.4 8v3.6c0 2.9 1.9 5.1 4.6 6.2z" fill="var(--surface)" opacity="0.92" />
    </svg>
  );
}

/* ---------- small components ---------- */
export function LevelBadge({ level }: { level: Level | Severity | string }) {
  const tone = level === "critical" || level === "high" || level === "medium" ? level : "";
  return <span className={`badge ${tone}`}><i className={`dot ${level}`} />{titleCase(level)}</span>;
}

const DECISIONS: Record<string, { label: string; tone: string }> = {
  allow: { label: "Allow", tone: "good" },
  allow_with_monitoring: { label: "Allow with monitoring", tone: "" },
  manual_review: { label: "Manual review", tone: "medium" },
  step_up_authentication: { label: "Step-up recommended", tone: "high" },
  deny: { label: "Deny (simulated)", tone: "critical" },
};

export function DecisionBadge({ decision }: { decision: string }) {
  const entry = DECISIONS[decision] ?? { label: titleCase(decision), tone: "" };
  return <span className={`badge ${entry.tone}`}>{entry.label}</span>;
}

export function State({ title, children }: { title: string; children?: ReactNode }) {
  return <div className="state" role="status"><strong>{title}</strong>{children}</div>;
}

export function ErrorNotice({ message, onRetry }: { message: string; onRetry?: () => void }) {
  return (
    <div className="notice error" role="alert">
      <Icon name="info" />
      <div><b>Something went wrong</b>{message}
        {onRetry && <div style={{ marginTop: 8 }}><button className="btn" onClick={onRetry} type="button">Try again</button></div>}
      </div>
    </div>
  );
}

/* ---------- charts ---------- */
const SEVERITY_ORDER: Severity[] = ["low", "medium", "high", "critical"];
const SEVERITY_COLOR: Record<Severity, string> = {
  critical: "var(--critical)", high: "var(--high)", medium: "var(--medium)", low: "var(--low)",
};

/** Detections per hour, stacked by severity. Hour labels are UTC. */
export function TrendChart({ data }: { data: Overview["detection_trend"] }) {
  const width = 560, height = 210, left = 28, bottom = 22, top = 8;
  const totals = data.map((d) => SEVERITY_ORDER.reduce((sum, s) => sum + d[s], 0));
  const peak = Math.max(1, ...totals);
  const ticks = Array.from(new Set([0, Math.ceil(peak / 2), peak]));
  const plotHeight = height - bottom - top;
  const step = (width - left) / Math.max(1, data.length);
  const barWidth = Math.max(4, step - 6);
  const y = (value: number) => top + plotHeight - (value / peak) * plotHeight;

  return (
    <figure style={{ margin: 0 }}>
      <svg viewBox={`0 0 ${width} ${height}`} role="img" width="100%"
        aria-label={`Detections per hour for 24 hours; ${totals.reduce((a, b) => a + b, 0)} in total.`}>
        {ticks.map((tick) => (
          <g key={tick}>
            <line x1={left} x2={width} y1={y(tick)} y2={y(tick)} stroke="var(--border)" strokeWidth="1" />
            <text x={left - 6} y={y(tick) + 4} textAnchor="end" fontSize="11" fill="var(--ink-3)">{tick}</text>
          </g>
        ))}
        {data.map((d, index) => {
          let base = 0;
          const x = left + index * step + (step - barWidth) / 2;
          const hour = d.hour.slice(11, 16);
          return (
            <g key={d.hour}>
              {SEVERITY_ORDER.filter((s) => d[s] > 0).map((s) => {
                const yTop = y(base + d[s]);
                const h = Math.max(2, y(base) - yTop - 2);     // 2px gap between segments
                base += d[s];
                return (
                  <rect key={s} x={x} y={yTop} width={barWidth} height={h} rx="2" fill={SEVERITY_COLOR[s]}>
                    <title>{`${hour} UTC — ${titleCase(s)}: ${d[s]}`}</title>
                  </rect>
                );
              })}
              {index % 4 === 0 && (
                <text x={x + barWidth / 2} y={height - 6} textAnchor="middle" fontSize="11" fill="var(--ink-3)">{hour}</text>
              )}
            </g>
          );
        })}
        <line x1={left} x2={width} y1={y(0)} y2={y(0)} stroke="var(--border-strong)" strokeWidth="1" />
      </svg>
      <figcaption className="legend" style={{ marginTop: 6 }}>
        {[...SEVERITY_ORDER].reverse().map((s) => (
          <span key={s}><i style={{ background: SEVERITY_COLOR[s] }} />{titleCase(s)}</span>
        ))}
        <span className="muted">Hours in UTC</span>
      </figcaption>
    </figure>
  );
}

/** Half-circle meter for one score from 0 to 100. */
export function RiskGauge({ score, level }: { score: number | null; level: Level | null }) {
  const radius = 62, cx = 80, cy = 78, length = Math.PI * radius;
  const value = score ?? 0;
  const color = level === "critical" ? "var(--critical)" : level === "high" ? "var(--high)"
    : level === "medium" ? "var(--medium)" : "var(--low)";
  const arc = `M ${cx - radius} ${cy} A ${radius} ${radius} 0 0 1 ${cx + radius} ${cy}`;
  return (
    <div className="gauge">
      <svg width="160" height="96" viewBox="0 0 160 96" role="img"
        aria-label={score === null ? "No current finding" : `Highest current risk ${score} out of 100`}>
        <path d={arc} fill="none" stroke="var(--low-soft)" strokeWidth="12" strokeLinecap="round" />
        {score !== null && (
          <path d={arc} fill="none" stroke={color} strokeWidth="12" strokeLinecap="round"
            strokeDasharray={`${(value / 100) * length} ${length}`} />
        )}
        <text x={cx} y={cy - 8} textAnchor="middle" fontSize="30" fontWeight="700" fill="var(--ink)">
          {score === null ? "—" : score}
        </text>
        <text x={cx} y={cy + 10} textAnchor="middle" fontSize="11" fill="var(--ink-3)">/ 100</text>
      </svg>
      <div>{level ? <LevelBadge level={level} /> : <span className="badge">No findings</span>}</div>
    </div>
  );
}

const STATUS: Array<{ key: AssetStatus; label: string; color: string }> = [
  { key: "normal", label: "Normal", color: "var(--good)" },
  { key: "under_review", label: "Under review", color: "var(--medium)" },
  { key: "at_risk", label: "At risk", color: "var(--critical)" },
  { key: "unknown", label: "Not in inventory", color: "var(--info)" },
];

export function statusLabel(status: AssetStatus): string {
  return STATUS.find((s) => s.key === status)?.label ?? titleCase(status);
}

export function AssetStatusBreakdown({ counts }: { counts: Record<AssetStatus, number> }) {
  const total = STATUS.reduce((sum, s) => sum + (counts[s.key] ?? 0), 0);
  if (total === 0) return <State title="No assets yet" />;
  return (
    <div>
      <div className="status-bar" role="img" aria-label={`${total} assets by status`}>
        {STATUS.filter((s) => counts[s.key] > 0).map((s) => (
          <i key={s.key} style={{ background: s.color, flex: counts[s.key] }} title={`${s.label}: ${counts[s.key]}`} />
        ))}
      </div>
      <ul className="status-list">
        {STATUS.map((s) => (
          <li key={s.key}>
            <i className="dot" style={{ background: s.color }} />{s.label}
            <b>{counts[s.key] ?? 0}</b><em>{Math.round(((counts[s.key] ?? 0) / total) * 100)}%</em>
          </li>
        ))}
      </ul>
    </div>
  );
}
