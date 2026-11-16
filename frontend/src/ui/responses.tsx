import { useEffect, useState, type FormEvent } from "react";

import {
  api, dateTime, titleCase,
  type ActionState, type CatalogueItem, type Operation, type ResponseAction, type Role,
} from "../client";
import { Icon } from "./parts";

const STATE_TONE: Record<ActionState, string> = {
  proposed: "", pending_approval: "medium", approved: "medium", rejected: "",
  executed_in_simulation: "high", rolled_back: "good", failed: "critical",
};

const STATE_LABEL: Record<ActionState, string> = {
  proposed: "Proposed", pending_approval: "Awaiting approval", approved: "Approved", rejected: "Rejected",
  executed_in_simulation: "Applied in simulation", rolled_back: "Rolled back", failed: "Failed",
};

export function StateBadge({ state }: { state: ActionState }) {
  return <span className={`badge ${STATE_TONE[state] ?? ""}`}>{STATE_LABEL[state] ?? titleCase(state)}</span>;
}

/** Which operations this role may perform on an action in this state (mirrors core/response.py). */
export function allowedOperations(state: ActionState, role: Role): Operation[] {
  const analyst = role === "soc_analyst" || role === "security_admin";
  const admin = role === "security_admin";
  if (state === "pending_approval") return admin ? ["approve", "reject"] : [];
  if (state === "proposed" || state === "approved") return analyst ? ["execute"] : [];
  if (state === "executed_in_simulation") return analyst ? ["rollback"] : [];
  return [];
}

const OPERATION_LABEL: Record<Operation, string> = {
  approve: "Approve", reject: "Reject", execute: "Apply in simulation", rollback: "Roll back",
};
const NEEDS_NOTE: Operation[] = ["reject", "rollback"];

/** Buttons for the operations available on one action, with a note when required. */
export function ActionControls({ action, role, onChanged }: {
  action: ResponseAction; role: Role; onChanged: () => void;
}) {
  const [pending, setPending] = useState<Operation | null>(null);
  const [note, setNote] = useState("");
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const operations = allowedOperations(action.state, role);

  async function run(operation: Operation, text?: string) {
    setBusy(true); setError(null);
    try {
      await api.operateResponse(action.action_id, operation, text);
      setPending(null); setNote(""); onChanged();
    } catch (reason) {
      setError(reason instanceof Error ? reason.message : "The operation failed.");
    } finally { setBusy(false); }
  }

  function submit(event: FormEvent<HTMLFormElement>) {
    event.preventDefault();
    if (pending) void run(pending, note.trim());
  }

  if (operations.length === 0) {
    return action.state === "pending_approval" && role === "soc_analyst"
      ? <span className="muted small">Waiting for an administrator</span> : null;
  }

  return (
    <div className="op-controls">
      {pending ? (
        <form onSubmit={submit} className="op-form">
          <input className="input" value={note} onChange={(e) => setNote(e.target.value)} autoFocus
            placeholder={`Reason to ${pending} (required)`} aria-label={`Reason to ${pending}`} disabled={busy} />
          <button className="btn primary" type="submit" disabled={busy || note.trim().length < 3}>{OPERATION_LABEL[pending]}</button>
          <button className="btn ghost" type="button" onClick={() => { setPending(null); setNote(""); }} disabled={busy}>Cancel</button>
        </form>
      ) : operations.map((operation) => (
        <button key={operation} type="button" disabled={busy}
          className={`btn ${operation === "approve" || operation === "execute" ? "primary" : ""}`}
          onClick={() => (NEEDS_NOTE.includes(operation) ? setPending(operation) : void run(operation))}>
          {OPERATION_LABEL[operation]}
        </button>
      ))}
      {error && <span role="alert" className="small" style={{ color: "var(--critical)" }}>{error}</span>}
    </div>
  );
}

/** Request form for a new simulated action on one finding. */
export function RequestAction({ groupId, catalogue, recommended, onCreated }: {
  groupId: string; catalogue: CatalogueItem[]; recommended: string[]; onCreated: () => void;
}) {
  const ordered = [...catalogue].sort((a, b) =>
    Number(recommended.includes(b.action_type)) - Number(recommended.includes(a.action_type)));
  const [actionType, setActionType] = useState(ordered[0]?.action_type ?? "");
  const [reason, setReason] = useState("");
  const [busy, setBusy] = useState(false);
  const [message, setMessage] = useState<{ ok: boolean; text: string } | null>(null);
  const chosen = catalogue.find((item) => item.action_type === actionType);

  useEffect(() => {                       // a result message is only relevant for a moment
    if (!message) return;
    const timer = window.setTimeout(() => setMessage(null), 6000);
    return () => window.clearTimeout(timer);
  }, [message]);

  async function submit(event: FormEvent<HTMLFormElement>) {
    event.preventDefault();
    setBusy(true); setMessage(null);
    try {
      const created = await api.requestResponse(groupId, actionType, reason.trim());
      setReason("");
      setMessage({ ok: true, text: created.state === "pending_approval"
        ? "Requested. A high-impact action waits for an administrator's approval."
        : "Applied in simulation. No real system was changed." });
      onCreated();
    } catch (reason) {
      setMessage({ ok: false, text: reason instanceof Error ? reason.message : "The request failed." });
    } finally { setBusy(false); }
  }

  return (
    <form onSubmit={submit} className="stack" style={{ gap: 8 }}>
      <select className="input" value={actionType} onChange={(e) => setActionType(e.target.value)}
        aria-label="Simulated action" disabled={busy}>
        {ordered.map((item) => (
          <option key={item.action_type} value={item.action_type}>
            {titleCase(item.action_type)}{recommended.includes(item.action_type) ? " (recommended)" : ""}
            {item.requires_approval ? " — needs approval" : ""}
          </option>
        ))}
      </select>
      {chosen && <p className="small muted">{chosen.effect}</p>}
      <input className="input" value={reason} onChange={(e) => setReason(e.target.value)} disabled={busy}
        placeholder="Reason for the action (required)" aria-label="Reason for the action" />
      <button className="btn primary block" type="submit" disabled={busy || reason.trim().length < 3 || !actionType}>
        <Icon name="bolt" size={16} />{busy ? "Requesting…" : "Request simulated action"}</button>
      {message && <p role={message.ok ? "status" : "alert"} className="small"
        style={{ color: message.ok ? "var(--ink-2)" : "var(--critical)" }}>{message.text}</p>}
    </form>
  );
}

export function ActionHistory({ action }: { action: ResponseAction }) {
  return (
    <ol className="history">
      {action.history.map((step, index) => (
        <li key={index}>
          <b>{titleCase(step.operation)}</b> by {step.by} <span className="muted">({step.role})</span>
          {" → "}<StateBadge state={step.state as ActionState} />
          <span className="muted mono small"> {dateTime(step.at)}</span>
          {step.note && <div className="muted small">{step.note}</div>}
        </li>
      ))}
    </ol>
  );
}
