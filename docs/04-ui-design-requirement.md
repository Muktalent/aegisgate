# AegisGate Academic — UI/UX Design Requirement (mandatory)

Recorded 15 November 2026. This requirement **replaces section 17.1** of the
Master Technical Development Specification v1.0, which recommended a dark
default theme. Reference image: `docs/reference/aegisgate-ui-reference.png`.

1. Modern, light-first, three-panel security workstation design, inspired by the reference image.
2. Prioritise structured information, clear navigation, contextual security analysis and compact professional layouts.
3. Do not redesign it as a conventional dark SOC dashboard dominated by decorative charts.
4. The primary workspace separates three clearly identifiable regions: navigation (left), technical evidence (centre), security interpretation (right).
5. The right-hand contextual analysis panel is a core feature. It shows evidence-based explanations, risk assessment, policy decision and available actions.
6. Light mode is the default; dark mode is optional.
7. All screens share one design system: typography, spacing, components and interaction patterns.

Constraints carried over from the specification: no fabricated metrics, no
decorative charts with invented values, Academic Mode always visible, simulated
actions labelled as simulated, keyboard access and adequate contrast.

Mapping of the right-hand panel to the analysis core (`docs/03-analysis-core.md`):

| Panel section | Source |
|---|---|
| Threat assessment | correlation group `finding` and `explanation` |
| Supporting evidence | detection `explanation`, `observations`, `supporting_events`, baseline comparison |
| Risk evaluation | `risk_score`, `detection_confidence`, `asset_criticality`, `factors` |
| Policy decision | `decision`, `explanation`, `policy_version` |
| Recommended actions | `recommended_actions` (executed through the simulated response engine, not yet built) |
