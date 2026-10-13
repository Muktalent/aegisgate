\# AegisGate — Crisis and Recovery Procedure



\## Document Status



Initial draft for laboratory use and pilot preparation.



This document does not constitute a declaration of ISO 22301 conformity

or certification. It does not authorize actions on external systems.



Document owner: to be assigned.

Approval: pending.

Next review: before the first pilot.



\## 1. Scope



This procedure covers coordination during AegisGate service disruptions

and verification of database and asset-inventory recovery.



Complete recovery of infrastructure, sensitive configuration, external

audit files, and integrations has not yet been validated.



\## 2. Proposed Activation Criteria



The incident coordinator shall assess whether to activate this procedure

when any of the following occurs:



\- Service unavailability prevents required operations.

\- Data is corrupted, lost, or suspected of being altered.

\- Recovery fails or no usable backup is available.

\- Credentials or the operating environment may be compromised.

\- The primary device or storage system is lost.



Duration and impact thresholds must be defined before the pilot.



\## 3. Roles and Responsibilities



Assign a primary owner, a substitute, and a contact channel for each role:



\- Incident Coordination:

&#x20; activates the procedure, prioritizes tasks, and maintains the

&#x20; incident record.

\- Technical Recovery:

&#x20; verifies backups and performs isolated recovery.

\- Security Review:

&#x20; assesses potential compromise, integrity, and recovery conditions.

\- Communications:

&#x20; informs affected stakeholders and schedules the next update.

\- Return-to-Service Approval:

&#x20; authorizes service resumption after reviewing verification evidence.



In the laboratory, one person may perform multiple roles.

Decisions must still be recorded.



\## 4. Initial Incident Record



Record the following without including secrets:



\- Incident identifier.

\- Detection time and time zone.

\- Reporting person.

\- Symptoms and affected services.

\- Confirmed impact and outstanding uncertainties.

\- Last known normal operation.

\- Actions taken and responsible persons.

\- Available backups and their capture dates.

\- Scheduled time for the next update.



Do not declare full recovery solely because the health endpoint

returns HTTP 200.



\## 5. Initial Actions



\- Determine whether the issue is an operational failure or a potential

&#x20; security compromise.

\- Preserve relevant evidence before making destructive changes.

\- Do not overwrite the affected database with a backup.

\- Do not recover into a potentially compromised environment without

&#x20; a security review.

\- Do not copy tokens, passwords, or keys into reports.

\- Select an isolated recovery environment and destination.

\- If data is at risk, explicitly decide whether to stop new writes

&#x20; and record the impact of that decision.



\## 6. Degraded Operation



While AegisGate is unavailable:



\- Inform stakeholders that its data and analysis may not be current.

\- Maintain critical activities through the organization's authorized

&#x20; alternative procedure.

\- Record pending operations for subsequent reconciliation.

\- Do not interpret the absence of alerts as the absence of incidents.

\- Do not assume that AegisGate retains incoming telemetry during

&#x20; an outage.



External collection, buffering, and replay of pending events require

separate design and validation.



\## 7. Recovery Package Selection



Before recovery:



\- Identify the package and its creation date.

\- Review the manifest and available application version.

\- Verify file hashes and database integrity.

\- Identify potential data loss after the snapshot.

\- Assess whether there is any reason to distrust the backup.

\- Reject incomplete packages or packages that fail verification.



Manifest hashes detect differences but do not, by themselves,

establish package authenticity.



\## 8. Isolated Recovery



Run the following steps from the project root.



\### Step 1 — Verify and Recover the Package



Run:



&#x20;   python scripts/verify\_recovery\_package.py --package PACKAGE\_PATH



The script recovers the package into a separate directory.



\### Step 2 — Review the Package Verification Report



Confirm that the verification succeeded and review the database,

inventory, and source-preservation results.



\### Step 3 — Verify Recovered Events and Cases Through the API



Run:



&#x20;   python scripts/verify\_restored\_api.py --database RECOVERED\_DATABASE\_PATH



\### Step 4 — Review the API Verification Report



Confirm that the API returned the expected events and cases,

including matching identifiers and case-to-alert relationships.



These scripts must not use the live database as a restoration destination.



The API verifier creates an additional database copy. It does not

automatically configure the recovered inventory as the API's active

asset inventory.



\## 9. Sensitive Configuration Recovery



Recover the following through a protected and authorized mechanism:



\- Authentication configuration.

\- Required keys and credentials.

\- Environment and integration configuration.



JWT and HMAC key retention or rotation policies must be defined

according to the incident and audit requirements.



The current backup copies do not resolve sensitive configuration recovery.



\## 10. Return-to-Service Approval Criteria



Before switching the primary service to the recovered environment,

confirm that:



\- The cause of the failure is understood, or residual risk has been

&#x20; explicitly accepted.

\- The application version is compatible.

\- The correct database and asset inventory are selected.

\- Recovered events and cases have been verified.

\- Authentication and permissions have been checked.

\- Sensitive configuration has been recovered securely.

\- Ingestion and asset correlation have been verified in the

&#x20; recovered environment.

\- Data loss has been assessed and pending operations identified.

\- Monitoring is available.

\- A rollback plan and approval have been recorded.



The final service switch and rollback procedure still require

implementation and rehearsal.



This document does not authorize manual overwriting of the primary database.



\## 11. Communications



Each update must state:



\- Current status: investigating, recovering, verifying, or restored.

\- Confirmed impact.

\- Actions completed.

\- Known limitations or data loss.

\- Time of the next update.



Do not communicate a guaranteed recovery time without sufficient evidence.



Notification obligations must be reviewed according to applicable

contracts, affected data, and jurisdiction.



\## 12. Closure and Review



Record:



\- Incident start, milestones, and completion.

\- Time required to recover necessary functions.

\- Observed data loss.

\- Verification evidence.

\- Decisions and approvals.

\- Problems encountered.

\- Corrective actions, owners, and target dates.



Update this procedure after each exercise or incident.



\## 13. Outstanding Work Before the Pilot



\- Assign owners and substitutes.

\- Complete the business impact and dependency analysis.

\- Define recovery objectives and acceptable data loss.

\- Schedule backups and backup-failure alerts.

\- Define backup retention and protection.

\- Maintain a backup outside the primary device.

\- Resolve external audit-file coverage.

\- Protect sensitive configuration recovery.

\- Validate complete recovery in a clean environment.

\- Implement and test service switching and rollback.

\- Conduct an exercise and record its results.
