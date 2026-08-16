# Essential Eight Maturity Assessment — SOC Detection Lab
 
**Assessment date:** August 2026
**Assessor:** Jerry Zhang
**Scope:** Self-built Linux SOC lab — 2× Ubuntu 22.04 hosts (`wazuh-lab`, `ubuntu-srv`),
SSH, nginx, and a Wazuh 4.x SIEM.
**Framework:** ACSC Essential Eight Maturity Model.
 
---
 
## 1. Scope & Applicability Statement
 
This report assesses a self-built Linux security lab against the ACSC Essential Eight
Maturity Model. **An important caveat governs the whole assessment:** the Essential
Eight was designed primarily for Microsoft Windows and Microsoft 365 environments.
Several mitigations (application control via AppLocker/WDAC, Office macro configuration,
user application hardening of Office/browsers) map awkwardly or not at all onto a Linux
environment.
 
Rather than force a score onto every control, this assessment states applicability
explicitly for each mitigation: **directly applicable** controls are scored against
evidence from the lab; **Windows-specific** controls are marked Not Applicable with a
justification and, where relevant, the Linux-equivalent control is noted. The intent is
to demonstrate correct use of the framework *including an understanding of its
boundaries* — not to inflate a score.
 
This is a learning lab, not a production environment. A low overall maturity is expected
and is not the point; the value is in the assessment method, the evidence, and the
prioritised remediation.
 
---
 
## 2. Methodology
 
- **Reference:** ACSC Essential Eight Maturity Model (note version applied).
- **Scoring:** each mitigation rated Maturity Level 0–3, supported by concrete evidence
  gathered from the lab hosts.
- **Evidence sources:** host configuration (`apt`, `sudoers`, SSH config,
  `unattended-upgrades`), and detection telemetry from the Wazuh SIEM.
- **Out of scope:** cloud identity is hosted separately in Microsoft Entra ID (assessed
  briefly under MFA, mitigation 7); this Linux lab does not cover it in full.
---
 
## 3. Control-by-Control Assessment
 
### 3.1 Application Control
**Applicability:** Partial (Windows-oriented). Linux equivalent: package-manager
restriction, AppArmor/SELinux enforcement.
**Current state:** No application allow-listing in place; AppArmor present but not in
strict enforcing mode for lab services.
**Maturity: Level 0.**
**Gap / remediation:** enable AppArmor enforcing profiles for exposed services (nginx,
sshd); document an approved-software baseline.
 
### 3.2 Patch Applications
**Applicability:** Applicable.
**Current state:** `wazuh-lab` fully patched (0 packages pending after
`apt update && apt upgrade`). `ubuntu-srv` has **55 packages pending** — only
`apt update` plus targeted agent/nginx installs were run, never a full upgrade.
**Maturity: Level 1.**
**Gap / remediation:** run full `apt upgrade` on `ubuntu-srv`; establish a consistent
patch window across both hosts.
 
### 3.3 Configure Microsoft Office Macro Settings
**Applicability:** **Not Applicable.** This control concerns Microsoft Office macro
execution, which does not exist in this Linux environment (no Office suite installed).
**Maturity: N/A.**
**Note:** correctly scoping this as N/A — rather than forcing a "Level 3" — is itself
part of applying the framework accurately.
 
### 3.4 User Application Hardening
**Applicability:** Partial (Windows/browser-oriented).
**Current state:** minimal attack surface (headless servers, no browser/Office); however
no formal hardening baseline documented.
**Maturity: Level 1.**
**Gap / remediation:** disable unnecessary services; document a hardening baseline.
 
### 3.5 Restrict Administrative Privileges
**Applicability:** Applicable.
**Current state:** several negative findings from the lab —
- `jerry` holds full admin (in `sudo`, `adm`, `lxd` groups) **with passwordless sudo**
  (`NOPASSWD:ALL` in `/etc/sudoers.d/90-jerry-lab`). *This NOPASSWD entry was added for
  lab automation and is not a system default — it is disclosed here as an
  assessment-of-the-as-built-state, not of a hardened baseline.*
- account `awong` (uid 1001) **still exists on `ubuntu-srv`** — the weak-password
  account that was compromised during brute-force testing (Alert #001).
**Maturity: Level 0.**
**Gap / remediation:** remove the `awong` account; remove the `NOPASSWD` entry so sudo
requires authentication; review group memberships against least privilege.
### 3.6 Patch Operating Systems
**Applicability:** Applicable.
**Current state:** both hosts run Ubuntu 22.04 with `unattended-upgrades` installed and
enabled (`Update-Package-Lists "1"`, `Unattended-Upgrade "1"`, timer enabled). **However**
`unattended-upgrades` by default applies only `-security` updates, not `-updates` (feature/
bug fixes) — which is why `ubuntu-srv` carries 55 pending non-security packages despite
automation being on.
**Maturity: Level 1** (automated security patching present; overall patch baseline lags,
no unified patch window).
**Gap / remediation:** bring `ubuntu-srv` current; extend the automation policy to cover
`-updates` where appropriate; define a patch cadence.
 
### 3.7 Multi-Factor Authentication
**Applicability:** Applicable.
**Current state:**
- SSH on the lab hosts uses key-based auth for `jerry` (a possession factor), **but
  password authentication remains enabled** — `awong` was compromised precisely because
  SSH accepted password login (Alert #001).
- Cloud identity in Microsoft Entra ID has **MFA enforced via Security Defaults** across
  all users (separate to this Linux lab).
**Maturity: Level 1** on the lab hosts (partial; password auth still permitted);
MFA is enforced on the cloud identity plane.
**Gap / remediation:** set `PasswordAuthentication no` in SSH (key-only); this both
enforces a stronger factor and closes the brute-force vector demonstrated in Alert #001.
### 3.8 Regular Backups
**Applicability:** Applicable.
**Current state:** no backup mechanism configured for either host or for the Wazuh data.
**Maturity: Level 0.**
**Gap / remediation:** implement scheduled backups of critical configuration and SIEM
data; test restoration.
 
---
 
## 4. Maturity Summary
 
| # | Mitigation | Applicability | Current Level | Target | Priority |
|---|---|---|---|---|---|
| 1 | Application Control | Partial | 0 | 1 | Medium |
| 2 | Patch Applications | Applicable | 1 | 2 | **High** |
| 3 | Office Macro Settings | N/A | — | — | — |
| 4 | User Application Hardening | Partial | 1 | 2 | Low |
| 5 | Restrict Admin Privileges | Applicable | 0 | 2 | **High** |
| 6 | Patch Operating Systems | Applicable | 1 | 2 | **High** |
| 7 | Multi-Factor Authentication | Applicable | 1 | 2 | **High** |
| 8 | Regular Backups | Applicable | 0 | 1 | Medium |
 
---
 
## 5. Gap Analysis & Remediation Roadmap
 
Prioritised, with the four highest-impact / lowest-effort items first (quick wins):
 
| Gap | Remediation | Mitigation | Effort |
|---|---|---|---|
| `ubuntu-srv` 55 pending updates | Run full `apt upgrade`; extend auto-update to `-updates` | Patch OS / Apps | Low |
| Compromised `awong` account still present | Remove the account | Restrict Admin / MFA | Low |
| Passwordless sudo for `jerry` | Remove `NOPASSWD` — require authentication | Restrict Admin | Low |
| SSH permits password auth | Set `PasswordAuthentication no` (key-only) | MFA | Low |
 
These four map directly to the negative findings surfaced by the detection lab:
Alert #001's successful compromise was only possible *because* of items 2–4 in this
table. **The detection side (SIEM, custom rules, triage) proved the attack; the E8
assessment explains the configuration weaknesses that let it succeed.** That linkage —
detection findings driving hardening priorities — is the core value of pairing the two.
 
---
 
## 6. Conclusion
 
As a learning environment, the lab sits at low overall maturity, which is expected. The
assessment demonstrates: correct application of the Essential Eight model, including
principled Not-Applicable scoring for Windows-specific controls; evidence-based rating
of each applicable mitigation; and a prioritised, actionable remediation roadmap tied to
real findings from the detection lab. The four quick-win items would materially raise
maturity across Patch, Restrict Admin, and MFA — and would close the exact weaknesses
that made the lab's simulated compromise succeed.
```
 
*This assessment was conducted on a personal lab environment for skills demonstration.*
