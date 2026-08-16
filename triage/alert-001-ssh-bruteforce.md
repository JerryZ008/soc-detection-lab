# Alert #001 — SSH Brute Force Against ubuntu-srv (Successful Compromise)
 
**Timestamp:** 2026-08-15 08:59:52–09:00:44 UTC (~52 seconds)
**Wazuh rule:** 5763 (level 10) "sshd: brute force trying to get access to the system"
**Supporting rules:** 2502, 5551, 40111 (all level 10), 5758 (level 8), 5760 (level 5)
**MITRE ATT&CK:** T1110.001 — Brute Force: Password Guessing
**Source IP:** 192.168.127.131 (attack host)
**Target:** ubuntu-srv 192.168.127.132, ssh/22 (Wazuh agent 001)
**Targeted account:** awong
 
## What triggered it
Wazuh correlated 32 failed SSH authentication attempts against a single account
(`awong`) from one source within ~52 seconds, generating 43 alerts total — including
four level-10 detections (5763, 2502, 5551, 40111). The volume and rate far exceed
human typing speed, and all failures targeted a single username in sequence: an
automated password-guessing attack, not a locked-out user.
 
## Analysis
- **Rate:** 32 attempts in 52 seconds — automated tooling (hydra).
- **Pattern:** repeated guesses against one account (`awong`) — password guessing
  against a known/enumerated user, consistent with T1110.001.
- **Source:** 192.168.127.131, with no legitimate prior auth history to this host.
- **Critical finding — the attack SUCCEEDED and the SIEM nearly missed it.**
  Ground truth in `auth.log` shows **2 × "Accepted password for awong"** — the weak
  password was guessed and the account was compromised. Yet the successful login
  produced only a level-3 5715 event and **no high-severity alert**. The default
  ruleset alerted loudly on the *attempts* (four level-10 rules) but was near-silent
  on the *moment of compromise*. An analyst watching only high-severity SIEM alerts,
  without correlating the raw logs, could wrongly conclude the attack failed.
## Verdict
**True positive — brute force SUCCEEDED. Account `awong` is compromised.**
 
## Action taken
1. Confirmed compromise via `auth.log` (2 accepted logins immediately after the burst).
2. Would immediately disable/reset `awong`, terminate active sessions, and hunt for
   post-access activity (new processes, persistence, lateral movement).
3. Escalate to L2 with source IP, timeframe, and confirmation of successful login.
4. **Detection gap logged for remediation** — see custom rule 100101 in
   `detections/local_rules.xml`.
## Notes for tuning — the detection gap (led to custom rule 100101)
Default rules detect brute-force *attempts* but do not correlate a successful login
from the same source immediately after. Custom rule **100101** was written to close
this: when an IP that just triggered a brute-force alert (5763) then produces a
successful auth (5715) to the same host within 120s → raise a **level-12** "brute
force followed by successful login — possible compromise" alert. This surfaces exactly
the compromise the shipped ruleset missed.
