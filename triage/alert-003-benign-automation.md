# Alert #003 — High-Frequency Successful Authentication (Benign Automation)
 
**Timestamp:** 2026-08-15 10:06:22–10:07:16 UTC (~54 seconds)
**Wazuh rule:** 5715 (level 3) "sshd: authentication success" ×19
**Source IP:** 192.168.127.131 (single source)
**Target:** ubuntu-srv 192.168.127.132 (agent 001)
**Account:** jerry (key-based, single account)
 
## What triggered it
19 successful SSH authentications from one source against ubuntu-srv within ~54
seconds. On volume alone this superficially resembles credential stuffing with valid
credentials, or an attacker operating with a stolen key.
 
Notably, Wazuh raised **only** rule 5715 (level 3) ×19 — no frequency-based or
high-severity alert. The default ruleset has no "multiple successful logins" frequency
rule *by design*, because high-frequency success is almost always automation
(monitoring / CI / health checks) and such a rule would be nearly all false positives.
 
## Analysis
Three hard indicators, each ruling out an attacker:
- **All successful, zero failures.** A real intrusion almost always leaves
  failed/anomalous states nearby (unlike Alert #001, which had 32 failures first).
  Clean success from the first try is the signature of a process using credentials it
  already legitimately holds.
- **Single known account, single source.** Not the multi-user / multi-host spread
  typical of credential stuffing.
- **Fixed regular interval (~3s) and identical behaviour.** Logins at 10:06:22, :25,
  :28, :31 … — machine-scheduled, not human. Same account, same key, same session
  shape, no command variation, no payload change, no path probing between sessions. A
  person does not authenticate on a metronome; an attacker would show exploratory
  behaviour.
Attributed to an automated health-check script.
 
## Verdict
**False positive — benign automation. Close, do not escalate.**
 
The instructive point is *why* it looked suspicious: volume alone is a weak signal.
Regularity and behavioural uniformity are what distinguish automation from an attacker
with working credentials.
 
## Action taken
Closed, no escalation. Documented the automation as a known-good baseline so a future
analyst seeing the same pattern has the context.
 
## Notes for tuning — including a flaw in custom rule 100101
This benign scenario exposed a false-positive surface in the custom rule 100101 built
for Alert #001. That rule correlates on `same_srcip` only, **not on user**. If the same
IP runs a brute force against one account (awong) and then, within the 120s window,
produces a legitimate login as a *different* account (jerry), rule 100101 would wrongly
flag a "compromise" — even though the two events are unrelated. It did not fire here
only because the interval exceeded 120s.
 
**Fix:** add a `same_user` condition so the rule only correlates a successful login to
the *same account* that was brute-forced, and/or whitelist known service accounts.
 
More generally: do not whitelist the source IP outright (that would hide a real
attacker on that host). Baseline the automation's pattern — timing, account, session
shape — and alert on deviation. **Baseline the behaviour, alert on the anomaly.**
