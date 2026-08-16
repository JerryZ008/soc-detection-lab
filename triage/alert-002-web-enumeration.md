# Alert #002 — Web Directory Enumeration Against ubuntu-srv
 
**Timestamp:** ~2026-08-15 09:59:28 UTC (~4,615 requests in 1–2 seconds, 20 threads)
**Wazuh rule:** 31151 (level 10) "Multiple web server 400 error codes from same source ip"
**Supporting rules:** 31516 (Suspicious URL access ×13), 31104 (Common web attack ×5),
31101 (per-request 404 ×8,530 cumulative across tests)
**MITRE ATT&CK:** T1595.003 — Active Scanning: Wordlist Scanning
**Source IP:** 192.168.127.131 (gobuster 3.6)
**Target:** ubuntu-srv 192.168.127.132, nginx 1.18.0, http/80 (agent 001)
 
## What triggered it
A single source generated ~4,615 HTTP requests in 1–2 seconds against the web server,
the overwhelming majority returning 404. Requested paths matched a common wordlist
(dirb common.txt, ~4,600 entries): `/.rhosts`, `/.bash_history`, `/.ssh`, `/.bashrc`,
`/.config` … — automated directory/content-discovery enumeration, not user browsing.
 
## Analysis
- **Intent:** clearly automated (4,600+ requests in ~2s, 20 threads) wordlist scan —
  reconnaissance, the earliest stage of an attack chain.
- **Success:** of ~4,615 requests, **only one non-404 response** — HTTP 200 on the
  root path (the default nginx page). No sensitive path was successfully discovered;
  no configuration files, backups or admin interfaces were exposed.
- **Wazuh classification:** beyond the volumetric 404 rule, Wazuh independently flagged
  13 paths as "suspicious URL access" and 5 as "common web attack" patterns — useful
  signal that the scan targeted known-sensitive filenames.
- **Detection reliability (contrast with Alert #001):** this detection was real-time
  and lossless, because nginx `access.log` is a flat file read directly by the agent
  (log_format apache) — unlike the journald-sourced SSH success events in Alert #001,
  which delivered unreliably. **The choice of log source directly determines detection
  reliability.**
## Verdict
**True positive (reconnaissance) — low impact, no compromise. Monitor, do not escalate.**
 
Genuinely malicious in intent but low in consequence: pure enumeration, nothing
exposed. Escalating every scan would bury an L2 team in noise. Correct L1 action is to
log, watchlist the source, and escalate only if activity progresses beyond enumeration.
 
## Action taken
1. Logged source and pattern; added 192.168.127.131 to a watchlist for follow-on activity.
2. Set escalation trigger: any non-404 success to a sensitive path from this source, or
   a shift from enumeration to exploitation attempts.
3. No immediate escalation.
## Notes for tuning
Severity (level 10 on the aggregate rule) is proportionate. A correlation rule that
escalates when the *same* source moves from 404-heavy scanning to a successful 200 on
a sensitive (non-root) path would add real value — mirroring the compromise-detection
logic built in rule 100101 for SSH.
