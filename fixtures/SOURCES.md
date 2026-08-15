# Fixture provenance

Every fixture in this directory is **real captured Windows telemetry**, not synthetic data. The
events come from published attack-simulation datasets, sliced (event-code level only, values
untouched) into the fire/silent halves each detection is proven against. Nothing here was
hand-written or generated to make a rule fire.

The committed captures are from **Splunk's `attack_data`** project
(<https://github.com/splunk/attack_data>, Apache-2.0), recorded in the Splunk Attack Range lab.
Hostnames such as `ar-win-dc.attackrange.local` and `win-dc-156.attackrange.local` are that lab's,
not a personal one. Attribution and the upstream Apache-2.0 license are preserved here.

| Fixture | Events | Upstream dataset (splunk/attack_data) | What it is |
|---|---|---|---|
| `dcsync-replication-nondc.attack.json` | 3 × 4662 | `T1003.006/mimikatz/xml-windows-security.log` | Directory-replication access (Get-Changes GUIDs) requested by a **non-machine** principal (`Administrator`) — the rule fires. |
| `dcsync-replication-nondc.benign.json` | 3 × 4662 | `T1003.006/impacket/windows-security-xml.log` | The same replication access performed under a **DC machine account** (`AR-WIN-DC$`) — legitimate replication the rule ignores. |
| `kerberoasting-rc4-service-ticket.attack.json` | 159 × 4769 | `T1558.003/unusual_number_of_kerberos_service_tickets_requested/windows-xml.log` | A real RC4-downgraded service-ticket burst (2 principals request 27 and 7 distinct SPNs) — the rule fires. |
| `asrep-roasting-no-preauth.benign.json` | 3 × 4768 | `T1078.002/suspicious_ticket_granting_ticket_request/windows-xml.log` | Normal TGT requests with pre-authentication (`PreAuthType=2`) — traffic the AS-REP rule must ignore. |

## What is proven, and what is still pending

Verified against a live Splunk (the CI `validate` job replays the ready pairs):

- **DCSync** has both halves and is **replay-ready** — it fires on the real attack fixture and stays
  silent on the real benign fixture.
- **Kerberoasting** ships its real **attack** half (the burst fires the rule). Its benign half needs
  real *normal* 4769 traffic, which the curated public attack datasets do not include.
- **AS-REP roasting** ships its real **benign** half (normal pre-auth, correctly ignored). Its attack
  half needs a real 4768 with `PreAuthType=0`, which was not available in the public datasets.

The missing halves are left genuinely pending rather than fabricated. Capture them from a lab you
control with the runbook in `../vm/README.md`, or from another real dataset, and drop them in here to
make those detections replay-ready too.
