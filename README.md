# kerberos-detections

[![CI](https://github.com/JacobRHess/kerberos-detections/actions/workflows/ci.yml/badge.svg)](https://github.com/JacobRHess/kerberos-detections/actions/workflows/ci.yml)
[![Security](https://github.com/JacobRHess/kerberos-detections/actions/workflows/security.yml/badge.svg)](https://github.com/JacobRHess/kerberos-detections/actions/workflows/security.yml)

**Active Directory / Kerberos attacks captured on real domain-controller telemetry, and the Splunk detections that prove themselves against it.**

This is a detection-engineering lab built the honest way I like: no synthetic events and no untested rules. Each detection is proven by replaying **real captured Windows Security-log telemetry** through a live Splunk container in CI — it has to fire on a real attack capture and stay silent on a real benign one. The committed fixtures come from published attack-simulation data (Splunk's [`attack_data`](https://github.com/splunk/attack_data), recorded in the Splunk Attack Range); their exact provenance is in [`fixtures/SOURCES.md`](fixtures/SOURCES.md), and `vm/README.md` is the runbook for capturing your own from a lab you control.

It covers three Kerberos techniques: **Kerberoasting** (T1558.003), **AS-REP roasting** (T1558.004), and **DCSync** (T1003.006). Each is only counted as *proven* once it has both fixture halves replaying green; where real public data supplied only one half, the other is left openly pending rather than fabricated (see the coverage table).

## The contract

```
detections.yaml            single source of truth (id, title, rule, attack, slice, fixtures)
rules/<id>.spl             native SPL, written against real Windows Security-log field names
fixtures/<id>.attack.json  sliced from a genuine capture of the attack
fixtures/<id>.benign.json  sliced from a genuine capture of normal domain activity
captures/                  raw DC exports (gitignored; slices stay out of git)
vm/                        audit-policy bootstrap + capture export scripts (run on the DC)
lab/                       single-node Splunk in Docker, the same one the CI validate job boots
src/kerbdetect/            the slicer, the replay engine, the coverage report
```

Adding a detection means adding an entry to `detections.yaml`, one `.spl` rule, and two fixtures sliced from real captures. CI replays both through Splunk and asserts `attack` fires and `benign` stays clean.

## The Kerberoasting detection

Kerberoasting abuses a normal Kerberos feature: any authenticated user can request a service ticket (TGS) for any account that has a Service Principal Name, and the ticket is encrypted with the service account's password hash. Request tickets for SPN-bearing user accounts, force RC4, and you can crack the weak ones offline. Every request writes a **4769** on the domain controller.

The rule (`rules/kerberoasting-rc4-service-ticket.spl`) keys on the canonical downgrade signal and the burst shape:

```spl
EventCode=4769 Status=0x0 TicketEncryptionType=0x17 ServiceName!="*$" ServiceName!="krbtgt"
| bin _time span=15m
| stats dc(ServiceName) as spn_count values(ServiceName) as service_names ... by _time TargetUserName IpAddress
| where spn_count >= 5
```

- `TicketEncryptionType=0x17` is RC4-HMAC, the encryption a roasting tool asks for because RC4 hashes crack fastest.
- Machine accounts (`ServiceName` ending in `$`) and `krbtgt` are excluded; roasting targets *user* accounts with SPNs.
- `bin _time span=15m` makes "many distinct SPNs" a *windowed* count that matches the deployed saved search's 15-minute schedule — so replay proves the same burst shape production would fire on, not a total collapsed over the whole capture. (Without it, a fixture spanning days would count SPNs that never co-occur in a real 15-minute window.)

**What it does not catch, honestly.** This is a downgrade-plus-volume heuristic, and it has a documented tier of blind spots. In an AES-only domain the attacker gets `0x12`/`0x11` tickets and the RC4 clause misses; the harder, noisier follow-on is a pure volume/entropy rule on distinct-SPN bursts regardless of cipher. The `>= 5` threshold is a starting point to tune against a real benign capture, not a universal constant, and the expected near-miss is a legitimate login script that touches several service-backed apps at once. It also groups by the *requesting* principal without excluding machine accounts — the real attack fixture's requester is itself a machine account, so that exclusion would drop proven coverage — which means a busy legacy account that still negotiates RC4 for many services can alert; a deployment allowlist of known-noisy principals is the fix, exactly as for the DCSync sync-account case. A patient attacker who requests one ticket for one high-value SPN, or drips a few requests a day, stays under any burst threshold; that single-high-value case belongs in its own rule with its own fixture pair. The rule is the cheap, high-signal first layer, and the README says so rather than implying full coverage.

## The AS-REP roasting detection

AS-REP roasting is the pre-authentication cousin of Kerberoasting. If an account has `DONT_REQUIRE_PREAUTH` set, anyone can request a TGT for it and receive a response encrypted with the account's password hash, with no credentials of their own. The domain controller logs the request as event **4768** with `PreAuthType=0`. The rule (`rules/asrep-roasting-no-preauth.spl`) is deliberately simple:

```spl
EventCode=4768 PreAuthType=0 Status=0x0
```

Unlike the 4769 rule, this one applies no machine-account or `krbtgt` exclusion and no volume threshold: a successful pre-auth-less TGT request is *already* the anomaly, so a single one deserves a row, whether the account is a user or a misconfigured machine. It catches the request, not the offline crack that may follow, and an attacker who flips `DONT_REQUIRE_PREAUTH` on and off quickly leaves only a thin 4768 trail. Like the Kerberoasting rule, it is unproven until a real capture provides its fixtures.

## The DCSync detection

DCSync impersonates a domain controller to ask a real DC to replicate directory data, which is how an attacker with the right rights pulls password hashes (including `krbtgt`) without touching a DC's disk. The replication request logs as event **4662** (directory-service access) whose `Properties` name the replication extended rights:

```spl
EventCode=4662 ObjectServer="DS" AccessMask="0x100"
(Properties="*1131f6aa-...*" OR Properties="*1131f6ad-...*") SubjectUserName!="*$"
```

The two GUIDs are `DS-Replication-Get-Changes` and `DS-Replication-Get-Changes-All`. The discriminator is `SubjectUserName!="*$"`: legitimate replication is performed by domain controllers under their own **machine** accounts (which end in `$`), so a *non-machine* principal requesting replication is the DCSync signal.

That exclusion is also why DCSync's benign fixture is the hardest one in this project. The machine-account case is only half of it: the sharper false positive is a **legitimate non-machine account that holds replication rights**, most commonly an Entra/Azure AD Connect sync account (`MSOL_*` or a custom account), and also an admin running `repadmin /syncall` as themselves or any account deliberately delegated the rights. Those replicate as *user* accounts, exactly what `SubjectUserName!="*$"` lets through, so an honest benign capture has to include them (an allowlist of known sync accounts is the real-world fix, and it belongs in a deployment lookup, not the bare rule). Proving a low false-positive rate also needs **real DC-to-DC replication** from a genuine DC computer account, which needs a second DC in the lab. The rule and its tests are committed, but this detection stays deliberately last until that benign capture exists; a detection is only as honest as the benign traffic it was proven against.

## The CLI

```powershell
uv run kerbdetect validate                          # detections.yaml + rules + fixtures conform
uv run kerbdetect capture captures/stage-01-*.xml --stage 01   # slice the attack fixture
uv run kerbdetect capture captures/benign-*.xml --benign       # slice benign fixtures
uv run kerbdetect replay                            # live Splunk: attack must fire, benign must not
uv run kerbdetect report [--markdown]               # technique coverage
uv run kerbdetect report --layer coverage.json      # ATT&CK Navigator layer of proven techniques
uv run kerbdetect build-app --out build/kerbdetect_app   # deployable Splunk app
uv run kerbdetect new <id> --stage 01 --title ... --technique T1558.004 --slice security=4768
```

`capture` applies each detection's `slice` spec (channel to event codes) to the export and writes the matching events verbatim into the fixture, so rules still earn their matches on real field values. Slicing is loud: an empty slice aborts, and every written fixture is schema-validated before it lands.

Splunk connection defaults to the local lab (`https://localhost:8089`/`:8088`, `admin`/`kerbdetect_dev_2026`, index `kerbdetect`); override with `KD_SPLUNK_URL`, `KD_SPLUNK_HEC_URL`, `KD_SPLUNK_USER`, `KD_SPLUNK_PASSWORD`, `KD_SPLUNK_INDEX` or the matching flags. Set `KD_SPLUNK_VERIFY=true` to verify TLS against a trusted endpoint (off by default for the lab's self-signed cert). The client bootstraps the index, `KV_MODE=json` props, and the HEC input over REST, so it works identically against the docker lab and the CI service container.

## The rule contract

Rules are plain SPL searching the production field names, and the replay harness prepends its scope (`index=kerbdetect kd_run="<run>"`) to them. So a rule:

- starts with bare search terms (no leading `|` or `search`)
- never binds `index=`, `earliest=`, or `latest=`; index and time binding belong to the deployment
- outputs one row per detection (zero rows means no detection); windowed logic operates on `_time`, which the harness sets from each captured event's own timestamp
- if it aggregates (`| stats`), it ends with `| where <count> > 0`, because Splunk emits one `count=0` row even when nothing matched and the benign fixture would otherwise always "fire"

`kerbdetect validate` enforces all of this before any replay runs.

## Deploying the detections

`kerbdetect build-app` renders the same rule files CI replays into an installable Splunk app: one scheduled saved search per detection, scoped to the deployment index and enriched with its ATT&CK technique and stage, plus a coverage dashboard. Drop the output directory in `$SPLUNK_HOME/etc/apps/`. **Proven detections install enabled; staged ones (fixtures not yet captured, so unproven) install `disabled = 1`** — they ship for review but do not fire as live alerts on a rule no replay has validated. The CI validate job installs the app and asserts every detection landed as a saved search.

## The data

The committed fixtures are real captured telemetry from published attack simulations (Splunk's `attack_data`); [`fixtures/SOURCES.md`](fixtures/SOURCES.md) lists each fixture's exact upstream dataset and what it contains. To capture your own instead, `vm/` has the lab runbook: two Gen-2 Hyper-V VMs on an isolated switch — a domain controller as the telemetry source and a domain-joined workstation as the attacker vantage. `vm/Install-Telemetry.ps1` turns on the Kerberos audit subcategories (4769/4770 service tickets, 4768/4771 authentication, directory-access for DCSync); `vm/Export-Stage.ps1` exports the Security-log window as raw EVTX XML. The full runbook, including seeding SPN service accounts, is in [`vm/README.md`](vm/README.md).

Fixtures carry the raw EVTX element names (`ServiceName`, `TicketEncryptionType`, `TargetUserName`) because the export serializes each event with `.ToXml()`. The one ingest assumption behind "runs unmodified in production" is `renderXml = true` on the Security input (sourcetype `XmlWinEventLog:Security`); `vm/README.md` spells out why.

## Local development

```powershell
uv sync --extra dev
docker compose -f lab/docker-compose.yml up -d   # Splunk on :8000, HEC :8088
uv run pytest                                    # offline gate
uv run pytest -m replay                          # needs the lab Splunk up
```

## CI

Two jobs: `gate` (ruff, ruff format, mypy strict, offline pytest at >=90% branch coverage, bandit, pip-audit) and `validate` (builds the deployable app, boots `splunk/splunk:9.4.2`, installs the app, and runs the replay-marked tests: a synthetic canary smoke proving ingest to extract to search end to end today, and every committed detection once captures land, then asserts the detections installed as saved searches). A separate `security` workflow audits the CI workflows with zizmor and scans history for secrets with gitleaks.

## Coverage, and what is still pending

| Technique | ATT&CK | Signal | Status |
|---|---|---|---|
| DCSync | T1003.006 | 4662 replication access from a non-DC principal | **Proven.** Real attack + real benign both replay green (fires on `Administrator` replication, silent on `DC$` machine-account replication). |
| Kerberoasting | T1558.003 | 4769 RC4 service-ticket burst | Real **attack** half proven (fires on a real 159-ticket RC4 burst). Benign half pending: needs real *normal* 4769 traffic, absent from public attack datasets. |
| AS-REP roasting | T1558.004 | 4768 with pre-auth disabled (`PreAuthType=0`) | Real **benign** half proven (silent on real normal TGTs). Attack half pending: needs a real 4768 `PreAuthType=0`, absent from public datasets. |

Replay is lifecycle-aware. A detection is **proven** only when both fixture halves are on disk and replay green; a detection missing a half is **staged** — its rule and schema are committed and the offline gate proves them, but `replay` skips it (loudly) and the ATT&CK Navigator "proven coverage" layer leaves it uncoloured. `report` shows this directly: "Techniques with a detection: 3/3" but "Replay-ready: 1/3". This is the honest state — one technique fully proven on real data, two with one real half each and the other openly pending. Nothing is fabricated to fill the gap; drop the missing halves in (from your own capture or another real dataset) and those detections turn green too.
