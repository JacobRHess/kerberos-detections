# kerberos-detections

[![CI](https://github.com/JacobRHess/kerberos-detections/actions/workflows/ci.yml/badge.svg)](https://github.com/JacobRHess/kerberos-detections/actions/workflows/ci.yml)
[![Security](https://github.com/JacobRHess/kerberos-detections/actions/workflows/security.yml/badge.svg)](https://github.com/JacobRHess/kerberos-detections/actions/workflows/security.yml)

**Active Directory / Kerberos attacks captured on real domain-controller telemetry, and the Splunk detections that prove themselves against it.**

This is a detection-engineering lab built the honest way I like: no synthetic events and no untested rules. An attack runs against a real Hyper-V Active Directory forest, the domain controller's own Security log records it, that capture is sliced into fixtures that keep the production field names, and every detection has to fire on the captured attack and stay silent on a captured benign window, replayed through a live Splunk container in CI on every push.

It starts with one technique done end to end rather than a wide shallow sweep. The first is **Kerberoasting** (T1558.003). AS-REP roasting (T1558.004) and DCSync (T1003.006) are staged in `detections.yaml` and land the same way as captures are recorded.

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
| stats dc(ServiceName) as spn_count values(ServiceName) as service_names ... by TargetUserName IpAddress
| where spn_count >= 5
```

- `TicketEncryptionType=0x17` is RC4-HMAC, the encryption a roasting tool asks for because RC4 hashes crack fastest.
- Machine accounts (`ServiceName` ending in `$`) and `krbtgt` are excluded; roasting targets *user* accounts with SPNs.
- Aggregating by the requesting principal and alerting on many distinct SPNs at once separates a roast from a user legitimately using one or two services.

**What it does not catch, honestly.** This is a downgrade-plus-volume heuristic, and it has a documented tier of blind spots. In an AES-only domain the attacker gets `0x12`/`0x11` tickets and the RC4 clause misses; the harder, noisier follow-on is a pure volume/entropy rule on distinct-SPN bursts regardless of cipher. The `>= 5` threshold is a starting point to tune against the real benign capture, not a universal constant, and the expected near-miss is a legitimate login script that touches several service-backed apps at once. A patient attacker who requests one ticket for one high-value SPN, or drips a few requests a day, stays under any burst threshold; that single-high-value case belongs in its own rule with its own fixture pair, not bolted onto this one. The rule is the cheap, high-signal first layer, and the README says so rather than implying full coverage.

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

That exclusion is also why DCSync's benign fixture is the hardest one in this project. Proving a low false-positive rate means the benign capture has to contain **real DC-to-DC replication** from a genuine DC computer account, which needs a second DC in the lab (or an honest note that the benign window only covers a single-DC forest). The rule and its tests are committed, but this detection stays deliberately last until that benign capture exists; a detection is only as honest as the benign traffic it was proven against.

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

`kerbdetect build-app` renders the same rule files CI replays into an installable Splunk app: one scheduled saved search per detection, scoped to the deployment index and enriched with its ATT&CK technique and stage, plus a coverage dashboard. Drop the output directory in `$SPLUNK_HOME/etc/apps/`. The CI validate job installs the generated app into the container on every push and asserts every detection landed as a saved search, so what deploys is what was proven.

## The lab

Two Gen-2 Hyper-V VMs on an isolated switch: a domain controller (`DC01.range.lab`) as the telemetry source, and a domain-joined workstation as the attacker vantage. `vm/Install-Telemetry.ps1` turns on the Kerberos audit subcategories (4769/4770 service tickets, 4768/4771 authentication, plus logon and directory-access for later slices); `vm/Export-Stage.ps1` exports the Security-log window as raw EVTX XML. The full runbook, including seeding SPN service accounts and running the roast, is in [`vm/README.md`](vm/README.md).

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
| Kerberoasting | T1558.003 | 4769 RC4 service-ticket burst | rule + tests in place; real fixtures pending first capture |
| AS-REP roasting | T1558.004 | 4768 with pre-auth disabled (`PreAuthType=0`) | rule + tests in place; real fixtures pending first capture |
| DCSync | T1003.006 | 4662 replication access from a non-DC principal | rule + tests in place; benign fixture is the hard one (real DC-to-DC replication) |

"Rule + tests in place" means the analytic, its schema contract, and its engine tests are committed and the offline gate proves them; it does **not** mean the search is validated. `report` says "Techniques with a detection: 3/3" but "Replay-ready: 0/3", and the ATT&CK Navigator layer stays empty until a detection has both real fixtures on disk. A technique only lights up the "proven coverage" layer once it has actually fired on a real capture and stayed silent on a real benign one in CI.

The engine, all three rules, the lab scripts, and both CI gates are done and green. What remains is the honest part that cannot be shortcut: the attack and benign **fixtures** come from real DC captures (see `vm/README.md`), and until they land, every technique above stays "staged, not proven." No fixtures are fabricated to close that gap.
