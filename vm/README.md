# Capture lab runbook

The Kerberoasting stage runs against an isolated Hyper-V Active Directory lab,
never the host. A domain controller is the telemetry source: `Install-Telemetry.ps1`
turns on the Kerberos audit subcategories, and `Export-Stage.ps1` exports the
Security-log window as raw event XML for the host-side slicing tool.

Kerberos tradecraft is a two-machine story - an attacker on a domain-joined
workstation requests service tickets, and the events land on the DC - but every
event the detections search is written to the **DC's** Security log, so the DC is
the only capture source. (The single-capture slicer derives its `host`/`stage`
from the first export file; that is correct here because one DC export holds the
whole picture. A future multi-host technique would need that relaxed.)

## 1. Build the lab

Hyper-V on the host (Windows 11 Pro has it as an optional feature). Two Gen-2 VMs
on a private/internal switch, no route to the host or internet during captures:

- **DC01** - Windows Server (2022/2025 eval), 4 GB RAM. Promote to a new forest:

  ```powershell
  Install-WindowsFeature AD-Domain-Services -IncludeManagementTools
  Install-ADDSForest -DomainName range.lab -DomainNetbiosName RANGE -InstallDns -Force
  ```

  The DC name lands in every fixture's `Computer` field. (The fixtures committed
  to this repo come from published datasets instead — see `../fixtures/SOURCES.md`
  — so they carry the Splunk Attack Range's hostnames, not this runbook's.)

- **WS01** - Windows 10/11 eval, domain-joined to `range.lab`, the attacker vantage.

Take a checkpoint on both before every capture so a noisy window replays clean.

## 2. Seed roastable service accounts (on DC01, as Administrator)

Kerberoasting targets **user** accounts that carry a Service Principal Name. Create
a handful with weak-ish passwords and register SPNs, plus a normal user to run the
attack and generate benign traffic:

```powershell
$pw = Read-Host -AsSecureString 'service account password'
foreach ($svc in 'svc_sql','svc_web','svc_backup','svc_report','svc_erp') {
    New-ADUser -Name $svc -SamAccountName $svc -AccountPassword $pw -Enabled $true `
        -PasswordNeverExpires $true
    setspn -A ("MSSQLSvc/$svc.range.lab:1433") $svc   # any plausible SPN works
}
New-ADUser -Name jdoe -SamAccountName jdoe -AccountPassword $pw -Enabled $true
```

Five+ SPN accounts matters: the detection fires on a *burst* of distinct SPNs
requested by one principal, so a realistic roast needs several targets.

## 3. Enable telemetry (once, on DC01, as Administrator)

Copy this `vm/` directory to DC01 (shared folder or `Copy-VMFile`), then:

```powershell
.\Install-Telemetry.ps1
```

Sets the audit subcategories the Security-log detections need: Kerberos Service
Ticket Operations (4769/4770), Kerberos Authentication Service (4768/4771), Logon
(4624/4625), Directory Service Access (4662, for the later DCSync slice), and
Security-log-cleared (1102). No Sysmon, no PowerShell logging - every event is a
native DC record.

## 4. Run the attack (on WS01, as the `jdoe` domain user)

Request service tickets for every roastable SPN, forcing RC4 (the classic
downgrade signal). Rubeus is the common tool; `Invoke-Kerberoast` or Impacket's
`GetUserSPNs.py -request` work too:

```powershell
.\Rubeus.exe kerberoast /rc4opsec /outfile:hashes.txt
```

Each request writes a 4769 on DC01 with `TicketEncryptionType 0x17`. No password
is cracked in the lab - the telemetry is the product, not the loot. Keep the
tools on WS01; they never touch the host.

## 5. Export the window (on DC01)

```powershell
.\Export-Stage.ps1 -Stage 01 -WindowMinutes 30
```

Copy the resulting `captures/stage-01-*.kerbdetect.xml` to the host, then slice it
into the attack fixture:

```powershell
uv run kerbdetect capture captures/stage-01-*.kerbdetect.xml --stage 01-credential-access
```

## AS-REP roasting variant (T1558.004)

Same lab, same channel, no telemetry change (`Install-Telemetry.ps1` already enables the Kerberos
Authentication Service subcategory that writes 4768). On DC01, flag one account as pre-auth-exempt:

```powershell
Set-ADAccountControl -Identity svc_report -DoesNotRequirePreAuth $true
```

From WS01, request TGTs for pre-auth-disabled accounts (Impacket's `GetNPUsers.py` or the
equivalent), which writes 4768 with `PreAuthType=0` on DC01. Export the same way
(`.\Export-Stage.ps1 -Stage 01`) and slice into the `asrep-roasting-no-preauth` attack fixture.
The benign window for this detection must include normal TGT activity (`PreAuthType=2`) so the
benign slice exercises the pre-auth filter rather than sidestepping it.

## DCSync variant (T1003.006)

`Install-Telemetry.ps1` already enables the Directory Service Access subcategory (4662). Grant a
non-admin test account the two replication rights (`DS-Replication-Get-Changes` and
`-Get-Changes-All`) on the domain object, then from WS01 run a replication request as that account
(Impacket's `secretsdump.py -just-dc`, or the equivalent). DC01 logs 4662 with `AccessMask=0x100`
and the replication GUIDs in `Properties`, under a non-machine `SubjectUserName`. Export and slice
into the `dcsync-replication-nondc` attack fixture.

The benign fixture is the hard one, for two reasons. First, credible benign traffic must contain
**real DC-to-DC replication**, which comes from a domain controller's own computer account
(`SubjectUserName` ending in `$`) — exactly what the rule excludes — and that needs a second DC in
the lab; a single-DC forest cannot produce it. Second, and sharper, the rule's `!="*$"` exclusion
lets through any legitimate *user* account with replication rights: an Entra/Azure AD Connect sync
account (`MSOL_*`), an admin running `repadmin /syncall`, or a delegated service account. A benign
window that omits those overstates the detection's precision. Until a two-DC capture with a real
sync account exists, record in the fixture metadata that the benign slice covers only single-DC 4662
noise, not the machine-account or sync-account near-misses the deployed rule needs an allowlist to
handle.

## Benign captures

Same export path over a scripted normal-usage window, then slice with `--benign`.
Those slices fill the `<id>.benign.json` halves.

A benign capture is only as strong as the near-misses it contains. Quiet
background 4769s prove a rule ignores idle service-ticket traffic; they do **not**
prove a low false-positive rate against activity that actually resembles a roast.
For the Kerberoasting detection that means the benign window should include the
legitimate look-alikes a real domain produces:

- a user or app legitimately touching **many** services in a short burst (a login
  script that maps drives and opens several SPN-backed apps),
- any **RC4** service tickets a legacy service or account still negotiates, so the
  benign slice exercises the encryption-type filter rather than sidestepping it,
- normal 4768 TGT activity and machine-account (`*$`) ticket traffic, which the
  rule deliberately excludes.

Script those into the window so the benign slice exercises the rule's decision
boundary, not just an empty domain. Until it does, treat the low-FP claim as
"ignores a quiet domain", not "survives realistic near-misses".

## Ingest field names (renderXml)

Fixtures carry the raw EVTX element names (`ServiceName`, `TicketEncryptionType`,
`TargetUserName`) because `Export-Stage.ps1` serializes each event with `.ToXml()`.
For the deployed rules to match those same names, a production forwarder must
ingest the Security channel with `renderXml = true` in `inputs.conf` (sourcetype
`XmlWinEventLog:Security`). Under the classic non-XML Security extraction the
Splunk Add-on for Windows derives different field names, and the rules would
silently never match. This is the single ingest assumption the "runs unmodified
in production" claim rests on, and it is stated so a reader can check it.
