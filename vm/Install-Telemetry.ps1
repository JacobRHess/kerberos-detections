# kerbdetect telemetry bootstrap - run INSIDE the domain controller, as
# Administrator. Enables the Security audit subcategories whose events the
# Kerberos detections search. No Sysmon, no PowerShell logging: every event
# this project uses is a native DC Security-log record.
#
# By default a DC already logs 4768/4769 at Success, but this makes the policy
# explicit (and adds Failure, which AS-REP/Kerberoast failures surface on) so a
# capture is reproducible on a freshly promoted DC.

#Requires -RunAsAdministrator
$ErrorActionPreference = 'Stop'

Write-Host 'Setting Kerberos and logon audit policy'
$policies = @(
    # subcategory, success, failure -> the Security EIDs the detections search
    @('Kerberos Service Ticket Operations', 'enable', 'enable'),   # 4769, 4770 (Kerberoasting)
    @('Kerberos Authentication Service', 'enable', 'enable'),      # 4768, 4771 (AS-REP roasting)
    @('Logon', 'enable', 'enable'),                                # 4624, 4625 (benign context)
    @('Directory Service Access', 'enable', 'disable')             # 4662 (DCSync)
)
foreach ($p in $policies) {
    # Quote each name:value argument: unquoted "/subcategory:$p[0]" is passed
    # literally and auditpol rejects it with error 87.
    & auditpol /set "/subcategory:$($p[0])" "/success:$($p[1])" "/failure:$($p[2])"
    if ($LASTEXITCODE -ne 0) {
        throw ("auditpol failed for '{0}'; run 'auditpol /list /subcategory:*' and fix the name" -f $p[0])
    }
}

Write-Host 'Done. Verify with:'
Write-Host "  auditpol /get /subcategory:'Kerberos Service Ticket Operations'"
Write-Host '  Get-WinEvent -MaxEvents 5 -FilterHashtable @{LogName="Security"; Id=4769}'
