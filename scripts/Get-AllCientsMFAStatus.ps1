#Requires -Modules PSToolkit
<#
 .DESCRIPTION
    This will grab the most relevant details of a user/clients mfa setup for the secure defaults change. You will need to supply the applicationid, application secret etc for your partner access token in the params. Based off of Kelvin Tegelaar's @Cyberdrain MFA Alerting.
 .SYNOPSIS
    This will grab the most relevant details of a user/clients mfa setup for the secure defaults change.
 .LINK
    https://www.bleepingcomputer.com/news/microsoft/microsoft-to-force-better-security-defaults-for-all-azure-ad-tenants/
 .LINK
    https://www.cyberdrain.com/monitoring-with-powershell-monitoring-mfa-usage/
#>
param(
    $ApplicationId,
    $ApplicationSecret,
    $TenantID,
    $RefreshToken
)

######### Secrets #########
$credential = New-Object System.Management.Automation.PSCredential($ApplicationId, $ApplicationSecret)

$aadGraphToken = New-PartnerAccessToken -ApplicationId $ApplicationId -Credential $credential -RefreshToken $refreshToken -Scopes 'https://graph.windows.net/.default' -ServicePrincipal -Tenant $tenantID
$graphToken = New-PartnerAccessToken -ApplicationId $ApplicationId -Credential $credential -RefreshToken $refreshToken -Scopes 'https://graph.microsoft.com/.default' -ServicePrincipal -Tenant $tenantID

Connect-MsolService -AdGraphAccessToken $aadGraphToken.AccessToken -MsGraphAccessToken $graphToken.AccessToken

$customers = Get-MsolPartnerContract -All
$Baseuri = "https://graph.microsoft.com/beta"
$customers | ForEach-Object -Begin {
    Clear-Host
    $i = 0
    $out = ""
} -Process {
    try {
        ### Graph Access ###
        $ClientName = $_.DefaultDomainName
        $CustGraphToken = New-PartnerAccessToken -ApplicationId $ApplicationId -Credential $credential -RefreshToken $refreshToken -Scopes "https://graph.microsoft.com/.default" -ServicePrincipal -Tenant $_.TenantId
        $Header = @{ Authorization = "Bearer $($CustGraphToken.AccessToken)" }

        ### Secure Defaults ###
        $SecureDefaultsState = (Invoke-RestMethod -Uri "$baseuri/policies/identitySecurityDefaultsEnforcementPolicy" -Headers $Header -Method get -ContentType "application/json").IsEnabled

        ### Conditional Access Policies ###
        $CAPolicies = (Invoke-RestMethod -Uri "$baseuri/identity/conditionalAccess/policies" -Headers $Header -Method get -ContentType "application/json").value
    } catch {
        $out = $out + "[Error] Unable to sign into $ClientName, setting Conditional Access and Secure Defaults to False.`n"
        $CAPolicies = $false
    }

    try {
        ### Legacy Clients ###
        $VersionReport = (Invoke-RestMethod -Uri "https://graph.microsoft.com/beta/reports/getEmailAppUsageVersionsUserCounts(period='D7')" -Headers $Header -Method get -ContentType "application/json") | ConvertFrom-Csv

        $LegacyClients = if ($versionreport.'Outlook 2007' -or $versionreport.'Outlook 2010' -or $versionreport.'Outlook 2013') {
            $True
        } Else {
            $False
        }

        ### Legacy Apps ###
        $AppReports = (Invoke-RestMethod -Uri "https://graph.microsoft.com/beta/reports/getEmailAppUsageAppsUserCounts(period='D7')" -Headers $Header -Method get -ContentType "application/json") | ConvertFrom-Csv
        $LegacyApplications = if ($AppReports.'Other For Mobile' -or $AppReports.'POP3 App' -or $AppReports.'SMTP App' -or $AppReports.'IMAP4 App' -or $AppReports.'Mail For Mac') {
            $True
        } else {
            $False
        }
    } catch {
        $out = $out + "[Error] Unable to sign into $ClientName, setting Legacy Apps and Clients to False.`n"
    }

    $EnforcedForUsers = foreach ($Policy in $CAPolicy) {
        if ($Policy.grantControls.builtincontrols -ne 'mfa') { if ($Policy.displayName -notlike '*Duo*') { continue } }
        if ($Policy.state -ne 'Enabled') { continue }
        if (($Policy.conditions.applications) -and ($Policy.conditions.applications.includeapplications -ne 'All')) {
            [PSCustomObject]@{
                Name   = $Policy.displayName
                Target = 'Specific Applications'
            }
            continue
        }
        if ($Policy.conditions.users.includeUsers -eq 'All') {
            [PSCustomObject]@{
                Name   = $_.displayName
                Target = 'All Users'
            }
        }
    }

    if ($EnforcedForUsers.Target -eq 'All Users') {
        $Enforced = $True
    } else {
        $Enforced = $False
    }

    If (!$CAPolicies) {
        $ConditionalAccess = $False
    } Else {
        $ConditionalAccess = $True
    }

    @{
        TenantName     = $ClientName
        Date           = (Get-Date -Format "yyyy/MM/dd hh:mm tt").ToString()
        SecureDefaults = $SecureDefaultsState.toString()
        CAPolicies     = $ConditionalAccess.toString()
        CAEnforced     = $Enforced.toString()
        LegacyClients  = $LegacyClients.toString()
        LegacyApps     = $LegacyApplications.toString()
    } | Send-ToFlow -FlowUri "https://prod-28.westus.logic.azure.com:443/workflows/notareauluri"

    $i = $i + 1
    Write-Progress -Activity "Scanning O365 Tenants..." -Status "Grabbing MFA Settings For: $ClientName" -PercentComplete ($i / $customers.count * 100)
} -End {
    Write-Host $out -ForegroundColor Red
}
