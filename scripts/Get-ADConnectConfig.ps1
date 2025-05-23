<#
 .DESCRIPTION
    This will grab the most relevant details of an AD Connect Config and add it to an excel spreadsheet.

    PowerAutomate is required but does not need to be installed on the machine (it'll make a post request to the configured endpoint).
 .SYNOPSIS
    This will grab weather its ou synced, group synced or neither.
 .EXAMPLE
    Get-ADConnectConfig.ps1 -clientName "Client"

    Sent to Flow
 .LINK
    https://iforgotmydomain.sharepoint.com/:x:/g/AFolder/asdfasdfasdf
#>
param($clientName)
# Grab ADSync Information and Domain
$ADdomain = (Get-ADDomain).DistinguishedName
$AADConnector = (Get-ADDomain).Forest
$AADConn = Get-ADSyncConnector -Name $AADConnector
$AADConPartition = Get-ADSyncConnectorPartition -Connector $AADConn[0] -Identifier $AADConn.Partitions.Identifier.Guid

# Get a list of all ou's included in the sync config (remember its recursive so if folder A is inside folder B and B is synced so is A)
$InclusionList = $AADConPartition.ConnectorPartitionScope.ContainerInclusionList

# Checks if all ou's are synced if they are its not really ou synced.
if ($ADdomain -eq $InclusionList) {
    $OUSynced = $false
} else {
    $OUSynced = $true
}

# Grab synced groups name
$GroupFilteringDN = (Get-ADSyncConnector).GlobalParameters | Where-Object Name -EQ Connector.GroupFilteringGroupDn

if (($GroupFilteringDN.Value) -ne "") {
    $GroupFiltered = $true
} else {
    $GroupFiltered = $false
}

# Updates flow
$FlowUri = "https://prod-28.westus.logic.azure.com:443/workflows/notarealuri"
$flowBody = @{
    ClientName  = $clientName
    Hostname    = [System.Net.Dns]::GetHostName()
    OUsynced    = $OUSynced.ToString()
    GroupSynced = $GroupFiltered.ToString()
    DateChecked = (Get-Date -Format "yyyy/MM/dd")
}
try {
    [System.Net.ServicePointManager]::SecurityProtocol = [System.Net.SecurityProtocolType]::Tls12
    Write-Output "Attempting to send data to flow"
    Invoke-RestMethod -Method Post -Uri $FlowUri -Body (ConvertTo-Json $flowBody) -ContentType "application/json" -ErrorVariable flowError
    Write-Output "Sent to Flow"
} catch {
    throw "[ERROR] Could not send update to Flow`n`n" + $flowError
}