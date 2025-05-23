#Requires -Modules PSToolkit
param(
    [Parameter(Position = 1)]
    [string]$clientName = "Unknown"
)

try {
    Get-BitLockerVolume | ForEach-Object {
        @{
            ClientName  = $clientName
            Hostname    = $env:COMPUTERNAME
            Volume      = ($_.MountPoint).ToString()
            Status      = ($_.VolumeStatus).ToString()
            Percentage  = ($_.EncryptionPercentage).ToString()
            LockStatus  = ($_.LockStatus).ToString()
            DateUpdated = (Get-Date -Format "yyyy/MM/dd hh:mm tt").ToString()
        } | Send-ToFlow -FlowUri "https://prod-12.westus.logic.azure.com:443/workflows/notarealuri"
    }
} catch {
    $Error | ForEach-Object {
        @{
            DateOccurred = (Get-Date -Format "yyyy/MM/dd hh:mm tt").ToString()
            ClientName   = $clientName
            Hostname     = $env:COMPUTERNAME
            ErrorMessage = $_.ToString()
        } | Send-ToFlow -FlowUri "https://prod-39.westus.logic.azure.com:443/workflows/notarealuri"
    }
}
