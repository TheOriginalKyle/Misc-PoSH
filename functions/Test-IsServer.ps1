function Test-IsServer {
    [Diagnostics.CodeAnalysis.SuppressMessageAttribute('PSAvoidUsingWMICmdlet', '',
        Justification = 'The WMI cmdlet is only used when Get-CimInstance is not available (PSVersion < 3).')]
    [CmdletBinding()]
    param()

    $OSInfo = if ($PSVersionTable.PSVersion.Major -lt 3) {
        Get-WmiObject -Class "Win32_OperatingSystem"
    } else {
        Get-CimInstance -ClassName "Win32_OperatingSystem"
    }

    if ($OSInfo.OperatingSystemSKU -eq 175){
        return $False
    }

    switch ($OSInfo.ProductType) {
        "1" { $False }
        "2" { $True }
        "3" { $True }
    }
}