#Requires -Version 5.1

<#
.SYNOPSIS
    Short Description
.DESCRIPTION
    Long Description

.EXAMPLE
    (No Parameters)
    ## EXAMPLE OUTPUT WITHOUT PARAMS ##

.PARAMETER SomeParam
    A brief explanation of the parameter.

.PARAMETER CustomFieldParam
    A brief explanation of the parameter.

.NOTES
    Minimum OS Architecture Supported: Windows 10, Windows Server 2016
    Release Notes: Initial Release

.LICENSE
    Copyright 2025 Kyle Bohlander - www.spacethoughts.net/about

    Licensed under the Apache License, Version 2.0 (the "License");
    you may not use this file except in compliance with the License.
    You may obtain a copy of the License at

        http://www.apache.org/licenses/LICENSE-2.0

    Unless required by applicable law or agreed to in writing, software
    distributed under the License is distributed on an "AS IS" BASIS,
    WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
    See the License for the specific language governing permissions and
    limitations under the License.
#>

[CmdletBinding()]
param ()

begin {

    function Test-IsDomainController {
        [Diagnostics.CodeAnalysis.SuppressMessageAttribute('PSAvoidUsingWMICmdlet', '',
            Justification = 'The WMI cmdlet is only used when Get-CimInstance is not available (PSVersion < 3).')]
        [CmdletBinding()]
        param()

        $OSInfo = if ($PSVersionTable.PSVersion.Major -lt 3) {
            Get-WmiObject -Class "Win32_OperatingSystem"
        } else {
            Get-CimInstance -ClassName "Win32_OperatingSystem"
        }

        switch ($OSInfo.ProductType) {
            "1" { $False }
            "2" { $True }
            "3" { $False }
        }
    }

    function Test-IsElevated {
        [CmdletBinding()]
        param ()

        # Get the current Windows identity of the user running the script
        $Identity = [System.Security.Principal.WindowsIdentity]::GetCurrent()

        # Create a WindowsPrincipal object based on the current identity
        $SecurityPrincipal = New-Object System.Security.Principal.WindowsPrincipal($Identity)

        # Check if the current user is in the Administrator role
        # The function returns $True if the user has administrative privileges, $False otherwise
        # 544 is the value for the Built In Administrators role
        # Reference: https://learn.microsoft.com/en-us/dotnet/api/system.security.principal.windowsbuiltinrole
        $SecurityPrincipal.IsInRole([System.Security.Principal.WindowsBuiltInRole]'544')
    }

    if (!$ExitCode) {
        $ExitCode = 0
    }
}
process {
    # Attempt to determine if the current session is running with Administrator privileges.
    try {
        $IsElevated = Test-IsElevated -ErrorAction Stop
    } catch {
        Write-Host -Object "[Error] $($_.Exception.Message)"
        Write-Host -Object "[Error] Unable to determine if the account '$env:Username' is running with Administrator privileges."
        exit 1
    }

    if (!$IsElevated) {
        Write-Host -Object "[Error] Access Denied: Please run with Administrator privileges."
        exit 1
    }

    try {
        $IsDomainController = Test-IsDomainController -ErrorAction Stop
    } catch {
        Write-Host -Object "[Error] $($_.Exception.Message)"
        Write-Host -Object "[Error] Unable to determine if this system is a Domain Controller or a Server."
        exit 1
    }

    if (!$IsDomainController) {
        Write-Host -Object "[Error] This device is not a Domain Controller. Unable to deploy LAPS."
        exit 1
    }

    try {
        Write-Host -Object "Verifying the domain functional level (DFL) is 2016 or higher."
        $DomainFunctionalLevel = Get-ADDomain -ErrorAction Stop | Select-Object -ExpandProperty DomainMode -ErrorAction Stop
        [int]$DomainFunctionalLevel = $DomainFunctionalLevel -replace "[^0-9]"
        if ([string]::IsNullOrWhiteSpace($DomainFunctionalLevel) -or $DomainFunctionalLevel -match "[^0-9]") {
            throw "Failed to parse the domain functional level."
        }
    } catch {
        Write-Host -Object "[Error] $($_.Exception.Message)"
        Write-Host -Object "[Error] Unable to determine the domain functional level."
        exit 1
    }

    if ($DomainFunctionalLevel -lt 2016) {
        Write-Host -Object "[Error] The domain functional level (DFL) is currently '$DomainFunctionalLevel'. This is not supported by either LAPS or this script."
        Write-Host -Object "[Error] https://learn.microsoft.com/windows-server/identity/laps/laps-scenarios-windows-server-active-directory#domain-functional-level-and-domain-controller-operating-system-version-requirements"
        exit 1
    }

    exit $ExitCode
}