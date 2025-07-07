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
    Minimum OS Architecture Supported: Windows Server 2016
    Version: 1.0
    Release Notes: Initial Release

.LICENSE
    Copyright © 2025 Kyle Pradlander - www.spacethoughts.net/about

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
param (
    [Parameter()]
    [String]$AccountToManage,
    [Parameter()]
    [String]$DesiredPassLength = 14,
    [Parameter()]
    [String]$DesiredMaxPassAge = 30
)

begin {

    # Check if the operating system build version is less than 14393 (Windows Server 2016 minimum requirement)
    if ([System.Environment]::OSVersion.Version.Build -lt 14393) {
        Write-Host -Object "`n[Warning] OS build '$([System.Environment]::OSVersion.Version.Build)' detected."
        Write-Host -Object "[Warning] The minimum OS version supported by this script is Windows Server 2016 (14393). You may experience unexpected issues related to this.`n"
    }

    if ([string]::IsNullOrWhiteSpace($AccountToManage)) {
        Write-Host -Object "[Error] You must provide the name of an account to manage with LAPS."
        exit 1
    }

    $AccountToManage = $AccountToManage.Trim()

    if ($AccountToManage -match '[\\/:;*?"<>|,+@]|\[|]') {
        Write-Host -Object "[Error] The account to manage you provided '$AccountToManage' is invalid."
        Write-Host -Object "[Error] It contains one of the following illegal characters: '\/[]:;*?`"<>|,+@'"
        Write-Host -Object "[Error] https://learn.microsoft.com/previous-versions/windows/it-pro/windows-2000-server/bb726984(v=technet.10)"
        exit 1
    }

    if ($AccountToManage.Length -gt 20) {
        Write-Host -Object "[Error] The account to manage you provided '$AccountToManage' is invalid."
        Write-Host -Object "[Error] It is greater than 20 characters."
        Write-Host -Object "[Error] https://learn.microsoft.com/previous-versions/windows/it-pro/windows-2000-server/bb726984(v=technet.10)"
        exit 1
    }

    if ([string]::IsNullOrWhiteSpace($DesiredPassLength)) {
        Write-Host -Object "[Error] You must provide a maximum length for the password used for the managed account."
        exit 1
    }

    if ($DesiredPassLength -match '[^0-9]') {
        Write-Host -Object "[Error] The maximum password length provided of '$DesiredPassLength' is invalid."
        Write-Host -Object "[Error] Only numeric characters are allowed."
        exit 1
    }

    try {
        [int]$PassLength = $DesiredPassLength
    } catch {
        Write-Host -Object "[Error] $($_.Exception.Message)"
        Write-Host -Object "[Error] Failed to convert the desired password length into an integer."
        exit 1
    }

    if ($PassLength -lt 7 -or $PassLength -gt 64) {
        Write-Host -Object "[Error] The passowrd length provided of '$PassLength' is invalid."
        Write-Host -Object "[Error] Only password lengths greater than or equal to 7 and less than or equal to 90 are supported."
        exit 1
    }

    if ([string]::IsNullOrWhiteSpace($DesiredMaxPassAge)) {
        Write-Host -Object "[Error] You must provide a maximum password age for the password used for the managed account."
        exit 1
    }

    if ($DesiredMaxPassAge -match '[^0-9]') {
        Write-Host -Object "[Error] The maximum password age provided of '$DesiredMaxPassAge' is invalid."
        Write-Host -Object "[Error] Only numeric characters are allowed."
        exit 1
    }

    try {
        [int]$MaxPassAge = $DesiredMaxPassAge
    } catch {
        Write-Host -Object "[Error] $($_.Exception.Message)"
        Write-Host -Object "[Error] Failed to convert the desired password age into an integer."
        exit 1
    }

    if ($MaxPassAge -lt 7 -or $MaxPassAge -gt 90) {
        Write-Host -Object "[Error] The password length provided of '$MaxPassAge' is invalid."
        Write-Host -Object "[Error] Only password ages greater than or equal to 7 and less than or equal to 90 are supported."
        exit 1
    }

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

    function Test-IsSystem {
        [CmdletBinding()]
        param ()

        # Retrieve the current Windows identity of the user or process running the script
        $WindowsIdentity = [System.Security.Principal.WindowsIdentity]::GetCurrent()

        # Check if the identity is a system account by verifying the IsSystem property
        # or comparing the User property to the well-known SID for the LocalSystem account (S-1-5-18)
        $WindowsIdentity.IsSystem -or $WindowsIdentity.User -eq "S-1-5-18"
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
        $IsElevated = Test-IsElevated -ErrorAction "Stop"
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
        $IsDomainController = Test-IsDomainController -ErrorAction "Stop"
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
        $DefaultPasswordPolicy = Get-ADDefaultDomainPasswordPolicy -ErrorAction "Stop"
    } catch {
        Write-Host -Object "[Error] $($_.Exception.Message)"
        Write-Host -Object "[Error] Failed to verify the password would meet the domains password complexity requirements."
        exit 1
    }

    if ($DefaultPasswordPolicy.MaxPasswordAge.TotalDays -ne 0 -and $DefaultPasswordPolicy.MaxPasswordAge.TotalDays -lt $MaxPassAge) {
        Write-Host -Object "[Error] The max password age you specified '$MaxPassAge' is invalid."
        Write-Host -Object "[Error] It is greater than the domains max password age of '$($DefaultPasswordPolicy.MaxPasswordAge.TotalDays)'."
        exit 1
    }

    if ($DefaultPasswordPolicy.MinPasswordLength -gt $PassLength) {
        Write-Host -Object "[Error] The password length you specified '$PassLength' is invalid."
        Write-Host -Object "[Error] It is less than the domains min password length of '$($DefaultPasswordPolicy.MinPasswordLength)'."
        exit 1
    }

    try {
        Write-Host -Object "Verifying the domain functional level (DFL) is 2016 or higher."
        $DomainFunctionalLevel = Get-ADDomain -ErrorAction "Stop" | Select-Object -ExpandProperty DomainMode -ErrorAction "Stop"
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

    if (!(Test-IsSystem)) {
        Write-Host -Object "Verifying that the user '$env:USERNAME' is a member of the Domain Admins, Schema Admins, Enterprise Admins group."

        try {
            $DomainSID = (Get-ADDomain -ErrorAction "Stop").DomainSID.Value
        } catch {
            Write-Host -Object "[Error] $($_.Exception.Message)"
            Write-Host -Object "[Error] Failed to fetch the SID of the Domain."
            exit 1
        }

        try {
            $ErrorActionPreference = "Stop"
            $WindowsIdentity = [System.Security.Principal.WindowsIdentity]::GetCurrent()
            $ErrorActionPreference = "Continue"
        } catch {
            $ErrorActionPreference = "Continue"
            Write-Host -Object "[Error] $($_.Exception.Message)"
            Write-Host -Object "[Error] Failed to retrieve the group membership of the individual user account."
            exit 1
        }

        if ($WindowsIdentity.Groups.Value -notcontains "$DomainSid-512") {
            Write-Host -Object "[Error] This account is currently not a member of the Domain Admins group."
            exit 1
        }

        if ($WindowsIdentity.Groups.Value -notcontains "$DomainSid-518") {
            Write-Host -Object "[Error] This account is currently not a member of the Schema Admins group."
            exit 1
        }

        if ($WindowsIdentity.Groups.Value -notcontains "$DomainSid-519") {
            Write-Host -Object "[Error] This account is currently not a member of the Enterprise Admins group."
            exit 1
        }
    }

    try {
        Write-Host -Object "Updating the active directory schema for LAPS."
        Update-LapsADSchema -Confirm:$False -ErrorAction "Stop"
        Write-Host -Object "Update was successful."
    } catch {
        Write-Host -Object "[Error] $($_.Exception.Message)"
        Write-Host -Object "[Error] Failed to update the LAPS Schema."
        Write-Host -Object "[Error] Is the account '$env:USERNAME' a member of the Schema Admins group and the Enterprise Admins group or the SYSTEM account?"
        exit 1
    }

    try {
        Write-Host -Object "Retrieving the current AD Domain."
        $ADDomain = Get-ADDomain -ErrorAction "Stop" | Select-Object -ExpandProperty DistinguishedName -ErrorAction "Stop"

        Write-Host -Object "Allowing each computer in '$ADDomain' to synchronize (i.e., push) its LAPS password to its own computer object in Active Directory."
        Set-LapsADComputerSelfPermission -Identity $ADDomain -ErrorAction "Stop" | Out-Null
        Write-Host -Object "Successfully updated the permissions."
    } catch {
        Write-Host -Object "[Error] $($_.Exception.Message)"
        Write-Host -Object "[Error] Failed to update the permissions."
        exit 1
    }



    exit $ExitCode
}