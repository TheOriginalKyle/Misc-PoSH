#Requires -Version 5.1

<#
.SYNOPSIS
    Short Description
.DESCRIPTION
    Long Description

.EXAMPLE
    -AccountToManage "testAdmin" -DesiredPassLength 14 -DesiredMaxPassAge 30 -LinkToRootOfDomain

    ## EXAMPLE OUTPUT WITHOUT PARAMS ##

.PARAMETER SomeParam
    A brief explanation of the parameter.

.PARAMETER CustomFieldParam
    A brief explanation of the parameter.

.NOTES
    Minimum OS Architecture Supported: Windows Server 2019
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
    [String]$DesiredMaxPassAge = 30,
    [Parameter()]
    [String]$WorkingDirectory = "$env:TEMP\Windows-LAPS-Script",
    [Parameter()]
    [String]$LGPOUrl = "https://download.microsoft.com/download/8/5/c/85c25433-a1b0-4ffa-9429-7e023e7da8d8/LGPO.zip",
    [Parameter()]
    [Switch]$LinkToRootOfDomain = [System.Boolean]::Parse($env:linkLapsGpoToDomainRoot),
    [Parameter()]
    [Switch]$Force = [System.Boolean]::Parse($env:force)
)

begin {
    # If Ninja script variables are used, replace the command line parameters with their value.
    # https://ninjarmm.zendesk.com/hc/articles/17783013460621-Automation-Library-Using-Variables-in-Scripts
    if ($env:accountToManage) { $AccountToManage = $env:accountToManage }
    if ($env:desiredPasswordLength) { $DesiredPassLength = $env:desiredPasswordLength }
    if ($env:desiredMaxPasswordAge) { $DesiredMaxPassAge = $env:desiredMaxPasswordAge }

    # Check if the operating system build version is less than 17763 (Windows Server 2019 minimum requirement)
    if ([System.Environment]::OSVersion.Version.Build -lt 17763) {
        Write-Host -Object "[Error] OS build '$([System.Environment]::OSVersion.Version.Build)' detected."
        Write-Host -Object "[Error] The minimum OS version supported by this script is Windows Server 2019 (17763)."
        Write-Host -Object "[Error] https://learn.microsoft.com/windows-server/identity/laps/laps-overview#windows-laps-supported-platforms"
        exit 1
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
        Write-Host -Object "[Error] Only password lengths greater than or equal to 7 and less than or equal to 64 are supported."
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

    function Invoke-LegacyCMDUtility {
        [CmdletBinding()]
        param (
            [Parameter(Mandatory = $True)]
            [String]$FilePath,
            [Parameter()]
            [String[]]$ArgumentList,
            [Parameter()]
            [Int]$Timeout = 30,
            [Parameter()]
            [System.Text.Encoding]$Encoding
        )

        # Validate that FilePath is not null or empty
        if ([String]::IsNullOrWhiteSpace($FilePath)) {
            throw (New-Object System.ArgumentNullException("FilePath", "FilePath cannot be null or empty."))
        }

        # Check for invalid characters in the file path
        if ($FilePath -match '[*?"<>|]' -or $FilePath.Substring(3) -match "[:]") {
            throw (New-Object System.ArgumentException("The path '$FilePath' contains invalid characters."))
        }

        # Validate folder names in the file path
        $FilePath -split '\\' | ForEach-Object {
            $Folder = ($_).Trim()
            if ($Folder -match '^(CON|PRN|AUX|NUL)$' -or $Folder -match '^(LPT|COM)\d$') {
                throw (New-Object System.ArgumentException("An invalid folder name was found in '$FilePath'. The following folder names are reserved: CON, PRN, AUX, NUL, COM1-9, LPT1-9."))
            }
        }

        # Resolve the file path if it is not rooted and does not exist in the current directory
        if (!([System.IO.Path]::IsPathRooted($FilePath)) -and !(Test-Path -Path $FilePath -PathType Leaf -ErrorAction SilentlyContinue)) {
            $EnvPaths = [System.Environment]::GetEnvironmentVariable("PATH").Split(";")
            $PathExts = [System.Environment]::GetEnvironmentVariable("PATHEXT").Split(";")

            $ResolvedPath = $null
            foreach ($Directory in $EnvPaths) {
                foreach ($FileExtension in $PathExts) {
                    $PotentialMatch = Join-Path $Directory ($FilePath + $FileExtension)
                    if (Test-Path $PotentialMatch -PathType Leaf) {
                        $ResolvedPath = $PotentialMatch
                        break
                    }
                }
                if ($ResolvedPath) { break }
            }

            if ($ResolvedPath) {
                $FilePath = $ResolvedPath
            }
        }

        # Throw an error if the file does not exist
        if (!(Test-Path -Path $FilePath -PathType Leaf -ErrorAction SilentlyContinue)) {
            throw (New-Object System.IO.FileNotFoundException("No file was found at '$FilePath'."))
        }

        # Validate Timeout parameter
        if ([String]::IsNullOrWhiteSpace($Timeout)) {
            throw (New-Object System.ArgumentNullException("Timeout", "Timeout cannot be null or empty."))
        }

        # Ensure Timeout is greater than or equal to 30 seconds
        if ($Timeout -lt 30) {
            throw (New-Object System.ArgumentException("Timeout must be greater than or equal to 30 seconds."))
        }

        # Configure process start information
        $ProcessInfo = New-Object System.Diagnostics.ProcessStartInfo
        $ProcessInfo.FileName = $FilePath
        $ProcessInfo.Arguments = $ArgumentList -join " "
        $ProcessInfo.UseShellExecute = $False
        $ProcessInfo.RedirectStandardInput = $True
        $ProcessInfo.RedirectStandardOutput = $True
        $ProcessInfo.RedirectStandardError = $True
        $ProcessInfo.CreateNoWindow = $True

        # Determine encoding for standard output/error streams
        if (!$Encoding) {
            try {
                if (-not ([System.Management.Automation.PSTypeName]'NativeMethods.Win32').Type) {
                    $Definition = '[DllImport("kernel32.dll")]' + "`n" + 'public static extern uint GetOEMCP();'
                    Add-Type -MemberDefinition $Definition -Name "Win32" -Namespace "NativeMethods" -ErrorAction Stop
                }
                [int]$OemCodePage = [NativeMethods.Win32]::GetOEMCP()
                $Encoding = [System.Text.Encoding]::GetEncoding($OemCodePage)
            } catch {
                throw $_
            }
        }
        $ProcessInfo.StandardOutputEncoding = $Encoding
        $ProcessInfo.StandardErrorEncoding = $Encoding

        # Create and configure the process object
        $Process = New-Object System.Diagnostics.Process
        $Process.StartInfo = $ProcessInfo
        $Process | Add-Member -MemberType NoteProperty -Name StdOut -Value (New-Object System.Collections.Generic.List[string]) -Force | Out-Null
        $Process | Add-Member -MemberType NoteProperty -Name StdErr -Value (New-Object System.Collections.Generic.List[string]) -Force | Out-Null

        # Start the process
        $Process.Start() | Out-Null

        $ProcessTimeout = 0
        $TimeoutInMilliseconds = $Timeout * 1000

        # Initialize buffers for output/error streams
        $StdOutBuffer = New-Object System.Text.StringBuilder
        $StdErrBuffer = New-Object System.Text.StringBuilder

        # Monitor process execution and read output/error streams
        while (!$Process.HasExited -and $ProcessTimeout -lt $TimeoutInMilliseconds ) {
            # Read standard output to prevent buffer overflow
            while (!$Process.StandardOutput.EndOfStream -and $Process.StandardOutput.Peek() -ne -1) {
                $Char = $Process.StandardOutput.Read()
                if ($Char -ne -1) {
                    $ActualCharacter = [char]$Char
                    if ($ActualCharacter -eq "`n") {
                        $Process.StdOut.Add($StdOutBuffer.ToString())
                        $null = $StdOutBuffer.Clear()
                    } elseif ($ActualCharacter -ne "`r") {
                        $null = $StdOutBuffer.Append($ActualCharacter)
                    }
                }
            }

            # Read standard error to prevent buffer overflow
            while (!$Process.StandardError.EndOfStream -and $Process.StandardError.Peek() -ne -1) {
                $Char = $Process.StandardError.Read()
                if ($Char -ne -1) {
                    $ActualCharacter = [char]$Char
                    if ($ActualCharacter -eq "`n") {
                        $Process.StdErr.Add($StdErrBuffer.ToString())
                        $null = $StdErrBuffer.Clear()
                    } elseif ($ActualCharacter -ne "`r") {
                        $null = $StdErrBuffer.Append($ActualCharacter)
                    }
                }
            }

            Start-Sleep -Milliseconds 100
            $ProcessTimeout = $ProcessTimeout + 10
        }

        # Add final buffered content to StdOut and StdErr properties
        if ($StdOutBuffer.Length -gt 0) {
            $Process.StdOut.Add($StdOutBuffer.ToString())
        }

        if ($StdErrBuffer.Length -gt 0) {
            $Process.StdErr.Add($StdErrBuffer.ToString())
        }

        try {
            # Handle timeout scenarios
            if ($ProcessTimeout -ge $TimeoutInMilliseconds) {
                throw (New-Object System.ServiceProcess.TimeoutException("The process has timed out."))
            }

            # Wait for the process to exit within the remaining timeout period
            $TimeoutRemaining = $TimeoutInMilliseconds - $ProcessTimeout
            if (!$Process.WaitForExit($TimeoutRemaining)) {
                throw (New-Object System.ServiceProcess.TimeoutException("The process has timed out."))
            }
        } catch {
            # Set the global exit code and dispose of the process
            if ($Process.ExitCode) {
                $GLOBAL:LASTEXITCODE = $Process.ExitCode
            } else {
                $GLOBAL:LASTEXITCODE = 1
            }

            if ($Process) {
                $Process.Dispose()
            }

            throw $_
        }

        # Final read of output and error streams to ensure all data is captured
        while (!$Process.StandardOutput.EndOfStream) {
            $Char = $Process.StandardOutput.Read()
            if ($Char -ne -1) {
                $ActualCharacter = [char]$Char
                if ($ActualCharacter -eq "`n") {
                    $Process.StdOut.Add($StdOutBuffer.ToString())
                    $null = $StdOutBuffer.Clear()
                } elseif ($ActualCharacter -ne "`r") {
                    $null = $StdOutBuffer.Append($ActualCharacter)
                }
            }
        }

        while (!$Process.StandardError.EndOfStream) {
            $Char = $Process.StandardError.Read()
            if ($Char -ne -1) {
                $ActualCharacter = [char]$Char
                if ($ActualCharacter -eq "`n") {
                    $Process.StdErr.Add($StdErrBuffer.ToString())
                    $null = $StdErrBuffer.Clear()
                } elseif ($ActualCharacter -ne "`r") {
                    $null = $StdErrBuffer.Append($ActualCharacter)
                }
            }
        }

        # Log errors from the standard error stream
        if ($Process.StdErr.Count -gt 0) {
            if ($Process.ExitCode -or $Process.ExitCode -eq 0) {
                $GLOBAL:LASTEXITCODE = $Process.ExitCode
            }

            if ($Process) {
                $Process.Dispose()
            }

            $Process.StdErr | Write-Error -Category "FromStdErr"
        }

        # Return the standard output if available
        if ($Process.StdOut.Count -gt 0) {
            $Process.StdOut
        }

        # Set the global exit code
        if ($Process.ExitCode -or $Process.ExitCode -eq 0) {
            $GLOBAL:LASTEXITCODE = $Process.ExitCode
        }

        if ($Process) {
            $Process.Dispose()
        }
    }

    function Invoke-Download {
        [CmdletBinding()]
        param(
            [Parameter(Mandatory = $True)]
            [System.Uri]$URL,
            [Parameter(Mandatory = $True)]
            [String]$Path,
            [Parameter()]
            [int]$Attempts = 3,
            [Parameter()]
            [Switch]$SkipSleep,
            [Parameter()]
            [Switch]$Overwrite
        )

        # Trim whitespace from URL and Path.
        if ($URL) { $URL = $URL.OriginalString.Trim() }
        if ($Path) { $Path = $Path.Trim() }

        # Validate URL and Path parameters.
        if (!($URL)) {
            throw (New-Object System.ArgumentNullException("URL", "URL cannot be null."))
        }
        if (!($Path)) {
            throw (New-Object System.ArgumentNullException("Path", "Path cannot be null."))
        }

        # Ensure URL starts with "http" or "https".
        if ($URL.OriginalString -notmatch "^http") {
            $URL = "https://$($URL.OriginalString)"
            Write-Host -Object "[Warning] The URL provided does not contain 'http'. Modifying it to '$($URL.AbsoluteUri)'."
        } else {
            Write-Host -Object "The URL provided was '$($URL.AbsoluteUri)'."
        }

        # Validate Path for invalid characters.
        if ($Path -match '[*?"<>|]' -or $Path.Substring(3) -match "[:]") {
            throw (New-Object System.ArgumentException("The path '$Path' contains invalid characters."))
        }

        # Check for reserved folder names in the Path.
        $Path -split '\\' | ForEach-Object {
            $Folder = ($_).Trim()
            if ($Folder -match '^(CON|PRN|AUX|NUL)$' -or $Folder -match '^(LPT|COM)\d$') {
                throw (New-Object System.ArgumentException("An invalid folder name was given in '$Path'. The following folder names are reserved: CON, PRN, AUX, NUL, COM1-9, LPT1-9."))
            }
        }

        # Ensure Path contains a filename.
        if (($Path | Split-Path -Leaf) -notmatch "[.]") {
            throw (New-Object System.ArgumentException("The path '$Path' must contain a filename."))
        }

        # Validate the number of attempts.
        if ($Attempts -le 0) {
            throw (New-Object System.ArgumentException("Attempts must be greater than 0."))
        }

        # Check if file already exists and handle overwrite flag.
        if ((Test-Path -Path $Path -PathType Leaf -ErrorAction SilentlyContinue) -and !($Overwrite)) {
            throw (New-Object System.IO.IOException("A file already exists at the path '$Path'."))
        }

        # Configure TLS settings for secure connections.
        $SupportedTLSVersions = [enum]::GetValues('Net.SecurityProtocolType')
        if (($SupportedTLSVersions -contains 'Tls13') -and ($SupportedTLSVersions -contains 'Tls12')) {
            [Net.ServicePointManager]::SecurityProtocol = (
                [Enum]::ToObject([Net.SecurityProtocolType], 12288) -bor [Enum]::ToObject([Net.SecurityProtocolType], 3072)
            )
        } else {
            try {
                [Net.ServicePointManager]::SecurityProtocol = [Enum]::ToObject([Net.SecurityProtocolType], 3072)
            } catch {
                Write-Host -Object "[Warning] $($_.Exception.Message)"
                Write-Host -Object "[Warning] PowerShell does not have access to TLS 1.2 or higher on this system. This download may fail."
            }
        }

        # Ensure the destination folder exists.
        $DestinationFolder = $Path | Split-Path
        if (!(Test-Path -Path $DestinationFolder -ErrorAction SilentlyContinue)) {
            try {
                Write-Host -Object "Attempting to create the folder '$DestinationFolder' as it does not exist."
                New-Item -Path $DestinationFolder -ItemType "Directory" -ErrorAction Stop | Out-Null
                Write-Host -Object "Successfully created the destination folder."
            } catch {
                throw $_
            }
        }

        Write-Host -Object "Downloading the file."

        # Suppress progress output during download.
        $PreviousProgressPreference = $ProgressPreference
        $ProgressPreference = 'SilentlyContinue'

        # Attempt to download the file multiple times.
        $DownloadAttempt = 1
        while ($DownloadAttempt -lt $Attempts) {
            if (!($SkipSleep)) {
                # Introduce random sleep between attempts.
                $SleepTime = Get-Random -Minimum 3 -Maximum 15
                Write-Host -Object "Waiting for $SleepTime seconds."
                Start-Sleep -Seconds $SleepTime
            }

            if ($DownloadAttempt -ne 1) { Write-Host -Object "" }
            Write-Host -Object "Download Attempt $DownloadAttempt"

            try {
                # Use Invoke-WebRequest for PowerShell 4.0+ or fallback to WebClient.
                if ($PSVersionTable.PSVersion.Major -ge 4) {
                    $WebRequestArgs = @{
                        Uri                = $URL
                        OutFile            = $Path
                        MaximumRedirection = 10
                        UseBasicParsing    = $true
                        TimeoutSec         = 300
                    }

                    Invoke-WebRequest @WebRequestArgs
                } else {
                    $WebClient = New-Object System.Net.WebClient
                    $WebClient.DownloadFile($URL, $Path)
                }

                # Verify if the file was downloaded successfully.
                $File = Test-Path -Path $Path -ErrorAction SilentlyContinue
            } catch {
                Write-Host -Object "[Warning] An error occurred while downloading!"
                Write-Host -Object "[Warning] $($_.Exception.Message)"

                # Remove partially downloaded file if an error occurs.
                if (Test-Path -Path $Path -ErrorAction SilentlyContinue) {
                    Remove-Item $Path -Force -Confirm:$false -ErrorAction SilentlyContinue
                }

                $File = $False
            }

            # Exit loop if download succeeds.
            if ($File) {
                $DownloadAttempt = $Attempts
            } else {
                Write-Host -Object "[Warning] File failed to download.`n"
            }

            $DownloadAttempt++
        }

        # Restore progress preference.
        $ProgressPreference = $PreviousProgressPreference

        # Verify final download success and return the file object.
        if (!(Test-Path -Path $Path -PathType Leaf -ErrorAction SilentlyContinue)) {
            throw [System.IO.FileNotFoundException]::New("Failed to download file. Please verify the URL '$($URL.AbsoluteUri)'.")
        } else {
            return (Get-Item -Path $Path)
        }
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

    if (!(Test-Path -Path $WorkingDirectory -ErrorAction SilentlyContinue)) {
        try {
            New-Item -Path $WorkingDirectory -ItemType "Directory" -Force -ErrorAction Stop | Out-Null
        } catch {
            Write-Host -Object "[Error] $($_.Exception.Message)"
            Write-Host -Object "[Error] Failed to create the working directory '$WorkingDirectory'."
            exit 1
        }
    }

    if (!(Get-Module -ListAvailable "LAPS" -ErrorAction SilentlyContinue)) {
        Write-Host -Object "[Error] The Windows LAPS PowerShell module is not currently installed."
        Write-Host -Object "[Error] The Windows LAPS PowerShell module was released as part of an update to Windows Server."
        exit 1
    }

    $ErrorActionPreference = "SilentlyContinue"
    $LegacyLAPS = Get-ADComputer -Identity "$env:COMPUTERNAME" -Properties "ms-mcs-AdmPwd" -ErrorAction SilentlyContinue
    $WindowsLAPS = Get-ADComputer -Identity "$env:COMPUTERNAME" -Properties "msLAPS-Password" -ErrorAction SilentlyContinue
    $ErrorActionPreference = "Continue"

    if ($LegacyLAPS) {
        Write-Host -Object "`n[Alert] Legacy LAPS is detected. Windows LAPS and Legacy LAPS can coexist so long as they are not managing the same account."
        Write-Host -Object "[Alert] Removal of Legacy LAPS is recommended."
        Write-Host -Object "[Alert] https://learn.microsoft.com/windows-server/identity/laps/laps-scenarios-migration`n"
    }

    try {
        Write-Host -Object "Updating the active directory schema for LAPS."

        if (!$WindowsLAPS) {
            Update-LapsADSchema -Confirm:$False -ErrorAction "Stop"
        } else {
            Write-Host -Object "The LAPS active directory schema is already present."
        }
        Write-Host -Object "Update was successful."
    } catch {
        Write-Host -Object "[Error] $($_.Exception.Message)"
        Write-Host -Object "[Error] Failed to update the LAPS Schema."
        Write-Host -Object "[Error] Is the account '$env:USERNAME' a member of the Schema Admins group and the Enterprise Admins group or the SYSTEM account?"
        exit 1
    }

    try {
        Write-Host -Object "Retrieving the current AD Domain."
        $ADDomain = Get-ADDomain -ErrorAction "Stop" | Select-Object -ExpandProperty "DistinguishedName" -ErrorAction "Stop"

        Write-Host -Object "Allowing each computer in '$ADDomain' to synchronize (i.e., push) its LAPS password to its own computer object in Active Directory."
        Set-LapsADComputerSelfPermission -Identity $ADDomain -ErrorAction "Stop" | Out-Null
        Write-Host -Object "Successfully updated the permissions."
    } catch {
        Write-Host -Object "[Error] $($_.Exception.Message)"
        Write-Host -Object "[Error] Failed to update the permissions."
        exit 1
    }

    $WindowsLAPSGPO = Get-GPO -Name "Windows LAPS" -ErrorAction SilentlyContinue
    if ($WindowsLAPSGPO -and !$Force) {
        Write-Host -Object "`nThe 'Windows LAPS' GPO is already present. Please use -Force to overwrite the existing GPO."
        $WindowsLAPSGPO

        if (!$LinkToRootOfDomain) {
            Write-Host -Object "You may need to link it to your desired OU to finish the deploy."
        }

        if ($LinkToRootOfDomain) {
            try {
                Write-Host -Object "`nLinking the new GPO to the root of the domain."
                $DistinguishedName = (Get-ADDomain -ErrorAction Stop).DistinguishedName
                $WindowsLAPSGPO | Set-GPLink -Target $DistinguishedName -LinkEnabled "Yes" -ErrorAction Stop
            } catch {
                try {
                    $WindowsLAPSGPO | New-GPLink -Target $DistinguishedName -LinkEnabled "Yes" -ErrorAction Stop
                } catch {
                    Write-Host -Object "[Error] $($_.Exception.Message)"
                    Write-Host -Object "[Error] Failed to link the GPO. You may need to link it manually."
                    exit 1
                }
            }
        }

        exit $ExitCode
    }

    if ($WindowsLAPSGPO -and $Force) {
        Write-Host -Object "`nThe 'Windows LAPS' GPO is already present. Overwriting it is as requested."
    }

    try {
        Write-Host -Object "`nCreating the Group Policy file structure at '$WorkingDirectory\{0B7D4FF6-4728-4D4D-8A11-EE2ABC897AE6}'."
        if (!(Test-Path -Path "$WorkingDirectory\{0B7D4FF6-4728-4D4D-8A11-EE2ABC897AE6}" -PathType "Container" -ErrorAction SilentlyContinue)) {
            New-Item -Path "$WorkingDirectory\{0B7D4FF6-4728-4D4D-8A11-EE2ABC897AE6}" -ItemType "Directory" -ErrorAction Stop | Out-Null
            New-Item -Path "$WorkingDirectory\{0B7D4FF6-4728-4D4D-8A11-EE2ABC897AE6}\DomainSysvol" -ItemType "Directory" -ErrorAction Stop | Out-Null
            New-Item -Path "$WorkingDirectory\{0B7D4FF6-4728-4D4D-8A11-EE2ABC897AE6}\DomainSysvol\GPO" -ItemType "Directory" -ErrorAction Stop | Out-Null
            New-Item -Path "$WorkingDirectory\{0B7D4FF6-4728-4D4D-8A11-EE2ABC897AE6}\DomainSysvol\GPO\Machine" -ItemType "Directory" -ErrorAction Stop | Out-Null
            New-Item -Path "$WorkingDirectory\{0B7D4FF6-4728-4D4D-8A11-EE2ABC897AE6}\DomainSysvol\GPO\User" -ItemType "Directory" -ErrorAction Stop | Out-Null
            New-Item -Path "$WorkingDirectory\{0B7D4FF6-4728-4D4D-8A11-EE2ABC897AE6}\DomainSysvol\GPO\Machine\Scripts" -ItemType "Directory" -ErrorAction Stop | Out-Null
            New-Item -Path "$WorkingDirectory\{0B7D4FF6-4728-4D4D-8A11-EE2ABC897AE6}\DomainSysvol\GPO\Machine\Scripts\Shutdown" -ItemType "Directory" -ErrorAction Stop | Out-Null
            New-Item -Path "$WorkingDirectory\{0B7D4FF6-4728-4D4D-8A11-EE2ABC897AE6}\DomainSysvol\GPO\Machine\Scripts\Startup" -ItemType "Directory" -ErrorAction Stop | Out-Null
        }
        $Comment = @"
<?xml version='1.0' encoding='utf-8'?>
<policyComments xmlns:xsd="http://www.w3.org/2001/XMLSchema" xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance" revision="1.0" schemaVersion="1.0" xmlns="http://www.microsoft.com/GroupPolicy/CommentDefinitions">
  <policyNamespaces>
    <using prefix="ns0" namespace="Microsoft.Policies.LAPS"></using>
  </policyNamespaces>
  <comments>
    <admTemplate></admTemplate>
  </comments>
  <resources minRequiredRevision="1.0">
    <stringTable></stringTable>
  </resources>
</policyComments>
"@
        $Comment | Out-File -FilePath "$WorkingDirectory\{0B7D4FF6-4728-4D4D-8A11-EE2ABC897AE6}\DomainSysvol\GPO\Machine\comment.cmtx" -Encoding "UTF8" -ErrorAction Stop


    } catch {
        Write-Host -Object "[Error] $($_.Exception.Message)"
        Write-Host -Object "[Error] Failed to create the group policy backup at '$WorkingDirectory\{0B7D4FF6-4728-4D4D-8A11-EE2ABC897AE6}'."
        exit 1
    }

    try {
        $RegistryPOL = @"
Computer
SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\LAPS
PasswordComplexity
DWORD:4

Computer
SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\LAPS
PasswordLength
DWORD:$DesiredPassLength[System.Net.Dns]::GetHostEntry($env:COMPUTERNA

Computer
SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\LAPS
PasswordAgeDays
DWORD:$DesiredMaxPassAge

Computer
SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\LAPS
PasswordExpirationProtectionEnabled
DWORD:1

Computer
SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\LAPS
BackupDirectory
DWORD:2

Computer
SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\LAPS
AdministratorAccountName
SZ:$AccountToManage

Computer
SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\LAPS
ADPasswordEncryptionEnabled
DWORD:1

Computer
SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\LAPS
ADEncryptedPasswordHistorySize
DWORD:3
"@
        $RegistryPOL | Out-File -FilePath "$WorkingDirectory\{0B7D4FF6-4728-4D4D-8A11-EE2ABC897AE6}\DomainSysvol\GPO\Machine\registrypol.txt" -Encoding "UTF8" -ErrorAction Stop
    } catch {
        Write-Host -Object "[Error] $($_.Exception.Message)"
        Write-Host -Object "[Error] Failed to create registry.pol file at '$WorkingDirectory\{0B7D4FF6-4728-4D4D-8A11-EE2ABC897AE6}\DomainSysvol\GPO\Machine\registry.pol'."
        exit 1
    }

    try {
        Write-Host -Object "Downloading the Local Group Policy Object Utility from the Microsoft Security Compliance Toolkit."
        $LGPOUtility = Invoke-Download -URL $LGPOUrl -Path "$WorkingDirectory\LGPO.zip" -Overwrite -ErrorAction Stop

        Write-Host -Object "Extracting LGPO.zip to '$WorkingDirectory'"
        $PreviousProgressPreference = $ProgressPreference
        $ProgressPreference = 'SilentlyContinue'

        Expand-Archive -Path "$WorkingDirectory\LGPO.zip" -DestinationPath "$WorkingDirectory\LGPO" -Force -ErrorAction Stop
        $ProgressPreference = $PreviousProgressPreference
    } catch {
        $ProgressPreference = $PreviousProgressPreference
        Write-Host -Object "[Error] $($_.Exception.Message)"
        Write-Host -Object "[Error] Failed to download and extract the Local Group Policy Object Utility."
        exit 1
    }

    try {
        Remove-Item -Path "$WorkingDirectory\LGPO.zip" -Force -ErrorAction Stop
    } catch {
        Write-Host -Object "[Warning] $($_.Exception.Message)"
        Write-Host -Object "[Warning] Failed to remove '$WorkingDirectory\LGPO.zip'"
    }

    try {
        Write-Host -Object "Converting '$WorkingDirectory\{0B7D4FF6-4728-4D4D-8A11-EE2ABC897AE6}\DomainSysvol\GPO\Machine\registrypol.txt' to a .pol file."
        $LGPOArguments = @(
            "/r"
            "$WorkingDirectory\{0B7D4FF6-4728-4D4D-8A11-EE2ABC897AE6}\DomainSysvol\GPO\Machine\registrypol.txt"
            "/w"
            "$WorkingDirectory\{0B7D4FF6-4728-4D4D-8A11-EE2ABC897AE6}\DomainSysvol\GPO\Machine\registry.pol"
        )
        Invoke-LegacyCMDUtility -FilePath "$WorkingDirectory\LGPO\LGPO_30\LGPO.exe" -ArgumentList $LGPOArguments -ErrorAction SilentlyContinue

        if (!(Test-Path -Path "$WorkingDirectory\{0B7D4FF6-4728-4D4D-8A11-EE2ABC897AE6}\DomainSysvol\GPO\Machine\registry.pol" -ErrorAction SilentlyContinue)) {
            throw (New-Object System.IO.FileNotFoundException("'$WorkingDirectory\{0B7D4FF6-4728-4D4D-8A11-EE2ABC897AE6}\DomainSysvol\GPO\Machine\registrypol.pol' was not found."))
        }

        $RegistryPOLData = Get-Content -Path "$WorkingDirectory\{0B7D4FF6-4728-4D4D-8A11-EE2ABC897AE6}\DomainSysvol\GPO\Machine\registry.pol" -ErrorAction SilentlyContinue

        if ([string]::IsNullOrWhiteSpace(($RegistryPOLData | Out-String))) {
            throw (New-Object System.IO.IOException("'$WorkingDirectory\{0B7D4FF6-4728-4D4D-8A11-EE2ABC897AE6}\DomainSysvol\GPO\Machine\registrypol.txt' failed to convert."))
        }
    } catch {
        Write-Host -Object "[Error] $($_.Exception.Message)"
        Write-Host -Object "[Error] Failed to convert registrypol.txt to a registry.pol file."
        exit 1
    }

    if (Test-Path -Path "$WorkingDirectory\LGPO" -PathType "Container" -ErrorAction SilentlyContinue) {
        try {
            Remove-Item -Path "$WorkingDirectory\LGPO" -Recurse -Force -Confirm:$False -ErrorAction Stop
        } catch {
            Write-Host -Object "[Error] $($_.Exception.Message)"
            Write-Host -Object "[Error] Failed to remove '$WorkingDirectory\LGPO'."
            $ExitCode = 1
        }
    }

    try {
        Remove-Item -Path "$WorkingDirectory\{0B7D4FF6-4728-4D4D-8A11-EE2ABC897AE6}\DomainSysvol\GPO\Machine\registrypol.txt" -Force -ErrorAction Stop
    } catch {
        Write-Host -Object "[Warning] $($_.Exception.Message)"
        Write-Host -Object "[Warning] Failed to remove '$WorkingDirectory\{0B7D4FF6-4728-4D4D-8A11-EE2ABC897AE6}\DomainSysvol\GPO\Machine\registrypol.txt'"
    }

    try {
        Write-Host -Object "Creating Backup and Backup Info xml at '$WorkingDirectory\{0B7D4FF6-4728-4D4D-8A11-EE2ABC897AE6}'"
        $DomainSid = (Get-ADDomain -ErrorAction Stop).DomainSID.Value
        $NetBiosName = (Get-ADDomain -ErrorAction Stop).NetBIOSName
        $FQHostname = $([System.Net.Dns]::GetHostEntry($env:COMPUTERNAME).HostName)
        $DomainName = $(([System.DirectoryServices.ActiveDirectory.Domain]::GetCurrentDomain()).Name)

        if ([string]::IsNullOrWhiteSpace($DomainSID) -or [string]::IsNullOrWhiteSpace($NetBiosName) -or [string]::IsNullOrWhiteSpace($FQHostname) -or [string]::IsNullOrWhiteSpace($DomainName)) {
            throw (New-Object System.ArgumentNullException("Failed to fetch some of the required domain information."))
        }

        $BackupXML = @"
<?xml version="1.0" encoding="utf-8"?><!-- Copyright (c) Microsoft Corporation.  All rights reserved. --><GroupPolicyBackupScheme bkp:version="2.0" bkp:type="GroupPolicyBackupTemplate" xmlns:bkp="http://www.microsoft.com/GroupPolicy/GPOOperations" xmlns="http://www.microsoft.com/GroupPolicy/GPOOperations">
    <GroupPolicyObject><SecurityGroups><Group bkp:Source="FromDACL"><Sid><![CDATA[$DomainSid-519]]></Sid><SamAccountName><![CDATA[Enterprise Admins]]></SamAccountName><Type><![CDATA[UniversalGroup]]></Type><NetBIOSDomainName><![CDATA[$NetBiosName]]></NetBIOSDomainName><DnsDomainName><![CDATA[$DomainName]]></DnsDomainName><UPN><![CDATA[Enterprise Admins@$DomainName]]></UPN></Group><Group bkp:Source="FromDACL"><Sid><![CDATA[$DomainSid-512]]></Sid><SamAccountName><![CDATA[Domain Admins]]></SamAccountName><Type><![CDATA[GlobalGroup]]></Type><NetBIOSDomainName><![CDATA[$NetBiosName]]></NetBIOSDomainName><DnsDomainName><![CDATA[$DomainName]]></DnsDomainName><UPN><![CDATA[Domain Admins@$DomainName]]></UPN></Group></SecurityGroups><FilePaths/><GroupPolicyCoreSettings><ID><![CDATA[{7D34FF20-69C9-4D02-B681-1CBB956F3F25}]]></ID><Domain><![CDATA[$DomainName]]></Domain><SecurityDescriptor>01 00 04 9c 00 00 00 00 00 00 00 00 00 00 00 00 14 00 00 00 04 00 ec 00 08 00 00 00 05 02 28 00 00 01 00 00 01 00 00 00 8f fd ac ed b3 ff d1 11 b4 1d 00 a0 c9 68 f9 39 01 01 00 00 00 00 00 05 0b 00 00 00 00 00 24 00 ff 00 0f 00 01 05 00 00 00 00 00 05 15 00 00 00 7c 0d 70 3d 7e 37 fc fe f4 5b b0 83 00 02 00 00 00 02 24 00 ff 00 0f 00 01 05 00 00 00 00 00 05 15 00 00 00 7c 0d 70 3d 7e 37 fc fe f4 5b b0 83 00 02 00 00 00 02 24 00 ff 00 0f 00 01 05 00 00 00 00 00 05 15 00 00 00 7c 0d 70 3d 7e 37 fc fe f4 5b b0 83 07 02 00 00 00 02 14 00 94 00 02 00 01 01 00 00 00 00 00 05 09 00 00 00 00 02 14 00 94 00 02 00 01 01 00 00 00 00 00 05 0b 00 00 00 00 02 14 00 ff 00 0f 00 01 01 00 00 00 00 00 05 12 00 00 00 00 0a 14 00 ff 00 0f 00 01 01 00 00 00 00 00 03 00 00 00 00</SecurityDescriptor><DisplayName><![CDATA[Windows LAPS]]></DisplayName><Options><![CDATA[0]]></Options><UserVersionNumber><![CDATA[0]]></UserVersionNumber><MachineVersionNumber><![CDATA[393222]]></MachineVersionNumber><MachineExtensionGuids><![CDATA[[{35378EAC-683F-11D2-A89A-00C04FBBCFA2}{D02B1F72-3407-48AE-BA88-E8213C6761F1}]]]></MachineExtensionGuids><UserExtensionGuids/><WMIFilter/></GroupPolicyCoreSettings>
        <GroupPolicyExtension bkp:ID="{35378EAC-683F-11D2-A89A-00C04FBBCFA2}" bkp:DescName="Registry">
            <FSObjectFile bkp:Path="%GPO_MACH_FSPATH%\registry.pol" bkp:SourceExpandedPath="\\$FQHostname\sysvol\$DomainName\Policies\{7D34FF20-69C9-4D02-B681-1CBB956F3F25}\Machine\registry.pol" bkp:Location="DomainSysvol\GPO\Machine\registry.pol"/>

            <FSObjectFile bkp:Path="%GPO_FSPATH%\Adm\*.*" bkp:SourceExpandedPath="\\$FQHostname\sysvol\$DomainName\Policies\{7D34FF20-69C9-4D02-B681-1CBB956F3F25}\Adm\*.*"/>
        </GroupPolicyExtension>









    <GroupPolicyExtension bkp:ID="{F15C46CD-82A0-4C2D-A210-5D0D3182A418}" bkp:DescName="Unknown Extension"><FSObjectFile bkp:Path="%GPO_MACH_FSPATH%\comment.cmtx" bkp:SourceExpandedPath="\\$FQHostname\sysvol\$DomainName\Policies\{7D34FF20-69C9-4D02-B681-1CBB956F3F25}\Machine\comment.cmtx" bkp:Location="DomainSysvol\GPO\Machine\comment.cmtx"/><FSObjectDir bkp:Path="%GPO_MACH_FSPATH%\Scripts" bkp:SourceExpandedPath="\\$FQHostname\sysvol\$DomainName\Policies\{7D34FF20-69C9-4D02-B681-1CBB956F3F25}\Machine\Scripts" bkp:Location="DomainSysvol\GPO\Machine\Scripts"/><FSObjectDir bkp:Path="%GPO_MACH_FSPATH%\Scripts\Shutdown" bkp:SourceExpandedPath="\\$FQHostname\sysvol\$DomainName\Policies\{7D34FF20-69C9-4D02-B681-1CBB956F3F25}\Machine\Scripts\Shutdown" bkp:Location="DomainSysvol\GPO\Machine\Scripts\Shutdown"/><FSObjectDir bkp:Path="%GPO_MACH_FSPATH%\Scripts\Startup" bkp:SourceExpandedPath="\\$FQHostname\sysvol\$DomainName\Policies\{7D34FF20-69C9-4D02-B681-1CBB956F3F25}\Machine\Scripts\Startup" bkp:Location="DomainSysvol\GPO\Machine\Scripts\Startup"/></GroupPolicyExtension></GroupPolicyObject>
</GroupPolicyBackupScheme>
"@
        $BackupXML | Out-File "$WorkingDirectory\{0B7D4FF6-4728-4D4D-8A11-EE2ABC897AE6}\Backup.xml" -Encoding "UTF8" -ErrorAction Stop

        $LastWriteTime = Get-ItemProperty -Path "$WorkingDirectory\{0B7D4FF6-4728-4D4D-8A11-EE2ABC897AE6}\Backup.xml" -ErrorAction Stop | Select-Object -ExpandProperty "LastWriteTime" -ErrorAction Stop

        $BackupInfoXML = @"
<BackupInst xmlns="http://www.microsoft.com/GroupPolicy/GPOOperations/Manifest"><GPOGuid><![CDATA[{7D34FF20-69C9-4D02-B681-1CBB956F3F25}]]></GPOGuid><GPODomain><![CDATA[$DomainName]]></GPODomain><GPODomainGuid><![CDATA[{2061ae04-eed7-43ea-a262-bf9bf9fe1e89}]]></GPODomainGuid><GPODomainController><![CDATA[$FQHostname]]></GPODomainController><BackupTime><![CDATA[$($LastWriteTime.ToUniversalTime().ToString("yyyy-MM-ddTHH:mm:ss"))]]></BackupTime><ID><![CDATA[{0B7D4FF6-4728-4D4D-8A11-EE2ABC897AE6}]]></ID><Comment><![CDATA[]]></Comment><GPODisplayName><![CDATA[Windows LAPS]]></GPODisplayName></BackupInst>
"@
        $BackupInfoXML | Out-File "$WorkingDirectory\{0B7D4FF6-4728-4D4D-8A11-EE2ABC897AE6}\bkupInfo.xml" -Encoding "UTF8" -ErrorAction Stop
        Set-ItemProperty -Path "$WorkingDirectory\{0B7D4FF6-4728-4D4D-8A11-EE2ABC897AE6}\bkupInfo.xml" -Name "Attributes" -Value ([System.IO.FileAttributes]::Hidden) -ErrorAction Stop
    } catch {
        Write-Host -Object "[Error] $($_.Exception.Message)"
        Write-Host -Object "[Error] Failed to create the backup xml."
        exit 1
    }

    try {
        Write-Host -Object "Attempting to import the new GPO."
        $NewGPO = Import-GPO -Path "$WorkingDirectory" -BackupGPOName "Windows LAPS" -TargetName "Windows LAPS" -CreateIfNeeded -ErrorAction Stop
        $NewGPO
        Write-Host -Object "The Windows LAPS GPO object has been imported."
    } catch {
        Write-Host -Object "[Error] $($_.Exception.Message)"
        Write-Host -Object "[Error] Failed to import the gpo."
        exit 1
    }

    if (Test-Path -Path "$WorkingDirectory\{0B7D4FF6-4728-4D4D-8A11-EE2ABC897AE6}" -PathType "Container" -ErrorAction SilentlyContinue) {
        try {
            Remove-Item -Path "$WorkingDirectory\{0B7D4FF6-4728-4D4D-8A11-EE2ABC897AE6}" -Recurse -Force -Confirm:$False -ErrorAction Stop
        } catch {
            Write-Host -Object "[Error] $($_.Exception.Message)"
            Write-Host -Object "[Error] Failed to remove '$WorkingDirectory\{0B7D4FF6-4728-4D4D-8A11-EE2ABC897AE6}'."
            $ExitCode = 1
        }
    }

    if (Test-Path -Path "$WorkingDirectory\manifest.xml" -PathType "Leaf" -ErrorAction SilentlyContinue) {
        try {
            Remove-Item -Path "$WorkingDirectory\manifest.xml" -Force -Confirm:$False -ErrorAction Stop
        } catch {
            Write-Host -Object "[Error] $($_.Exception.Message)"
            Write-Host -Object "[Error] Failed to remove '$WorkingDirectory\manifest.xml'."
            $ExitCode = 1
        }
    }

    if (!$LinkToRootOfDomain) {
        Write-Host -Object "`nThe GPO object has been imported. Please link it to your desired OU to finish the deploy."
    }

    if ($LinkToRootOfDomain) {
        try {
            Write-Host -Object "`nLinking the new GPO to the root of the domain."
            $DistinguishedName = (Get-ADDomain -ErrorAction Stop).DistinguishedName
            $NewGPO | Set-GPLink -Target $DistinguishedName -LinkEnabled "Yes" -ErrorAction Stop
            Write-Host -Object "Successfully linked the new GPO."
        } catch {
            try {
                $NewGPO | New-GPLink -Target $DistinguishedName -LinkEnabled "Yes" -ErrorAction Stop
            } catch {
                Write-Host -Object "[Error] $($_.Exception.Message)"
                Write-Host -Object "[Error] Failed to link the GPO. You may need to link it manually."
                exit 1
            }
        }
    }

    exit $ExitCode
}