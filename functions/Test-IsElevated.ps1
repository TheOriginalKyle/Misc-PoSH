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

<#
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
#>