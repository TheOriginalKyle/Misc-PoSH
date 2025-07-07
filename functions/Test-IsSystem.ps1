function Test-IsSystem {
    [CmdletBinding()]
    param ()

    # Retrieve the current Windows identity of the user or process running the script
    $WindowsIdentity = [System.Security.Principal.WindowsIdentity]::GetCurrent()

    # Check if the identity is a system account by verifying the IsSystem property
    # or comparing the User property to the well-known SID for the LocalSystem account (S-1-5-18)
    $WindowsIdentity.IsSystem -or $WindowsIdentity.User -eq "S-1-5-18"
}