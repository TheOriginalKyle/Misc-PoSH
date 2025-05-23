<#
   .SYNOPSIS
   This script will remove all sharepoint sites from the windows search index
   .DESCRIPTION
   This script will remove all sharepoint sites from the windows search index by checking this registry key for the file path's HKU:\$($_.SID)\SOFTWARE\Microsoft\OneDrive\Accounts\*\Tenants\* and then adding that path to this key HKLM:\SOFTWARE\Microsoft\Windows Search\CurrentPolicies\PreventIndexingCertainPaths
   .LINK
   https://docs.microsoft.com/en-us/previous-versions/windows/it-pro/windows-server-2008-R2-and-2008/cc732491(v=ws.10)?redirectedfrom=MSDN#windows-search-policy-registry-location
#>
[CmdletBinding()]
param()
# Regex pattern for SIDs
#!PS
$PatternSID = 'S-1-5-((32-\d*)|(21-\d*-\d*-\d*-\d*))'

New-PSDrive -PSProvider Registry -Name HKU -Root HKEY_USERS | Out-Null
# Get Username, SID, and location of ntuser.dat for all users
$ProfileList = Get-ItemProperty 'HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\ProfileList\*' |
    Where-Object { $_.PSChildName -match $PatternSID } | Select-Object @{name = "SID"; expression = { $_.PSChildName } },
    @{name = "UserHive"; expression = { "$($_.ProfileImagePath)\ntuser.dat" } },
    @{name = "Username"; expression = { $_.ProfileImagePath -replace '^(.*[\\\/])', '' } }

# Get all user SIDs found in HKEY_USERS (ntuder.dat files that are loaded)
$LoadedHives = Get-ChildItem Registry::HKEY_USERS | Where-Object { $_.PSChildname -match $PatternSID } |
    Select-Object @{name = "SID"; expression = { $_.PSChildName } }

$UnloadedHives = Compare-Object -ReferenceObject @($LoadedHives | Select-Object) -DifferenceObject @($ProfileList | Select-Object) | Select-Object @{name = "SID"; expression = { $_.InputObject } }, UserHive, Username

$ProfileList | ForEach-Object {
    if ($_.SID -in $UnloadedHives.SID) {
        reg load HKU\$($_.SID) $($_.UserHive) | Out-Null
    }

    if (Test-Path -Path "HKU:\$($_.SID)\SOFTWARE\Microsoft\OneDrive\Accounts") {
        # This will scan HKEY_USERS for all SharePoint Directories used by the OneDrive client and save it as a list for later use.

        $dirList = $dirList + (Get-ChildItem "HKU:\$($_.SID)\SOFTWARE\Microsoft\OneDrive\Accounts\*\Tenants\*" |
                Select-Object -Unique Property -ExpandProperty Property | Where-Object Property -NotLike "*OneDrive*" )
        }


        # Unload ntuser.dat
        if ($_.SID -in $UnloadedHives.SID) {
            ### Garbage collection and closing of ntuser.dat ###
            [gc]::Collect()
            reg unload HKU\$($_.SID) | Out-Null
        }

        # Removing any duplicates
        $dirList = $dirList | Sort-Object -Unique
    }

    # This is the registry path used by the Windows Search GPO see the below link for more info.
    # https://docs.microsoft.com/en-us/previous-versions/windows/it-pro/windows-server-2008-R2-and-2008/cc732491(v=ws.10)?redirectedfrom=MSDN#windows-search-policy-registry-location
    # Computer Config > Admin Templates > Windows Components > Search
    $registryPath = "HKLM:\SOFTWARE\Microsoft\Windows Search\CurrentPolicies\PreventIndexingCertainPaths"

    ### Check if registry path is already present and create it if it doesn't.
    if (!(Test-Path $registryPath)) {
        New-Item -Path $registryPath -Force | Out-Null
    }

    # Time to add the exclusions! This will go through each item of the list and add an exclusion if one hasn't already been added.
    $dirList | ForEach-Object {
        ### Check if registry key is already present and if not create it.
        $Check_Key_Present = (Get-ItemProperty $registryPath).$_
        if ($Check_Key_Present -eq "$_") {
            Write-Host "Success $_ Already Set"
        } else {
            New-ItemProperty -Path $registryPath -Name $_ -Value $_ -PropertyType String -Force | Out-Null
        }

        ### Verify Key Correct, if not add a failure message.
        $Verify_Key_Value = (Get-ItemProperty $registryPath).$_
        if ($Verify_Key_Value -eq "$_") {
            Write-Host "Success $_ Excluded from index!"
        } else {
            Write-Error "Failure $_ Not Set"
        }
    }
