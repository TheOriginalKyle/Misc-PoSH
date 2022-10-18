<#
   .SYNOPSIS
   This script will enable outlook signatures and attempt to restore archived ones for all users
   .DESCRIPTION
   This script will enable outlook signatures by setting this regkey HKU:\*\SOFTWARE\Microsoft\Office\16.0\Common\MailSettings\DisableSignatures and attempt to restore .old'd signature folders
   .LINK
   https://www.codetwo.com/kb/disable-outlook-signatures-with-intune/
#>
[CmdletBinding()]
param()

# This will check for archived signatures in all the user directories
$archivedSignatures = Get-Item C:\Users\*\AppData\Roaming\Microsoft\Signatures.old
$archivedSignatures | ForEach-Object {
    if ($archivedSignatures) {
        Write-Verbose "Archived signatures folder found checking if empty..."
        # The for each will give me each signature folder individually fullname is the full path and the name is just the name
        $signatureFiles = Get-ChildItem $_
        if ($signatureFiles) {
            Write-Verbose "Not empty, attempting to restore..."

            # The folder is named the same minus the .old so I just trim that off the end for the destination path
            $destination = ($_.FullName).SubString(0, $($_.FullName).Length - 4)

            # Outlook should create this folder automagically but it does this when it needs it not immediately
            if (!(test-path -Path $destination)) { 
                New-Item -Path $destination -ItemType Directory | Out-Null
            }
            try {
                # Moving the signature files this way should preserve the directory structure
                $archive = $_.FullName
                Move-Item $archive\* -Destination $destination
                Write-Output "Successfully restored signatures in $($_.FullName)"
                if(!(Test-Path $archive\*)){
                    Remove-Item -Path $archive
                    Write-Output "Removed archive in $($_.FullName)"
                }
            }
            catch {
                Write-Error "[Error] Unable to move archived signatures in $($_.FullName)"
            }
        }
        else {
            Write-Verbose "Archive Folder is empty moving on..."
        }     
    }
    else {
        Write-Verbose "No Archive Signature's detected"
    }
}

# This will attempt to unblock the signature for all users
try {
    # Regex pattern for SIDs
    $PatternSID = 'S-1-5-((32-\d*)|(21-\d*-\d*-\d*-\d*))'
        
    New-PSDrive -PSProvider Registry -Name HKU -Root HKEY_USERS | Out-Null
    # Get Username, SID, and location of ntuser.dat for all users
    $ProfileList = Get-ItemProperty 'HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\ProfileList\*' | 
    Where-Object { $_.PSChildName -match $PatternSID } | 
    Select-Object  @{name = "SID"; expression = { $_.PSChildName } }, 
    @{name = "UserHive"; expression = { "$($_.ProfileImagePath)\ntuser.dat" } }, 
    @{name = "Username"; expression = { $_.ProfileImagePath -replace '^(.*[\\\/])', '' } }
      
    # Get all user SIDs found in HKEY_USERS (ntuder.dat files that are loaded)
    $LoadedHives = Get-ChildItem Registry::HKEY_USERS | Where-Object { $_.PSChildname -match $PatternSID } |
    Select-Object @{name = "SID"; expression = { $_.PSChildName } }
      
    # Get all users that are not currently logged
    $UnloadedHives = Compare-Object -ReferenceObject @($LoadedHives | Select-Object) -DifferenceObject @($ProfileList | Select-Object) | Select-Object @{name = "SID"; expression = { $_.InputObject } }, UserHive, Username
     
    $ProfileList | ForEach-Object {
        if ($_.SID -in $UnloadedHives.SID) {
            reg load HKU\$($_.SID) $($_.UserHive) | Out-Null
        }

        try {
            # Create mail settings if it does not exist
            if (!(Test-Path "HKU:\$($_.SID)\SOFTWARE\Microsoft\Office\16.0\Common\MailSettings")) {
                New-Item -Path "HKU:\$($_.SID)\SOFTWARE\Microsoft\Office\16.0\Common\MailSettings" -Force -EA Stop | Out-Null
            }
        }catch {
            Write-Error "[Error] Unable to set regkey for $($_.Username)"
        }
        

        # Disable Outlook Signatures
        try{
            New-ItemProperty -Path "HKU:\$($_.SID)\SOFTWARE\Microsoft\Office\16.0\Common\MailSettings" -Name "DisableSignatures" -Value "0" -Type DWORD -Force -EA Stop | Out-Null
            Write-Output "Signature unblocked for $($_.Username)"
        }catch{
            Write-Error "Cannot unblock signature for $($_.Username)"
        }
        
        
           
        # Unload ntuser.dat        
        if ($_.SID -in $UnloadedHives.SID) {
            ### Garbage collection and closing of ntuser.dat ###
            [gc]::Collect()
            reg unload HKU\$($_.SID) | Out-Null
        }
    }
}
catch {
    Write-Error "[Error] Unable to unblock signatures!"
}