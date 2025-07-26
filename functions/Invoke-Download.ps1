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