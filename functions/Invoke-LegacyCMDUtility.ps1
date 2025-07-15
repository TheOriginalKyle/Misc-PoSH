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
