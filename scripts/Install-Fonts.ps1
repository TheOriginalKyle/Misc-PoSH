param ($DLURL, $zipName)

# Setting Working Directory and where the download will be
$WorkingDir = "C:\Working\Fonts"

# Create Working Directory if it does not exist
if (!(Test-Path -Path $WorkingDir)) {
    New-Item -ItemType "Directory" $WorkingDir | Out-Null
}

# Download Zip File
Start-BitsTransfer $DLURL ($WorkingDir + "\" + $zipName)

# Check if failed
if (!(Test-Path -Path ($WorkingDir + "\" + $zipName))) {
    Write-Host "Download has failed"
    Exit
}

# Extract the zip file
Expand-Archive -LiteralPath ($WorkingDir + "\" + $zipName) -DestinationPath $WorkingDir

$fontList = Get-ChildItem ($WorkingDir + "\*") -Include *.otf, *.ttf

foreach ($font in $fontList) {
    $oShell = New-Object -com shell.application
    $Folder = $oShell.namespace($font.DirectoryName)
    $Item = $Folder.Items().Item($font.Name)
    $FontName = $Folder.GetDetailsOf($Item, 21)

    try {
        switch ($font.Extension) {
            ".ttf" { $FontName = $FontName + [char]32 + '(TrueType)' }
            ".otf" { $FontName = $FontName + [char]32 + '(OpenType)' }
        }
        $Copy = $true
        Write-Host ('Copying' + [char]32 + $font.Name + '.....') -NoNewline
        Copy-Item -Path $font.FullName -Destination ("C:\Windows\Fonts\" + $font.Name) -Force
        #Test if font is copied over
        If ((Test-Path ("C:\Windows\Fonts\" + $font.Name)) -eq $true) {
            Write-Host ('Success')
        } else {
            Write-Host ('Failed')
        }
        $Copy = $false
        #Test if font registry entry exists
        If ($null -ne (Get-ItemProperty -Name $FontName -Path "HKLM:\Software\Microsoft\Windows NT\CurrentVersion\Fonts" -ErrorAction SilentlyContinue)) {
            #Test if the entry matches the font file name
            If ((Get-ItemPropertyValue -Name $FontName -Path "HKLM:\Software\Microsoft\Windows NT\CurrentVersion\Fonts") -eq $font.Name) {
                Write-Host ('Adding' + [char]32 + $FontName + [char]32 + 'to the registry.....') -NoNewline
                Write-Host ('Success')
            } else {
                $AddKey = $true
                Remove-ItemProperty -Name $FontName -Path "HKLM:\Software\Microsoft\Windows NT\CurrentVersion\Fonts" -Force
                Write-Host ('Adding' + [char]32 + $FontName + [char]32 + 'to the registry.....') -NoNewline
                New-ItemProperty -Name $FontName -Path "HKLM:\Software\Microsoft\Windows NT\CurrentVersion\Fonts" -PropertyType string -Value $font.Name -Force -ErrorAction SilentlyContinue | Out-Null
                If ((Get-ItemPropertyValue -Name $FontName -Path "HKLM:\Software\Microsoft\Windows NT\CurrentVersion\Fonts") -eq $font.Name) {
                    Write-Host ('Success')
                } else {
                    Write-Host ('Failed')
                }
                $AddKey = $false
            }
        } else {
            $AddKey = $true
            Write-Host ('Adding' + [char]32 + $FontName + [char]32 + 'to the registry.....') -NoNewline
            New-ItemProperty -Name $FontName -Path "HKLM:\Software\Microsoft\Windows NT\CurrentVersion\Fonts" -PropertyType string -Value $font.Name -Force -ErrorAction SilentlyContinue | Out-Null
            If ((Get-ItemPropertyValue -Name $FontName -Path "HKLM:\Software\Microsoft\Windows NT\CurrentVersion\Fonts") -eq $font.Name) {
                Write-Host ('Success')
            } else {
                Write-Host ('Failed')
            }
            $AddKey = $false
        }

    } catch {
        If ($Copy -eq $true) {
            Write-Host ('Failed')
            $Copy = $false
        }
        If ($AddKey -eq $true) {
            Write-Host ('Failed')
            $AddKey = $false
        }
        Write-Warning $_.exception.message
    }
}

Get-ChildItem ($WorkingDir + "\*") | Remove-Item