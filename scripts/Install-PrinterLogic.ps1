param ($AuthCode, $PL_HOME_URL)

$MSI_Name = "PrinterInstallerClient.msi"
$WorkingDir = "C:\Working\PrinterLogic"
$DL_URL = $PL_HOME_URL + "/client/setup/" + $MSI_Name
$MSI_Location = $WorkingDir + "\" + $MSI_Name
$MSI_Log = $MSI_Location + "_install.log"
$MSI_Arguments = @(
    "/i"
    $MSI_Location
    ("/qn HOMEURL=" + $PL_HOME_URL)
    ("AUTHORIZATION_CODE=" + $AuthCode)
    ("/l*v " + $MSI_Log)
)
$SoftwareName = "Printer Installer Client"

if (!(Test-Path -Path $WorkingDir)) {
    New-Item -ItemType directory -Path $WorkingDir | Out-Null
}

Start-BitsTransfer $DL_URL $MSI_Location

if (!(Test-Path -Path $MSI_Location)) {
    Write-Host "Download has failed"
}

Start-Process msiexec.exe -Wait -ArgumentList $MSI_Arguments

if (!(Get-CimInstance Win32_Product | Where-Object Name -EQ $SoftwareName)) {
    Write-Host "Install Failed"
} else {
    Remove-Item $MSI_Log | Out-Null
    Remove-Item $MSI_Location | Out-Null
    Remove-Item $WorkingDir | Out-Null
}