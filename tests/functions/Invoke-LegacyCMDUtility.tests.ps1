BeforeAll {
    # Get script path
    $Path = ".\functions\$($PSCommandPath | Split-Path -Leaf)" -replace '.tests.', '.'
    # Test that the script exists
    Test-Path -Path $Path | Should -BeTrue -Because "Script file should exist!"

    Mock Write-Host { $Object | ForEach-Object { Write-Verbose -Message $_ } }

    . $Path
}
Describe "$(($PSCommandPath | Split-Path -Leaf) -Replace '.tests.', '.')" {
    Context "Under ideal conditions and using default values" {
        It "Should Not Throw Error" {

            { . $Path } | Should -Not -Throw
            { Invoke-LegacyCMDUtility -FilePath "$env:WINDIR\System32\quser.exe" } | Should -Not -Throw

            Should -Not -Invoke Write-Host -ParameterFilter { $Object -match "Error" }
        }
    }
    Context "Validation" {
        It "Should throw an error for the file path '<TestFilePath>'" -TestCases @(
            @{ TestFilePath = $Null }
            @{ TestFilePath = " " }
            @{ TestFilePath = $env:ProgramData }
            @{ TestFilePath = "C:\Some|Folder\file.exe" }
            @{ TestFilePath = "C:\Some:Folder\file.exe" }
            @{ TestFilePath = "C:\Some*Folder\file.exe" }
            @{ TestFilePath = "C:\Some?Folder\file.exe" }
            @{ TestFilePath = "C:\Some`"Folder\file.exe" }
            @{ TestFilePath = "C:\Some<Folder\file.exe" }
            @{ TestFilePath = "C:\Some>Folder\file.exe" }
            @{ TestFilePath = "C:\ThisFolderDoesNotExist\file.exe" }
            @{ TestFilePath = "C:\CON\impossiblefile.exe" }
        ) {

            { . $Path } | Should -Not -Throw
            { Invoke-LegacyCMDUtility -FilePath $TestFilePath } | Should -Throw

            Should -Not -Invoke Write-Host -ParameterFilter { $Object -match "Error" }
        }
        It "Should throw an error for the timeout '<TestTimeout>'" -TestCases @(
            @{ TestTimeout = "0" }
            @{ TestTimeout = "-5" }
            @{ TestTimeout = " " }
            @{ TestTimeout = $null }
            @{ TestTimeout = "a" }
            @{ TestTimeout = "1 0" }
            @{ TestTimeout = "29" }
        ) {

            { . $Path } | Should -Not -Throw
            { Invoke-LegacyCMDUtility -FilePath "$env:WINDIR\System32\quser.exe" -Timeout $TestTimeout } | Should -Throw

            Should -Not -Invoke Write-Host -ParameterFilter { $Object -match "Error" }
        }
    }
    Context "Action" {
        It "Should be able to execute <testProgram>" -TestCases @(
            @{ testProgram = "gpupdate" }
            @{ testProgram = "quser" }
        ) {

            { . $Path } | Should -Not -Throw
            { Invoke-LegacyCMDUtility -FilePath $testProgram } | Should -Not -Throw

            Should -Not -Invoke Write-Host -ParameterFilter { $Object -match "Error" }
        }
        It "Should accept arguments" {

            { . $Path } | Should -Not -Throw
            { Invoke-LegacyCMDUtility -FilePath "gpresult" -ArgumentList ("/H", "$env:TEMP\gpreport.html") } | Should -Not -Throw

            Should -Not -Invoke Write-Host -ParameterFilter { $Object -match "Error" }

            Test-Path -Path "$env:TEMP\gpreport.html" -ErrorAction SilentlyContinue | Should -BeTrue

            if (Test-Path -Path "$env:TEMP\gpreport.html" -ErrorAction SilentlyContinue){
                Remove-Item -Path "$env:TEMP\gpreport.html" -Force -Confirm:$False
            }
        }
    }
}