BeforeAll {
    # Get script path
    $Path = ".\functions\$($PSCommandPath | Split-Path -Leaf)" -replace '.tests.', '.'
    # Test that the script exists
    Test-Path -Path $Path | Should -BeTrue -Because "Script file should exist!"

    Mock Write-Host { $Object | ForEach-Object { Write-Verbose -Message $_ } }
    Mock Start-Sleep

    . $Path
}
AfterAll {
    if (Test-Path -Path "$env:TEMP\DownloadTest" -ErrorAction SilentlyContinue) {
        Remove-Item -Path "$env:TEMP\DownloadTest" -Recurse -Confirm:$False -Force
    }
}
Describe "$(($PSCommandPath | Split-Path -Leaf) -Replace '.tests.', '.')" {
    Context "Under ideal conditions and using default values" {
        It "Should Not Throw Error" {

            { . $Path } | Should -Not -Throw
            { Invoke-Download -URL "https://www.google.com/favicon.ico" -Path "$env:TEMP\DownloadTest\favicon.ico" } | Should -Not -Throw

            Should -Not -Invoke Write-Host -ParameterFilter { $Object -match "Error" }
        }
    }
    Context "Validation" {
        BeforeEach {
            if (Test-Path -Path "$env:TEMP\DownloadTest" -ErrorAction SilentlyContinue) {
                Remove-Item -Path "$env:TEMP\DownloadTest" -Recurse -Confirm:$False -Force
            }
        }
        It "Should throw error for filepaths that look like '<TestFilePath>'" -TestCases @(
            @{ TestFilePath = "$env:TEMP\DownloadTest\CON\favicon.ico" }
            @{ TestFilePath = "$env:TEMP\DownloadTest\some:File\favicon.ico" }
            @{ TestFilePath = "$env:TEMP\DownloadTest\some?File\favicon.ico" }
            @{ TestFilePath = "$env:TEMP\DownloadTest\some`"File\favicon.ico" }
            @{ TestFilePath = "$env:TEMP\DownloadTest\some<File\favicon.ico" }
            @{ TestFilePath = "$env:TEMP\DownloadTest\some>File\favicon.ico" }
            @{ TestFilePath = "$env:TEMP\DownloadTest\some|File\favicon.ico" }
            @{ TestFilePath = $Null }
            @{ TestFilePath = "$env:TEMP\DownloadTest\someFolder" }
        ) {

            { . $Path } | Should -Not -Throw
            { Invoke-Download -URL "https://www.google.com/favicon.ico" -Path $TestFilePath } | Should -Throw

            Should -Not -Invoke Write-Host -ParameterFilter { $Object -match "Error" }
        }
        It "Should throw error if given the invalid attempts '<InvalidAttempts>'" -TestCases @(
            @{ InvalidAttempts = 0 }
            @{ InvalidAttempts = -1 }
        ) {
            { . $Path } | Should -Not -Throw
            { Invoke-Download -URL "https://www.google.com/favicon.ico" -Path "$env:TEMP\DownloadTest\favicon.ico" -Attempts $InvalidAttempts } | Should -Throw

            Should -Not -Invoke Write-Host -ParameterFilter { $Object -match "Error" }
        }
        It "Should error if given the path to a file that already exists" {
            { . $Path } | Should -Not -Throw
            { Invoke-Download -URL "https://www.google.com/favicon.ico" -Path "$env:TEMP\DownloadTest\favicon.ico" } | Should -Not -Throw
            { Invoke-Download -URL "https://www.google.com/favicon.ico" -Path "$env:TEMP\DownloadTest\favicon.ico" } | Should -Throw

            Should -Not -Invoke Write-Host -ParameterFilter { $Object -match "Error" }
        }
    }
    Context "Action" {
        BeforeEach {
            if (Test-Path -Path "$env:TEMP\DownloadTest" -ErrorAction SilentlyContinue) {
                Remove-Item -Path "$env:TEMP\DownloadTest" -Recurse -Confirm:$False -Force
            }
        }
        It "Should switch to TLS1.2 and TLS1.3" {

            { . $Path } | Should -Not -Throw
            { Invoke-Download -URL "https://www.google.com/favicon.ico" -Path "$env:TEMP\DownloadTest\favicon.ico" } | Should -Not -Throw

            Should -Not -Invoke Write-Host -ParameterFilter { $Object -match "Error" }

            [Net.ServicePointManager]::SecurityProtocol | Should -match "Tls12"
            [Net.ServicePointManager]::SecurityProtocol | Should -match "Tls13"
        }
        It "Should create the destination folder if it does not exist" {

            { . $Path } | Should -Not -Throw
            { Invoke-Download -URL "https://www.google.com/favicon.ico" -Path "$env:TEMP\DownloadTest\favicon.ico" } | Should -Not -Throw

            Should -Not -Invoke Write-Host -ParameterFilter { $Object -match "Error" }

            Test-Path -Path "$env:TEMP\DownloadTest" -ErrorAction SilentlyContinue | Should -BeTrue
        }
        It "Should download the file '<TestFile>' when provided '<TestURL>'" -TestCases @(
            @{ TestFile = "$env:TEMP\DownloadTest\favicon.ico" ; TestURL = "https://www.google.com/favicon.ico" }
            @{ TestFile = "$env:TEMP\DownloadTest\favicon.ico" ; TestURL = "www.google.com/favicon.ico" }
            @{ TestFile = "C:\favicon.ico" ; TestURL = "https://www.google.com/favicon.ico" }
            @{ TestFile = "$env:TEMP\DownloadTest\Windows11InstallationAssistant.exe" ; TestURL = "https://go.microsoft.com/fwlink/?linkid=2171764" }
        ){

            { . $Path } | Should -Not -Throw
            { Invoke-Download -URL $TestURL -Path $TestFile } | Should -Not -Throw

            Should -Not -Invoke Write-Host -ParameterFilter { $Object -match "Error" }

            Test-Path -Path $TestFile -ErrorAction SilentlyContinue | Should -BeTrue

            if (Test-Path -Path $TestFile -ErrorAction SilentlyContinue){
                Remove-Item -Path $TestFile -Confirm:$False -Force
            }
        }
        It "Should output the Get-Item of the resulting file" {

            { . $Path } | Should -Not -Throw
            { Invoke-Download -URL "https://www.google.com/favicon.ico" -Path "$env:TEMP\DownloadTest\favicon.ico" } | Should -Not -Throw
            $DownloadedFile = Get-Item -Path "$env:TEMP\DownloadTest\favicon.ico"
            Invoke-Download -URL "https://www.google.com/favicon.ico" -Path "$env:TEMP\DownloadTest\favicon.ico" -Overwrite | Select-Object -ExpandProperty FullName | Should -Be $DownloadedFile.FullName

            Should -Not -Invoke Write-Host -ParameterFilter { $Object -match "Error" }
        }
    }
}