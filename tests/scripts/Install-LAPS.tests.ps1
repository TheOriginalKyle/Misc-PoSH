BeforeAll {
    # Get script path
    $Path = ".\scripts\$($PSCommandPath | Split-Path -Leaf)" -Replace '.tests.', '.'
    # Test that the script exists
    Test-Path -Path $Path | Should -BeTrue -Because "Script file should exist!"

    <#
    if ((Get-Command my.exe -ErrorAction SilentlyContinue).Count -eq 0) {
        function my.exe () {}
    }
    if ((Get-Command Get-MyFunction -ErrorAction SilentlyContinue).Count -eq 0) {
        function Get-MyFunction () {}
    }

    Mock My.exe {}
    Mock Get-MyFunction {}
    #>

    Mock Get-CimInstance {
        [PSCustomObject]@{
            ProductType = 2
        }
    } -ParameterFilter { $ClassName -match "Win32_OperatingSystem" }

    if ((Get-Command Get-ADDomain -ErrorAction SilentlyContinue).Count -eq 0) {
        function Get-ADDomain () {}
    }

    if ((Get-Command Get-ADDefaultDomainPasswordPolicy -ErrorAction SilentlyContinue).Count -eq 0) {
        function Get-ADDefaultDomainPasswordPolicy () {}
    }

    Mock Get-ADDefaultDomainPasswordPolicy {
        [PSCustomObject]@{
            MaxPasswordAge = New-TimeSpan -Days 42
            MinPasswordLength = 7
        }
    }

    Mock Write-Host { $Object | ForEach-Object { Write-Verbose -Message $_ } }
}
Describe "$(($PSCommandPath | Split-Path -Leaf) -Replace '.tests.', '.')" {
    Context "Input and Environment Validation" {
        It "Should error when not running on a server" {
            Mock Get-CimInstance {
                [PSCustomObject]@{
                    ProductType = 1
                }
            } -ParameterFilter { $ClassName -match "Win32_OperatingSystem" }

            { . $Path -AccountToManage "myAdmin" } | Should -Not -Throw

            Should -Invoke Write-Host -ParameterFilter { $Object -match "Error" -and $Object -match "controller" }

            $LASTEXITCODE | Should -Be 1
        }
        It "Should error when the domain functional level is less than 2016" {
            Mock Get-ADDomain {
                [PSCustomObject]@{
                    DomainMode = "Windows2012Domain"
                }
            }

            { . $Path -AccountToManage "myAdmin" } | Should -Not -Throw

            Should -Invoke Write-Host -ParameterFilter { $Object -match "Error" -and $Object -match "level" }

            $LASTEXITCODE | Should -Be 1
        }
        It "Should error when given the account '<TestAccount>'" -TestCases @(
            @{ TestAccount = $Null }
            @{ TestAccount = "" }
            @{ TestAccount = " " }
            @{ TestAccount = "jsmi\th" }
            @{ TestAccount = "jsmi/th" }
            @{ TestAccount = "jsmi[th" }
            @{ TestAccount = "jsmi]th" }
            @{ TestAccount = "jsmi:th" }
            @{ TestAccount = "jsmi;th" }
            @{ TestAccount = "jsmi*th" }
            @{ TestAccount = "jsmi?th" }
            @{ TestAccount = "jsmi`"th" }
            @{ TestAccount = "jsmi<th" }
            @{ TestAccount = "jsmi>th" }
            @{ TestAccount = "jsmi|th" }
            @{ TestAccount = "jsmi,th" }
            @{ TestAccount = "jsmi+th" }
            @{ TestAccount = "jsmi@th" }
            @{ TestAccount = "thisisareallylongacct" }
        ){

            { . $Path -AccountToManage $TestAccount } | Should -Not -Throw

            Should -Invoke Write-Host -ParameterFilter { $Object -match "Error" -and $Object -match "account" }

            $LASTEXITCODE | Should -Be 1
        }
        It "Should error when given the password length of '<TestPassLength>'" -TestCases @(
            @{ TestPassLength = $Null }
            @{ TestPassLength = "" }
            @{ TestPassLength = " " }
            @{ TestPassLength = "invalid" }
            @{ TestPassLength = "6" }
            @{ TestPassLength = "20.5" }
            @{ TestPassLength = "65" }
        ){

            { . $Path -AccountToManage "myAdmin" -DesiredPassLength $TestPassLength } | Should -Not -Throw

            Should -Invoke Write-Host -ParameterFilter { $Object -match "Error" -and $Object -match "length" }

            $LASTEXITCODE | Should -Be 1
        }
        It "Should error when given the password age of '<TestPassAge>'" -TestCases @(
            @{ TestPassAge = $Null }
            @{ TestPassAge = "" }
            @{ TestPassAge = " " }
            @{ TestPassAge = "invalid" }
            @{ TestPassAge = "6" }
            @{ TestPassAge = "20.5" }
            @{ TestPassAge = "91" }
        ){

            { . $Path -AccountToManage "myAdmin" -DesiredMaxPassAge $TestPassAge } | Should -Not -Throw

            Should -Invoke Write-Host -ParameterFilter { $Object -match "Error" -and $Object -match "age" }

            $LASTEXITCODE | Should -Be 1
        }
    }
}