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

    Mock Write-Host { $Object | ForEach-Object { Write-Verbose -Message $_ } }
    Mock Get-ADDomain {
        [PSCustomObject]@{
            DomainMode = "Windows2016Domain"
        }
    }
}
Describe "$(($PSCommandPath | Split-Path -Leaf) -Replace '.tests.', '.')" {
    Context "Under ideal conditions and using default values" {
        It "Should Not Throw Error" {

            { . $Path } | Should -Not -Throw

            Should -Not -Invoke Write-Host -ParameterFilter { $Object -match "Error" }

            $LASTEXITCODE | Should -Be 0
        }
    }
    Context "Input and Environment Validation" {
        It "Should error when not running on a server" {
            Mock Get-CimInstance {
                [PSCustomObject]@{
                    ProductType = 1
                }
            } -ParameterFilter { $ClassName -match "Win32_OperatingSystem" }

            { . $Path } | Should -Not -Throw

            Should -Invoke Write-Host -ParameterFilter { $Object -match "Error" -and $Object -match "controller" }

            $LASTEXITCODE | Should -Be 1
        }
        It "Should error when the domain functional level is less than 2016" {
            Mock Get-ADDomain {
                [PSCustomObject]@{
                    DomainMode = "Windows2012Domain"
                }
            }

            { . $Path } | Should -Not -Throw

            Should -Invoke Write-Host -ParameterFilter { $Object -match "Error" -and $Object -match "level" }

            $LASTEXITCODE | Should -Be 1
        }
    }
}