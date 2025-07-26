BeforeAll {
    # Get script path
    $Path = ".\functions\$($PSCommandPath | Split-Path -Leaf)" -Replace '.tests.', '.'
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

    Mock Write-Host { $Object | ForEach-Object { Write-Verbose -Message $_ } }

    . $Path
}
Describe "$(($PSCommandPath | Split-Path -Leaf) -Replace '.tests.', '.')" {
    Context "Under ideal conditions and using default values" {
        It "Should Not Throw Error" {

            { . $Path } | Should -Not -Throw
            { Test-IsDomainController }| Should -Not -Throw

            Should -Not -Invoke Write-Host -ParameterFilter { $Object -match "Error" }
        }
    }
}