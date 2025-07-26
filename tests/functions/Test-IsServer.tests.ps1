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
            { Test-IsServer } | Should -Not -Throw

            Should -Not -Invoke Write-Host -ParameterFilter { $Object -match "Error" }
        }
    }
}