# Misc-PoSH
A compilation of random PowerShell scripts I've written over the years.

## Support
This code is provided under the terms of the [Apache 2.0 License](http://www.apache.org/licenses/LICENSE-2.0). It is offered "as is", without any warranty, and support is not guaranteed. Contributions are welcome, feel free to submit pull requests.

## Expected PowerShell Version
Most scripts expect at least PowerShell 5.1 (the default shipped with Server 2016 and Windows 10).
Please see the `#requires` statement at the top of each script as well as its accompanying help block, as older versions may be supported on a case-by-case basis.

## Unit Testing / Pester Setup
### Current Version In Use
**5.7.1**
### Installation
Most Windows operating systems ship with Pester pre-installed. All tests **DO NOT** use this version. Please install the version specified above using https://pester.dev/docs/introduction/installation. The instructions below may be outdated.
```PowerShell
# This will allow you to install Pester side-by-side with its existing version.
# See https://pester.dev/docs/introduction/installation if you would like to remove the existing version (it would likely make updates easier).

Install-Module -Name Pester -Force -SkipPublisherCheck
```

## Folder Structure
```Bash
repo-root/
│
├── README.md                 # Overview of the project
├── LICENSE                   # Project license
├── .gitignore                # Git ignore rules
│
│── .vscode
│   └── Project settings and snippets
│
├── functions/
│   └── Common helper functions used throughout scripts
│
├── modules/
│   └── PowerShell modules (if any)
│
├── scripts/
│   └── Individual scripts
│
└── tests/
    └── Pester tests   # These tests are for the individual scripts and should share the same name as the script they're testing.
```