# Mark A. Ziesemer, www.ziesemer.com
# SPDX-FileCopyrightText: Copyright © 2020-2021, Mark A. Ziesemer

# At least as of 2021-12-04, this tends to hang Visual Studio Code if run normally from within VSC.
# This seems to be due to VSC attaching a debugger and then struggling to track breakpoints used by Pester, with no option that I can find at present to disable.
# For now, recommend simply running directly from a PowerShell console:
#   .\Coverage.ps1
# Please provide feedback if anyone knows or finds a better way to manage this...

#Requires -Version 5.1
#Requires -Modules @{ModuleName='Pester'; ModuleVersion='5.3.1'}

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

$Configuration = [PesterConfiguration]::Default
$Configuration.CodeCoverage.Enabled = $true
$Configuration.CodeCoverage.OutputFormat = 'CoverageGutters'

Invoke-Pester -Configuration $Configuration
