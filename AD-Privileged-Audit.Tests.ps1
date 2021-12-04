# Mark A. Ziesemer, www.ziesemer.com
# SPDX-FileCopyrightText: Copyright © 2020-2021, Mark A. Ziesemer

#Requires -Version 5.1
#Requires -Modules @{ModuleName='Pester'; ModuleVersion='5.3.1'}

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

Describe 'AD-Privileged-Audit' {

	It 'Source-Only' {
		. $PSScriptRoot\AD-Privileged-Audit.ps1
	}

	It 'Clean-Environment' {
		Test-Path variable:version | Should -Be $false
		Test-Path Function:\Write-Log | Should -Be $false
		. $PSScriptRoot\AD-Privileged-Audit.ps1
		Test-Path variable:version | Should -Be $true
		Test-Path Function:\Write-Log | Should -Be $true
	}

}
