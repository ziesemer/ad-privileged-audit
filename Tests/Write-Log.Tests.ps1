# Mark A. Ziesemer, www.ziesemer.com
# SPDX-FileCopyrightText: Copyright © 2020-2022, Mark A. Ziesemer

#Requires -Version 5.1
#Requires -Modules @{ModuleName='Pester'; ModuleVersion='5.3.1'}

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

Describe 'Write-Log'{
	BeforeAll {
		# Work-around as required for https://github.com/pester/vscode-adapter/issues/85 .
		function Set-StrictMode(){}

		. $PSScriptRoot\..\AD-Privileged-Audit.ps1
	}

	BeforeEach {
		# Continued work-around as required for https://github.com/pester/vscode-adapter/issues/85 .
		Microsoft.PowerShell.Core\Set-StrictMode -Version Latest
	}

	It 'Write-Log'{
		$lastInfo = @($null)
		function Write-Information {$lastInfo[0] = $args}

		$startTimePattern = '^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2} '

		Write-Log 'Test-Trace' -Severity TRACE
		$lastInfo[0].Message | Should -MatchExactly ($startTimePattern + '\[TRACE\] Test-Trace$')
		$lastInfo[0].ForegroundColor | Should -Be ([ConsoleColor]::DarkGray)

		Write-Log 'Test-Debug' -Severity DEBUG
		$lastInfo[0].Message | Should -MatchExactly ($startTimePattern + '\[DEBUG\] Test-Debug$')
		$lastInfo[0].ForegroundColor | Should -Be ([ConsoleColor]::Gray)

		Write-Log 'Test-Info' -Severity INFO
		$lastInfo[0].Message | Should -MatchExactly ($startTimePattern + '\[INFO\] Test-Info$')
		$lastInfo[0].ForegroundColor | Should -Be ([ConsoleColor]::Cyan)

		$warnings.Count | Should -Be 0

		Write-Log 'Test-Warning' -Severity WARN
		$lastInfo[0].Message | Should -MatchExactly ($startTimePattern + '\[WARN\] Test-Warning$')
		$lastInfo[0].ForegroundColor | Should -Be ([ConsoleColor]::Yellow)
		$warnings.Count | Should -Be 1
		$warnings[0].Text | Should -Be 'Test-Warning'

		Write-Log 'Test-Error' -Severity ERROR
		$lastInfo[0].Message | Should -MatchExactly ($startTimePattern + '\[ERROR\] Test-Error$')
		$lastInfo[0].ForegroundColor | Should -Be ([ConsoleColor]::Red)
		$warnings.Count | Should -Be 1
	}
}
