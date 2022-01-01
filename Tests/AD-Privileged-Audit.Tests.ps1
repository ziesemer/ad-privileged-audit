# Mark A. Ziesemer, www.ziesemer.com
# SPDX-FileCopyrightText: Copyright © 2020-2022, Mark A. Ziesemer

#Requires -Version 5.1
#Requires -Modules @{ModuleName='Pester'; ModuleVersion='5.3.1'}

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

Describe 'Structure' {
	It 'Source-Only' {
		# Work-around as required for https://github.com/pester/vscode-adapter/issues/85 .
		function Set-StrictMode(){}

		. $PSScriptRoot\..\AD-Privileged-Audit.ps1
	}

	It 'Clean-Environment' {
		Test-Path variable:version | Should -Be $false
		Test-Path Function:\Write-Log | Should -Be $false
		. $PSScriptRoot\..\AD-Privileged-Audit.ps1
		Test-Path variable:version | Should -Be $true
		Test-Path Function:\Write-Log | Should -Be $true
	}
}

Describe 'AD-Privileged-Audit' {
	BeforeAll {
		# Work-around as required for https://github.com/pester/vscode-adapter/issues/85 .
		function Set-StrictMode(){}

		. $PSScriptRoot\..\AD-Privileged-Audit.ps1

		function Get-ADDomain{
			@{
				DNSRoot = 'test.example.com'
				DomainSID = [System.Security.Principal.SecurityIdentifier]::new('S-1-5-21-3580816576-12345678901-1234567890')
			}
		}
	}

	BeforeEach {
		# Continued work-around as required for https://github.com/pester/vscode-adapter/issues/85 .
		Microsoft.PowerShell.Core\Set-StrictMode -Version Latest
	}

	It 'Get-ADPrivReportsFolder' {
		Get-ADPrivReportsFolder | Should -BeOfType [string]
	}

	It 'Get-ADPrivInteractive' {
		Get-ADPrivInteractive | Should -Be $true
	}

	It 'Test-ADPrivIsAdmin' {
		Mock Write-Log -Verifiable -ParameterFilter {$Severity -eq 'WARN'}
		Test-ADPrivIsAdmin ([System.Security.Principal.WindowsIdentity]::GetCurrent()) (Get-ADDomain)
		Should -InvokeVerifiable
	}

	It 'Resolve-ADPrivProps' {
		$ctx = @{
			adProps = [ordered]@{}
		}
		Initialize-ADPrivProps $ctx
		$ctx.adProps.source += @{type='invalidType'}
		{Resolve-ADPrivProps 'user'} | Should -Throw 'Unhandled property type: invalidType'
	}

	Context 'With-Mock'{
		BeforeAll {
			function Get-ADPrivInteractive{
				$false
			}

			function Get-ADPrivReportsFolder{
				Join-Path '.Tests' 'AD-Reports'
			}

			function Test-ADPrivIsAdmin{
				$true
			}
		}

		It 'Initialize-ADPrivObjectCache' {
			$ctx = @{}
			Initialize-ADPrivObjectCache $ctx
		}

		It 'Initialize-ADPrivReports' {
			Mock Test-ADPrivIsAdmin {$true} -Verifiable
			$ctx = Initialize-ADPrivReports
			$ctx | Should -BeOfType [System.Collections.Specialized.OrderedDictionary]
			Should -InvokeVerifiable
		}

		It 'New-ADPrivReport-Empty' {
			$ctx = Initialize-ADPrivReports
			$oldCount = $ctx.reportFiles.Count
			New-ADPrivReport -ctx $ctx -name 'sampleNameA' -title 'Sample Title' -dataSource {}
			$ctx.reportFiles.Count | Should -Be ($oldCount + 1)
		}

		It 'New-ADPrivReport-Sample' {
			$ctx = Initialize-ADPrivReports
			$oldCount = $ctx.reportFiles.Count
			New-ADPrivReport -ctx $ctx -name 'sampleNameB' -title 'Sample Title' -dataSource {[PSCustomObject]@{'Name'='A1'}}
			$ctx.reportFiles.Count | Should -Be ($oldCount + 1)
		}

		It 'New-ADPrivReport-NonInteractive' {
			$ctx = Initialize-ADPrivReports
			Mock Out-GridView {}
			New-ADPrivReport -ctx $ctx -name 'sampleNameC' -title 'Sample Title' -dataSource {[PSCustomObject]@{'Name'='A1'}}
			Should -CommandName Out-GridView -Times 0
		}

		It 'New-ADPrivReport-Interactive' {
			$ctx = Initialize-ADPrivReports
			Mock Get-ADPrivInteractive {$true}
			Mock Out-GridView {}
			New-ADPrivReport -ctx $ctx -name 'sampleNameD' -title 'Sample Title' -dataSource {[PSCustomObject]@{'Name'='A1'}}
			Should -CommandName Out-GridView -Times 1
			Should -CommandName Out-GridView -Times 1 -ParameterFilter {$title -eq 'Sample Title (sampleNameD): 1'}
		}

		It 'Out-ADPrivReports-NoPassThru' {
			$ctx = Initialize-ADPrivReports
			[PSCustomObject]@{'Name'='A1'} | Out-ADPrivReports -ctx $ctx -name 'sampleNameE' -title 'Sample Title'
			$ctx.reports.Count | Should -Be 0
		}

		It 'Out-ADPrivReports-PassThru' {
			$ctx = Initialize-ADPrivReports
			$ctx.params.passThru = $true
			[PSCustomObject]@{'Name'='A1'} | Out-ADPrivReports -ctx $ctx -name 'sampleNameF' -title 'Sample Title'
			$ctx.reports.Count | Should -Be 1
			$ctx.reports['sampleNameF'][0].Name | Should -Be 'A1'
		}

		It 'ConvertTo-ADPrivRows' {
			$result = 'A' | ConvertTo-ADPrivRows
			$result[0].'Row#' | Should -Be 1
		}

		It 'ConvertTo-ADPrivRows-Props' {
			$result = 'A' | ConvertTo-ADPrivRows -property 'B', 'C'
			($result[0].PSObject.Properties | Select-Object -First 1).Name | Should -Be 'Row#'
			$result[0].'Row#' | Should -Be 1
		}

		It 'ConvertTo-ADPrivRows-dateProps' {
			$result = [PSCustomObject]@{'lastLogonTimestamp'=0} | ConvertTo-ADPrivRows
			$names = $result[0].PSObject.Properties.Name
			$names[1] | Should -Be 'lastLogonTimestampDate'
			$names[2] | Should -Be 'lastLogonTimestamp'
			$result[0].'lastLogonTimestamp' | Should -Be 0
			$result[0].'lastLogonTimestampDate' | Should -Be ([DateTime]::FromFileTime(0))
		}

		It 'ConvertTo-ADPrivRows-dateProps-null' {
			$result = [PSCustomObject]@{'lastLogonTimestamp'=$null} | ConvertTo-ADPrivRows
			$result[0].'lastLogonTimestamp' | Should -Be $null
			$result[0].'lastLogonTimestampDate' | Should -Be $null
		}

		It 'ConvertTo-ADPrivRows-ConsistencyGuid' {
			$result = [PSCustomObject]@{'mS-DS-ConsistencyGuid'=[byte]1,2,3} | ConvertTo-ADPrivRows
			$result[0].'mS-DS-ConsistencyGuid' | Should -Be 'AQID'
		}
	}

}
