﻿# Mark A. Ziesemer, www.ziesemer.com
# SPDX-FileCopyrightText: Copyright © 2020-2024, Mark A. Ziesemer

#Requires -Version 5.1
#Requires -Modules @{ModuleName='Pester'; ModuleVersion='5.3.1'}

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

Describe 'Structure' {
	It 'Source-Only' {
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
		. $PSScriptRoot\..\AD-Privileged-Audit.ps1

		function Get-ADDomain{
			@{
				DistinguishedName = 'DC=example,DC=com'
				DNSRoot = 'test.example.com'
				DomainControllersContainer = 'OU=Domain Controllers,DC=example,DC=com'
				DomainSID = [System.Security.Principal.SecurityIdentifier]::new('S-1-5-21-3580816576-12345678901-1234567890')
			}
		}
	}

	BeforeEach {
		$warnings.Clear()
		$batch = $true
		$noFiles = $true
		$reportsFolder = "$PSScriptRoot\..\.Tests\AD-Reports"
		$batch -and $noFiles -and $reportsFolder | Should -Be $true
	}

	It 'Get-ADPrivReportsFolder' {
		$folder = Get-ADPrivReportsFolder
		$folder | Should -BeOfType [string]
		$folder | Should -Not -BeLike '*..*'
	}

	It 'Test-ADPrivIsAdmin' {
		Mock Write-Log -Verifiable -ParameterFilter {$Severity -eq 'WARN'}
		Test-ADPrivIsAdmin ([System.Security.Principal.WindowsIdentity]::GetCurrent()) (Get-ADDomain)
		Should -InvokeVerifiable
	}

	Context 'Resolve-ADPrivProps' {
		BeforeEach{
			$ctx = @{
				adProps = [ordered]@{}
			}
			Initialize-ADPrivProps $ctx
		}

		It 'Resolve-ADPrivProps-InvalidType' {
			$ctx.adProps.source += @{type='invalidType'}
			{Resolve-ADPrivProps 'user'} | Should -Throw 'Unhandled property type: invalidType'
		}

		It 'Resolve-ADPrivProps-StalePasswordsContext' {
			Resolve-ADPrivProps 'user' -generated | Should -Not -Contain 'RC4'
			Resolve-ADPrivProps 'user' -generated -context 'stalePasswords' | Should -Contain 'RC4'
		}
	}

	Context 'With-Mock'{
		BeforeAll {
			function Test-ADPrivIsAdmin{
				$true
			}

			function Invoke-ADPrivFilter{
				[CmdletBinding()]
				param(
					[Parameter(ValueFromPipeline)]
					$InputSource,
					[string]$Filter
				)
				Begin{
					Write-Log "Test Invoke-ADPrivFilter filter: $Filter"
					# Rudimentary solution to process the "PowerShell Expression Language" syntax used by the ActiveDirectory module filters.
					# See the documentation under the "-Filter" parameter:
					# - https://docs.microsoft.com/en-us/powershell/module/activedirectory/get-aduser?view=windowsserver2022-ps#parameters
					if($Filter){
						$lastPos = 0
						$Filter = $Filter -replace '(?<=^|[ ()]+)([^ ()]+) -like ''\*''', '($0 -and $1 -ne $null)'
						$filterCode = ([System.Management.Automation.PSParser]::Tokenize($Filter, [ref]$null) | ForEach-Object{
							# AD properties to resolve are passed-in as if they were Commands or Command Arguments,
							#   depending upon if they are before or after a comparison operator, respectively.
							if($_.Type -in [System.Management.Automation.PSTokenType]::Command,
									[System.Management.Automation.PSTokenType]::CommandArgument){
								# Pass-through other tokens by substring instead of content to maintain existing quoting and spacing,
								#   and for efficiency of keeping multiple non-matching tokens combined as one.
								$Filter.Substring($lastPos, $_.Start - $lastPos)
								# Reposition to the end of this token.
								$lastPos = $_.Start + $_.Length
								# Use function calls to defer resolving properties.
								# This avoids needing to handle multiple data types (including quoting),
								#   and should provide additional efficiency through reusing the same otherwise static ScriptBlock built
								#   here across multiple runs that resolve against different values.
								"(`Resolve-ADPrivProperty '$($_.Content)')"
							}
						} -End {
							$Filter.Substring($lastPos)
						}) -join ''

						$filterScript = [scriptblock]::Create($filterCode)
						Write-Log "  filterScript: $filterScript" -Severity TRACE
					}else{
						$filterScript = $false
					}
				}
				Process{
					function Resolve-ADPrivProperty([string]$name){
						if($name -eq 'pwdLastSet'){
							($PSItem.'PasswordLastSet').ToFileTime()
						}else{
							$PSItem.$name
						}
					}

					if(!$filterScript -or (& $filterScript)){
						return $PSItem
					}
				}
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

		It 'New-ADPrivGroups' {
			$ctx = Initialize-ADPrivReports
			$groupsIn = New-ADPrivGroups -ctx $ctx
			$groupsIn | Should -Not -BeNullOrEmpty
		}

		It 'Server' {
			$server = '192.0.2.123'
			$server | Should -Be $server
			$ctx = Initialize-ADPrivReports
			$ctx.params.adConnectParams.Server | Should -Be $server
		}

		Context 'Invoke-ADPrivReportHistory'{
			It 'Invoke-ADPrivReportHistory-RowCountCache' {
				$noFiles = $false
				$noFiles | Should -Be $false
				$reportsFolder = Join-Path $reportsFolder 'RowCountCache'
				if(Test-Path $reportsFolder -PathType Container){
					Get-ChildItem $reportsFolder -File | Remove-Item
				}
				$ctx = Initialize-ADPrivReports
				$ctx.params.passThru = $true
				$ctx.reports.Count | Should -Be 0

				$rptHistRowCountCacheCsv = Join-Path $reportsFolder 'test.example.com-reportHistory-RowCountCache.csv'
				Test-Path $rptHistRowCountCacheCsv -PathType Leaf | Should -Be $false

				foreach($simRowCount in 3,5){
					1..$simRowCount | ForEach-Object{
						[PSCustomObject][ordered]@{
							Row = $_
							Value = "Abc$_"
						}
					} | Out-ADPrivReports -ctx $ctx -name 'test' -title 'Test'

					Invoke-ADPrivReportHistory -ctx $ctx
					Test-Path $rptHistRowCountCacheCsv -PathType Leaf | Should -Be $true

					$ctx.reports['reportHistory'][0].RowCount | Should -Be $simRowCount
				}

				$ctx.reports.Count | Should -Be 2
				$ctx.reports['reportHistory'].Count | Should -Be 1

				$ctx = Initialize-ADPrivReports
				$ctx.params.passThru = $true
				$ctx.reports.Count | Should -Be 0
				Invoke-ADPrivReportHistory -ctx $ctx
				$ctx.reports['reportHistory'][0].RowCount | Should -Be 5
			}

			It 'Invoke-ADPrivReportHistory-LAPS-Rename' {
				$noFiles = $false
				$noFiles | Should -Be $false
				$reportsFolder = Join-Path $reportsFolder 'LAPS-Rename'
				if(Test-Path $reportsFolder -PathType Container){
					Get-ChildItem $reportsFolder -File | Remove-Item
				}
				$ctx = Initialize-ADPrivReports

				foreach($dir in 'In', 'Out'){
					foreach($fn in "LAPS-$dir-2022-01-07", "LAPS-$dir-2022-01-08", "laps$dir-2022-01-08"){
						New-Item -Path (Join-Path $reportsFolder "test.example.com-$fn.csv") -ItemType File
					}
				}

				Invoke-ADPrivReportHistory -ctx $ctx

				foreach($dir in 'In', 'Out'){
					foreach($date in '2022-01-07', '2022-01-08'){
						Test-Path (Join-Path $reportsFolder "test.example.com-laps$dir-$date.csv") -PathType Leaf | Should -Be $true
						Test-Path (Join-Path $reportsFolder "test.example.com-LAPS-$dir-$date.csv") -PathType Leaf | Should -Be $false
					}
				}
			}

			It 'Invoke-ADPrivReportHistory-staleComps-Rename' {
				$noFiles = $false
				$noFiles | Should -Be $false
				$reportsFolder = Join-Path $reportsFolder 'staleComps-Rename'
				if(Test-Path $reportsFolder -PathType Container){
					Get-ChildItem $reportsFolder -File | Remove-Item
				}
				$ctx = Initialize-ADPrivReports

				foreach($fn in 'staleComps-2024-02-12', 'staleComps-2024-02-13', 'staleComputers-2024-02-13'){
					New-Item -Path (Join-Path $reportsFolder "test.example.com-$fn.csv") -ItemType File
				}

				Invoke-ADPrivReportHistory -ctx $ctx

				foreach($date in '2024-02-12', '2024-02-13'){
					Test-Path (Join-Path $reportsFolder "test.example.com-staleComputers-$date.csv") -PathType Leaf | Should -Be $true
					Test-Path (Join-Path $reportsFolder "test.example.com-staleComps-$date.csv") -PathType Leaf | Should -Be $false
				}
			}

			It 'Invoke-ADPrivReportHistory-LAPS-NoReports' {
				$reportsFolder = Join-Path $reportsFolder 'LAPS-NoReports'
				Test-Path $reportsFolder | Should -Be $false
				$ctx = Initialize-ADPrivReports
				Invoke-ADPrivReportHistory -ctx $ctx
			}
		}

		Context 'New-ADPrivReport' {
			It 'New-ADPrivReport-<Name>' -ForEach @(
				@{Name='Empty'; data=$false}
				@{Name='Sample'; data=$true}
			){
				$noFiles = $false
				$noFiles | Should -Be $false
				$reportsFolder = Join-Path $reportsFolder $Name
				$ctx = Initialize-ADPrivReports
				if($data){
					$dataSource = {[PSCustomObject]@{'Name'='A1'; 'Value'='A2'}}
				}else{
					$dataSource = {}
				}
				$rptName = "test$($Name)"
				New-ADPrivReport -ctx $ctx -name $rptName -title "Sample Title $Name" -dataSource $dataSource
				$ctx.reportFiles.Count | Should -Be 2
				$file = $ctx.reportFiles[$rptName]
				Test-Path -Path $file -PathType Leaf | Should -Be $true
				$fileItem = (Get-Item -Path $file)
				$fileItem.LastWriteTime | Should -BeGreaterOrEqual $ctx.params.now
				if($data){
					@(Import-Csv -Path $file).Count | Should -Be 1

					# Confirm UTF-8 format by checking for byte order mark (BOM).
					$buffer = [byte[]]::new(3)
					$stream = [System.IO.File]::OpenRead($file)
					try{
						[void]$stream.Read($buffer, 0, 3)
					}finally{
						$stream.Close()
					}
					$buffer | Should -Be 0xEF,0xBB,0xBF
				}else{
					$fileItem.Length | Should -Be 0
				}
			}

			It 'New-ADPrivReport-NonInteractive' {
				$ctx = Initialize-ADPrivReports
				Mock Out-GridView {}
				New-ADPrivReport -ctx $ctx -name 'sampleNameC' -title 'Sample Title' -dataSource {[PSCustomObject]@{'Name'='A1'}}
				Should -CommandName Out-GridView -Times 0
			}

			It 'New-ADPrivReport-Interactive' {
				$batch = $false
				$batch | Should -Be $false
				$ctx = Initialize-ADPrivReports
				Mock Out-GridView {}
				New-ADPrivReport -ctx $ctx -name 'sampleNameD' -title 'Sample Title' -dataSource {[PSCustomObject]@{'Name'='A1'}}
				Should -CommandName Out-GridView -Times 1
				Should -CommandName Out-GridView -Times 1 -ParameterFilter {$title -eq 'Sample Title (sampleNameD): 1'}
			}

			It 'New-ADPrivReport-Fail-Expected-NotBatch' {
				$batch = $false
				$batch | Should -Be $false
				$ctx = Initialize-ADPrivReports
				Mock Format-List {}
				New-ADPrivReport -ctx $ctx -name 'sampleNameE' -title 'Sample Title' -dataSource {throw 'ExpectedMockFailure'}
				Should -CommandName Format-List -Times 1
				Should -CommandName Format-List -Times 1 -ParameterFilter {$InputObject.GetType().Name -eq 'ErrorRecord'}
				$warnings.Count | Should -Be 1
				$warnings.Text | Should -Be 'Failed report: Sample Title (sampleNameE) - ExpectedMockFailure'
			}

			It 'New-ADPrivReport-Fail-Expected-Batch' {
				$ctx = Initialize-ADPrivReports
				New-ADPrivReport -ctx $ctx -name 'sampleNameF' -title 'Sample Title' -dataSource {throw 'ExpectedMockFailure'}
				$warnings.Count | Should -Be 1
				$warnings.Text | Should -Be 'Failed report: Sample Title (sampleNameF) - ExpectedMockFailure'
			}

			It 'New-ADPrivReport-Fail-NotExpected' {
				$ctx = Initialize-ADPrivReports
				{New-ADPrivReport -ctx $ctx -name 'sampleNameG' -title 'Sample Title' -mayNotFail -dataSource {throw 'ExpectedMockFailure'}} `
					| Should -Throw 'ExpectedMockFailure'
			}
		}

		Context 'Out-ADPrivReports' {
			It 'Out-ADPrivReports-NoPassThru' {
				$ctx = Initialize-ADPrivReports
				[PSCustomObject]@{'Name'='A1'} | Out-ADPrivReports -ctx $ctx -name 'sampleNameE' -title 'Sample Title'
				$ctx.reports.Count | Should -Be 0
			}

			It 'Out-ADPrivReports-PassThru' {
				$PassThru = $true
				$PassThru | Should -Be $true
				$ctx = Initialize-ADPrivReports
				[PSCustomObject]@{'Name'='A1'} | Out-ADPrivReports -ctx $ctx -name 'sampleNameF' -title 'Sample Title'
				$ctx.reports.Count | Should -Be 1
				$ctx.reports['sampleNameF'][0].Name | Should -Be 'A1'
			}
		}

		Context 'ConvertTo-ADPrivRows' {
			It 'ConvertTo-ADPrivRows' {
				$result = 'A' | ConvertTo-ADPrivRows
				$result[0].'Row#' | Should -Be 1
			}

			It 'ConvertTo-ADPrivRows-Props' {
				$result = 'A' | ConvertTo-ADPrivRows -property 'B', 'C'
				($result[0].PSObject.Properties | Select-Object -First 1).Name | Should -Be 'Row#'
				$result[0].'Row#' | Should -Be 1
			}

			It 'ConvertTo-ADPrivRows-DefaultPropsOrder' {
				$result = [PSCustomObject][ordered]@{
					'B' = $null
					'A' = $null
				} | ConvertTo-ADPrivRows
				($result[0].PSObject.Properties).Name | Should -Be @('Row#', 'B', 'A')
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

		Context 'Get-ADPrivObjectCache' {
			BeforeAll {
				$noFiles = $true
				$ctx = Initialize-ADPrivReports
				# Work-around to silence "is assigned but never used" warning from PSScriptAnalyzer.
				$noFiles | Should -Be $true
				$ctx | Should -Not -BeNullOrEmpty

				$mockGetAdFunc = {
					[CmdletBinding()]
					param(
						[Parameter(ValueFromPipeline)]
						$InputObject,
						$Filter,
						$Server,
						$Properties
					)
					[void]$adResults.Add(@{
						'Command' = '$commandName'
						'InputObject' = $InputObject
						'Filter' = $Filter
						'Server' = $Server
						'Properties' = $Properties
					})
					"sampleData-$InputObject"
				}
				foreach($t in 'User', 'Computer', 'Group', 'Object'){
					$d = $mockGetAdFunc -replace '$commandName', "Get-AD$($t)"
					Invoke-Expression "function Get-AD$($t){$d}"
				}
			}

			BeforeEach {
				Initialize-ADPrivObjectCache $ctx

				$adResults = [System.Collections.ArrayList]::new()
				# Work-around to silence "is assigned but never used" warning from PSScriptAnalyzer.
				$adResults.Count | Should -Be 0
			}

			It 'Get-ADPrivObjectCache-InvalidClass' {
				{Get-ADPrivObjectCache 'testUser' 'invalidClass' $ctx} | Should -Throw 'Unhandled cache type: invalidClass'
			}

			It 'Get-ADPrivObjectCache-InvalidClass-Mismatch' {
				$ctx.adPrivGroupsObjCache['invalidClassMismatch'] = @{}
				{Get-ADPrivObjectCache 'testUser' 'invalidClassMismatch' $ctx} | Should -Throw 'Unhandled cache type: invalidClassMismatch'
			}

			It 'Get-ADPrivObjectCache-User-DN' {
				Get-ADPrivObjectCache @{DistinguishedName='testUser1Dn'} 'user' $ctx | Should -Match 'sampleData.*'
			}

			It 'Get-ADPrivObjectCache-User' {
				Get-ADPrivObjectCache 'testUser1' 'user' $ctx | Should -Be 'sampleData-testUser1'
				$adResults.Count | Should -Be 1
				Get-ADPrivObjectCache 'testUser1' 'user' $ctx | Should -Be 'sampleData-testUser1'
				Get-ADPrivObjectCache 'testUser1' 'object' $ctx | Should -Be 'sampleData-testUser1'
				$adResults.Count | Should -Be 1
				Get-ADPrivObjectCache 'testUser2' 'user' $ctx | Should -Be 'sampleData-testUser2'
				Get-ADPrivObjectCache 'testUser2' 'object' $ctx | Should -Be 'sampleData-testUser2'
				$adResults.Count | Should -Be 2
			}

			It 'Get-ADPrivObjectCache-Computer' {
				Get-ADPrivObjectCache 'testComputer1' 'computer' $ctx | Should -Be 'sampleData-testComputer1'
				$adResults.Count | Should -Be 1
				Get-ADPrivObjectCache 'testComputer1' 'computer' $ctx | Should -Be 'sampleData-testComputer1'
				Get-ADPrivObjectCache 'testComputer1' 'object' $ctx | Should -Be 'sampleData-testComputer1'
				$adResults.Count | Should -Be 1
				Get-ADPrivObjectCache 'testComputer2' 'computer' $ctx | Should -Be 'sampleData-testComputer2'
				Get-ADPrivObjectCache 'testComputer2' 'object' $ctx | Should -Be 'sampleData-testComputer2'
				$adResults.Count | Should -Be 2
			}

			It 'Get-ADPrivObjectCache-Group' {
				$ctx.adProps.groupIn = Resolve-ADPrivProps 'group'

				Get-ADPrivObjectCache 'testGroup1' 'group' $ctx | Should -Be 'sampleData-testGroup1'
				$adResults.Count | Should -Be 1
				Get-ADPrivObjectCache 'testGroup1' 'group' $ctx | Should -Be 'sampleData-testGroup1'
				Get-ADPrivObjectCache 'testGroup1' 'object' $ctx | Should -Be 'sampleData-testGroup1'
				$adResults.Count | Should -Be 1
				Get-ADPrivObjectCache 'testGroup2' 'group' $ctx | Should -Be 'sampleData-testGroup2'
				Get-ADPrivObjectCache 'testGroup2' 'object' $ctx | Should -Be 'sampleData-testGroup2'
				$adResults.Count | Should -Be 2
			}

			It 'Get-ADPrivObjectCache-Object' {
				$ctx.adProps.objectIn = Resolve-ADPrivProps 'object'

				Get-ADPrivObjectCache 'testObject1' 'object' $ctx | Should -Be 'sampleData-testObject1'
				$adResults.Count | Should -Be 1
				Get-ADPrivObjectCache 'testObject1' 'object' $ctx | Should -Be 'sampleData-testObject1'
				$adResults.Count | Should -Be 1
				Get-ADPrivObjectCache 'testObject2' 'object' $ctx | Should -Be 'sampleData-testObject2'
				$adResults.Count | Should -Be 2
			}

			It 'Get-ADPrivObjectCache-PrimaryGroupMembers' {
				Get-ADPrivObjectCache 'testPrimaryGroupMembers1' '@PrimaryGroupMembers' $ctx | Should -Be @('sampleData-', 'sampleData-')
				$adResults.Count | Should -Be 2
				Get-ADPrivObjectCache 'testPrimaryGroupMembers1' '@PrimaryGroupMembers' $ctx | Should -Be @('sampleData-', 'sampleData-')
				$adResults.Count | Should -Be 2
				Get-ADPrivObjectCache 'testPrimaryGroupMembers2' '@PrimaryGroupMembers' $ctx
				$adResults.Count | Should -Be 4
			}
		}

		Context 'Test-ADPrivRecycleBin' {
			It 'Test-ADPrivRecycleBin-Disabled' {
				function Get-ADOptionalFeature{
					@{EnabledScopes=@()}
				}
				Test-ADPrivRecycleBin
				$warnings.Count | Should -Be 1
				$warnings.Text | Should -Be 'AD Recycle Bin is not enabled!'
			}

			It 'Test-ADPrivRecycleBin-Enabled' {
				function Get-ADOptionalFeature{
					@{EnabledScopes=@(
						'CN=Partitions,CN=Configuration,DC=example,DC=com',
						'CN=NTDS Settings,CN=test-dc1,CN=Servers,CN=Default-First-Site-Name,CN=Sites,CN=Configuration,DC=example,DC=com'
					)}
				}
				Test-ADPrivRecycleBin
				$warnings.Count | Should -Be 0
			}
		}

		Context 'Test-ADPrivGroupPolicyCentralStore' {
			BeforeAll {
				$noFiles = $true
				$ctx = Initialize-ADPrivReports
				$testDnsRoot = '\\test.example.com\SYSVOL\test.example.com\policies\PolicyDefinitions\'
				# Work-around to silence "is assigned but never used" warning from PSScriptAnalyzer.
				$noFiles | Should -Be $true
				$ctx | Should -Not -BeNullOrEmpty
				$testDnsRoot | Should -Be $testDnsRoot
			}

			It 'Test-ADPrivGroupPolicyCentralStore-Missing' {
				Mock Test-Path -Verifiable -ParameterFilter {$Path -eq $testDnsRoot} {$false}
				Test-ADPrivGroupPolicyCentralStore -ctx $ctx
				Should -InvokeVerifiable
				$warnings.Count | Should -Be 1
				$warnings.Text | Should -Be "AD Group Policy Central Store does not exist: $testDnsRoot"
			}

			It 'Test-ADPrivGroupPolicyCentralStore-Exists' {
				Mock Test-Path -Verifiable -ParameterFilter {$Path -eq $testDnsRoot} {$true}
				Test-ADPrivGroupPolicyCentralStore -ctx $ctx
				Should -InvokeVerifiable
				$warnings.Count | Should -Be 0
			}
		}

		Context 'Invoke-ADPrivReports' {
			# Warning: The following code serves some needed purposes for unit testing, but should NOT be referenced for production code usages!
			BeforeAll{
				$testReportsMockCtx = @{
					laps = $null
					lapsOnDc = $null
					testDataDefault = $null
					testData = $null
					createDate = Get-Date -Date '2020-01-01'
					oldPasswordDate = Get-Date -Date '2019-01-01'
					lapsPwdSchemaGuid = [guid]::NewGuid()
					lapsPwdAttrsSchemaGuid = [guid]::NewGuid()
					lapsPwdExpSchemaGuid = [guid]::NewGuid()
					admPwdSchemaGuid = [guid]::NewGuid()
					admPwdExpSchemaGuid = [guid]::NewGuid()
				}

				function Reset-TestReportsMockCtx{
					foreach($x in @{
						laps1 = $true
						laps2 = $true
						lapsOnDc = $false
						testData = $testReportsMockCtx.testDataDefault
						createDate = Get-Date -Date '2020-01-01'
						oldPasswordDate = Get-Date -Date '2019-01-01'
					}.GetEnumerator()){
						$testReportsMockCtx[$x.Name] = $x.Value
					}
				}

				function New-ADPrivTestData{
					Write-Log 'New-ADPrivTestData...'
					$testData = @{}

					$testData.groups = @(
						@{
							Name = 'Domain Admins'
							DistinguishedName = 'CN=Domain Admins,OU=Users,DC=example,DC=com'
							GroupScope = 'Global'
							objectSid = [System.Security.Principal.SecurityIdentifier]::new('S-1-5-21-3580816576-12345678901-1234567890-512')
							Members = @(
								'CN=Administrator,OU=Users,DC=example,DC=com',
								'CN=Administrators,CN=Builtin,DC=example,DC=com',
								'CN=Invalid,OU=Users,DC=example,DC=com')
						}
						@{
							Name = 'Administrators'
							DistinguishedName = 'CN=Administrators,CN=Builtin,DC=example,DC=com'
							GroupScope = 'DomainLocal'
							objectSid = [System.Security.Principal.SecurityIdentifier]::new('S-1-5-32-544')
							Members = @('CN=Domain Admins,OU=Users,DC=example,DC=com')
						}
						@{
							Name = 'Domain Controllers'
							DistinguishedName = 'CN=Domain Controllers,OU=Users,DC=example,DC=com'
							GroupScope = 'Global'
							objectSid = [System.Security.Principal.SecurityIdentifier]::new('S-1-5-21-3580816576-12345678901-1234567890-516')
							Members = @(
								'CN=test-dc1,OU=Domain Controllers,DC=example,DC=com'
								'CN=test-dc2,OU=Domain Controllers,DC=example,DC=com'
							)
						}
						@{
							Name = 'Read-Only Domain Controllers'
							DistinguishedName = 'CN=Read-Only Domain Controllers,OU=Users,DC=example,DC=com'
							GroupScope = 'Global'
							objectSid = [System.Security.Principal.SecurityIdentifier]::new('S-1-5-21-3580816576-12345678901-1234567890-521')
							Members = @()
							whenCreated = $testReportsMockCtx.createDate
						}
					) | ForEach-Object{
						$_.ObjectClass = 'group'
						$_.SIDHistory = @(,[guid]::NewGuid())
						[PSCustomObject]$_
					}
					$testData.groupsByName = $testData.groups `
						| Group-Object -Property 'Name' -AsHashTable

					$testData.users = @(
						@{
							Name = 'Administrator'
							DistinguishedName = 'CN=Administrator,OU=Users,DC=example,DC=com'
							PasswordLastSet = $testReportsMockCtx.createDate
							whenCreated = $testReportsMockCtx.createDate
						}
						@{
							Name = 'TestOldPassword1'
							DistinguishedName = 'CN=TestOldPassword1,OU=Users,DC=example,DC=com'
							PasswordLastSet = $testReportsMockCtx.oldPasswordDate
							whenCreated = $testReportsMockCtx.oldPasswordDate
						}
						@{
							Name = 'TestOldPassword2'
							DistinguishedName = 'CN=TestOldPassword2,OU=Users,DC=example,DC=com'
							PasswordLastSet = [DateTime]::FromFileTime(0)
							whenCreated = $testReportsMockCtx.oldPasswordDate
						}
						@{
							Name = 'krbtgt'
							Enabled = $false
							DistinguishedName = 'CN=krbtgt,OU=Users,DC=example,DC=com'
							PasswordLastSet = $testReportsMockCtx.createDate
							whenCreated = $testReportsMockCtx.createDate
						}
						@{
							Name = 'krbtgt_1234'
							Enabled = $false
							DistinguishedName = 'CN=krbtgt_1234,OU=Users,DC=example,DC=com'
							PasswordLastSet = $testReportsMockCtx.oldPasswordDate
							whenCreated = $testReportsMockCtx.oldPasswordDate
						}
						@{
							Name = 'krbtgt_2345'
							Enabled = $false
							DistinguishedName = 'CN=krbtgt_2345,OU=Users,DC=example,DC=com'
							PasswordLastSet = Get-Date
							whenCreated = $testReportsMockCtx.oldPasswordDate
						}
						@{
							Name = 'TestOldDisabled'
							Enabled = $false
							DistinguishedName = 'CN=TestOldDisabled,OU=Users,DC=example,DC=com'
							PasswordLastSet = $testReportsMockCtx.createDate
							whenCreated = $testReportsMockCtx.createDate
						}
					) | ForEach-Object{
						if(!$_.ContainsKey('Enabled')){
							$_.Enabled = $true
						}
						$_.lastLogonTimestamp = $testReportsMockCtx.createDate.ToFileTime()
						$_.PasswordNotRequired = $false
						$_.sAMAccountName = $_.Name
						$_.ObjectClass = 'user'
						$_.PrimaryGroup = 'CN=Domain Users,OU=Users,DC=example,DC=com'
						$_.PrimaryGroupID = 513
						$_.SIDHistory = @(,[guid]::NewGuid())
						[PSCustomObject]$_
					}
					$testData.usersByDn = $testData.Users `
						| Group-Object -Property 'DistinguishedName' -AsHashTable

					$testData.computers = @(
						foreach($dcNum in 1..2){
							$c = @{
								Name = "test-dc$dcNum"
								DistinguishedName = "CN=test-dc$dcNum,OU=Domain Controllers,DC=example,DC=com"
								OperatingSystem = 'Windows Server 2022 Standard'
								OperatingSystemVersion = '10.0 (20348)'
								PrimaryGroup = 'CN=Domain Controllers,OU=Users,DC=example,DC=com'
								PrimaryGroupID = 516
							}
							if($testReportsMockCtx.lapsOnDc -and $dcNum -eq 1){
								$c.'ms-Mcs-AdmPwd' = 'someRandomLapsPassword'
								$c.'ms-Mcs-AdmPwdExpirationTime' = (Get-Date).AddDays(30).ToFileTime()
							}
							$c
						}
						@{
							Name = 'testComp1'
							DistinguishedName = 'CN=testComp1,CN=Computers,DC=example,DC=com'
							OperatingSystem = 'Windows Server 2008 R2 Standard'
							OperatingSystemVersion = '6.1 (7601)'
							PrimaryGroup = 'CN=Domain Computers,OU=Users,DC=example,DC=com'
							PrimaryGroupID = 515
						}
						@{
							Name = 'testComp2'
							DistinguishedName = 'CN=testComp2,CN=Computers,DC=example,DC=com'
							OperatingSystem = 'Windows 8'
							OperatingSystemVersion = '6.2 (0000)'
							PrimaryGroup = 'CN=Domain Computers,OU=Users,DC=example,DC=com'
							PrimaryGroupID = 515
						}
						foreach($compNum in 3..12){
							$c = @{
								Name = "testComp$compNum"
								DistinguishedName = "CN=testComp$compNum,CN=Computers,DC=example,DC=com"
								OperatingSystem = 'Windows Server 2022 Standard'
								OperatingSystemVersion = '10.0 (20348)'
								PrimaryGroup = 'CN=Domain Computers,OU=Users,DC=example,DC=com'
								PrimaryGroupID = 515
							}
							if($compNum -ge 3 -and $compNum -le 4){
								$c.'ms-Mcs-AdmPwd' = 'someRandomLapsPassword'
								$c.'ms-Mcs-AdmPwdExpirationTime' = (Get-Date).AddDays(30).ToFileTime()
							}
							$c
						}
					) | ForEach-Object{
						$_.Enabled = $true
						$_.lastLogonTimestamp = $testReportsMockCtx.createDate.ToFileTime()
						if(!$_.ContainsKey('ms-Mcs-AdmPwd')){
							$_.'ms-Mcs-AdmPwd' = $null
							$_.'ms-Mcs-AdmPwdExpirationTime' = $null
						}
						if(!$_.ContainsKey('ms-LAPS-PasswordExpirationTime')){
							$_.'ms-LAPS-Password' = $null
							$_.'ms-LAPS-EncryptedPassword' = $null
							$_.'ms-LAPS-PasswordExpirationTime' = $null
							$_.'msLAPS-Password' = $null
							$_.'msLAPS-EncryptedPassword' = $null
							$_.'msLAPS-PasswordExpirationTime' = $null
						}
						$_.ObjectClass = 'computer'
						$_.SIDHistory = @(,[guid]::NewGuid())
						[PSCustomObject]$_
					}
					$testData.computersByDn = $testData.computers `
						| Group-Object -Property 'DistinguishedName' -AsHashTable

					$testData.objects = @(
						[PSCustomObject]@{
							Name = 'Invalid'
							DistinguishedName = 'CN=Invalid,OU=Users,DC=example,DC=com'
							ObjectClass = 'Invalid'
						}
						[PSCustomObject]@{
							Name = 'AzureADPasswordProtectionDCAgent'
							DistinguishedName = 'CN=AzureADPasswordProtectionDCAgent,CN=test-dc1,OU=Domain Controllers,DC=example,DC=com'
							ObjectClass = 'serviceConnectionPoint'
							'msDS-Settings' = '{"SoftwareVersion":"1.2.177.1","ServerFQDN":"test-dc1.example.com",' +
								'"HeartbeatUTC":"2022-04-10T20:11:14.0595804Z","PasswordPolicyDateUTC":"2022-04-10T20:10:12.3456789Z",' +
								'"Site":"Default-First-Site-Name","Domain":"example.com","Forest":"example.com","TenantName":"","TenantId":""}'
							'keywords' = @('{2BAC71E6-A293-4D5B-BA3B-50B995237946};Domain=example.com')
						}
						[PSCustomObject]@{
							Name = 'Invalid'
							DistinguishedName = 'CN=Invalid,CN=test-dc1,OU=Domain Controllers,DC=example,DC=com'
							ObjectClass = 'serviceConnectionPoint'
							'keywords' = @('{2BAC71E6-A293-4D5B-BA3B-50B995237946};Domain=example.com')
						}
						foreach($path in 'CN=test-dc2,OU=Domain Controllers', 'CN=testComp3,CN=Computers'){
							[PSCustomObject]@{
								Name = 'AzureADPasswordProtectionProxy'
								DistinguishedName = "CN=AzureADPasswordProtectionProxy,$path,DC=example,DC=com"
								ObjectClass = 'serviceConnectionPoint'
								# This is an overly-simplified mock-up.
								# Specifically, this uses the HS256 algorithm instead of RS256 that would normally be seen here for signing, but this should suffice for the needs here.
								'msDS-Settings' = `
									'eyJhbGciOiJIUzI1NiJ9.eyJTb2Z0d2FyZVZlcnNpb24iOiIxLjIuMTI1LjAiLCJIZWFydGJlYXRVdGMiOiIyMDIyLTA0LTEwVDIxOjA5OjAzLjEyMDUzOD' +
									'ZaIiwiU2VydmVyRlFETiI6InRlc3QtZGMxLmV4YW1wbGUuY29tIiwiRG9tYWluIjoiZXhhbXBsZS5jb20iLCJGb3Jlc3QiOiJleGFtcGxlLmNvbSIsIkhvc' +
									'3RDb21wdXRlclNpZCI6IlMtMS01LTIxLTM1ODA4MTY1NzYtMTIzNDU2Nzg5MDEtMTIzNDU2Nzg5MC0xMDAxIiwiVGVuYW50TmFtZSI6ImV4YW1wbGUuY29t' +
									'IiwiVGVuYW50SWQiOiI3MjY0QTM4OS1EM0M2LTQ5OTMtODdGQi0zNUE3RUQ0N0VBOTgiLCJTZXJ2ZXJBbm5vdGF0aW9uIjoiQUFEUHdkUHJvdFByb3h5LUN' +
									'DMDQyRDhBLUJGODItNEEyNi05RDEwLTgyRkYzNTQyRkNBNyIsIlNpZ25lZFByb3h5Q2VydGlmaWNhdGVDaGFpbiI6IlUwRk5VRXhGIn0.bomgyG0bEx8XMq' +
									'GbQ795qo8XPYWw8RpRAZfBMMM6JCo'
								'keywords' = @('{ebefb703-6113-413d-9167-9f8dd4d24468};Domain=example.com')
							}
						}
					)
					$testData.objectsByDn = ($testData.groups + $testData.users + $testData.computers + $testdata.objects) `
						| Group-Object -Property 'DistinguishedName' -AsHashTable

					[PSCustomObject]$testData
				}

				$testReportsMockCtx.testDataDefault = New-ADPrivTestData

				function Get-ADPrivGroup($identity){
					if($identity -is [PSCustomObject]){
						return $identity
					}
					$g = $testReportsMockCtx.testData.groupsByName[$identity]
					if($g){
						return $g
					}
				}

				function Get-ADUser{
					[CmdletBinding()]
					param(
						[Parameter(ValueFromPipeline)]
						$InputObject,
						$Filter,
						$Server,
						$Properties
					)
					@(if($InputObject){
						if($InputObject -isnot [string]){
							$InputObject
						}
						$u = $testReportsMockCtx.testData.usersByDn[$InputObject]
						if($u){
							$u
						}
					}else{
						$testReportsMockCtx.testData.users
					}) | Invoke-ADPrivFilter -Filter $Filter
				}

				function Get-ADComputer{
					[CmdletBinding()]
					param(
						[Parameter(ValueFromPipeline)]
						$InputObject,
						$Identity,
						$Filter,
						$SearchBase,
						$Server,
						$Properties
					)
					$testData = $testReportsMockCtx.testData
					if($Identity){
						$InputObject = $Identity
					}
					@(if($InputObject){
						if($InputObject -isnot [string]){
							$InputObject
						}
						$c = $testData.computersByDn[$InputObject]
						if($c){
							$c
						}
					}else{
						if($SearchBase){
							$testData.computers | Where-Object {$_.DistinguishedName.EndsWith(',' + $SearchBase)}
						}else{
							$testData.computers
						}
					}) | Invoke-ADPrivFilter -Filter $Filter
				}

				function Get-ADGroup{
					[CmdletBinding()]
					param(
						[Parameter(ValueFromPipeline)]
						$InputObject,
						$Filter,
						$Server,
						$Properties
					)
					@(if($InputObject){
						Get-ADPrivGroup $InputObject
					}else{
						$testReportsMockCtx.testData.groups
					}) | Invoke-ADPrivFilter -Filter $Filter
				}

				function Get-ADObject{
					[CmdletBinding()]
					param(
						[Parameter(ValueFromPipeline)]
						$InputObject,
						$Identity,
						$Filter,
						$SearchBase,
						$Server,
						$Properties
					)
					@(if($InputObject){
						$o = $testReportsMockCtx.testData.objectsByDn[$InputObject]
						if($o){
							$o
						}
					}else{
						if($SearchBase -ceq 'CN=Schema,CN=Configuration,DC=example,DC=com'){
							if($testReportsMockCtx.laps2){
								[PSCustomObject]@{
									Name = 'ms-LAPS-Password'
									DistinguishedName = 'ms-LAPS-Password,CN=Schema,CN=Configuration,DC=example,DC=com'
									SchemaIDGUID = $testReportsMockCtx.lapsPwdSchemaGuid.ToByteArray()
								}
								[PSCustomObject]@{
									Name = 'ms-LAPS-PasswordExpirationTime'
									DistinguishedName = 'ms-LAPS-PasswordExpirationTime,CN=Schema,CN=Configuration,DC=example,DC=com'
									SchemaIDGUID = $testReportsMockCtx.lapsPwdExpSchemaGuid.ToByteArray()
								}
							}
							if($testReportsMockCtx.laps1){
								[PSCustomObject]@{
									Name = 'ms-Mcs-AdmPwd'
									DistinguishedName = 'ms-Mcs-AdmPwd,CN=Schema,CN=Configuration,DC=example,DC=com'
									SchemaIDGUID = $testReportsMockCtx.admPwdSchemaGuid.ToByteArray()
								}
								[PSCustomObject]@{
									Name = 'ms-Mcs-AdmPwdExpirationTime'
									DistinguishedName = 'ms-Mcs-AdmPwdExpirationTime,CN=Schema,CN=Configuration,DC=example,DC=com'
									SchemaIDGUID = $testReportsMockCtx.admPwdExpSchemaGuid.ToByteArray()
								}
							}
						}elseif($Identity -ceq 'CN=ms-LAPS-Encrypted-Password-Attributes,CN=Extended-Rights,CN=Configuration,DC=example,DC=com'){
							[PSCustomObject]@{
								rightsGuid = $testReportsMockCtx.lapsPwdAttrsSchemaGuid.ToByteArray()
							}
						}else{
							$testReportsMockCtx.testData.objects
						}
					}) | Invoke-ADPrivFilter -Filter $Filter
				}

				function Get-ADRootDSE{
					@{
						'ConfigurationNamingContext' = 'CN=Configuration,DC=example,DC=com'
						'SchemaNamingContext' = 'CN=Schema,CN=Configuration,DC=example,DC=com'
					}
				}

				function Get-Acl($Path){
					$acl = @{
						AreAccessRulesProtected = $false
						Access = @()
					}
					# Operate on 5-12 (8).
					if($path -match '(?:Microsoft\.ActiveDirectory\.Management\.dll\\ActiveDirectory:://RootDSE/|AD:)CN=testComp(\d+),CN=Computers,DC=example,DC=com'){
						$compNum = [int]$Matches[1]
						if($compNum -ge 5){
							$compNum -= 5

							if($compNum -band 4){
								$acl.AreAccessRulesProtected = $true
							}
							if($compNum -band 2){
								foreach($schemaGuid in 'lapsPwdSchemaGuid', 'lapsPwdAttrsSchemaGuid', 'admPwdSchemaGuid'){
									$acl.Access += [PSCustomObject]@{
										IdentityReference = 'NT AUTHORITY\SELF'
										AccessControlType = [System.Security.AccessControl.AccessControlType]::Allow
										ObjectType = $testReportsMockCtx.$schemaGuid
										ActiveDirectoryRights = [System.DirectoryServices.ActiveDirectoryRights]::WriteProperty
									}
								}
							}
							if($compNum -band 1){
								foreach($schemaGuid in 'lapsPwdExpSchemaGuid', 'admPwdExpSchemaGuid'){
									$acl.Access += [PSCustomObject]@{
										IdentityReference = 'NT AUTHORITY\SELF'
										AccessControlType = [System.Security.AccessControl.AccessControlType]::Allow
										ObjectType = $testReportsMockCtx.$schemaGuid
										ActiveDirectoryRights = [System.DirectoryServices.ActiveDirectoryRights]::ReadProperty + [System.DirectoryServices.ActiveDirectoryRights]::WriteProperty
									}
								}
							}
						}
					}
					return [PSCustomObject]$acl
				}

				function Test-ADPrivRecycleBin{}
			}

			BeforeEach{
				Reset-TestReportsMockCtx
			}

			It 'TestData-krbtgt-Disabled' {
				$testData = New-ADPrivTestData
				$testData.usersByDn['CN=krbtgt,OU=Users,DC=example,DC=com'][0].Enabled | Should -Be $false
			}

			It 'Default-Full' {
				$noFiles = $false
				$noFiles | Should -Be $false
				$reportsFolder = Join-Path $reportsFolder 'Default-Full'
				$ctx = Initialize-ADPrivReports
				Invoke-ADPrivReports -ctx $ctx | Should -Be $null
			}

			It 'Default-Full-Initial' {
				$noFiles = $false
				$noFiles | Should -Be $false
				$reportsFolder = Join-Path $reportsFolder 'Default-Full-Initial'
				if(Test-Path $reportsFolder -PathType Container){
					Get-ChildItem $reportsFolder -File | Remove-Item
				}
				$ctx = Initialize-ADPrivReports
				Invoke-ADPrivReports -ctx $ctx | Should -Be $null
				Test-Path (Join-Path $reportsFolder 'test.example.com-*-*-Initial.csv') -PathType Leaf | Should -Be $true
			}

			It 'Test-ADPrivSidHistory' {
				$ctx = Initialize-ADPrivReports
				$ctx.params.passThru = $true
				Test-ADPrivSidHistory -ctx $ctx

				$objTypes = @{}
				foreach($h in $ctx.reports['sidHistory']){
					$typeCol = $objTypes[$h.ObjectClass]
					if(!$typeCol){
						$typeCol = $objTypes[$h.ObjectClass] = [System.Collections.ArrayList]::new()
					}
					[void]$typeCol.Add($h)
				}
				$testData = $testReportsMockCtx.testData
				@($objTypes['user']).Count | Should -Be $testData.users.Count
				@($objTypes['computer']).Count | Should -Be $testData.computers.Count
				@($objTypes['group']).Count | Should -Be $testData.groups.Count
			}

			Context 'ADPrivAADPasswordProtection' {
				BeforeEach{
					$ctx = Initialize-ADPrivReports
					$ctx.params.passThru = $true

					$dcs = $ctx.attribs.domainControllers = @{}
					Initialize-ADPrivObjectCache $ctx
					Get-ADGroupMemberSafe -Identity (Get-ADGroup 'Domain Controllers') -ctx $ctx | ForEach-Object{
						$dcs[$_.entry.DistinguishedName] = $_.entry
					}
				}

				It 'Test-ADPrivAADPasswordProtection' {
					Test-ADPrivAADPasswordProtection -ctx $ctx
					$aadppHosts = $ctx.reports['aadPasswordProtection'] | Group-Object -Property 'Name' -AsHashTable

					$testDc1 = $aadppHosts['test-dc1'][0]
					$testDc1.IsDC | Should -Be $true
					$testDc1.IsAgent | Should -Be $true
					$testDc1.IsProxy | Should -Be $false
					$testDc1.AgentVersion | Should -Be '1.2.177.1'
					$testDc1.AgentHeartbeat.ToUniversalTime() | Should -Be ([datetime]'2022-04-10T20:11:14.0595804Z').ToUniversalTime()
					$testDc1.AgentPasswordPolicyDate.ToUniversalTime() | Should -Be ([datetime]'2022-04-10T20:10:12.3456789Z').ToUniversalTime()
					$testDc1.ProxyVersion | Should -Be $null
					$testDc1.ProxyHeartbeat | Should -Be $null
					$testDc1.ProxyTenantName | Should -Be $null
					$testDc1.ProxyTenantId | Should -Be $null

					$testDc2 = $aadppHosts['test-dc2'][0]
					$testDc2.IsDC | Should -Be $true
					$testDc2.IsAgent | Should -Be $false
					$testDc2.IsProxy | Should -Be $true
					$testDc2.AgentVersion | Should -Be $null
					$testDc2.AgentHeartbeat | Should -Be $null
					$testDc2.AgentPasswordPolicyDate | Should -Be $null
					$testDc2.ProxyVersion | Should -Be '1.2.125.0'
					$testDc2.ProxyHeartbeat.ToUniversalTime() | Should -Be ([datetime]'2022-04-10T21:09:03.1205386Z').ToUniversalTime()
					$testDc2.ProxyTenantName | Should -Be 'example.com'
					$testDc2.ProxyTenantId | Should -Be '7264A389-D3C6-4993-87FB-35A7ED47EA98'

					$testComp3 = $aadppHosts['testComp3'][0]
					$testComp3.IsDC | Should -Be $false
					$testComp3.IsAgent | Should -Be $false
					$testComp3.IsProxy | Should -Be $true

					$aadppHosts.Count | Should -Be 3

					$warnings.Count | Should -Be 2
					$warnings.Text | Should -Contain 'Unexpected DN searching for AzureADPasswordProtectionDCAgent: CN=Invalid,CN=test-dc1,OU=Domain Controllers,DC=example,DC=com'
					$warnings.Text | Should -Contain 'Azure Active Directory (AAD) Password Protection: Not consistently deployed to every Domain Controller!'
				}

				It 'Test-ADPrivAADPasswordProtection-NoWarnings' {
					$testReportsMockCtx.testData = New-ADPrivTestData
					$testReportsMockCtx.testData.objects = $testReportsMockCtx.testData.objects `
						| Where-Object {!$_.DistinguishedName.StartsWith('CN=Invalid,')}
					$testDc2Agent = $testReportsMockCtx.testData.objectsByDn['CN=AzureADPasswordProtectionDCAgent,CN=test-dc1,OU=Domain Controllers,DC=example,DC=com'] | ConvertTo-Json | ConvertFrom-Json
					$testDc2Agent.DistinguishedName = 'CN=AzureADPasswordProtectionDCAgent,CN=test-dc2,OU=Domain Controllers,DC=example,DC=com'
					$testReportsMockCtx.testData.objects += $testDc2Agent

					Test-ADPrivAADPasswordProtection -ctx $ctx
					$ctx.reports.Contains('aadPasswordProtection') | Should -Be $true
					$warnings.Count | Should -Be 0
				}

				It 'Test-ADPrivAADPasswordProtection-NotDeployed' {
					$testReportsMockCtx.testData = New-ADPrivTestData
					$testReportsMockCtx.testData.objects = $testReportsMockCtx.testData.objects `
						| Where-Object {$_.ObjectClass -ne 'serviceConnectionPoint'}

					Test-ADPrivAADPasswordProtection -ctx $ctx
					$ctx.reports.Contains('aadPasswordProtection') | Should -Be $false
					$warnings.Text | Should -Contain 'Azure Active Directory (AAD) Password Protection: Not deployed.  (Does require AAD Premium licensing.)'
				}

				It 'Test-ADPrivAADPasswordProtection-NoProxies' {
					$testReportsMockCtx.testData = New-ADPrivTestData
					$testReportsMockCtx.testData.objects = $testReportsMockCtx.testData.objects `
						| Where-Object {!$_.DistinguishedName.StartsWith('CN=AzureADPasswordProtectionProxy,')}

					Test-ADPrivAADPasswordProtection -ctx $ctx
					$ctx.reports.Contains('aadPasswordProtection') | Should -Be $true
					$warnings.Text | Should -Contain 'Azure Active Directory (AAD) Password Protection: No proxies found!'
				}

				It 'Test-ADPrivAADPasswordProtection-OneProxy' {
					$testReportsMockCtx.testData = New-ADPrivTestData
					$testReportsMockCtx.testData.objects = $testReportsMockCtx.testData.objects `
						| Where-Object {!$_.DistinguishedName.StartsWith('CN=AzureADPasswordProtectionProxy,CN=testComp3,')}

					Test-ADPrivAADPasswordProtection -ctx $ctx
					$ctx.reports.Contains('aadPasswordProtection') | Should -Be $true
					$warnings.Text | Should -Contain 'Azure Active Directory (AAD) Password Protection: Only 1 proxy found for more than one Domain Controller.'
				}
			}

			Context 'DataConditionals' {
				BeforeEach{
					$ctx = Initialize-ADPrivReports
					$ctx.params.passThru = $true
					$warnings = [System.Collections.ArrayList]::new()
					$warnings.Count | Should -Be 0
				}

				Context 'Test-ADPrivLaps' {
					BeforeAll{
						$laps2TestCols = 'msLAPS-PasswordExpirationTime', 'msLAPS-Password', 'msLAPS-EncryptedPassword', 'ACL-Self-LapsPwd-W', 'ACL-Self-LapsEncPwd-W', 'ACL-Self-LapsPwdExp-RW'
						$laps2TestCols | Should -Be $laps2TestCols
						$laps1TestCols = 'ms-Mcs-AdmPwdExpirationTimeDate', 'ms-Mcs-AdmPwdExpirationTime', 'ACL-Self-AdmPwd-W', 'ACL-Self-AdmPwdExp-RW'
						$laps1TestCols | Should -Be $laps1TestCols
					}

					It 'Test-ADPrivLaps-Default' {
						Test-ADPrivLaps -ctx $ctx | Should -Be $null
						$warnings.Count | Should -Be 0
						$ctx.reports['lapsIn'].Count | Should -Be 2
						$ctx.reports['lapsOut'].Count | Should -Be 10

						$lapsOuts = $ctx.reports['lapsOut'] | Group-Object -Property 'Name' -AsHashTable
						foreach($compNum in 0..7){
							$testComp = $lapsOuts["testComp$($compNum + 5)"][0]
							$testComp.'ACL-Inherited' | Should -Be (!($compNum -band 4) -eq 4)
							$testComp.'ACL-Self-LapsPwd-W' | Should -Be (($compNum -band 2) -eq 2)
							$testComp.'ACL-Self-LapsEncPwd-W' | Should -Be (($compNum -band 2) -eq 2)
							$testComp.'ACL-Self-LapsPwdExp-RW' | Should -Be (($compNum -band 1) -eq 1)
							$testComp.'ACL-Self-AdmPwd-W' | Should -Be (($compNum -band 2) -eq 2)
							$testComp.'ACL-Self-AdmPwdExp-RW' | Should -Be (($compNum -band 1) -eq 1)
						}

						$props = $ctx.reports['lapsOut'][0].PSObject.Properties.Name
						foreach($col in $laps1TestCols + $laps2TestCols){
							$props | Should -Contain $col
						}
					}

					It 'Test-ADPrivLaps-Laps2' {
						$testReportsMockCtx.laps2 = $true
						$testReportsMockCtx.laps1 = $false
						Test-ADPrivLaps -ctx $ctx | Should -Be $null
						$warnings.Count | Should -Be 0

						$props = $ctx.reports['lapsOut'][0].PSObject.Properties.Name
						foreach($col in $laps2TestCols){
							$props | Should -Contain $col
						}
						foreach($col in $laps1TestCols){
							$props | Should -Not -Contain $col
						}
					}

					It 'Test-ADPrivLaps-Laps1' {
						$testReportsMockCtx.laps2 = $false
						$testReportsMockCtx.laps1 = $true
						Test-ADPrivLaps -ctx $ctx | Should -Be $null
						$warnings.Count | Should -Be 0

						$props = $ctx.reports['lapsOut'][0].PSObject.Properties.Name
						foreach($col in $laps2TestCols){
							$props | Should -Not -Contain $col
						}
						foreach($col in $laps1TestCols){
							$props | Should -Contain $col
						}
					}

					It 'Test-ADPrivLaps-NoLaps' {
						$testReportsMockCtx.laps2 = $false
						$testReportsMockCtx.laps1 = $false
						Test-ADPrivLaps -ctx $ctx | Should -Be $null
						$warnings.Text | Should -Contain 'LAPS is not deployed!  (Neither ms-Mcs-AdmPwd nor ms-LAPS-Password attribute exist.)'
						$ctx.reports | Should -Not -Contain 'lapsIn'
						$ctx.reports | Should -Not -Contain 'lapsOut'
					}

					It 'Test-ADPrivLaps-LapsOnDc' {
						$testReportsMockCtx.lapsOnDc = $true
						$testReportsMockCtx.testData = New-ADPrivTestData
						Test-ADPrivLaps -ctx $ctx | Should -Be $null
						$warnings.Text | Should -Contain 'LAPS found on possible domain controller: CN=test-dc1,OU=Domain Controllers,DC=example,DC=com'
						$ctx.reports['lapsIn'].Count | Should -Be 3
						$ctx.reports['lapsOut'].Count | Should -Be 10
					}

					It 'Test-ADPrivLaps-ACL-PSDrive' {
						Mock Get-Acl -ParameterFilter {$Path -like 'Microsoft.ActiveDirectory.Management.dll\ActiveDirectory:://RootDSE/*'} `
							-MockWith {
								# Fail like Windows Server 2016
								throw [System.Management.Automation.ProviderNotFoundException]::new(
									"Cannot find a provider with the name 'Microsoft.ActiveDirectory.Management.dll\ActiveDirectory'.")
							} -Verifiable `

						Test-ADPrivLaps -ctx $ctx | Should -Be $null
						Should -InvokeVerifiable
						$warnings.Count | Should -Be 0
					}
				}

				Context 'Invoke-ADPrivReports-StalePasswordsRodcDate' {
					BeforeEach{
						$rodcLog = @($false)

						$writeLog = Get-Command Write-Log
						Mock Write-Log{
							& $writeLog @args
							$rodcLog[0] = $true
						} -ParameterFilter {
							$Severity -eq '' `
								-and $Message -eq ("Read-Only Domain Controllers (RODC) creation date is more recent than requested stale password filter threshold, using RODC creation date instead: {0}" -f $rodcDate)
						}
					}

					It 'Invoke-ADPrivReports-StalePasswordsRodcDate-Default' {
						Invoke-ADPrivReports -ctx $ctx
						$ctx.attribs.rodcDate | Should -Be $testReportsMockCtx.createDate
						$rodcLog[0] | Should -Be $false
					}

					It 'Invoke-ADPrivReports-StalePasswordsRodcDate-RecentUpgrade' {
						# Tests recent 2008 functional level upgrade.

						$rodcDate = (Get-Date).AddDays(-15)
						$testReportsMockCtx.testData = New-ADPrivTestData
						$testReportsMockCtx.testData.groupsByName['Read-Only Domain Controllers'][0].whenCreated = $rodcDate

						Invoke-ADPrivReports -ctx $ctx
						$ctx.attribs.rodcDate | Should -Be $rodcDate
						$rodcLog[0] | Should -Be $true
					}

					It 'Invoke-ADPrivReports-StalePasswordsRodcDate-MissingRODC' {
						$testReportsMockCtx.testData = New-ADPrivTestData
						$testReportsMockCtx.testData.groupsByName.Remove('Read-Only Domain Controllers')

						Invoke-ADPrivReports -ctx $ctx
						$ctx.attribs.rodcDate | Should -Be $null
						$rodcLog[0] | Should -Be $false
					}
				}
			}

			Context 'Default-Checks' {
				BeforeAll{
					Reset-TestReportsMockCtx

					$batch = $true
					$noFiles = $true
					$ctx = Initialize-ADPrivReports
					$ctx.params.passThru = $true

					# Work-around to silence "is assigned but never used" warning from PSScriptAnalyzer.
					$batch -and $noFiles | Should -Be $true

					$results = Invoke-ADPrivReports -ctx $ctx
					$results | Should -BeOfType [PSCustomObject]
				}

				Context 'Stale-Passwords' {
					BeforeAll{
						$stalePasswords = @{}
						foreach($p in $results.reports['stalePasswords']){
							$stalePasswords[$p.Name] = $p
						}
						# As this is executing in BeforeAll vs. BeforeEach, need to keep a copy before the warnings are cleared in the parent BeforeEach.
						$testWarnings = $warnings.Clone()
						$testWarnings | Should -Not -Be $null
					}

					It 'krbtgt' {
						$stalePasswords.Keys | Should -Contain 'krbtgt'
					}

					It 'krbtgt_1234' {
						$stalePasswords.Keys | Should -Contain 'krbtgt_1234'
					}

					It 'krbtgt_2345' {
						$testReportsMockCtx.testData.usersByDn.Keys | Should -Contain 'CN=krbtgt_2345,OU=Users,DC=example,DC=com'
						$stalePasswords.Keys | Should -Not -Contain 'krbtgt_2345'
					}

					It 'TestOldDisabled' {
						$testReportsMockCtx.testData.usersByDn.Keys | Should -Contain 'CN=TestoldDisabled,OU=Users,DC=example,DC=com'
						$stalePasswords.Keys | Should -Not -Contain 'TestOldDisabled'
					}

					It 'RC4-Warnings' {
						$testWarnings.Text | Should -Contain 'stalePasswords: 3 passwords are most likely using insecure RC4 secret keys.'
					}

					It 'RC4-Passwords-Administrator' {
						$stalePasswords['Administrator'].RC4 | Should -Be $null
					}

					It 'RC4-Passwords-TestOldPasswords' {
						$op1 = $stalePasswords['TestOldPassword1']
						$op1.RC4 | Should -Be $true
						$op1.PasswordLastSet | Should -BeOfType [DateTime]
						$op2 = $stalePasswords['TestOldPassword2']
						$op2.RC4 | Should -Be $true
						$op2.PasswordLastSet | Should -Be ([DateTime]::FromFileTime(0))
					}
				}
			}
		}
	}
}
