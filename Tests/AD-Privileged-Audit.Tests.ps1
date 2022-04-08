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
				DistinguishedName = 'DC=example,DC=com'
				DNSRoot = 'test.example.com'
				DomainControllersContainer = 'OU=Domain Controllers,DC=example,DC=com'
				DomainSID = [System.Security.Principal.SecurityIdentifier]::new('S-1-5-21-3580816576-12345678901-1234567890')
			}
		}
	}

	BeforeEach {
		# Continued work-around as required for https://github.com/pester/vscode-adapter/issues/85 .
		Microsoft.PowerShell.Core\Set-StrictMode -Version Latest

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
					$Filter
				)
				Begin{
					Write-Log "Test Invoke-ADPrivFilter filter: $Filter"
				}
				Process{
					# This can't yet actually process the actual filter, without further work to process the PowerShell Expression Language syntax.
					# Return all results for now...
					return $PSItem
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

		Context 'Invoke-ADPrivReportHistory-LAPS'{
			It 'Invoke-ADPrivReportHistory-LAPS-Rename' {
				$noFiles = $false
				$noFiles | Should -Be $false
				$reportsFolder = Join-Path $reportsFolder 'LAPS-Rename'
				if(Test-Path $reportsFolder -PathType Container){
					Get-ChildItem $reportsFolder -File | Remove-Item
				}
				$ctx = Initialize-ADPrivReports

				New-Item -Path (Join-Path $reportsFolder 'test.example.com-LAPS-In-2022-01-08.csv') -ItemType File

				Invoke-ADPrivReportHistory -ctx $ctx

				Test-Path (Join-Path $reportsFolder 'test.example.com-lapsIn-2022-01-08.csv') -PathType Leaf | Should -Be $true
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
					"sampleData-$InputObject" | Invoke-ADPrivFilter -Filter $Filter
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
						'CN=NTDS Settings,CN=test-dc,CN=Servers,CN=Default-First-Site-Name,CN=Sites,CN=Configuration,DC=example,DC=com'
					)}
				}
				Test-ADPrivRecycleBin
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
				}

				function Reset-TestReportsMockCtx{
					foreach($x in @{
						laps = $true
						lapsOnDc = $false
						testData = $testReportsMockCtx.testDataDefault
						createDate = Get-Date -Date '2020-01-01'
						oldPasswordDate = Get-Date -Date '2019-01-01'
					}.GetEnumerator()){
						$testReportsMockCtx[$x.Name] = $x.Value
					}
				}

				function New-ADPrivTestData{
					$testData = @{}

					$testData.groups = @(
						[PSCustomObject]@{
							Name = 'Domain Admins'
							DistinguishedName = 'CN=Domain Admins,OU=Users,DC=example,DC=com'
							objectClass = 'group'
							GroupScope = 'Global'
							objectSid = [System.Security.Principal.SecurityIdentifier]::new('S-1-5-21-3580816576-12345678901-1234567890-512')
							Members = @(
								'CN=Administrator,OU=Users,DC=example,DC=com',
								'CN=Administrators,CN=Builtin,DC=example,DC=com',
								'CN=Invalid,OU=Users,DC=example,DC=com')
						}
						[PSCustomObject]@{
							Name = 'Administrators'
							DistinguishedName = 'CN=Administrators,CN=Builtin,DC=example,DC=com'
							objectClass = 'group'
							GroupScope = 'DomainLocal'
							objectSid = [System.Security.Principal.SecurityIdentifier]::new('S-1-5-32-544')
							Members = @('CN=Domain Admins,OU=Users,DC=example,DC=com')
						}
						[PSCustomObject]@{
							Name = 'Domain Controllers'
							DistinguishedName = 'CN=Domain Controllers,OU=Users,DC=example,DC=com'
							objectClass = 'group'
							GroupScope = 'Global'
							objectSid = [System.Security.Principal.SecurityIdentifier]::new('S-1-5-21-3580816576-12345678901-1234567890-516')
							Members = @('CN=test-dc,OU=Domain Controllers,DC=example,DC=com')
						}
						[PSCustomObject]@{
							Name = 'Read-Only Domain Controllers'
							DistinguishedName = 'CN=Read-Only Domain Controllers,OU=Users,DC=example,DC=com'
							objectClass = 'group'
							GroupScope = 'Global'
							objectSid = [System.Security.Principal.SecurityIdentifier]::new('S-1-5-21-3580816576-12345678901-1234567890-521')
							Members = @()
							whenCreated = $testReportsMockCtx.createDate
						}
					)
					$testData.groupsByName = $testData.groups `
						| Group-Object -Property 'Name' -AsHashTable

					$testData.users = @(
						[PSCustomObject]@{
							Name = 'Administrator'
							DistinguishedName = 'CN=Administrator,OU=Users,DC=example,DC=com'
							objectClass = 'user'
							PasswordLastSet = $testReportsMockCtx.createDate
							whenCreated = $testReportsMockCtx.createDate
						}
						[PSCustomObject]@{
							Name = 'TestOldPassword1'
							DistinguishedName = 'CN=TestOldPassword1,OU=Users,DC=example,DC=com'
							objectClass = 'user'
							PasswordLastSet = $testReportsMockCtx.oldPasswordDate
							whenCreated = $testReportsMockCtx.oldPasswordDate
						}
						[PSCustomObject]@{
							Name = 'TestOldPassword2'
							DistinguishedName = 'CN=TestOldPassword2,OU=Users,DC=example,DC=com'
							objectClass = 'user'
							PasswordLastSet = $null
							whenCreated = $testReportsMockCtx.oldPasswordDate
						}
					)
					$testData.usersByDn = $testData.Users `
						| Group-Object -Property 'DistinguishedName' -AsHashTable

					$testData.computers = @(
						[PSCustomObject]@{
							Name = 'test-dc'
							DistinguishedName = 'CN=test-dc,OU=Domain Controllers,DC=example,DC=com'
							objectClass = 'computer'
							OperatingSystem = 'Windows Server 2022 Standard'
							OperatingSystemVersion = '10.0 (20348)'
							PrimaryGroupID = 516
						}
						[PSCustomObject]@{
							Name = 'testComp1'
							DistinguishedName = 'CN=testComp1,OU=Domain Controllers,DC=example,DC=com'
							objectClass = 'computer'
							OperatingSystem = 'Windows Server 2008 R2 Standard'
							OperatingSystemVersion = '6.1 (7601)'
							PrimaryGroupID = 515
						}
						[PSCustomObject]@{
							Name = 'testComp2'
							DistinguishedName = 'CN=testComp2,OU=Domain Controllers,DC=example,DC=com'
							objectClass = 'computer'
							OperatingSystem = 'Windows 8'
							OperatingSystemVersion = '6.2 (0000)'
							PrimaryGroupID = 515
						}
					)
					$testData.computersByDn = $testData.computers `
						| Group-Object -Property 'DistinguishedName' -AsHashTable

					$testData.objects = @(
						[PSCustomObject]@{
							DistinguishedName = 'CN=Invalid,OU=Users,DC=example,DC=com'
							objectClass = 'Invalid'
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
					[void](Invoke-ADPrivFilter -Filter $Filter)
					if($InputObject){
						if($InputObject -isnot [string]){
							$InputObject
						}
						$u = $testReportsMockCtx.testData.usersByDn[$InputObject]
						if($u){
							$u
						}
					}else{
						$testReportsMockCtx.testData.users
					}
				}

				function Get-ADComputer{
					[CmdletBinding()]
					param(
						[Parameter(ValueFromPipeline)]
						$InputObject,
						$Filter,
						$SearchBase,
						$Server,
						$Properties
					)
					$testData = $testReportsMockCtx.testData
					[void](Invoke-ADPrivFilter -Filter $Filter)
					if($InputObject){
						if($InputObject -isnot [string]){
							$InputObject
						}
						$c = $testData.computersByDn[$InputObject]
						if($c){
							$c
						}
					}else{
						if($SearchBase -eq $ctx.params.domain.DomainControllersContainer){
							if($testReportsMockCtx.lapsOnDc){
								$testData.computersByDn['CN=test-dc,OU=Domain Controllers,DC=example,DC=com']
							}
						}else{
							if(([string]$Filter) -notlike '*PrimaryGroupID -eq *'){
								$testData.computers
							}
						}
					}
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
					[void](Invoke-ADPrivFilter -Filter $Filter)
					if($InputObject){
						Get-ADPrivGroup $InputObject
					}else{
						$testReportsMockCtx.testData.groups
					}
				}

				function Get-ADObject{
					[CmdletBinding()]
					param(
						[Parameter(ValueFromPipeline)]
						$InputObject,
						$Filter,
						$SearchBase,
						$Server,
						$Properties
					)
					[void](Invoke-ADPrivFilter -Filter $Filter)
					if($InputObject){
						$o = $testReportsMockCtx.testData.objectsByDn[$InputObject]
						if($o){
							$o
						}
					}else{
						if($SearchBase -ceq 'CN=Schema,CN=Configuration,DC=example,DC=com' -and $testReportsMockCtx.laps){
							@(,'ms-Mcs-AdmPwd,CN=Schema,CN=Configuration,DC=example,DC=com')
						}
					}
				}

				function Get-ADRootDSE{
					@{
						'SchemaNamingContext' = 'CN=Schema,CN=Configuration,DC=example,DC=com'
					}
				}

				function Test-ADPrivRecycleBin{}
			}

			BeforeEach{
				Reset-TestReportsMockCtx
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
					$typeCol = $objTypes[$h.objectClass]
					if(!$typeCol){
						$typeCol = $objTypes[$h.objectClass] = [System.Collections.ArrayList]::new()
					}
					[void]$typeCol.Add($h)
				}
				$testData = $testReportsMockCtx.testData
				@($objTypes['user']).Count | Should -Be $testData.users.Count
				@($objTypes['computer']).Count | Should -Be $testData.computers.Count
				@($objTypes['group']).Count | Should -Be $testData.groups.Count
			}

			Context 'DataConditionals' {
				BeforeEach{
					$ctx = Initialize-ADPrivReports
					$ctx | Should -Not -BeNullOrEmpty
				}

				It 'Invoke-ADPrivReports-Default' {
					Invoke-ADPrivReports -ctx $ctx | Should -Be $null
					$warnings.Text | Should -Not -Contain 'LAPS is not deployed!  (ms-Mcs-AdmPwd attribute does not exist.)'
				}

				It 'Invoke-ADPrivReports-NoLaps' {
					$testReportsMockCtx.laps = $false
					Invoke-ADPrivReports -ctx $ctx | Should -Be $null
					$warnings.Text | Should -Contain 'LAPS is not deployed!  (ms-Mcs-AdmPwd attribute does not exist.)'
				}

				It 'Invoke-ADPrivReports-LapsOnDc' {
					$testReportsMockCtx.lapsOnDc = $true
					Invoke-ADPrivReports -ctx $ctx | Should -Be $null
					$warnings.Text | Should -Contain 'LAPS found on possible domain controller: CN=test-dc,OU=Domain Controllers,DC=example,DC=com'
				}

				It 'Invoke-ADPrivReports-PassThru' {
					$ctx.params.passThru = $true
					Invoke-ADPrivReports -ctx $ctx | Should -BeOfType [PSCustomObject]
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

				Context 'RC4-Passwords' {
					BeforeAll{
						$stalePasswords = @{}
						foreach($p in $results.reports['stalePasswords']){
							$stalePasswords[$p.Name] = $p
						}
						# As this is executing in BeforeAll vs. BeforeEach, need to keep a copy before the warnings are cleared in the parent BeforeEach.
						$testWarnings = $warnings.Clone()
						$testWarnings | Should -Not -Be $null
					}

					It 'RC4-Warnings' {
						$testWarnings.Text | Should -Contain 'stalePasswords: 2 passwords are most likely using insecure RC4 secret keys.'
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
						$op2.PasswordLastSet | Should -Be $null
					}
				}
			}
		}
	}
}
