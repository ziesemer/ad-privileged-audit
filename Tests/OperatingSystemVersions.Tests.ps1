# Mark A. Ziesemer, www.ziesemer.com
# SPDX-FileCopyrightText: Copyright © 2023-2024, Mark A. Ziesemer

#Requires -Version 5.1
#Requires -Modules @{ModuleName='Pester'; ModuleVersion='5.3.1'}

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

Describe 'OperatingSystemVersions'{
	BeforeAll {
		. $PSScriptRoot\..\AD-Privileged-Audit.ps1

		$osVersions = Initialize-ADPrivOSVersions
		# Work-around to silence "is assigned but never used" warning from PSScriptAnalyzer.
		$osVersions | Should -Not -BeNullOrEmpty

		$ctx = [PSCustomObject]@{
			osVersions = $osVersions
			params = [PSCustomObject]@{
				now = Get-Date
			}
		}
		$ctx | Should -Be $ctx

		function Test-ADPrivOSExclusion($row){
			if($row.'OperatingSystem' -match '(Preview( \d+)?|Evaluation)$'){
				return $true
			}
			if($row.'OperatingSystem' -eq 'Windows 10 Team'){
				return $true
			}
			if($row.'OperatingSystem' -eq 'Windows XP Professional'){
				if($row.'OperatingSystemVersion' -in '5.2 (3790)'){ # Beta 1
					return $true
				}
			}
			if($row.'OperatingSystemVersion' -in
						# Insider Preview Builds
						'10.0 (22598)',
						'10.0 (25393)',
						'10.0 (26085)'
					){
				return $true
			}
		}
	}

	It 'Availability-IsDate' {
		$osVersions.Values | ForEach-Object{
			$_.'Builds'.Values.'Availability' | ForEach-Object{
				if($_ -is [string]){
					Get-Date -Date $_
				}else{
					$_.Values | ForEach-Object{
						Get-Date -Date $_
					}
				}
			}
		}
	}

	It 'EndOfServicing-Tuesday' {
		$exemptDates = @('2004-12-31', '2005-06-30')
		$osVersions.Values | ForEach-Object{
			$_.'Builds'.Values.'EndOfServicing'.Values | ForEach-Object{
				if($_ -is [string]){
					if($_ -notin $exemptDates){
						(Get-Date -Date $_).DayOfWeek | Should -Be 'Tuesday'
					}
				}else{
					$_.Values | ForEach-Object{
						if($_ -notin $exemptDates){
							(Get-Date -Date $_).DayOfWeek | Should -Be 'Tuesday'
						}
					}
				}
			}
		}
	}

	It 'Unmatched-Version-Build' {
		$row = [PSCustomObject]@{
			'OperatingSystem' = '$Unmatched'
			'OperatingSystemVersion' = '10.0 (22598)'
		}
		Write-Log "Inspecting: $row"
		$osVer = Get-ADPrivOSVersion $ctx $row
		$osVer | Should -Not -Be $null
		Write-Log "  Found: $osVer"
		$osVer.Version | Should -Be '10.0'
		$osVer.Build | Should -Be 22598
		$osVer.Build | Should -BeOfType [int]
	}

	BeforeDiscovery {
		$sampleOsVersions = Import-Csv -Path 'Tests\OperatingSystemVersions.csv'
		$sampleOsVersions | Should -Be $sampleOsVersions
	}

	Context 'CSV-Samples'{

		Context '<_>' -ForEach $sampleOsVersions {
			It 'Raw' {
				$row = $_
				if(Test-ADPrivOSExclusion $row){
					return
				}
				Write-Log "Inspecting: $row"
				$osMatch = $osVersionPattern.Match($row.'OperatingSystemVersion')
				$osMatch.Success | Should -Be $true -Because $row.'OperatingSystemVersion'

				$osVer = $osVersions[$osMatch.Groups[1].Value]
				$osVer | Should -Not -Be $null
				$cats = $osVer.'Categories'
				$cats.Keys | Should -Contain $row.'OperatingSystem'

				$tier = $cats[$row.'OperatingSystem']
				$tier | Should -Not -Be $null

				$searchBuild = $osMatch.Groups[2].Value
				if($searchBuild -ne ''){
					$searchBuild = [int]$searchBuild
				}
				$build = $osVer.'Builds'[$searchBuild]
				$build | Should -Not -Be $null

				$build.Version | Should -Not -Be $null

				$availability = $build.Availability
				$availability | Should -Not -Be $null
				if($availability -isnot [string]){
					$availability = $build.Availability[$tier]
					$availability | Should -Not -Be $null
				}

				$endOfServicing = $build.EndOfServicing
				$endOfServicing | Should -Not -Be $null
				if($endOfServicing -isnot [string]){
					$endOfServicing = $build.EndOfServicing[$tier]
					$endOfServicing | Should -Not -Be $null
				}

				Write-Log "  Found: - T: $tier - V: $($build.Version) - A: $availability - EOS: $endOfServicing"
			}

			Context 'Get-ADPrivOSVersion' {

				BeforeAll {
					$row = $_
					$exclude = Test-ADPrivOSExclusion $row
					if(!$exclude){
						Write-Log "Inspecting: $row"
						$osVer = Get-ADPrivOSVersion $ctx $row
						$osVer | Should -Be $osVer
					}
				}

				It 'Get' {
					if($exclude){
						return
					}
					$osVer | Should -Not -Be $null
					Write-Log "  Found: $osVer"
				}

				It 'EndOfServicingMainstream' {
					if($exclude){
						return
					}
					$osVer.EndOfServicingMainstream | Should -BeOfType [string]
					Get-Date -Date $osVer.EndOfServicingMainstream
				}

				It 'EndOfServicingMaxLife' {
					if($exclude){
						return
					}
					$osVer.EndOfServicingMaxLife | Should -BeOfType [int]
				}
			}
		}
	}
}
