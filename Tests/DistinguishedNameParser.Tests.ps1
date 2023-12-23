# Mark A. Ziesemer, www.ziesemer.com
# SPDX-FileCopyrightText: Copyright © 2020-2023, Mark A. Ziesemer

#Requires -Version 5.1
#Requires -Modules @{ModuleName='Pester'; ModuleVersion='5.3.1'}

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

Describe 'DistinguishedNameParser'{
	BeforeAll {
		. $PSScriptRoot\..\AD-Privileged-Audit.ps1

		$dnp = [DistinguishedNameParser]::new()
		# Work-around to silence "is assigned but never used" warning from PSScriptAnalyzer.
		$dnp | Should -Not -BeNullOrEmpty
	}

	It 'Test-Hex'{
		$dnp.IsHex('0') | Should -Be $true
		$dnp.IsHex('A') | Should -Be $true
		$dnp.IsHex('a') | Should -Be $true
		$dnp.IsHex('x') | Should -Be $false
	}

	It 'DN-Parse-Trial-<name>' -ForEach @(
		# - https://docs.microsoft.com/en-us/previous-versions/windows/desktop/ldap/distinguished-names
		@{Name='Test-MS-0'; dn='CN=Jeff Smith,OU=Sales,DC=Fabrikam,DC=COM'; expected=(
			('CN', 'Jeff Smith'),	('OU', 'Sales'), ('DC', 'Fabrikam'), ('DC', 'COM')
		)}
		@{Name='Test-MS-1'; dn='CN=Karen Berge,CN=admin,DC=corp,DC=Fabrikam,DC=COM'; expected=(
			('CN', 'Karen Berge'),	('CN', 'admin'), ('DC', 'corp'), ('DC', 'Fabrikam'), ('DC', 'COM')
		)}
		@{Name='Test-MS-2'; dn='CN=Litware,OU=Docs\, Adatum,DC=Fabrikam,DC=COM'; expected=(
			('CN', 'Litware'), ('OU', 'Docs, Adatum'), ('DC', 'Fabrikam'), ('DC', 'COM')
		)}
		@{Name='Test-MS-3'; dn='CN=Before\0DAfter,OU=Test,DC=North America,DC=Fabrikam,DC=COM'; expected=(
			('CN', "Before`rAfter"), ('OU', 'Test'), ('DC', 'North America'), ('DC', 'Fabrikam'), ('DC', 'COM')
		)}

		# - https://datatracker.ietf.org/doc/html/rfc2253#section-5
		@{Name='Test-RFC-2253-5-0'; dn='CN=Steve Kille,O=Isode Limited,C=GB'; expected=(
			('CN', 'Steve Kille'),	('O', 'Isode Limited'), ('C', 'GB')
		)}
		# Need to further consider how to even work with multi-valued RDNs - as they are not even supported by AD.
		# - https://docs.microsoft.com/en-us/openspecs/windows_protocols/ms-adts/3c96b56d-d7a7-46f1-9883-7d031f9fa01e
		# - https://social.technet.microsoft.com/Forums/lync/en-US/68710ea7-3f70-4a88-acdc-b226ea429131/does-ad-lds-support-multivalued-rdn?forum=winserverDS
		# - https://stackoverflow.com/questions/24511367/active-directory-multi-valued-rdn
		# @{Name='Test-RFC-2253-5-1'; dn='OU=Sales+CN=J. Smith,O=Widget Inc.,C=US'; expected=(
		# )}
		@{Name='Test-RFC-2253-5-2'; dn='CN=L. Eagle,O=Sue\, Grabbit and Runn,C=GB'; expected=(
			('CN', 'L. Eagle'),	('O', 'Sue, Grabbit and Runn'), ('C', 'GB')
		)}
		@{Name='Test-RFC-2253-5-3'; dn='CN=Before\0DAfter,O=Test,C=GB'; expected=(
			('CN', "Before`rAfter"),	('O', 'Test'), ('C', 'GB')
		)}
		# Even this comes back as UTF-8 from AD without escaping to hexadecimal - but may as well support...
		@{Name='Test-RFC-2253-5-5'; dn='SN=Lu\C4\8Di\C4\87'; expected=(
			# If this doesn't round-trip through the test as expected, ensure this test file is saved as UTF-8 with BOM (utf8bom).
			,('SN', 'Lučić')
		)}
		# Test consecutive hexpairs.
		@{Name='Test-RFC-2253-5-5b'; dn='SN=Lu\C4\8D\C4\87'; expected=(
			,('SN', 'Lučć')
		)}
		# Test consecutive, variable-width hexpairs (3-byte + 2-byte).
		@{Name='Test-RFC-2253-5-5c'; dn='SN=Lu\E2\82\AC\C4\8D'; expected=(
			,('SN', 'Lu€č')
		)}

		@{Name='Test0'; dn='DC=example,DC=com'; expected=(
			('DC', 'example'), ('DC', 'com')
		)}
		@{Name='Test1'; dn='CN=Test1,OU=Test2,DC=example,DC=com'; expected=(
			('CN', 'Test1'), ('OU', 'Test2'), ('DC', 'example'), ('DC', 'com')
		)}
		@{Name='Test2'; dn='CN=Test1,OU=Test2,DC=bad\,example,DC=com'; expected=(
			('CN', 'Test1'), ('OU', 'Test2'), ('DC', 'bad,example'), ('DC', 'com')
		)}
		@{Name='Test3'; dn='CN=Test1,OU=Test2\,DC\=Test3,DC=example,DC=com'; expected=(
			('CN', 'Test1'), ('OU', 'Test2,DC=Test3'), ('DC', 'example'), ('DC', 'com')
		)}
		@{Name='Test4'; dn='CN=Test1,OU=Test2\\,DC=Test3,DC=example,DC=com'; expected=(
			('CN', 'Test1'), ('OU', 'Test2\'), ('DC', 'Test3'), ('DC', 'example'), ('DC', 'com')
		)}

		@{Name='TestEmpty'; dn=''; expected=@()}
		@{Name='TestIncompleteEscape'; dn='DC=com\'; expected=(
			,('DC', 'com\'))}
	){
		$split = $dnp.Split($dn)

		$x = foreach($y in $expected){
			[System.ValueTuple]::Create($y[0], $y[1])
		}
		$split | Should -Be $x
	}

	It 'Invalid-Unicode-Escape' {
		{$dnp.Split('CN=\ag')} | Should -Throw -ExpectedMessage 'Invalid unicode escape!'
	}

	It 'GetDnsDomain' {
		$rdns = $dnp.Split('CN=Jeff Smith,OU=Sales,DC=Fabrikam,DC=COM')
		$domain = $dnp.GetDnsDomain($rdns)
		$domain | Should -Be 'Fabrikam.COM'
	}
}
