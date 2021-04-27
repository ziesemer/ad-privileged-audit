# Mark A. Ziesemer, www.ziesemer.com - 2020-08-27, 2021-04-27
# SPDX-FileCopyrightText: Copyright © 2020-2021, Mark A. Ziesemer

#Requires -Version 5.1

Param(
	# Technically, most of this works without elevation - but certain AD queries will not work properly without,
	#   such as filters around enabled status on AD objects.
	[Parameter(ParameterSetName='notElevated')]
	[switch]$notElevated,

	[Parameter(ParameterSetName='elevated', Mandatory=$true)]
	[switch]$elevated,
	[Parameter(ParameterSetName='elevated')]
	[switch]$batch,
	[Parameter(ParameterSetName='elevated')]
	[IO.FileInfo]$reportsFolder = $null,
	[Parameter(ParameterSetName='elevated')]
	[switch]$noFiles,
	[Parameter(ParameterSetName='elevated')]
	[switch]$noZip
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'
$InformationPreference = 'Continue'

$version = '2021-04-27'
$interactive = !$batch

$warnings = [System.Collections.ArrayList]::new()

function Write-Log{
	[CmdletBinding()]
	param(
		[Parameter()]
		[ValidateNotNullOrEmpty()]
		[object]$Message,

		[Parameter()]
		[ValidateNotNullOrEmpty()]
		[ValidateSet('ERROR', 'WARN', 'INFO', 'DEBUG', 'TRACE', IgnoreCase = $false)]
		[string]$Severity = 'INFO'
	)

	if($severity -ceq 'TRACE'){
		$color = [ConsoleColor]::DarkGray
	}elseif($severity -ceq 'DEBUG'){
		$color = [ConsoleColor]::Gray
	}elseif($severity -ceq 'INFO'){
		$color = [ConsoleColor]::Cyan
	}elseif($severity -ceq 'WARN'){
		$color = [ConsoleColor]::Yellow
		[void]$warnings.Add([PSCustomObject]@{
			Text = $Message
		})
	}elseif($severity -ceq 'ERROR'){
		$color = [ConsoleColor]::Red
	}

	$msg = "$(Get-Date -f s) [$Severity] $Message"

	# - https://stackoverflow.com/questions/38523369/write-host-vs-write-information-in-powershell-5
	# - https://blog.kieranties.com/2018/03/26/write-information-with-colours
	Write-Information $([System.Management.Automation.HostInformationMessage]@{
		Message = $msg
		ForegroundColor = $color
	})
}

function ConvertTo-ADPrivRows{
	[CmdletBinding()]
	param(
		[Parameter(Mandatory, ValueFromPipeline)]
		[PSCustomObject]$row,
		[Object[]]$property,
		[System.Collections.Generic.HashSet[string]]$dateProps = 'lastLogonTimestamp'
	)

	Begin{
		$rowCount = 1
		if($property){
			$outProps = @(, 'Row#') + $property
		}else{
			$outProps = $null
		}
	}
	Process{
		$out = [ordered]@{
			'Row#' = $rowCount++
		}
		$row |
				Get-Member -MemberType Properties |
				Select-Object -ExpandProperty Name |
				ForEach-Object{
			if($dateProps.Contains($_)){
				$out.($_ + 'Date') = if($row.$_){
					[DateTime]::FromFileTime($row.$_)
				}else{
					$null
				}
			}
			$out.$_ = $row.$_
		}
		# The Select-Object here must be called only after the the object is re-created above,
		#   including null properties for the columns requested,
		#   or operating under StrictMode will throw a PropertyNotFoundException (PropertyNotFoundException).
		return [PSCustomObject]$out |
			Select-Object -Property $outProps
	}
}

function Out-ADReports{
	[CmdletBinding()]
	param(
		[Parameter(Mandatory, ValueFromPipeline)]
		[PSCustomObject]$inputResults,
		[Parameter(Mandatory)]
		$ctx,
		[Parameter(Mandatory)]
		[string]$name,
		[string]$title
	)
	Begin{
		Write-Log "Processing $title ($name)..."
		$results = [System.Collections.ArrayList]::new()
	}
	Process{
		[void]$results.Add([PSCustomObject]$inputResults)
	}
	End{
		$results = $results.ToArray()
		$caption = "  $title ($name): "
		if($results){
			$caption += $results.Count
		}else{
			$caption += 0
		}
		Write-Log $caption
		$ctx.reports.$name = $results
		$path = ($ctx.filePattern -f ('-' + $name)) + '.csv'
		if($results){
			if(!$noFiles){
				$results | Export-Csv -NoTypeInformation -Path $path
				$ctx.reportFiles += $path
			}
			if($interactive){
				$results | Out-GridView -Title $caption
			}
		}elseif(!$noFiles){
			# Write (or overwrite) an empty file.
			[System.IO.FileStream]::new(
					$path, [System.IO.FileMode]::Create, [System.IO.FileAccess]::Write
				).Close()
			$ctx.reportFiles += $path
		}
	}
}

<#
.SYNOPSIS
	Required over the ActiveDirectory module's Get-ADGroupMember to avoid failures when ForeignSecurityPrinciples are included -
		especially for unresolved or orphaned FSPs, or due to insufficient permissions in the foreign domain.
	Also provides group details - including for potentially empty groups - and details the path by which entity is included.
#>
function Get-ADGroupMemberSafe($identity, $ctx, $path){

	Write-Log ('  Get-ADGroupMemberSafe: {0}' `
			-f $identity) `
		-Severity DEBUG

	$group = $identity | Get-ADGroup -Properties ($ctx.adProps.groupIn + 'Members')

	if(!$path){
		$path = @($group.DistinguishedName)
	}

	function New-ADGroupMemberContext($entry){
		[PSCustomObject]@{
			entry = $entry
			path = $path
		}
	}

	$group `
		| Select-Object -ExpandProperty Members `
		| Get-ADObject -PipelineVariable gm `
		| ForEach-Object{

		$oc = $gm.objectClass

		Write-Log ('    Member: gm={0}, oc={1}, group={2}' `
				-f $gm, $oc, $group) `
			-Severity DEBUG

		if($oc -ceq 'user'){
			New-ADGroupMemberContext ($gm | Get-ADUser -Properties $ctx.adProps.userIn)
		}elseif($oc -ceq 'computer'){
			New-ADGroupMemberContext ($gm | Get-ADComputer -Properties $ctx.adProps.compIn)
		}elseif($oc -ceq 'group'){
			New-ADGroupMemberContext $group
			$dn = $gm.DistinguishedName
			if($path -contains $dn){
				Write-Log ('ADGroupMemberSafe Circular Reference: "{0}" already in "{1}".' `
						-f $dn, ($path -join '; ')) `
					-Severity WARN
			}else{
				Get-ADGroupMemberSafe -identity $gm -ctx $ctx -path ($path + $dn)
			}
		}else{
			if($oc -cnotin (
				'foreignSecurityPrincipal',
				'msDS-ManagedServiceAccount',
				'msDS-GroupManagedServiceAccount'
			)){
				Write-Log ('Unexpected group member type: {0} / {1}.' `
						-f $oc, $gm.DistinguishedName) `
					-Severity WARN
			}
			New-ADGroupMemberContext ($gm | Get-ADObject -Properties $ctx.adProps.objectIn)
		}
	}
}

function Invoke-ADPrivGroups($ctx){
	# - https://docs.microsoft.com/en-us/windows-server/identity/ad-ds/plan/security-best-practices/appendix-b--privileged-accounts-and-groups-in-active-directory
	# - https://docs.microsoft.com/en-us/troubleshoot/windows-server/identity/security-identifiers-in-windows
	# - https://docs.microsoft.com/en-us/previous-versions/windows/it-pro/windows-server-2012-r2-and-2012/dn579255(v=ws.11)
	$dsid = $domain.DomainSID.Value + '-'
	$groupsIn = [ordered]@{
		'Domain Admins' = $dsid + '512'
		'Enterprise Admins' = $dsid + '519'
		'Administrators' = 'S-1-5-32-544'
		'Schema Admins' = $dsid + '518'
		'Account Operators' = 'S-1-5-32-548'
		'Server Operators' = 'S-1-5-32-549'
		'Backup Operators' = 'S-1-5-32-551'
		# DnsAdmins and DnsUpdateProxy are documented in the "dn579255" reference
		#   above as having RIDs 1102/1103.
		# However, I've also seen these as 1101/1102, and these are no longer
		#  documented as "well-known" in current documentation.
		'DnsAdmins' = $null
		'DnsUpdateProxy' = $null
		'DHCP Administrators' = $null
		'Domain Controllers' = $dsid + '516'
	}

	$groups = [System.Collections.ArrayList]::new($groupsIn.Count)
	$ctx.adProps.allOut = Get-ADProps -generated
	$ctx.adProps.objectIn = Get-ADProps 'object'
	$ctx.adProps.groupIn = Get-ADProps 'group'
	$ctx.adProps.groupOut = Get-ADProps 'group' -generated

	function Get-ADPrivGroup($identity){
		try{
			return Get-ADGroup -Identity $identity -Properties $ctx.adProps.groupIn
		}catch [Microsoft.ActiveDirectory.Management.ADIdentityNotFoundException]{
			Write-Log $_ -Severity WARN
		}
	}

	$groupsIn.GetEnumerator() | ForEach-Object{
		$groupName = $_.Name
		$expectedGroup = $_.Value

		Write-Log "  - Processing group: $($groupName)..."

		$group = Get-ADPrivGroup $groupName
		$group
		if((!$group -or $group.SID.Value -ne $expectedGroup) -and $expectedGroup){
			Write-Log ("Group `"$($groupName)`" not found, or with unexpected SID." +
					"  Also attempting as $($expectedGroup)..."
				) -Severity WARN
			$group = Get-ADPrivGroup $expectedGroup
			$group
		}
	} | ForEach-Object{
		$group = $_
		[void]$groups.Add($group)

		Get-ADGroupMemberSafe -identity $group -ctx $ctx | ForEach-Object{
			$gm = $_
			$x = [ordered]@{
				GroupSid = $group.objectSid
				GroupName = $group.Name
			}

			$gm.entry `
					| Get-Member -MemberType Properties `
					| Select-Object -ExpandProperty Name `
					| ForEach-Object{
				$x.$_ = $gm.entry.$_
			}
			$x.MemberEntry = $gm.entry
			$x.MemberPathArray = $gm.path
			$x.MemberPath = $gm.path -join '; '
			$x.MemberDepth = $gm.path.Count

			[PSCustomObject]$x
		}
	} | ConvertTo-ADPrivRows -property (@('GroupSid', 'GroupName') + $ctx.adProps.allOut + @('MemberPath', 'MemberDepth')) `
		| Out-ADReports -ctx $ctx -name 'privGroupMembers' -title 'Privileged AD Group Members'

	$groups | ConvertTo-ADPrivRows -property $ctx.adProps.groupOut `
		| Out-ADReports -ctx $ctx -name 'privGroups' -title 'Privileged AD Groups'
}

function Invoke-Reports(){
	$ctx = [ordered]@{
		params = [ordered]@{
			version = $version
			currentUser = $null
			hostName = [System.Net.Dns]::GetHostName()
			domain = $null
		}
		reports = [ordered]@{}
		reportFiles = @()
		filePattern = $null
		adProps = [ordered]@{}
	}

	Write-Log ('Version: ' + $version)

	if(!$reportsFolder){
		$desktopPath = [System.Environment]::GetFolderPath([System.Environment+SpecialFolder]::Desktop)
		$reportsFolder = Join-Path $desktopPath 'AD-Reports'
	}
	$ctx.params.reportsFolder = $reportsFolder
	Write-Log ('$reportsFolder: {0}' -f $reportsFolder)
	[void](New-Item -ItemType Directory -Path $reportsFolder -Force)

	# This doesn't affect Out-GridView, which falls back to the current user preferences in Windows.
	$currentThread = [System.Threading.Thread]::CurrentThread
	$culture = [CultureInfo]::InvariantCulture.Clone()
	$culture.DateTimeFormat.ShortDatePattern = 'yyyy-MM-dd'
	$currentThread.CurrentCulture = $culture
	$currentThread.CurrentUICulture = $culture

	$now = $ctx.params.now = Get-Date
	Write-Log ('$now: {0}' -f $now)
	$filterDate = $ctx.params.filterDate = $now.AddDays(-90)
	Write-Log ('$filterDate: {0}' -f $filterDate)
	$filterDatePassword = $ctx.params.filterDatePassword = $now.AddDays(-365)
	Write-Log ('$filterDatePassword: {0}' -f $filterDatePassword)

	$domain = $ctx.params.domain = Get-ADDomain

	$filePattern = $ctx.filePattern = Join-Path $reportsFolder `
		($domain.DNSRoot +
			'{0}-' +
			$(Get-Date -Date $now -Format 'yyyy-MM-dd'))
	Write-Log ('$filePattern: {0}' -f $filePattern)

	Write-Log 'Checking for execution as Domain Administrator...'

	$domainAdminsSid = [System.Security.Principal.SecurityIdentifier]::new(
		[System.Security.Principal.WellKnownSidType]::AccountDomainAdminsSid,
		$domain.DomainSID
	)
	$currentUser = $ctx.params.currentUser = [System.Security.Principal.WindowsIdentity]::GetCurrent()
	$windowsPrincipal = [System.Security.Principal.WindowsPrincipal]::new($currentUser)
	if($windowsPrincipal.IsInRole($domainAdminsSid)){
		Write-Log "  Running as Domain Admin: $($currentUser.Name), $domainAdminsSid"
	}else{
		Write-Log ("Current user ($($currentUser.Name)) is not running as a Domain Administrator." +
			'  Results may be incomplete!') -Severity WARN
	}

	Write-Log 'Writing parameters JSON file...'

	$paramsJsonPath = $filePattern -f '-params' + '.json'
	$ctx.params | ConvertTo-Json | Out-File $paramsJsonPath -Force
	$ctx.reportFiles += $paramsJsonPath

	# - https://docs.microsoft.com/en-us/windows/win32/adschema/classes-all
	$commonAdProps = 'objectSid', 'Name',
		@{type='class'; class='user', 'computer'; props=
			'Enabled',
			@{type='generated'; props='lastLogonTimestampDate'}, 'lastLogonTimestamp',
			'PasswordLastSet', 'PasswordNeverExpires', 'CannotChangePassword'
		},
		'whenCreated', 'whenChanged',
		'DistinguishedName', 'sAMAccountName', 
		'DisplayName', 'Description',
		@{type='class'; class='user', 'computer'; props=
			'UserPrincipalName', 'Company', 'Title', 'Department', 'EmployeeID', 'EmployeeNumber'},
		@{type='class'; class='group'; props=
			'GroupCategory', 'GroupScope', 'groupType'},
		'ObjectClass', 'ObjectGUID',
		'isCriticalSystemObject', 'ProtectedFromAccidentalDeletion'

	function Get-ADProps([string]$class, [switch]$generated){
		$props = [System.Collections.ArrayList]::new()
		function Expand-ADProp($p){
			if($p -is [string]){
				[void]$props.Add($p)
			}elseif($p -is [array]){
				$p | ForEach-Object{
					Expand-ADProp $_
				}
			}elseif($p.type -ceq 'class'){
				if(!$class -or $class -in $p.class){
					Expand-ADProp $p.props
				}
			}elseif($p.type -ceq 'generated'){
				if($generated){
					Expand-ADProp $p.props
				}
			}else{
				throw "Unhandled property type: $($p.type)"
			}
		}

		Expand-ADProp $commonAdProps
		return $props
	}

	$ctx.adProps.userIn = Get-ADProps 'user'
	$ctx.adProps.userOut = Get-ADProps 'user' -generated
	$ctx.adProps.compIn = Get-ADProps 'computer'
	$ctx.adProps.compOut = Get-ADProps 'computer' -generated

	# Privileged AD Groups and Members...

	Invoke-ADPrivGroups -ctx $ctx

	# Users that haven't logged-in within # days...

	Get-ADUser `
			-Filter {
				Enabled -eq $true -and (lastLogonTimestamp -lt $filterDate -or lastLogonTimestamp -notlike '*')
			} `
			-Properties $ctx.adProps.userIn `
		| Sort-Object -Property lastLogonTimestamp `
		| ConvertTo-ADPrivRows -property $ctx.adProps.userOut `
		| Out-ADReports -ctx $ctx -name 'staleUsers' -title 'Stale Users'

	# Users with passwords older than # days...

	Get-ADUser `
			-Filter {
				Enabled -eq $true -and (PasswordLastSet -lt $filterDatePassword)
			} `
			-Properties $ctx.adProps.userIn `
		| Sort-Object -Property PasswordLastSet `
		| ConvertTo-ADPrivRows -property $ctx.adProps.userOut `
		| Out-ADReports -ctx $ctx -name 'stalePasswords' -title 'Stale Passwords'

	# Computers that haven't logged-in within # days...

	Get-ADComputer `
			-Filter {
				Enabled -eq $true -and (lastLogonTimestamp -lt $filterDate -or lastLogonTimestamp -notlike '*')
			} `
			-Properties $ctx.adProps.compIn `
		| Sort-Object -Property lastLogonTimestamp `
		| ConvertTo-ADPrivRows -property $ctx.adProps.compOut `
		| Out-ADReports -ctx $ctx -name 'staleComps' -title 'Stale Computers'

	# Computers that haven't checked-in to LAPS, or are past their expiration times.

	$admPwdAttr = Get-ADObject -SearchBase (Get-ADRootDSE).SchemaNamingContext -Filter {name -eq 'ms-Mcs-AdmPwd'}
	if($admPwdAttr){
		function Invoke-LAPSReport($filter){
			Get-ADComputer -Filter $filter `
				-Properties ($ctx.adProps.compIn + 'ms-Mcs-AdmPwdExpirationTime') `
			| ConvertTo-ADPrivRows -property (@('ms-Mcs-AdmPwdExpirationTimeDate', 'ms-Mcs-AdmPwdExpirationTime') + $ctx.adProps.compOut) `
				-dateProps 'lastLogonTimestamp', 'ms-Mcs-AdmPwdExpirationTime'
		}
	
		Invoke-LAPSReport {
					Enabled -eq $true -and (ms-Mcs-AdmPwd -notlike '*' -or ms-Mcs-AdmPwdExpirationTime -lt $now)
				} `
			| Out-ADReports -ctx $ctx -name 'LAPS-Out' -title 'Computers without LAPS or expired.'
		Invoke-LAPSReport {
					Enabled -eq $true -and -not (ms-Mcs-AdmPwd -notlike '*' -or ms-Mcs-AdmPwdExpirationTime -lt $now)
				} `
			| Out-ADReports -ctx $ctx -name 'LAPS-In' -title 'Computers with current LAPS.'
	}else{
		Write-Log 'LAPS is not deployed!  (ms-Mcs-AdmPwd attribute does not exist.)' -Severity WARN
	}

	# Warnings

	$warnings `
		| ConvertTo-ADPrivRows `
		| Out-ADReports -ctx $ctx -name 'warnings' -title 'Warnings'

	if(!($noFiles -or $noZip)){
		Write-Log 'Creating compressed archive...'
		Compress-Archive -Path $ctx.reportFiles -DestinationPath ($filePattern -f '' + '.zip') -CompressionLevel 'Optimal' -Force
	}

	return [PSCustomObject]$ctx
}

try{
	if($elevated){
		Import-Module ActiveDirectory
		Invoke-Reports
		Write-Log 'Done!'
		if($interactive){
			Pause
		}
	}else{
		Write-Log 'Elevating...'

		Start-Process powershell.exe -ArgumentList `
			"-ExecutionPolicy Unrestricted -File `"$PSCommandPath`" -elevated" `
			-Verb RunAs
	}
}catch{
	Write-Log 'Error:', $_ -Severity ERROR
	if($interactive){
		$_ | Format-List -Force
		Pause
	}else{
		throw $_
	}
}
