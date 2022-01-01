# Mark A. Ziesemer, www.ziesemer.com - 2020-08-27, 2022-01-01
# SPDX-FileCopyrightText: Copyright © 2020-2022, Mark A. Ziesemer
# - https://github.com/ziesemer/ad-privileged-audit

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
	[switch]$noZip,
	[switch]$PassThru
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'
$InformationPreference = 'Continue'

$version = '2022-01-01'
$warnings = [System.Collections.ArrayList]::new()

function Get-ADPrivInteractive{
	!$batch
}

function Write-Log{
	[CmdletBinding()]
	param(
		[Parameter()]
		[ValidateNotNullOrEmpty()]
		[object]$Message,

		[Parameter()]
		[ValidateNotNullOrEmpty()]
		[ValidateSet('ERROR', 'WARN', 'INFO', 'DEBUG', 'TRACE', IgnoreCase=$false)]
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
	Write-Information ([System.Management.Automation.HostInformationMessage]@{
		Message = $msg
		ForegroundColor = $color
	})
}

function Invoke-Elevate{
	$path = $PSCommandPath
	Write-Log "Resolving path: $path"

	# Handle that if running from a mapped drive, the same mapping probably will not exist in the RunAs context.
	if($path -match '^([A-Z]):(.+)$'){
		$drive = Get-PSDrive $Matches[1]
		if($drive.DisplayRoot){
			$path = Join-Path $drive.DisplayRoot $Matches[2]
			Write-Log "Resolved path: $path"
		}
	}

	$psExe = (Get-Process -Id $PID).Path
	Write-Log "PowerShell executable: $psExe"

	Start-Process $psExe -ArgumentList `
		"-ExecutionPolicy Unrestricted -File `"$path`" -elevated" `
		-Verb RunAs
}

function Get-ADPrivProps([string]$class, [switch]$generated){
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

	Expand-ADProp $ctx.adProps.source
	return $props
}

function Set-ADPrivProps($ctx){
	# - https://docs.microsoft.com/en-us/windows/win32/adschema/classes-all
	$ctx.adProps.source = 'objectSid', 'Name',
		@{type='class'; class='user', 'computer'; props=
			'Enabled',
			@{type='generated'; props='lastLogonTimestampDate'}, 'lastLogonTimestamp',
			'PasswordLastSet', 'LastBadPasswordAttempt', 'PasswordExpired', 'PasswordNeverExpires', 'PasswordNotRequired', 'CannotChangePassword', 'userAccountControl'
		},
		'whenCreated', 'whenChanged',
		@{type='class'; class='user', 'computer'; props=
			'UserPrincipalName'
		},
		'sAMAccountName', 'DistinguishedName', 'CanonicalName',
		'DisplayName', 'Description',
		@{type='class'; class='user', 'computer'; props=
			'Company', 'Title', 'Department', 'Manager', 'EmployeeID', 'EmployeeNumber',
			'PrimaryGroupID', 'PrimaryGroup'},
		@{type='class'; class='group'; props=
			'GroupCategory', 'GroupScope', 'groupType'},
		@{type='class'; class='group', 'computer'; props=
			'ManagedBy'},
		@{type='class'; class='computer'; props=
			'OperatingSystem', 'OperatingSystemVersion', 'OperatingSystemServicePack', 'OperatingSystemHotfix'},
		'ObjectClass', 'ObjectGUID', 'mS-DS-ConsistencyGuid',
		'isCriticalSystemObject', 'ProtectedFromAccidentalDeletion'

	$ctx.adProps.userIn = Get-ADPrivProps 'user'
	$ctx.adProps.userOut = Get-ADPrivProps 'user' -generated
	$ctx.adProps.compIn = Get-ADPrivProps 'computer'
	$ctx.adProps.compOut = Get-ADPrivProps 'computer' -generated
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
				$out.($_ + 'Date') = if($null -ne $row.$_){
					[DateTime]::FromFileTime($row.$_)
				}else{
					$null
				}
			}
			if($_ -ieq 'mS-DS-ConsistencyGuid'){
				$out.$_ = [System.Convert]::ToBase64String($row.$_)
			}else{
				$out.$_ = $row.$_
			}
		}
		# The Select-Object here must be called only after the the object is re-created above,
		#   including null properties for the columns requested,
		#   or operating under StrictMode will throw a PropertyNotFoundException (PropertyNotFoundException).
		return [PSCustomObject]$out |
			Select-Object -Property $outProps
	}
}

function Out-ADPrivReports{
	[CmdletBinding()]
	param(
		[Parameter(Mandatory, ValueFromPipeline)]
		[PSCustomObject]$inputResults,
		[Parameter(Mandatory)]
		$ctx,
		[Parameter(Mandatory)]
		[string]$name,
		[Parameter(Mandatory)]
		[string]$title
	)
	Begin{
		$results = [System.Collections.ArrayList]::new()
	}
	Process{
		[void]$results.Add([PSCustomObject]$inputResults)
	}
	End{
		$results = $results.ToArray()
		$caption = "$title ($name): "
		if($results){
			$caption += $results.Count
		}else{
			$caption += 0
		}
		Write-Log "  $caption"
		# Reduce unnecessary memory usage in large directories with large reports.
		if($ctx.params.passThru){
			$ctx.reports.$name = $results
		}
		$path = ($ctx.filePattern -f ('-' + $name)) + '.csv'
		if($results){
			if(!$noFiles){
				$results | Export-Csv -NoTypeInformation -Path $path
				$ctx.reportFiles += $path
			}
			if(Get-ADPrivInteractive){
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
		Effectively wraps a report.
		Ensures that the processing is logged at the start of the activity, as well as providing a structure for potential future hooks.
	.NOTES
		The Get-AD* cmdlets, in particular, completely block a subsequent pipeline from even initializing - due to it returning its results in its Begin (vs. Process) block.
#>
function New-ADPrivReport{
	[CmdletBinding()]
	param(
		[Parameter(Mandatory)]
		$ctx,
		[Parameter(Mandatory)]
		[string]$name,
		[Parameter(Mandatory)]
		[string]$title,
		[Parameter(Mandatory)]
		[scriptblock]$dataSource
	)

	Write-Log "Processing $title ($name)..."
	& $dataSource | Out-ADPrivReports -ctx $ctx -name $name -title $title
}

<#
	.SYNOPSIS
		Parses RFC-2253 Distinguished Names into a list of ValueTuples.
		Required as there is no equivilent functionality publicly and readily-available to .Net or PowerShell as of this development without including 3rd-party libraries.
		(Beyond needing to introduce 3rd-party dependencies into this script, the available 3rd-party libraries reviewed would introduce further concerns
			- including that many would not even pass the unit tests included in this project, along with performance concerns, etc.)
	.NOTES
		Thread Safety: Instances of this class are absolutely *not* thread-safe.
			If used by multiple threads, each thread must use its own instance of this class.
#>
class DistinguishedNameParser{
	[System.Collections.Generic.IList[System.ValueTuple[string, string]]]$_names `
    = [System.Collections.Generic.List[System.ValueTuple[string, string]]]::new(8)
	[System.Text.StringBuilder]$_sb = [System.Text.StringBuilder]::new(32)
	[byte[]]$_utfBytes = [byte[]]::new(4)

	[bool]IsHex([char]$c){
		return ($c -cge '0' -and $c -cle '9') `
			-or ($c -cge 'A' -and $c -cle 'F') `
			-or ($c -cge 'a' -and $c -cle 'f')
	}

	[System.Collections.Generic.IList[System.ValueTuple[string, string]]]Split([string]$dn){
		[System.Collections.Generic.IList[System.ValueTuple[string, string]]]$names = $this._names
		[System.Text.StringBuilder]$sb = $this._sb
		[byte[]]$utfBytes = $this._utfBytes

		[byte]$utfBytesPos = 0
		[int]$dnLen = $dn.Length
		[string]$typePart = $null
		[string]$valuePart = $null
		[bool]$inType = $true

		$names.Clear()
		$sb.Clear()

		:charLoop for($pos = 0; $pos -lt $dnLen){
			$c = $dn[$pos++]
			while($c -ceq '\' -and $pos -lt $dnLen){
				$c1 = $dn[$pos++]
				if($this.IsHex($c1) -and $pos -lt $dnLen){
					$c2 = $dn[$pos++]
					if($this.IsHex($c2)){
						# Growing the byte array may be necessary as an unknown number of consecutive escaped byte values could be received,
						#   and without attempting to inspect each UTF-8 byte to determine the number of bytes per character.
						if($utfBytes.Length -eq $utfBytesPos){
							[byte[]]$utfBytes2 = [byte[]]::new($utfBytes.Length * 2)
							[array]::Copy($utfBytes, $utfBytes2, $utfBytesPos)
							$this._utfBytes = $utfBytes = $utfBytes2
						}
						$utfBytes[$utfBytesPos++] = [convert]::ToInt16($c1 + $c2, 16)

						if($pos -lt $dnLen){
							$c = $dn[$pos++]
							continue
						}else{
							$sb.Append([System.Text.Encoding]::UTF8.GetString($utfBytes, 0, $utfBytesPos))
							$utfBytesPos = 0
						}
					}else{
						throw 'Invalid unicode escape!'
					}
				}else{
					$sb.Append($c1)
				}
				continue charLoop
			}
			if($utfBytesPos){
				$sb.Append([System.Text.Encoding]::UTF8.GetString($utfBytes, 0, $utfBytesPos))
				$utfBytesPos = 0
			}
			if($c -ceq '='){
				$inType = $false
				$typePart = $sb.ToString()
				$sb.Clear()
				continue
			}
			if($c -ceq ','){
				$inType = $true
				$valuePart = $sb.ToString()
				$sb.Clear()
				$names.Add([System.ValueTuple]::Create($typePart, $valuePart))
				continue
			}
			$sb.Append($c)
		}
		$valuePart = $sb.ToString()
		if($typePart.Length -or $valuePart.Length){
			$names.Add([System.ValueTuple]::Create($typePart, $valuePart))
		}

		return $names
	}

	[string]GetDnsDomain([System.Collections.Generic.IList[System.ValueTuple[string, string]]]$rdns){
		return ($rdns | Where-Object{$_.Item1 -ieq 'DC'} | ForEach-Object{$_.Item2}) -join '.'
	}
}

function Initialize-ADPrivObjectCache($ctx){
	$ctx.adPrivGroupsObjCache = @{}
	foreach($cacheKey in @('user', 'computer', 'group', 'object', '@PrimaryGroupMembers')){
		$ctx.adPrivGroupsObjCache[$cacheKey] = @{}
	}
	$ctx.adPrivGroupsObjCache.dnParser = [DistinguishedNameParser]::new()
}

function Get-ADPrivObjectCache($identity, $class, $ctx){
	$cache = $ctx.adPrivGroupsObjCache
	# Had considered using a flat cache to the identity - ignoring class.
	# However, loading as a generic "object" is sometimes first required to determine the object's class
	# - which is then missing the object-class's specific attributes, without incurring a sometimes-unnecessary eager lookup.
	$classCache = $cache[$class]

	if($identity -is [string]){
		$id = $identity
	}else{
		$id = $identity.DistinguishedName
	}
	$result = $classCache[$id]
	if(!$result){
		Write-Log -Severity DEBUG "Cache miss: $class $id"
		$adParams = @{}
		$dnsDomain = $cache.dnParser.GetDnsDomain($cache.dnParser.Split($id))
		if($dnsDomain -ine $ctx.params.domain.DNSRoot){
			$adParams['Server'] = $dnsDomain
		}

		# Also store each result into more-generic "object" class cache to improve cache hits.
		if($class -ceq 'user'){
			$result = $identity | Get-ADUser @adParams -Properties $ctx.adProps.userIn
			$cache['object'][$id] = $result
		}elseif($class -ceq 'computer'){
			$result = $identity | Get-ADComputer @adParams -Properties $ctx.adProps.compIn
			$cache['object'][$id] = $result
		}elseif($class -ceq 'group'){
			$result = $identity | Get-ADGroup @adParams -Properties ($ctx.adProps.groupIn + 'Members')
			$cache['object'][$id] = $result
		}elseif($class -ceq 'object'){
			$result = $identity | Get-ADObject @adParams -Properties $ctx.adProps.objectIn
		}elseif($class -ceq '@PrimaryGroupMembers'){
			# Simply otherwise calling Get-ADObject here fails to return the computer objects.
			$result = @(Get-ADUser @adParams -Filter {PrimaryGroup -eq $group.DistinguishedName} -Properties $ctx.adProps.userIn) `
				+ @(Get-ADComputer @adParams -Filter {PrimaryGroup -eq $group.DistinguishedName} -Properties $ctx.adProps.compIn)
		}else{
			throw "Unhandled cache type: $class"
		}
		$classCache[$id] = $result
	}
	return $result
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

	$group = Get-ADPrivObjectCache $identity 'group' $ctx

	if(!$path){
		$path = @($group.DistinguishedName)
	}

	function New-ADGroupMemberContext{
		[CmdletBinding()]
		param(
			[Parameter(Mandatory, ValueFromPipeline)]
			$entry
		)
		Process{
			[PSCustomObject]@{
				entry = $entry
				path = $path
			}
		}
	}

	$group `
		| Select-Object -ExpandProperty Members `
		| ForEach-Object{

		$gm = Get-ADPrivObjectCache $_ 'object' $ctx
		$oc = $gm.objectClass

		Write-Log ('    Member: gm={0}, oc={1}, group={2}' `
				-f $gm, $oc, $group) `
			-Severity DEBUG

		if($oc -ceq 'user'){
			Get-ADPrivObjectCache $gm 'user' $ctx | New-ADGroupMemberContext
		}elseif($oc -ceq 'computer'){
			Get-ADPrivObjectCache $gm 'computer' $ctx | New-ADGroupMemberContext
		}elseif($oc -ceq 'group'){
			Get-ADPrivObjectCache $gm 'group' $ctx | New-ADGroupMemberContext
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
			Get-ADPrivObjectCache $gm 'object' $ctx | New-ADGroupMemberContext
		}
	}

	if($group.GroupScope -ne 'DomainLocal'){
		Get-ADPrivObjectCache $group '@PrimaryGroupMembers' $ctx | New-ADGroupMemberContext
	}
}

function Get-ADPrivReportsFolder(){
	if(!$reportsFolder){
		$desktopPath = [System.Environment]::GetFolderPath([System.Environment+SpecialFolder]::Desktop)
		$reportsFolder = Join-Path $desktopPath 'AD-Reports'
	}
	$reportsFolder
}

function Test-ADPrivIsAdmin($user, $domain){
	Write-Log 'Checking for execution as Domain Administrator...'

	$domainAdminsSid = [System.Security.Principal.SecurityIdentifier]::new(
		[System.Security.Principal.WellKnownSidType]::AccountDomainAdminsSid,
		$domain.DomainSID
	)

	$windowsPrincipal = [System.Security.Principal.WindowsPrincipal]::new($user)
	if($windowsPrincipal.IsInRole($domainAdminsSid)){
		Write-Log "  Running as Domain Admin: $($user.Name), $domainAdminsSid"
		$true
	}else{
		Write-Log ("  Current user ($($user.Name)) is not running as a Domain Administrator." +
			'  Results may be incomplete!') -Severity WARN
		$false
	}
}

function Initialize-ADPrivReports(){
	$ctx = [ordered]@{
		params = [ordered]@{
			version = $version
			currentUser = $null
			hostName = [System.Net.Dns]::GetHostName()
			domain = $null
			psExe = (Get-Process -Id $PID).Path
			psVersionTable = $PSVersionTable
			passThru = $PassThru
		}
		reports = [ordered]@{}
		reportFiles = @()
		filePattern = $null
		adProps = [ordered]@{}
	}

	Write-Log ('Version: ' + $version)

	$reportsFolder = Get-ADPrivReportsFolder
	$ctx.params.reportsFolder = $reportsFolder
	Write-Log ('$reportsFolder: {0}' -f $reportsFolder)
	if(!$noFiles){
		[void](New-Item -ItemType Directory -Path $reportsFolder -Force)
	}

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
			(Get-Date -Date $now -Format 'yyyy-MM-dd'))
	Write-Log ('$filePattern: {0}' -f $filePattern)

	$currentUser = $ctx.params.currentUser = [System.Security.Principal.WindowsIdentity]::GetCurrent()
	[void](Test-ADPrivIsAdmin $currentUser $domain)

	if(!$noFiles){
		Write-Log 'Writing parameters JSON file...'

		$paramsJsonPath = $filePattern -f '-params' + '.json'
		$ctx.params | ConvertTo-Json | Out-File $paramsJsonPath -Force
		$ctx.reportFiles += $paramsJsonPath
	}

	Set-ADPrivProps $ctx

	return $ctx
}

function Invoke-ADPrivGroups($ctx){
	# - https://docs.microsoft.com/en-us/windows-server/identity/ad-ds/plan/security-best-practices/appendix-b--privileged-accounts-and-groups-in-active-directory
	# - https://docs.microsoft.com/en-us/troubleshoot/windows-server/identity/security-identifiers-in-windows
	# - https://docs.microsoft.com/en-us/previous-versions/windows/it-pro/windows-server-2012-r2-and-2012/dn579255(v=ws.11)
	$dsid = $ctx.params.domain.DomainSID.Value + '-'
	$groupsIn = [ordered]@{
		'Domain Admins' = $dsid + '512'
		'Enterprise Admins' = $dsid + '519'
		'Administrators' = 'S-1-5-32-544'
		'Schema Admins' = $dsid + '518'
		'Account Operators' = 'S-1-5-32-548'
		'Server Operators' = 'S-1-5-32-549'
		'Print Operators' = 'S-1-5-32-550'
		'Backup Operators' = 'S-1-5-32-551'
		# DnsAdmins and DnsUpdateProxy are documented in the "dn579255" reference
		#   above as having RIDs 1102/1103.
		# However, I've also seen these as 1101/1102, and these are no longer
		#  documented as "well-known" in current documentation.
		'DnsAdmins' = $null
		'DnsUpdateProxy' = $null
		'DHCP Administrators' = $null
		'Domain Controllers' = $dsid + '516'
		'Enterprise Read-Only Domain Controllers' = $dsid + '498'
		'Read-Only Domain Controllers' = $dsid + '521'
	}

	$groups = [System.Collections.ArrayList]::new($groupsIn.Count)
	$ctx.adProps.allOut = Get-ADPrivProps -generated
	$ctx.adProps.objectIn = Get-ADPrivProps 'object'
	$ctx.adProps.groupIn = Get-ADPrivProps 'group'
	$ctx.adProps.groupOut = Get-ADPrivProps 'group' -generated

	Initialize-ADPrivObjectCache $ctx

	function Get-ADPrivGroup($identity){
		try{
			return Get-ADGroup -Identity $identity -Properties $ctx.adProps.groupIn
		}catch [Microsoft.ActiveDirectory.Management.ADIdentityNotFoundException]{
			Write-Log $_ -Severity WARN
		}
	}

	New-ADPrivReport -ctx $ctx -name 'privGroupMembers' -title 'Privileged AD Group Members' -dataSource {
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
		} | ConvertTo-ADPrivRows -property (@('GroupSid', 'GroupName') + $ctx.adProps.allOut + @('MemberPath', 'MemberDepth'))
	}

	$ctx.adPrivGroupsObjCache = $null

	New-ADPrivReport -ctx $ctx -name 'privGroups' -title 'Privileged AD Groups' -dataSource {
		$groups | ConvertTo-ADPrivRows -property $ctx.adProps.groupOut
	}
}

function Invoke-ADPrivReports(){
	$ctx = Initialize-ADPrivReports

	# Filters support only "simple variable references", no expressions unless shortcutted here.
	# - https://stackoverflow.com/a/44184818/751158

	$now = $ctx.params.now
	$filterDate = $ctx.params.filterDate
	$filterDatePassword = $ctx.params.filterDatePassword

	# Privileged AD Groups and Members...

	Invoke-ADPrivGroups -ctx $ctx

	# Users that haven't logged-in within # days...

	New-ADPrivReport -ctx $ctx -name 'staleUsers' -title 'Stale Users' -dataSource {
		Get-ADUser `
				-Filter {
					Enabled -eq $true -and (lastLogonTimestamp -lt $filterDate -or lastLogonTimestamp -notlike '*')
				} `
				-Properties $ctx.adProps.userIn `
			| Sort-Object -Property 'lastLogonTimestamp' `
			| ConvertTo-ADPrivRows -property $ctx.adProps.userOut
	}

	# Users with passwords older than # days...

	New-ADPrivReport -ctx $ctx -name 'stalePasswords' -title 'Stale Passwords' -dataSource {
		Get-ADUser `
				-Filter {
					Enabled -eq $true -and (PasswordLastSet -lt $filterDatePassword)
				} `
				-Properties $ctx.adProps.userIn `
			| Sort-Object -Property 'PasswordLastSet' `
			| ConvertTo-ADPrivRows -property $ctx.adProps.userOut
	}

	# Users with PasswordNotRequired set...

	New-ADPrivReport -ctx $ctx -name 'passwordNotRequired' -title 'Password Not Required' -dataSource {
		Get-ADUser `
				-Filter {
					PasswordNotRequired -eq $true
				} `
				-Properties $ctx.adProps.userIn `
			| Sort-Object -Property 'UserPrincipalName' `
			| ConvertTo-ADPrivRows -property $ctx.adProps.userOut
	}

	# Users with SIDHistory...

	New-ADPrivReport -ctx $ctx -name 'sidHistory' -title 'SID History' -dataSource {
		Get-ADUser `
				-Filter {
					SIDHistory -like '*'
				} `
				-Properties $ctx.adProps.userIn `
			| Sort-Object -Property 'UserPrincipalName' `
			| ConvertTo-ADPrivRows -property $ctx.adProps.userOut
	}

	# Computers that haven't logged-in within # days...

	New-ADPrivReport -ctx $ctx -name 'staleComps' -title 'Stale Computers' -dataSource {
		Get-ADComputer `
				-Filter {
					Enabled -eq $true -and (lastLogonTimestamp -lt $filterDate -or lastLogonTimestamp -notlike '*')
				} `
				-Properties $ctx.adProps.compIn `
			| Sort-Object -Property 'lastLogonTimestamp' `
			| ConvertTo-ADPrivRows -property $ctx.adProps.compOut
	}

	# Computers with unsupported operating systems...

	New-ADPrivReport -ctx $ctx -name 'unsupportedOS' -title 'Unsupported Operating Systems' -dataSource {
		Get-ADComputer `
				-Filter {
					Enabled -eq $true -and (OperatingSystem -like 'Windows*')
				} `
				-Properties $ctx.adProps.compIn `
			| ForEach-Object {
				$osVer = $_.OperatingSystemVersion -split ' '
				$osVer1 = [decimal]$osVer[0]
				if($_.OperatingSystem.StartsWith('Windows Server')){
					if($osVer1 -lt 6.2){
						$_
					}
				}elseif($osVer1 -lt 6.3){
					$_
				}
			} | Sort-Object -Property 'OperatingSystemVersion' `
			| ConvertTo-ADPrivRows -property $ctx.adProps.compOut
	}

	# Computers that haven't checked-in to LAPS, or are past their expiration times.

	$admPwdAttr = Get-ADObject -SearchBase (Get-ADRootDSE).SchemaNamingContext -Filter {name -eq 'ms-Mcs-AdmPwd'}
	if($admPwdAttr){
		function Invoke-LAPSReport($filter){
			Get-ADComputer -Filter $filter `
					-Properties ($ctx.adProps.compIn + 'ms-Mcs-AdmPwdExpirationTime') `
				| Sort-Object -Property 'ms-Mcs-AdmPwdExpirationTime', 'lastLogonTimestamp' `
				| ConvertTo-ADPrivRows -property (@('ms-Mcs-AdmPwdExpirationTimeDate', 'ms-Mcs-AdmPwdExpirationTime') + $ctx.adProps.compOut) `
					-dateProps 'lastLogonTimestamp', 'ms-Mcs-AdmPwdExpirationTime'
		}

		New-ADPrivReport -ctx $ctx -name 'LAPS-Out' -title 'Computers without LAPS or expired.' -dataSource {
			Invoke-LAPSReport {
				Enabled -eq $true -and (ms-Mcs-AdmPwd -notlike '*' -or ms-Mcs-AdmPwdExpirationTime -lt $now -or ms-Mcs-AdmPwdExpirationTime -notlike '*')
			} | Where-Object {
				-not ($_.DistinguishedName -eq ('CN=' + $_.Name + ',' + $ctx.params.domain.DomainControllersContainer) -and $_.PrimaryGroupID -in (516, 498, 521))
			}
		}
		New-ADPrivReport -ctx $ctx -name 'LAPS-In' -title 'Computers with current LAPS.' -dataSource {
			Invoke-LAPSReport {
				Enabled -eq $true -and -not (ms-Mcs-AdmPwd -notlike '*' -or ms-Mcs-AdmPwdExpirationTime -lt $now -or ms-Mcs-AdmPwdExpirationTime -notlike '*')
			}
		}

		@(Get-ADComputer -Filter {
			Enabled -eq $true
				-and (ms-Mcs-AdmPwd -like '*' -or ms-Mcs-AdmPwdExpirationTime -like '*')
				-and (PrimaryGroupID -eq 516 -or PrimaryGroupID -eq 498 -or PrimaryGroupID -eq 521)
		}) + @(Get-ADComputer -Filter {
			Enabled -eq $true
				-and (ms-Mcs-AdmPwd -like '*' -or ms-Mcs-AdmPwdExpirationTime -like '*')
		} -SearchBase $ctx.params.domain.DomainControllersContainer) `
			| Sort-Object -Unique DistinguishedName `
			| ForEach-Object{
				Write-Log "LAPS found on possible domain controller: $($_.DistinguishedName)" -Severity WARN
			}
	}else{
		Write-Log 'LAPS is not deployed!  (ms-Mcs-AdmPwd attribute does not exist.)' -Severity WARN
	}

	# Warnings

	New-ADPrivReport -ctx $ctx -name 'warnings' -title 'Warnings' -dataSource {
		$warnings `
			| ConvertTo-ADPrivRows
	}

	if(!($noFiles -or $noZip)){
		Write-Log 'Creating compressed archive...'
		Compress-Archive -Path $ctx.reportFiles -DestinationPath ($ctx.filePattern -f '' + '.zip') -CompressionLevel 'Optimal' -Force
	}

	if($PassThru){
		return [PSCustomObject]$ctx
	}
}

function Invoke-ADPrivMain(){
	try{
		if($elevated){
			Import-Module ActiveDirectory
			Invoke-ADPrivReports
			Write-Log 'Done!'
			if(Get-ADPrivInteractive){
				Pause
			}
		}else{
			Write-Log 'Elevating...'
			Invoke-Elevate
		}
	}catch{
		Write-Log 'Error:', $_ -Severity ERROR
		if(Get-ADPrivInteractive){
			$_ | Format-List -Force
			Pause
		}else{
			throw $_
		}
	}
}

if($MyInvocation.InvocationName -ne '.'){
	Invoke-ADPrivMain
}
