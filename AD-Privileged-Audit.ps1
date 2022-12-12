# Mark A. Ziesemer, www.ziesemer.com - 2020-08-27, 2022-12-12
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

$version = '2022-12-12'
$warnings = [System.Collections.ArrayList]::new()

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

	if($Severity -ceq 'TRACE'){
		$color = [ConsoleColor]::DarkGray
	}elseif($Severity -ceq 'DEBUG'){
		$color = [ConsoleColor]::Gray
	}elseif($Severity -ceq 'INFO'){
		$color = [ConsoleColor]::Cyan
	}elseif($Severity -ceq 'WARN'){
		$color = [ConsoleColor]::Yellow
		[void]$warnings.Add([PSCustomObject]@{
			Text = $Message
		})
	}elseif($Severity -ceq 'ERROR'){
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

function Resolve-ADPrivProps([string]$class, [string]$context=$null, [switch]$generated){
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
		}elseif($p.type -ceq 'context'){
			if($context -and $context -in @($p.context)){
				Expand-ADProp $p.props
			}
		}else{
			throw "Unhandled property type: $($p.type)"
		}
	}

	Expand-ADProp $ctx.adProps.source
	return $props
}

function Initialize-ADPrivProps($ctx){
	# - https://docs.microsoft.com/en-us/windows/win32/adschema/classes-all
	$ctx.adProps.source = 'objectSid', 'Name',
		@{type='class'; class='user', 'computer'; props=
			'Enabled',
			@{type='generated'; props='lastLogonTimestampDate'}, 'lastLogonTimestamp',
			'PasswordLastSet',
			@{type='context'; context='stalePasswords'; props='RC4'},
			'LastBadPasswordAttempt', 'PasswordExpired', 'PasswordNeverExpires', 'PasswordNotRequired', 'CannotChangePassword', 'userAccountControl'
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

	$ctx.adProps.allOut = Resolve-ADPrivProps -generated
	$ctx.adProps.userIn = Resolve-ADPrivProps 'user'
	$ctx.adProps.userOut = Resolve-ADPrivProps 'user' -generated
	$ctx.adProps.compIn = Resolve-ADPrivProps 'computer'
	$ctx.adProps.compOut = Resolve-ADPrivProps 'computer' -generated
	$ctx.adProps.groupIn = Resolve-ADPrivProps 'group'
	$ctx.adProps.groupOut = Resolve-ADPrivProps 'group' -generated
	$ctx.adProps.objectIn = Resolve-ADPrivProps 'object'
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
		foreach($p in $row.PSObject.Properties.Name){
			if($dateProps.Contains($p)){
				$out.($p + 'Date') = if($null -ne $row.$p){
					[DateTime]::FromFileTime($row.$p)
				}else{
					$null
				}
			}
			if($p -ieq 'mS-DS-ConsistencyGuid'){
				$out.$p = [System.Convert]::ToBase64String($row.$p)
			}else{
				$out.$p = $row.$p
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
		$path = ($ctx.params.filePattern -f ('-' + $name)) + '.csv'
		if($results){
			if(!$ctx.params.noFiles){
				$results | Export-Csv -NoTypeInformation -Path $path -Encoding $ctx.params.fileEncoding
				$ctx.reportFiles[$name] = $path
			}
			if($ctx.params.interactive){
				$results | Out-GridView -Title $caption
			}
		}elseif(!$ctx.params.noFiles){
			# Write (or overwrite) an empty file.
			[System.IO.FileStream]::new(
					$path, [System.IO.FileMode]::Create, [System.IO.FileAccess]::Write
				).Close()
			$ctx.reportFiles[$name] = $path
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
	if(!$classCache){
		throw "Unhandled cache type: $class"
	}

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
			$gsearchId = $id.Replace("'", "''")
			$result = @(Get-ADUser @adParams -Filter "PrimaryGroup -eq '$gsearchId'" -Properties $ctx.adProps.userIn) `
				+ @(Get-ADComputer @adParams -Filter "PrimaryGroup -eq '$gsearchId'" -Properties $ctx.adProps.compIn)
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
		$oc = $gm.ObjectClass

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
	$ExecutionContext.SessionState.Path.GetUnresolvedProviderPathFromPSPath($reportsFolder)
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
			interactive = !$batch
			filePattern = $null
			firstRunFiles = $false
			noFiles = $noFiles
			noZip = $noZip
			passThru = $PassThru
			fileEncoding = "UTF8"
		}
		attribs = @{
			domainControllers = $null
			rodcDate = $null
		}
		reports = [ordered]@{}
		reportFiles = [ordered]@{}
		adProps = [ordered]@{}
	}

	Write-Log ('Version: ' + $version)

	$reportsFolder = Get-ADPrivReportsFolder
	$ctx.params.reportsFolder = $reportsFolder
	Write-Log ('$reportsFolder: {0}' -f $reportsFolder)
	if(!$ctx.params.noFiles){
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

	if($PSVersionTable.PSVersion.Major -ge 6){
		$ctx.params.fileEncoding = 'utf8BOM'
	}

	$domain = $ctx.params.domain = Get-ADDomain

	$currentUser = $ctx.params.currentUser = [System.Security.Principal.WindowsIdentity]::GetCurrent()
	[void](Test-ADPrivIsAdmin $currentUser $domain)

	$filePattern = $ctx.params.filePattern = Join-Path $reportsFolder `
		($domain.DNSRoot +
			'{0}-' +
			(Get-Date -Date $now -Format 'yyyy-MM-dd'))
	Write-Log ('$filePattern: {0}' -f $filePattern)

	if(!$ctx.params.noFiles){
		$firstRunSearch = Join-Path $reportsFolder ($domain.DNSRoot + '-*')
		if(!(Get-ChildItem -Path $firstRunSearch -File)){
			Write-Log ('firstRunFiles: {0}' -f $firstRunSearch)
			$ctx.params.firstRunFiles = $true
		}

		Write-Log 'Writing parameters JSON file...'

		$paramsJsonPath = $filePattern -f '-params' + '.json'
		$ctx.params | ConvertTo-Json | Out-File $paramsJsonPath -Force -Encoding $ctx.params.fileEncoding
		$ctx.reportFiles['params'] = $paramsJsonPath
	}

	Initialize-ADPrivProps $ctx

	return $ctx
}

function New-ADPrivGroups($ctx){
	# - https://docs.microsoft.com/en-us/windows/security/identity-protection/access-control/active-directory-security-groups
	# 	- https://docs.microsoft.com/en-us/previous-versions/windows/it-pro/windows-server-2012-r2-and-2012/dn579255(v=ws.11)
	# - https://docs.microsoft.com/en-us/windows-server/identity/ad-ds/plan/security-best-practices/appendix-b--privileged-accounts-and-groups-in-active-directory
	# - https://docs.microsoft.com/en-us/troubleshoot/windows-server/identity/security-identifiers-in-windows
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
	return $groupsIn
}

function Get-ADPrivGroup($identity){
	try{
		return Get-ADGroup -Identity $identity -Properties $ctx.adProps.groupIn
	}catch [Microsoft.ActiveDirectory.Management.ADIdentityNotFoundException]{
		Write-Log $_ -Severity WARN
	}
}

function Invoke-ADPrivGroups($ctx){
	$groupsIn = New-ADPrivGroups -ctx $ctx
	$groups = [System.Collections.ArrayList]::new($groupsIn.Count)
	$dcs = $ctx.attribs.domainControllers = @{}
	$dcSid = $groupsIn['Domain Controllers']
	$rodcSid = $groupsIn['Read-Only Domain Controllers']

	Initialize-ADPrivObjectCache $ctx

	New-ADPrivReport -ctx $ctx -name 'privGroupMembers' -title 'Privileged AD Group Members' -dataSource {
		$groupsIn.GetEnumerator() | ForEach-Object{
			$groupName = $_.Name
			$expectedGroup = $_.Value

			Write-Log "  - Processing group: $($groupName)..."

			$group = Get-ADPrivGroup $groupName
			$group
			if((!$group -or $group.objectSid.Value -ne $expectedGroup) -and $expectedGroup){
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

				if($group.objectSid -eq $dcSid){
					$dcs[$gm.entry.DistinguishedName] = $gm.entry
				}

				$x = [ordered]@{
					GroupSid = $group.objectSid
					GroupName = $group.Name
				}

				foreach($p in $gm.entry.PSObject.Properties.Name){
					$x.$p = $gm.entry.$p
				}
				$x.MemberEntry = $gm.entry
				$x.MemberPathArray = $gm.path
				$x.MemberPath = $gm.path -join '; '
				$x.MemberDepth = $gm.path.Count

				[PSCustomObject]$x
			}

			if($group.objectSid -eq $rodcSid){
				$ctx.attribs.rodcDate = $group.whenCreated
			}
		} | ConvertTo-ADPrivRows -property (@('GroupSid', 'GroupName', 'MemberDepth') + $ctx.adProps.allOut + @('MemberPath'))
	}

	$ctx.adPrivGroupsObjCache = $null

	New-ADPrivReport -ctx $ctx -name 'privGroups' -title 'Privileged AD Groups' -dataSource {
		$groups | ConvertTo-ADPrivRows -property $ctx.adProps.groupOut
	}
}

function Invoke-ADPrivReportHistory($ctx){
	if(!(Test-Path $ctx.params.reportsFolder -PathType Container)){
		Write-Log 'Invoke-ADPrivReportHistory: reportsFolder does not exist, exiting.'
		return
	}

	New-ADPrivReport -ctx $ctx -name 'reportHistory' -title 'AD Privileged Audit Report History' -dataSource {

		# Rename LAPS report files created prior to 2022-01-08 to standard.

		$reportNameLapsPattern = [regex]::new('(.*)-LAPS-((?:In|Out)-\d{4}-\d{2}-\d{2}\.csv)')
		Get-ChildItem -Path ($ctx.params.reportsFolder + '\*-LAPS-*.csv') | ForEach-Object{
			$match = $reportNameLapsPattern.Match($_.Name)
			if($match.Success){
				$newName = $match.Groups[1].Value + "-laps" + $match.Groups[2].Value
				Write-Log ('Renaming prior LAPS CSV to new standard: "{0}" -> "{1}"' -f $_.Name, $newName)
				Rename-Item -Path $_.FullName -NewName $newName
			}
		}

		$rowCounts = @{}
		$rptHistRowCountCacheCsv = Join-Path $ctx.params.reportsFolder "$($ctx.params.domain.DNSRoot)-reportHistory-RowCountCache.csv"
		if(Test-Path $rptHistRowCountCacheCsv -PathType Leaf){
			Import-Csv -Path $rptHistRowCountCacheCsv | ForEach-Object{
				$rowCounts[$_.CsvFile] = [int]$_.RowCount
			}
		}else{
			Write-Log '  No row count cache found.'
		}

		$reportNamePattern = [regex]::new('(.*)-(.*)-(\d{4}-\d{2}-\d{2})(?:-(initial))?\.csv')
		Get-ChildItem -Path ($ctx.params.reportsFolder + '\*.csv') -Exclude '*-reportHistory-*' | ForEach-Object -Process {
			$csvFile = $_
			$rowCount = $rowCounts[$csvFile.Name]
			if($null -eq $rowCount){
				$rowCount = (Import-Csv -Path $csvFile | Measure-Object).Count
				$rowCounts[$csvFile.Name] = $rowCount
			}
			$result = [PSCustomObject][ordered]@{
				'CsvFile' = $csvFile.Name
				'Domain' = $null
				'Report' = $null
				'Date' = $null
				'DateSuffix' = $null
				'RowCount' = $rowCount
			}

			$match = $reportNamePattern.Match($csvFile.Name)
			if($match.Success){
				$result.Domain = $match.Groups[1].Value
				$result.Report = $match.Groups[2].Value
				$result.Date = $match.Groups[3].Value
				$result.DateSuffix = $match.Groups[4].Value
			}

			$result
		} -End{
			$rowCounts.GetEnumerator() | Sort-Object -Property Key | ForEach-Object{
				[PSCustomObject][ordered]@{
					CsvFile = $_.Key
					RowCount = $_.Value
				}
			} | Export-Csv -NoTypeInformation -Path $rptHistRowCountCacheCsv -Encoding $ctx.params.fileEncoding
		} | Sort-Object -Property 'Domain', 'Report', 'Date', 'DateSuffix', 'CsvFile' `
			| ConvertTo-ADPrivRows
	}
}

function Test-ADPrivStalePasswords($ctx, $filterDatePasswd){
	$rodcDate = $ctx.attribs.rodcDate
	if($rodcDate -and $rodcDate -gt $filterDatePasswd){
		Write-Log ('Read-Only Domain Controllers (RODC) creation date is more recent than requested stale password filter threshold, using RODC creation date instead: {0}' -f $rodcDate)
		$filterDatePasswd = $ctx.attribs.rodcDate
	}

	$filterDatePasswdFt = $filterDatePasswd.ToFileTime()
	$filterDatePasswdKrbtgtFt = $ctx.params.now.AddDays(-90).ToFileTime()
	$outProps = Resolve-ADPrivProps 'user' -context 'stalePasswords' -generated
	$rc4Count = 0

	New-ADPrivReport -ctx $ctx -name 'stalePasswords' -title 'Stale Passwords' -dataSource {
		Get-ADUser `
				-Filter (
					"(Enabled -eq `$true -and pwdLastSet -lt $filterDatePasswdFt) -or ((sAMAccountName -eq 'krbtgt' -or sAMAccountName -like 'krbtgt_*') -and pwdLastSet -lt $filterDatePasswdKrbtgtFt)"
				) `
				-Properties $ctx.adProps.userIn `
			| Sort-Object -Property 'PasswordLastSet', 'whenCreated' `
			| ConvertTo-ADPrivRows -property $outProps `
			| ForEach-Object{
				if($rodcDate){
					$rc4 = $false
					if($_.PasswordLastSet){
						if($_.PasswordLastSet -lt $rodcDate){
							$rc4 = $true
						}
					}elseif($_.whenCreated -lt $rodcDate){
						$rc4 = $true
					}
					if($rc4){
						$_.RC4 = $true
						([ref]$rc4Count).Value++
					}
				}
				$_
			}
	}

	if($rc4Count){
		Write-Log "stalePasswords: $rc4Count passwords are most likely using insecure RC4 secret keys." -Severity WARN
	}
}

function Test-ADPrivSidHistory($ctx){
	New-ADPrivReport -ctx $ctx -name 'sidHistory' -title 'SID History' -dataSource {
		$filter = (
			"SIDHistory -like '*'"
		)
		@(Get-ADUser -Filter $filter -Properties $ctx.adProps.userIn) `
			+ @(Get-ADComputer -Filter $filter -Properties $ctx.adProps.compIn) `
			+ @(Get-ADGroup -Filter $filter -Properties $ctx.adProps.objectIn) `
			| Sort-Object -Property 'Name' `
			| ConvertTo-ADPrivRows -property $ctx.adProps.allOut
	}
}

function Test-ADPrivAADPasswordProtection($ctx){
	$ppStats = @{
		numDCAgents = 0
		numProxies = 0
		numDCsMissingAgents = 0
	}

	$ppObjTemplate = @{
		Computer = $null
		IsDC = $false
		IsAgent = $false
		IsProxy = $false
		AgentVersion = $null
		AgentHeartbeat = $null
		AgentPasswordPolicyDate = $null
		ProxyVersion = $null
		ProxyHeartbeat = $null
		ProxyTenantName = $null
		ProxyTenantId = $null
	}

	$ppObjs = @{}
	$ctx.attribs.domainControllers.GetEnumerator() | ForEach-Object{
		$x = $ppObjTemplate.Clone()
		$x.Computer = $_.Value
		$x.IsDC = $true
		$ppObjs[$_.Name] = $x
	}

	function ConvertFrom-ADPrivAADPPMsdsSettings($s){
		if($s.StartsWith('{')){
			return $s | ConvertFrom-Json
		}
		$x = $s.Split('.')[1].Replace('-', '+').Replace('_', '/')
		if($m = $x.Length % 4){
			$x = $x + '=' * (4 - $m)
		}
		[text.encoding]::UTF8.GetString([convert]::FromBase64String($x)) `
			| ConvertFrom-Json
	}

	function Invoke-ADPrivAADPPSCP($cn, $keyword, [scriptblock]$sb){
		Get-ADObject -Filter "ObjectClass -eq 'serviceConnectionPoint' -and keywords -like '{$keyword}*'" -Properties 'msDS-Settings' | ForEach-Object{
			Write-Log "${cn}: $($_.DistinguishedName)" -Severity DEBUG
			$prefix = "CN=$cn,"
			if($_.DistinguishedName.StartsWith($prefix)){
				$compDn = $_.DistinguishedName.Substring($prefix.Length)

				$ppObj = $ppObjs[$compDn]
				if(!$ppObj){
					$ppObj = $ppObjTemplate.Clone()
					$ppObj.Computer = Get-ADComputer -Identity $compDn -Properties $ctx.adProps.compIn
					$ppObjs[$compDn] = $ppObj
				}

				$ppMsds = ConvertFrom-ADPrivAADPPMsdsSettings $_.'msDS-Settings'

				& $sb -ppObj $ppObj -ppMsds $ppMsds
			}else{
				Write-Log ('Unexpected DN searching for {0}: {1}' `
						-f $cn, $_.DistinguishedName) `
					-Severity WARN
			}
		}
	}

	Invoke-ADPrivAADPPSCP 'AzureADPasswordProtectionDCAgent' '2bac71e6-a293-4d5b-ba3b-50b995237946' {
		param($ppObj, $ppMsds)
		$ppObj.IsAgent = $true
		$ppObj.AgentVersion = $ppMsds.SoftwareVersion
		$ppObj.AgentHeartbeat = [datetime]$ppMsds.HeartbeatUTC
		$ppObj.AgentPasswordPolicyDate = [datetime]$ppMsds.PasswordPolicyDateUTC
		$ppStats.numDCAgents++
	}
	Invoke-ADPrivAADPPSCP 'AzureADPasswordProtectionProxy' 'ebefb703-6113-413d-9167-9f8dd4d24468' {
		param($ppObj, $ppMsds)
		$ppObj.IsProxy = $true
		$ppObj.ProxyVersion = $ppMsds.SoftwareVersion
		$ppObj.ProxyHeartbeat = [datetime]$ppMsds.HeartbeatUTC
		$ppObj.ProxyTenantName = $ppMsds.TenantName
		$ppObj.ProxyTenantId = $ppMsds.TenantId
		$ppStats.numProxies++
	}

	foreach($ppObj in $ppObjs.Values){
		if($ppObj.IsDC -and !$ppObj.IsAgent){
			$ppStats.numDCsMissingAgents++
		}
	}

	$logPrefix = 'Azure Active Directory (AAD) Password Protection: '
	if(($ppStats.numDCAgents + $ppStats.numProxies) -eq 0){
		Write-Log ($logPrefix + 'Not deployed.  (Does require AAD Premium licensing.)') -Severity WARN
	}else{
		if($ppStats.numDCAgents -ne $ctx.attribs.domainControllers.Count -or $ppStats.numDCsMissingAgents){
			Write-Log ($logPrefix + 'Not consistently deployed to every Domain Controller!') -Severity WARN
		}
		if($ppStats.numProxies -eq 0){
			Write-Log ($logPrefix + 'No proxies found!') -Severity WARN
		}elseif($ppStats.numProxies -eq 1 -and $ctx.attribs.domainControllers.Count -gt 1){
			Write-Log ($logPrefix + 'Only 1 proxy found for more than one Domain Controller.') -Severity WARN
		}

		New-ADPrivReport -ctx $ctx -name 'aadPasswordProtection' -title 'Azure Active Directory (AAD) Password Protection' -dataSource {
			$ppObjs.Values | ForEach-Object{
				$x = $_.Clone()
				foreach($p in $_.Computer.PSObject.Properties.Name){
					$x.$p = $_.Computer.$p
				}
				[PSCustomObject]$x
			} | Sort-Object -Property 'Name' `
				| ConvertTo-ADPrivRows -property (@(
					'Name', 'IsDC', 'IsAgent', 'IsProxy'
					'AgentVersion', 'AgentHeartbeat', 'AgentPasswordPolicyDate'
					'ProxyVersion', 'ProxyHeartbeat', 'ProxyTenantName', 'ProxyTenantId'
				) + ($ctx.adProps.compOut | Where-Object {$_ -ne 'Name'}))
		}
	}
}

function Test-ADPrivRecycleBin($ctx){
	$recycleBinEnabledScopes = (Get-ADOptionalFeature -Filter "Name -eq 'Recycle Bin Feature'").EnabledScopes
	if($recycleBinEnabledScopes){
		Write-Log 'AD Recycle Bin is enabled.'
	}else{
		Write-Log 'AD Recycle Bin is not enabled!' -Severity WARN
	}
}

function Invoke-ADPrivReports($ctx){
	# Filters support only "simple variable references", no expressions unless shortcutted here.
	# - https://stackoverflow.com/a/44184818/751158

	$filterDate = $ctx.params.filterDate.ToFileTime()

	# Privileged AD Groups and Members...

	Invoke-ADPrivGroups -ctx $ctx

	# Users that haven't logged-in within # days...

	New-ADPrivReport -ctx $ctx -name 'staleUsers' -title 'Stale Users' -dataSource {
		Get-ADUser `
				-Filter (
					"Enabled -eq `$true -and (lastLogonTimestamp -lt $filterDate -or lastLogonTimestamp -notlike '*')"
				) `
				-Properties $ctx.adProps.userIn `
			| Sort-Object -Property 'lastLogonTimestamp', 'whenCreated' `
			| ConvertTo-ADPrivRows -property $ctx.adProps.userOut
	}

	# Users with passwords older than # days...

	Test-ADPrivStalePasswords -ctx $ctx -filterDatePasswd $ctx.params.filterDatePassword

	# Users with PasswordNotRequired set...

	New-ADPrivReport -ctx $ctx -name 'passwordNotRequired' -title 'Password Not Required' -dataSource {
		Get-ADUser `
				-Filter (
					"PasswordNotRequired -eq `$true"
				) `
				-Properties $ctx.adProps.userIn `
			| Sort-Object -Property 'UserPrincipalName' `
			| ConvertTo-ADPrivRows -property $ctx.adProps.userOut
	}

	# SIDHistory...

	Test-ADPrivSidHistory -ctx $ctx

	# Computers that haven't logged-in within # days...

	New-ADPrivReport -ctx $ctx -name 'staleComps' -title 'Stale Computers' -dataSource {
		Get-ADComputer `
				-Filter (
					"Enabled -eq `$true -and (lastLogonTimestamp -lt $filterDate -or lastLogonTimestamp -notlike '*')"
				) `
				-Properties $ctx.adProps.compIn `
			| Sort-Object -Property 'lastLogonTimestamp', 'whenCreated' `
			| ConvertTo-ADPrivRows -property $ctx.adProps.compOut
	}

	# Users / computers with future lastLogonTimestamps...

	New-ADPrivReport -ctx $ctx -name 'futureLastLogons' -title 'Future lastLogonTimestamps' -dataSource {
		# (Consider this comment itself an obligatory "Back to the Future" reference!)
		$filterDate = $ctx.params.now.AddDays(7).ToFileTime()
		$filter = (
			"Enabled -eq `$true -and (lastLogonTimestamp -ge $filterDate)"
		)
		@(Get-ADUser -Filter $filter -Properties $ctx.adProps.userIn) `
			+ @(Get-ADComputer -Filter $filter -Properties $ctx.adProps.compIn) `
			| Sort-Object -Property 'lastLogonTimestamp' `
			| ConvertTo-ADPrivRows -property $ctx.adProps.compOut
	}

	# Computers with unsupported operating systems...

	New-ADPrivReport -ctx $ctx -name 'unsupportedOS' -title 'Unsupported Operating Systems' -dataSource {
		Get-ADComputer `
				-Filter (
					"Enabled -eq `$true -and (OperatingSystem -like 'Windows*')"
				) `
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
			} | Sort-Object -Property 'OperatingSystemVersion', 'OperatingSystem', 'lastLogonTimestamp' `
			| ConvertTo-ADPrivRows -property $ctx.adProps.compOut
	}

	# Computers that haven't checked-in to LAPS, or are past their expiration times.

	$admPwdAttr = Get-ADObject -SearchBase (Get-ADRootDSE).SchemaNamingContext -Filter "name -eq 'ms-Mcs-AdmPwd'"
	if($admPwdAttr){
		$now = $ctx.params.now.ToFileTime()

		function Invoke-LAPSReport([string]$adFilter, [scriptblock]$whereFilter){
			if(!$whereFilter){
				$whereFilter = {$true}
			}
			Get-ADComputer -Filter $adFilter `
					-Properties ($ctx.adProps.compIn + 'ms-Mcs-AdmPwdExpirationTime') `
				| Where-Object $whereFilter `
				| Sort-Object -Property 'ms-Mcs-AdmPwdExpirationTime', 'lastLogonTimestamp' `
				| ConvertTo-ADPrivRows -property (@('ms-Mcs-AdmPwdExpirationTimeDate', 'ms-Mcs-AdmPwdExpirationTime') + $ctx.adProps.compOut) `
					-dateProps 'lastLogonTimestamp', 'ms-Mcs-AdmPwdExpirationTime'
		}

		New-ADPrivReport -ctx $ctx -name 'lapsOut' -title 'Computers without LAPS or expired.' -dataSource {
			Invoke-LAPSReport `
				-adFilter "Enabled -eq `$true -and (ms-Mcs-AdmPwd -notlike '*' -or ms-Mcs-AdmPwdExpirationTime -lt $now -or ms-Mcs-AdmPwdExpirationTime -notlike '*')" `
				-whereFilter {
					-not ($_.DistinguishedName -eq ('CN=' + $_.Name + ',' + $ctx.params.domain.DomainControllersContainer) -and $_.PrimaryGroupID -in (516, 498, 521))
				}
		}
		New-ADPrivReport -ctx $ctx -name 'lapsIn' -title 'Computers with current LAPS.' -dataSource {
			Invoke-LAPSReport `
				"Enabled -eq `$true -and -not (ms-Mcs-AdmPwd -notlike '*' -or ms-Mcs-AdmPwdExpirationTime -lt $now -or ms-Mcs-AdmPwdExpirationTime -notlike '*')"
		}

		@(Get-ADComputer -Filter `
			("Enabled -eq `$true" `
				+ " -and (ms-Mcs-AdmPwd -like '*' -or ms-Mcs-AdmPwdExpirationTime -like '*')" `
				+ ' -and (PrimaryGroupID -eq 516 -or PrimaryGroupID -eq 498 -or PrimaryGroupID -eq 521)')
		) + @(Get-ADComputer -Filter `
			("Enabled -eq `$true" `
				+ " -and (ms-Mcs-AdmPwd -like '*' -or ms-Mcs-AdmPwdExpirationTime -like '*')") `
			-SearchBase $ctx.params.domain.DomainControllersContainer
		) | Sort-Object -Unique DistinguishedName `
			| ForEach-Object{
				Write-Log "LAPS found on possible domain controller: $($_.DistinguishedName)" -Severity WARN
			}
	}else{
		Write-Log 'LAPS is not deployed!  (ms-Mcs-AdmPwd attribute does not exist.)' -Severity WARN
	}

	# Azure Active Directory (AAD) Password Protection

	Test-ADPrivAADPasswordProtection -ctx $ctx

	# Recycle Bin

	Test-ADPrivRecycleBin -ctx $ctx

	# Warnings

	New-ADPrivReport -ctx $ctx -name 'warnings' -title 'Warnings' -dataSource {
		$warnings `
			| ConvertTo-ADPrivRows
	}

	# Post-run File Processing

	if(!($ctx.params.noFiles)){
		if(!($ctx.params.noZip)){
			Write-Log 'Creating compressed archive...'
			$zipPath = $ctx.params.filePattern -f '' + '.zip'
			Compress-Archive -Path $ctx.reportFiles.Values -DestinationPath $zipPath -CompressionLevel 'Optimal' -Force
			$ctx.reportFiles['zip'] = $zipPath
		}

		if($ctx.params.firstRunFiles){
			Write-Log 'Copying files as initial run...'
			foreach($f in $ctx.reportFiles.Values){
				$f2 = $f -replace '\.[^\.\\]+$', '-initial$0'
				Copy-Item -Path $f -Destination $f2
			}
		}

		Invoke-ADPrivReportHistory -ctx $ctx
	}

	if($ctx.params.passThru){
		return [PSCustomObject]$ctx
	}
}

function Invoke-ADPrivMain(){
	try{
		if($elevated){
			Import-Module ActiveDirectory
			$ctx = Initialize-ADPrivReports
			Invoke-ADPrivReports -ctx $ctx
			Write-Log 'Done!'
			if($ctx.params.interactive){
				Pause
			}
		}else{
			Write-Log 'Elevating...'
			Invoke-Elevate
		}
	}catch{
		Write-Log 'Error:', $_ -Severity ERROR
		if(!$batch){
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
