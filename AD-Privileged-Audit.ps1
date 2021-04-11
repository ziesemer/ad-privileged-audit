#Requires -Version 5.1
#Requires -Modules ActiveDirectory

# Mark A. Ziesemer, www.ziesemer.com - 2020-08-27, 2021-04-11

Param(
	# Technically, most of this works without elevation - but certain AD queries will not work properly without,
	#   such as filters around enabled status on AD objects.
	[Parameter(ParameterSetName="notElevated")]
	[switch]$notElevated,

	[Parameter(ParameterSetName="elevated", Mandatory=$true)]
	[switch]$elevated,
	[Parameter(ParameterSetName="elevated")]
	[switch]$batch,
	[Parameter(ParameterSetName="elevated")]
	[IO.FileInfo]$reportsFolder = $null,
	[Parameter(ParameterSetName="elevated")]
	[switch]$noFiles,
	[Parameter(ParameterSetName="elevated")]
	[switch]$noZip
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'
$InformationPreference = 'Continue'

$version = '2021-04-11'
$interactive = !$batch

function Write-Log{
	[CmdletBinding()]
	param(
		[Parameter()]
		[ValidateNotNullOrEmpty()]
		[object]$Message,

		[Parameter()]
		[ValidateNotNullOrEmpty()]
		[ValidateSet('ERROR', 'WARN', 'INFO', 'DEBUG', 'TRACE')]
		[string]$Severity = 'INFO'
	)

	switch($Severity){
		'ERROR'{
			$color = [ConsoleColor]::Red
		}
		'WARN'{
			$color = [ConsoleColor]::Yellow
		}
		'INFO'{
			$color = [ConsoleColor]::Cyan
		}
		'DEBUG'{
			$color = [ConsoleColor]::Gray
		}
		'TRACE'{
			$color = [ConsoleColor]::DarkGray
		}
	}

	$msg = "$(Get-Date -f s) [$Severity] $Message"

	# - https://stackoverflow.com/questions/38523369/write-host-vs-write-information-in-powershell-5
	# - https://blog.kieranties.com/2018/03/26/write-information-with-colours
	Write-Information $([System.Management.Automation.HostInformationMessage]@{
		Message = $msg
		ForegroundColor = $color
	})
}

function Convert-Timestamps{
	[CmdletBinding()]
	param(
		[Parameter(Mandatory, ValueFromPipeline)]
		[PSCustomObject]$row,
		[System.Collections.Generic.HashSet[string]]$dateProps = 'lastLogonTimestamp'
	)

	Process{
		$out = [ordered]@{}
		$row | Get-Member -MemberType Properties | Select-Object -ExpandProperty Name | ForEach-Object {
			if($dateProps.Contains($_)){
				$out.($_ + 'Date') = if($row.$_){
					[DateTime]::FromFileTime($row.$_)
				}else{
					$null
				}
			}
			$out.$_ = $row.$_
		}
		return [PSCustomObject]$out
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
		$results = New-Object System.Collections.ArrayList
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
			[void][System.IO.FileStream]::new($path, [System.IO.FileMode]::Create, [System.IO.FileAccess]::Write)
			$ctx.reportFiles += $path
		}
	}
}

function Invoke-ADPrivGroups(){
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
	$groupAdProps = Get-ADProps 'group'

	function Get-ADPrivGroup($identity){
		try{
			$group = Get-ADGroup -Identity $identity -Properties $groupAdProps
			[void]$groups.Add($group)
			return $group
		}catch [Microsoft.ActiveDirectory.Management.ADIdentityNotFoundException]{
			Write-Log $_ -Severity WARN
		}
	}

	Write-Log 'Processing Privileged AD Group Members (phase 1)...'

	$groupsIn.GetEnumerator() | ForEach-Object{
		$groupName = $_.Name
		$expectedGroup = $_.Value

		Write-Log "  - Processing group: $($groupName)..."

		$group = Get-ADPrivGroup $groupName
		if((!$group -or $group.SID.Value -ne $expectedGroup) -and $expectedGroup){
			Write-Log ("Group `"$($groupName)`" not found, or with unexpected SID." +
				"  Also attempting as $($expectedGroup)..."
			) -Severity WARN
			$group = Get-ADPrivGroup $expectedGroup
		}
	}

	$groups | ForEach-Object{
		$group = $_
		Write-Log "  - Processing group: $($group.Name)..."

		$group | Get-ADGroupMember -Recursive -PipelineVariable gm | ForEach-Object{
			$getCmd = (&{switch($gm.objectClass){
				'user'{
					'Get-ADUser'
				}
				'computer'{
					'Get-ADComputer'
				}
				'group'{
					# Ignore, handled by -Recursive above.
				}
				default{
					throw "Unhandled group member type: $gm.objectClass"
				}
			}})

			$ado = $gm | & $getCmd -Properties $userAdPropsIn

			$x = [ordered]@{
				GroupSid = $group.objectSid
				GroupName = $group.Name
			}

			$userAdPropsIn | ForEach-Object {
				$x.$_ = $ado.$_
			}

			[PSCustomObject]$x
		}
	} | Convert-Timestamps `
		| Select-Object -Property (@('GroupSid', 'GroupName') + $userAdPropsOut) `
		| Out-ADReports -ctx $out -name 'privGroupMembers' -title 'Privileged AD Group Members'

	$groups | Select-Object -Property $groupAdProps `
		| Out-ADReports -ctx $out -name 'privGroups' -title 'Privileged AD Groups'
}

function Invoke-Reports(){
	$out = [ordered]@{
		params = [ordered]@{
			version = $version
			currentUser = $null
			hostName = [System.Net.Dns]::GetHostName()
			domain = $null
		}
		reports = [ordered]@{}
		reportFiles = @()
		filePattern = $null
	}

	Write-Log ('Version: ' + $version)

	if(!$reportsFolder){
		$desktopPath = [System.Environment]::GetFolderPath([System.Environment+SpecialFolder]::Desktop)
		$reportsFolder = Join-Path $desktopPath 'AD-Reports'
	}
	$out.params.reportsFolder = $reportsFolder
	Write-Log ('$reportsFolder: {0}' -f $reportsFolder)
	[void](New-Item -ItemType Directory -Path $reportsFolder -Force)

	# This doesn't affect Out-GridView, which falls back to the current user preferences in Windows.
	$currentThread = [System.Threading.Thread]::CurrentThread
	$culture = [CultureInfo]::InvariantCulture.Clone()
	$culture.DateTimeFormat.ShortDatePattern = 'yyyy-MM-dd'
	$currentThread.CurrentCulture = $culture
	$currentThread.CurrentUICulture = $culture

	$now = $out.params.now = Get-Date
	Write-Log ('$now: {0}' -f $now)
	$filterDate = $out.params.filterDate = $now.AddDays(-90)
	Write-Log ('$filterDate: {0}' -f $filterDate)
	$filterDatePassword = $out.params.filterDatePassword = $now.AddDays(-365)
	Write-Log ('$filterDatePassword: {0}' -f $filterDatePassword)

	$domain = $out.params.domain = Get-ADDomain

	$filePattern = $out.filePattern = Join-Path $reportsFolder `
		($domain.DNSRoot +
			'{0}-' +
			$(Get-Date -Date $now -Format 'yyyy-MM-dd'))
	Write-Log ('$filePattern: {0}' -f $filePattern)

	Write-Log 'Checking for execution as Domain Administrator...'

	$domainAdminsSid = [System.Security.Principal.SecurityIdentifier]::new(
		[System.Security.Principal.WellKnownSidType]::AccountDomainAdminsSid,
		$domain.DomainSID
	)
	$currentUser = $out.params.currentUser = [System.Security.Principal.WindowsIdentity]::GetCurrent()
	$windowsPrincipal = [System.Security.Principal.WindowsPrincipal]::new($currentUser)
	if($windowsPrincipal.IsInRole($domainAdminsSid)){
		Write-Log "  Running as Domain Admin: $($currentUser.Name), $domainAdminsSid"
	}else{
		Write-Log ("Current user ($($currentUser.Name)) is not running as a Domain Administrator." +
			'  Results may be incomplete!') -Severity WARN
	}

	Write-Log 'Writing parameters JSON file...'

	$paramsJsonPath = $filePattern -f '-params' + '.json'
	$out.params | ConvertTo-Json | Out-File $paramsJsonPath -Force
	$out.reportFiles += $paramsJsonPath

	$commonAdProps = 'objectSid', 'Name',
		@{type='class'; class='user', 'computer'; props=
			'Enabled',
			@{type='generated'; props='lastLogonTimestampDate'}, 'lastLogonTimestamp',
			'PasswordLastSet', 'PasswordNeverExpires', 'CannotChangePassword'
		},
		'whenCreated', 'whenChanged',
		'DistinguishedName', 'sAMAccountName', 
		'DisplayName', 'Description',
		@{type='class'; class='user'; props=
			'UserPrincipalName', 'Company', 'Title', 'Department', 'EmployeeID', 'EmployeeNumber'},
		@{type='class'; class='group'; props=
			'GroupCategory', 'GroupScope', 'groupType'},
		'ObjectClass', 'ObjectGUID',
		'isCriticalSystemObject', 'ProtectedFromAccidentalDeletion'

	function Get-ADProps([string]$class, [switch]$generated){
		$props = New-Object System.Collections.ArrayList
		function Expand-ADProp($p){
			if($p -is [string]){
				[void]$props.Add($p)
			}elseif($p -is [array]){
				$p | ForEach-Object{
					Expand-ADProp $_
				}
			}else{
				switch($p.type){
					'class'{
						if($class -in $p.class){
							Expand-ADProp $p.props
						}
					}
					'generated'{
						if($generated){
							Expand-ADProp $p.props
						}
					}
					default{
						throw "Unhandled property type: $($p.type)"
					}
				}
			}
		}

		Expand-ADProp $commonAdProps
		return $props
	}

	$userAdPropsIn = Get-ADProps 'user'
	$userAdPropsOut = Get-ADProps 'user' -generated
	$compAdPropsIn = Get-ADProps 'computer'
	$compAdPropsOut = Get-ADProps 'computer' -generated

	# Privileged AD Groups and Members...

	Invoke-ADPrivGroups

	# Users that haven't logged-in within # days...

	Get-ADUser `
			-Filter {
				Enabled -eq $true -and (lastLogonTimestamp -lt $filterDate -or lastLogonTimestamp -notlike '*')
			} `
			-Properties $userAdPropsIn `
		| Convert-Timestamps `
		| Sort-Object -Property lastLogonTimestamp `
		| Select-Object -Property $userAdPropsOut `
		| Out-ADReports -ctx $out -name 'staleUsers' -title 'Stale Users'

	# Users with passwords older than # days...

	Get-ADUser `
			-Filter {
				Enabled -eq $true -and (PasswordLastSet -lt $filterDatePassword)
			} `
			-Properties $userAdPropsIn `
		| Convert-Timestamps `
		| Sort-Object -Property PasswordLastSet `
		| Select-Object -Property $userAdPropsOut `
		| Out-ADReports -ctx $out -name 'stalePasswords' -title 'Stale Passwords'

	# Computers that haven't logged-in within # days...

	Get-ADComputer `
			-Filter {
				Enabled -eq $true -and (lastLogonTimestamp -lt $filterDate -or lastLogonTimestamp -notlike '*')
			} `
			-Properties $compAdPropsIn `
		| Convert-Timestamps `
		| Sort-Object -Property lastLogonTimestamp `
		| Select-Object -Property $compAdPropsOut `
		| Out-ADReports -ctx $out -name 'staleComps' -title 'Stale Computers'

	# Computers that haven't checked-in to LAPS, or are past their expiration times.

	$admPwdAttr = Get-ADObject -SearchBase (Get-ADRootDSE).SchemaNamingContext -Filter {name -eq 'ms-Mcs-AdmPwd'}
	if($admPwdAttr){
		function Invoke-LAPSReport($filter){
			Get-ADComputer -Filter $filter `
				-Properties ($compAdPropsIn + 'ms-Mcs-AdmPwdExpirationTime') `
			| Convert-Timestamps -dateProps 'lastLogonTimestamp', 'ms-Mcs-AdmPwdExpirationTime' `
			| Select-Object -Property (@('ms-Mcs-AdmPwdExpirationTimeDate', 'ms-Mcs-AdmPwdExpirationTime') + $compAdPropsOut)
		}
	
		Invoke-LAPSReport {
					Enabled -eq $true -and (ms-Mcs-AdmPwd -notlike '*' -or ms-Mcs-AdmPwdExpirationTime -lt $now)
				} `
			| Out-ADReports -ctx $out -name 'LAPS-Out' -title 'Computers without LAPS or expired.'
		Invoke-LAPSReport {
					Enabled -eq $true -and -not (ms-Mcs-AdmPwd -notlike '*' -or ms-Mcs-AdmPwdExpirationTime -lt $now)
				} `
			| Out-ADReports -ctx $out -name 'LAPS-In' -title 'Computers with current LAPS.'
	}else{
		Write-Log 'LAPS is not deployed!  (ms-Mcs-AdmPwd attribute does not exist.)' -Severity WARN
	}

	if(!($noFiles -or $noZip)){
		Write-Log 'Creating compressed archive...'
		Compress-Archive -Path $out.reportFiles -DestinationPath ($filePattern -f '' + '.zip') -CompressionLevel 'Optimal' -Force
	}

	return [PSCustomObject]$out
}

try{
	if($elevated){
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
