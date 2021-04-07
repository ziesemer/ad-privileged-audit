#Requires -Version 5.1
#Requires -Modules ActiveDirectory

# Mark A. Ziesemer, www.ziesemer.com - 2020-08-27, 2021-04-06

Param(
	# Technically, most of this works without elevation - but certain AD queries will not work properly without,
	#   such as filters around enabled status on AD objects.
	[switch]$elevated = $false,
	[switch]$batch = $false,
	[IO.FileInfo]$reportsFolder = $null
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'
$InformationPreference = 'Continue'

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

function Out-Reports{
	[CmdletBinding()]
	param(
		[Parameter(Mandatory, ValueFromPipeline)]
		[object[]]$results,
		[Parameter(Mandatory)]
		$ctx,
		[Parameter(Mandatory)]
		[string]$name,
		[string]$title
	)
	Begin{
		Write-Log "Processing $title ($name)..."
	}
	End{
		$caption = "  $title ($name): "
		if($results){
			$caption += $results.Count
		}else{
			$caption += 0
		}
		Write-Log $caption
		$ctx.reports.$name = $results
		$path = $ExecutionContext.InvokeCommand.ExpandString($ctx.filePattern)
		if($results){
			$results | Export-Csv -NoTypeInformation -Path $path
			if($interactive){
				$results | Out-GridView -Title $caption
			}
		}else{
			# Write (or overwrite) an empty file.
			[void][System.IO.FileStream]::new($path, [System.IO.FileMode]::Create, [System.IO.FileAccess]::Write)
		}
	}
}

function Invoke-Reports(){
	$out = [ordered]@{
		params = [ordered]@{}
		reports = [ordered]@{}
		filePattern = $null
	}

	if(!$reportsFolder){
		$desktopPath = [System.Environment]::GetFolderPath([System.Environment+SpecialFolder]::Desktop)
		$reportsFolder = Join-Path $desktopPath 'AD-Reports'
	}
	$out.params.reportsFolder = $reportsFolder
	Write-Log ('$reportsFolder: {0}' -f $reportsFolder)
	[void](New-Item -ItemType Directory -Path $reportsFolder -Force)

	$domain = $out.params.domain = Get-ADDomain

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

	$filePattern = $out.filePattern = Join-Path $reportsFolder `
		($domain.DNSRoot +
			'-$($name)-' +
			$(Get-Date -Date $now -Format 'yyyy-MM-dd') +
			'.csv')
	Write-Log ('$filePattern: {0}' -f $filePattern)

	$commonAdProps = 'Name', 'Enabled',
		@{key='lastLogonTimestampDate'; generated=$true}, 'lastLogonTimestamp',
		'PasswordLastSet', 'whenCreated', 'whenChanged',
		'DisplayName', 'DistinguishedName', 'UserPrincipalName', 'SamAccountName', 'ObjectClass', 
		'Description',
		'ObjectGUID', 'ObjectSID'

	$commonAdPropsIn = $commonAdProps | ForEach-Object{
		if($_ -is [string]){
			$_
		}elseif(!$_.generated -eq $true){
			$_.key
		}
	}
	$commonAdPropsOut = $commonAdProps | ForEach-Object{
		if($_ -is [string]){
			$_
		}elseif($_.generated -eq $true){
			$_.key
		}
	}

	# Privileged AD Group Members...

	# - https://docs.microsoft.com/en-us/windows-server/identity/ad-ds/plan/security-best-practices/appendix-b--privileged-accounts-and-groups-in-active-directory
	('Domain Admins', 'Administrators', 'Schema Admins', 'Enterprise Admins',
			'Account Operators', 'Backup Operators', 'Server Operators',
			'DnsAdmins', 'DHCP Administrators', 'Domain Controllers'
			) | ForEach-Object{
		$groupName = $_

		Write-Log "  - Processing group: $($groupName)..."

		try{
			$group = Get-ADGroup -Identity $groupName
		}catch [Microsoft.ActiveDirectory.Management.ADIdentityNotFoundException]{
			Write-Log $_ -Severity WARN
		}

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

			$ado = $gm | & $getCmd -Properties $commonAdPropsIn

			$x = [Ordered]@{
				Group = $group.DistinguishedName
			}

			$commonAdPropsIn | ForEach-Object {
				$x.$_ = $ado.$_
			}

			[PSCustomObject]$x
		}
	} | Convert-Timestamps `
		| Select-Object -Property @(,'Group' + $commonAdPropsOut) `
		| Out-Reports -ctx $out -name 'privGroupMembers' -title 'Privileged AD Group Members'

	# Users that haven't logged-in within # days...

	Get-ADUser `
			-Filter {
				Enabled -eq $true -and (lastLogonTimestamp -lt $filterDate -or lastLogonTimestamp -notlike '*')
			} `
			-Properties $commonAdPropsIn `
		| Convert-Timestamps `
		| Sort-Object -Property lastLogonTimestamp `
		| Select-Object -Property $commonAdPropsOut `
		| Out-Reports -ctx $out -name 'staleUsers' -title 'Stale Users'

	# Users with passwords older than # days...

	Get-ADUser `
			-Filter {
				Enabled -eq $true -and (PasswordLastSet -lt $filterDatePassword)
			} `
			-Properties $commonAdPropsIn `
		| Convert-Timestamps `
		| Sort-Object -Property PasswordLastSet `
		| Select-Object -Property $commonAdPropsOut `
		| Out-Reports -ctx $out -name 'stalePasswords' -title 'Stale Passwords'

	# Computers that haven't logged-in within # days...

	Get-ADComputer `
			-Filter {
				Enabled -eq $true -and (lastLogonTimestamp -lt $filterDate -or lastLogonTimestamp -notlike '*')
			} `
			-Properties $commonAdPropsIn `
		| Convert-Timestamps `
		| Sort-Object -Property lastLogonTimestamp `
		| Select-Object -Property $commonAdPropsOut `
		| Out-Reports -ctx $out -name 'staleComps' -title 'Stale Computers'

	# Computers that haven't checked-in to LAPS, or are past their expiration times.

	$admPwdAttr = Get-ADObject -SearchBase (Get-ADRootDSE).SchemaNamingContext -Filter {name -eq 'ms-Mcs-AdmPwd'}
	if($admPwdAttr){
		Get-ADComputer -Filter {
					Enabled -eq $true -and (ms-Mcs-AdmPwd -notlike '*' -or ms-Mcs-AdmPwdExpirationTime -lt $now)
				} `
				-Properties ($commonAdPropsIn + 'ms-Mcs-AdmPwdExpirationTime') `
			| Convert-Timestamps -dateProps 'lastLogonTimestamp', 'ms-Mcs-AdmPwdExpirationTime' `
			| Select-Object -Property (@('ms-Mcs-AdmPwdExpirationTimeDate', 'ms-Mcs-AdmPwdExpirationTime') + $commonAdPropsOut) `
			| Out-Reports -ctx $out -name 'noLAPS' -title 'Computers without LAPS'
	}else{
		Write-Log 'LAPS is not deployed!  (ms-Mcs-AdmPwd attribute does not exist.)' -Severity WARN
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
