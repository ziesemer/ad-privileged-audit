#Requires -Version 5.1
#Requires -Modules ActiveDirectory

# Mark A. Ziesemer, www.ziesemer.com - 2020-08-27, 2021-03-31

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
	[cmdletbinding()]
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

function Invoke-Reports(){
	$out = [ordered]@{}

	if(!$reportsFolder){
		$desktopPath = [System.Environment]::GetFolderPath([System.Environment+SpecialFolder]::Desktop)
		$reportsFolder = "$desktopPath\AD-Reports"
	}
	$out.reportsFolder = $reportsFolder
	Write-Log "`$reportsFolder: $($reportsFolder)"
	[void](New-Item -ItemType Directory -Path $reportsFolder -Force)

	$now = Get-Date
	$filterDate = $out.filterDate = $now.AddDays(-90)
	Write-Log "`$filterDate: $filterDate"
	$filterDatePassword = $out.filterDatePasword = $now.AddDays(-365)
	Write-Log "`$filterDatePassword: $filterDatePassword"

	$csvDateExt = '-' + $(Get-Date -Format 'yyyy-MM-dd') + '.csv'
	Write-Log "`$csvDateExt: $csvDateExt"

	$currentThread = [System.Threading.Thread]::CurrentThread
	$culture = [CultureInfo]::InvariantCulture.Clone()
	$culture.DateTimeFormat.ShortDatePattern = 'yyyy-MM-dd'
	$currentThread.CurrentCulture = $culture
	$currentThread.CurrentUICulture = $culture

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

	Write-Log 'Processing AD Privileged Groups...'

	$privGroupMembers = $out.privGroupMembers = @(
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
	} | Convert-Timestamps | Select-Object -Property @(,'Group' + $commonAdPropsOut) )

	$privGroupMembers | Export-Csv -NoTypeInformation -Path (Join-Path $reportsFolder ('GroupMembers' + $csvDateExt))
	if($interactive){
		$privGroupMembers | Out-GridView -Title "Privileged AD Group Members ($($privGroupMembers.Count))"
	}

	# Users that haven't logged-in within # days...

	Write-Log 'Processing stale users...'

	$staleUsers = $out.staleUsers = @(Get-ADUser `
			-Filter {
				Enabled -eq $true -and (lastLogonTimestamp -lt $filterDate -or lastLogonTimestamp -notlike '*')
			} `
			-Properties $commonAdPropsIn `
		| Convert-Timestamps `
		| Sort-Object -Property lastLogonTimestamp `
		| Select-Object -Property $commonAdPropsOut)
	$staleUsers | Export-Csv -NoTypeInformation -Path (Join-Path $reportsFolder ('staleUsers' + $csvDateExt))
	Write-Log "Stale users: $($staleUsers.Count)"
	if($staleUsers -and $interactive){
		$staleUsers | Out-GridView -Title "Stale Users ($($staleUsers.Count))"
	}

	# Users with passwords older than # days...

	Write-Log 'Processing stale passwords...'

	$stalePasswords = $out.stalePasswords = @(Get-ADUser `
			-Filter {
				Enabled -eq $true -and (PasswordLastSet -lt $filterDatePassword)
			} `
			-Properties $commonAdPropsIn `
		| Convert-Timestamps `
		| Sort-Object -Property PasswordLastSet `
		| Select-Object -Property $commonAdPropsOut)
	$stalePasswords | Export-Csv -NoTypeInformation -Path (Join-Path $reportsFolder ('stalePasswords' + $csvDateExt))
	Write-Log "Stale Passwords: $($stalePasswords.Count)"
	if($stalePasswords -and $interactive){
		$stalePasswords | Out-GridView -Title "Stale Passwords ($($stalePasswords.Count))"
	}

	# Computers that haven't logged-in within # days...

	Write-Log 'Processing stale computers...'

	$staleComps = $out.staleComputers = @(Get-ADComputer `
			-Filter {
				Enabled -eq $true -and (lastLogonTimestamp -lt $filterDate -or lastLogonTimestamp -notlike '*')
			} `
			-Properties $commonAdPropsIn `
		| Convert-Timestamps `
		| Sort-Object -Property lastLogonTimestamp `
		| Select-Object -Property $commonAdPropsOut)
	$staleComps | Export-Csv -NoTypeInformation -Path (Join-Path $reportsFolder ('staleComps' + $csvDateExt))
	Write-Log "Stale Computers: $($staleComps.Count)"
	if($staleComps -and $interactive){
		$staleComps | Out-GridView -Title "Stale Computers ($($staleComps.Count))"
	}

	# Computers that haven't recently checked-in to LAPS...

	Write-Log 'Processing LAPS...'

	$admPwdAttr = Get-ADObject -SearchBase (Get-ADRootDSE).SchemaNamingContext -Filter {name -eq 'ms-Mcs-AdmPwd'}
	if($admPwdAttr){
		$noLAPS = $out.noLAPS = @(Get-ADComputer -Filter {
					Enabled -eq $true -and (ms-Mcs-AdmPwd -notlike '*' -or ms-Mcs-AdmPwdExpirationTime -lt $filterDate)
				} `
				-Properties ($commonAdPropsIn + 'ms-Mcs-AdmPwdExpirationTime') `
			| Convert-Timestamps -dateProps 'lastLogonTimestamp', 'ms-Mcs-AdmPwdExpirationTime' `
			| Select-Object -Property (@('ms-Mcs-AdmPwdExpirationTimeDate', 'ms-Mcs-AdmPwdExpirationTime') + $commonAdPropsOut))
		$noLAPS | Export-Csv -NoTypeInformation -Path (Join-Path $reportsFolder ('noLAPS' + $csvDateExt))
		Write-Log "Missing LAPS: $($noLAPS.Count)"
		if($noLAPS -and $interactive){
			$noLAPS | Out-GridView -Title "Computers without LAPS ($($noLAPS.Count))"
		}
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
	Write-Log 'Error:', $_
	$_ | Format-List -Force
	Pause
}
