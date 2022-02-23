# AD Privileged Audit

## Summary

Provides various Windows Server Active Directory (AD) security-focused [reports](#reports).

1. Designed to be fast and efficient, typically provides "immediate" (no post-processing required) results within a minute.
2. Available for anyone to run for free, especially when paid tools are maybe not available.
3. Non-invasive / "read-only".  Does not install any components or dependencies, or make any changes to the environment - outside of writing reports to a (new) "AD-Reports" folder on the running users' Desktop by default, which can be redirected or disabled.
4. Does not require any Internet access (outside of someone downloading the script from here), and does not collect or report any data outside of what is provided to the running user.

These reports reflect a measurement of cybersecurity hygiene.  Unfortunately, I have personally seen too many organization environments fall victim to ransomware and other cybersecurity attacks.  I've lead incident response efforts for many victim organizations.  I continue to assist in security reviews, remediation, and hardening efforts - post-incident when the need arises, but much rather prefer to work with organizations proactively.  In many cases of direct experience, I continue to find that many security incidents most likely could have been at least limited in scope and severity had the items identified by these reports been previously recognized and remediated.

This script was written to assist with my professional information security consulting efforts.  Please consider engaging with myself or one of my co-workers through my employer for any needed assistance in running this tool, or especially in interpreting and managing the reported results.

This script is provided with the intent to allow any organization to report upon, and hopefully continuously improve upon their AD security posture.  Ideally, reports would be run weekly/periodically, with a goal of reducing most reports to or near 0 results.

If this script is useful to you, please consider watching and/or staring this GitHub project page to show your support.

## Execution

(Download and run.)

This script was designed to run directly on an AD Domain Controller (DC).  However, as a security practice, please don't be installing or using a web browser on a DC!  Environments secured to best practices will not even allow Internet access from DCs and other such servers.  Use a workstation to retrieve the script, then transfer it to a DC or other location from which it can be run.

There are multiple methods and options for executing this script depending upon the environment, but a general process is as follows:

1. Right-click **[here](AD-Privileged-Audit.ps1?raw=1)**, then click "Save Link As..." from your web browser.
	1. Remove the additional `.txt` extension that may be automatically appended by GitHub and/or your web browser, keeping the filename as simply `AD-Privileged-Audit.ps1`.  This may not be possible or the extra extension even shown in some browsers / system combinations, in which case it will need to be removed after download / before use.
	2. Save to your Downloads, Desktop, or another convenient location.
2. Remote Desktop (RDP) to a DC, [referencing requirements below](#dependencies).
3. Copy the script to the Desktop of the DC.  (Should be able to just copy & paste through the RDP session.)
4. Right-click the script from the Desktop of the DC, then click "Run with PowerShell".
5. Reports will be provided directly to the screen (using PowerShell's [`Out-GridView`](https://docs.microsoft.com/en-us/powershell/module/microsoft.powershell.utility/out-gridview)), as well as to dated files in an `AD-Reports` folder that will be created on the Desktop (if it does not already exist).
6. The displayed grids can be minimized or closed one-at-a-time as they are reviewed.  Completing the "Press Enter to continue..." prompt in or closing the main PowerShell window will close any remaining windows.

The script will attempt to self-elevate when run.  It will also attempt to resolve mapped drive letters to UNC paths that might otherwise not exist once in the elevated context.  However, there are other complexities that may exist in some environments that are not accounted for here - and the best way to ensure that the script executes is to simply run it from the Desktop, or at least elsewhere on a local drive.

### PowerShell Run-Time Parameters / Options

Command-line arguments are typically not required.  For now, available options can be referenced from the script itself.  These are subject to change, especially as I have several pending TODO items for improvement related to them.

## Dependencies

1. [PowerShell](https://docs.microsoft.com/en-us/powershell/) - version 5.1 or later.
	1. Version 5.1 is available by default on Windows 10 since version 1607, and on Windows Server 2016 or higher.
	2. Windows Server 2012 (including R2) require the Windows Management Framework (WMF) 5.1: <https://docs.microsoft.com/en-us/powershell/scripting/windows-powershell/wmf/setup/install-configure>
		1. PowerShell is only required where the script is being run _from_, and not required on the Domain Controller(s) being queried - unless being run from a DC itself.
	3. Windows Server 2008 (including R2) and older servers are not tested or supported.
		1. These operating systems are over 10 years old, no longer supported by Microsoft, and should no longer be used.
2. The `ActiveDirectory` PowerShell module installed and available.
	1. Windows Server: `Install-WindowsFeature RSAT-AD-PowerShell`
3. Execution as a member of "Domain Admins".
	1. Though it is possible to run with lesser privileges, many of the reports may be inaccurate or incomplete, due to not being able to read attributes with restricted security.

## Reports

Current reports include:

1. Privileged AD Group Members (`privGroupMembers`).
	1. Current reported groups include:
		1. Domain Admins
		2. Enterprise Admins
		3. Administrators
		4. Schema Admins
		5. Account Operators
		6. Server Operators
		7. Print Operators
		8. Backup Operators
		9. DnsAdmins
		10. DnsUpdateProxy
		11. DHCP Administrators
		12. Domain Controllers
		13. Enterprise Read-Only Domain Controllers
		14. Read-Only Domain Controllers
	2. Groups are omitted when they don't exist, though will be reported as warnings (below).
	3. (Further [Group Considerations](#group-considerations) below.)
2. Privileged AD Groups (`privGroups`).
	1. Provides the detail of each group itself included above, whereas the above report details each groups' membership.
3. Stale Users (`staleUsers`).
	1. Users that haven't logged-in within 90 days (~3 months), based on [lastLoginTimestamp](#lastlogintimestamp).
	2. Note that this report does not (yet) account for accounts that are logging-in to only Azure Active Directory (AAD).  As such, exercise caution against disabling or deleting accounts listed here that may be synchronized to AAD without checking for use in AAD first.
4. Stale Passwords (`stalePasswords`).
	1. Users with passwords older than 365 days (1 year).
	2. A stale password is a stale password, regardless of if the account is being used in AD and/or AAD (unlike with Stale Users, above).
5. Password Not Required (`passwordNotRequired`).
	1. Interdomain trust accounts - where the UserAccountControl is 0x820 (2080) - can be safely ignored here as long as the account is recognized as part of a current and valid domain trust.  See <https://docs.microsoft.com/en-us/troubleshoot/windows-server/identity/useraccountcontrol-manipulate-account-properties> for details of these values.  Exclusions for this may be added in the future with some further considerations around this.
6. SID History (`sidHistory`).
7. Stale Computers (`staleComputers`), based on [lastLoginTimestamp](#lastlogintimestamp).
	1. Computers that haven't logged-in within 90 days (~3 months).
8. Unsupported Operating Systems (`unsupportedOS`).
9. Future lastLoginTimestamps (`futureLastLogins`).
	1. May appear in hopefully rare cases where the system time on one or more Domain Controllers was set into the future.  There are currently not any known great fixes for this, but such a state shown be made aware of - as impacted objects will maintain their incorrect lastLoginTimestamps and not be updated to current (past) dates.
10. Computers without [LAPS](#laps) or expired (`lapsOut`).
11. Computers with current [LAPS](#laps) (`lapsIn`).
	1. This report is the inverse of `lapsOut` - and opposite of all the others in that a higher result count here is better.
12. Warnings (`warnings`).
	1. Current reported warnings include:
		1. If the script is not running as a Domain Administrator, as results may be incomplete ([Dependencies](#dependencies)).
		2. If an expected AD privileged group is not found, or with an unexpected SID ([Group Considerations](#group-considerations)).
			1. Such warnings here may be expected in child domains of a forest, where "Enterprise Admins" and "Schema Admins" will not exist.  "DHCP Administrators" may also be an expected missing group.
		3. For any circular references in privileged AD group memberships.
		4. If [LAPS](#laps) is not deployed, or found on a possible DC.
		5. If the AD Recycle Bin is not enabled.
13. AD Privileged Audit Report History (`reportHistory`).

Each report includes a significant and consistent set of columns of details that should remove most of the need for cross-referencing Active Directory Users and Computers (ADUC) or other similar tools for further details on reported objects, as well as providing some value in terms of digital forensics.

### LAPS

LAPS is Microsoft's "Local Administrator Password Solution".  If you are not yet using it, you should be.

1. <https://www.microsoft.com/en-us/download/details.aspx?id=46899>
	1. Official download site.  Download includes a datasheet, technical specification, and operations guide (manual).
2. <https://techcommunity.microsoft.com/t5/core-infrastructure-and-security/local-administrator-password-solution-laps-implementation-hints/ba-p/258296>
	1. Microsoft TechNet repost from 2015-12-28 with some additional useful information, commentary, and considerations.

### Group Considerations

1. Groups are searched for by both name and SID, accounting for groups that may have been renamed from their (supported) defaults.
2. Group memberships are dynamically queried such that:
	1. Membership limits are avoided.  `Get-ADGroupMember` otherwise falls to the limit in Active Directory Web Services (ADWS), where `MaxGroupOrMemberEntries` has a default limit of 5,000.
	2. Circular references are properly handled (and reported as warnings).
	3. ForeignSecurityPrincipals (FSPs) are properly handled - especially for unresolved or orphaned FSPs, or due to insufficient permissions in the foreign domain.
	4. Group details are included - including for potentially empty groups - along with the nested path by which entity is included.

### lastLoginTimestamp

Currently, this script only consults the `lastLogonTimestamp` attribute.  Unlike `lastLogon`, only `lastLogonTimestamp` is replicated across Domain Controllers - but it not updated in real-time.  [From an old TechNet article](https://techcommunity.microsoft.com/t5/ask-the-directory-services-team/8220-the-lastlogontimestamp-attribute-8221-8211-8220-what-it-was/ba-p/396204):

> It is important to note that the intended purpose of the lastLogontimeStamp attribute to help identify inactive computer and user accounts. The lastLogon attribute is not designed to provide real time logon information. With default settings in place the lastLogontimeStamp will be 9-14 days behind the current date.

See also:

* <https://techcommunity.microsoft.com/t5/ask-the-directory-services-team/8220-the-lastlogontimestamp-attribute-8221-8211-8220-what-it-was/ba-p/396204>
* <https://docs.microsoft.com/en-us/windows/win32/adschema/a-lastlogontimestamp>
* <https://social.technet.microsoft.com/wiki/contents/articles/22461.understanding-the-ad-account-attributes-lastlogon-lastlogontimestamp-and-lastlogondate.aspx>

### Enabled vs. Disabled Accounts

One common misconception observed when reviewing these reports together with environment owners is that most of the returned results can be ignored because they had already disabled the accounts in question.  To the contrary - results being returned on these reports are only those accounts that should be of concern.  This should be clearly visible by the provided "Enabled" column, which is the 3rd displayed column on most reports.

With the exception of 2 reports, only enabled (where "Enabled" is "True") accounts are returned.  The exceptions are:

1. Privileged AD Group Members (`privGroupMembers`).  If a disabled account is nested into one of these privileged groups, it is all too easy for such an account to be accidentally or maliciously re-enabled at some point in the future - so disabled accounts are included here for review and consideration.  It is a common practice to disable unused or unneeded accounts before removing them - but this should only be temporary, and on the order of days, not for a month or more.
2. Password Not Required (`passwordNotRequired`).  Again - in most cases, this attribute has been set on accounts due to gross misconfigurations and/or errant scripting - and any such accounts (even disabled) should either have this attribute reset, or the account removed completely if it is no longer required.

## Author

Mark Ziesemer, CISSP, CCSP, CSSLP

* <https://www.ziesemer.com>
* <https://www.linkedin.com/in/ziesemer/>
