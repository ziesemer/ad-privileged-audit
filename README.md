# AD Privileged Audit

## Summary

Provides various Windows Server Active Directory (AD) security-focused reports.

1. Designed to be fast and efficient, typically provides "immediate" (no post-processing required) results within a minute.
2. Available for anyone to run for free, especially when paid tools are maybe not available.
3. Non-invasive / "read-only".  Does not install any components or dependencies, or make any changes to the environment - outside of writing reports to a (new) "AD-Reports" folder on the running users' Desktop by default, which can be redirected or disabled.
4. Outside of someone downloading the script from here, does not require any Internet access, and does not collect or report any data outside of what is provided to the running user.

This script was written to assist with my professional information security consulting efforts.  Please consider engaging with myself or one of my co-workers through my employer for any needed assistance in running this tool, or especially in interpreting and managing the reported results.

This script is provided with the intent to allow any organization to report upon, and hopefully continuously improve upon their AD security posture.  Ideally, reports would be run weekly/periodically, with a goal of reducing most reports to or near 0 results.

If this script is useful to you, please consider watching and/or staring this GitHub project page to show your support.

## Execution

(Download and run.)

This script was designed to run directly on an AD Domain Controller (DC).  However, as a security practice, please don't be installing or using a web browser on a domain controller!  Environments secured to best practices will not even allow Internet access from DCs and other such servers.  Use a typical workstation to retrieve the script, then transfer it to a DC or other location from which it can be run.

There are multiple methods and options for executing this script depending upon the environment, but a general process is as follows:

1. Right-click **[here](AD-Privileged-Audit.ps1?raw=1)**, then click "Save Link As..." from your web browser.
	1. Remove the additional `.txt` extension that is automatically appended by GitHub, keeping the filename as simply `AD-Privileged-Audit.ps1`.  This may not be possible or the extra extension even shown in some browsers / system combinations, in which case it will need to be removed after download / before use.
	2. Save to your Downloads, Desktop, or another convenient location.
2. Remote Desktop to a Domain Controller (reference requirements below).
3. Copy the script to the Desktop of the Domain Controller.  (Should be able to just copy & paste through the RDP session.)
4. Right-click the script from the Desktop of the Domain Controller, then click "Run with PowerShell".
5. Reports will be provided directly to the screen (using PowerShell's [`Out-GridView`](https://docs.microsoft.com/en-us/powershell/module/microsoft.powershell.utility/out-gridview), as well as to dated files in an `AD-Reports` folder that will be created on the Desktop (if it does not already exist).
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

1. Privileged AD Group Members.
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
	2. Groups are omitted when they don't exist.
	3. (Further considerations below.)
2. Privileged AD Groups.
	1. Provides the detail of each group itself included above, whereas the above report details each groups' membership.
3. Stale Users.
	1. Users that haven't logged-in within 90 days.
4. Stale Passwords.
	1. Users with passwords older than 365 days.
5. Password Not Required.
6. SID History.
7. Stale Computers.
	1. Computers that haven't logged-in within 90 days.
8. Unsupported Operating Systems.
9. Computers without LAPS or expired.
10. Computers with current LAPS.
11. Warnings.

LAPS is Microsoft's "Local Administrator Password Solution".  If you are not yet using it, you should be.

* <https://www.microsoft.com/en-us/download/details.aspx?id=46899>

Each report includes a significant and consistent set of columns of details that should remove most of the need for cross-referencing Active Directory Users and Computers (ADUC) or other similar tools for further details on reported objects, as well as providing some value in terms of digital forensics.

### Further Considerations

1. Groups are searched for by both name and SID, accounting for groups that may have been renamed from their (supported) defaults.
2. Group memberships are manually queried such that:
	1. Membership limits are avoided.  `Get-ADGroupMember` otherwise falls to the limit in Active Directory Web Services (ADWS), where `MaxGroupOrMemberEntries` has a default limit of 5,000.
	2. ForeignSecurityPrincipals (FSPs) are properly handled - especially for unresolved or orphaned FSPs, or due to insufficient permissions in the foreign domain.
	3. Group details are included - including for potentially empty groups - along with the nested path by which entity is included.

## Author

Mark Ziesemer, CISSP, CCSP, CSSLP

* <https://www.ziesemer.com>
* <https://www.linkedin.com/in/ziesemer/>
