<#
	.SYNOPSIS
		This script collects data from your SCOM Environment that can be very helpful in troubleshooting.
	
	.DESCRIPTION
		For full support, please run this script from a Management Server..
	
	.PARAMETER AdditionalEventLogs
		Gather additional Event Logs. (Example: -AdditionalEventLogs Security)
	
	.PARAMETER All
		Allows you to Specify all the Switches Available for use. (Except: MSInfo32)
	
	.PARAMETER AssumeYes
		This will allow you to not be prompted for anything. (This will not bypass -SCXAgents questions)
	
	.PARAMETER BuildPipeline
		Azure DevOps Build Pipeline switch to output the SDC Results file without any File Date or CaseNumber.
	
	.PARAMETER CaseNumber
		Add an Optional Case Number to the Output of the Zip File.
	
	.PARAMETER CheckCertificates
		Check the Certificates for validity for SCOM use, output in TXT format.
	
	.PARAMETER CheckGroupPolicy
		Check the group policy for each server listed in -Servers as well as any Management Servers and SQL Servers.
	
	.PARAMETER CheckPorts
		Check SCOM Common Ports against every Management Server in Management Group and SQL Servers, as well as any -Servers listed.
	
	.PARAMETER CheckTLS
		Check for TLS 1.2 Readiness, output in TXT format.
	
	.PARAMETER ExportMPs
		Export all Sealed/Unsealed MP's.
	
	.PARAMETER ExportSCXCertificates
		Export the Management Server(s) SCX Certificate(s).
	
	.PARAMETER ExportMSCertificates
		Export all Management Server Certificates.
	
	.PARAMETER GenerateHTML
		Generate a HTML Report Page {EXPERIMENTAL}
	
	.PARAMETER GetConfiguration
		Gather the Registry / ConfigService.config Configuration of the Management Servers.
	
	.PARAMETER GetEventLogs
		Gather Event Logs with the localemetadata to ensure that you are able to open the Event log from any machine.
	
	.PARAMETER GetInstalledSoftware
		Gather software installed from Management Servers / Agents / Gateways.
	
	.PARAMETER GetInstallLogs
		A description of the GetInstallLogs parameter.
	
	.PARAMETER GetLocalSecurity
		Get Local Administrators and Logon Rights.
	
	.PARAMETER GetNotificationSubscriptions
		A description of the GetNotificationSubscriptions parameter.
	
	.PARAMETER GetRulesAndMonitors
		A description of the GetRulesAndMonitors parameter.
	
	.PARAMETER GetRunAsAccounts
		Get RunAs Accounts that are set on each Management Server.
	
	.PARAMETER GetSPN
		Get SPN Configuration from Active Directory.
	
	.PARAMETER GetUserRoles
		Gathers User Roles and the configurations from SCOM.
	
	.PARAMETER GPResult
		Gathers Group Policy Results to verify Harmful Policies are not present, Generated in HTML and TXT Format.
	
	.PARAMETER LeastAmount
		Pull the least amount of data from SCOM.
	
	.PARAMETER ManagementServers
		Only run data gathering against the Management Servers specified here.
	
	.PARAMETER MSInfo32
		Export MSInfo32 for viewing in TXT Format.
	
	.PARAMETER NoSQLPermission
		Internal Script Switch.
	
	.PARAMETER PingAll
		Ping every Management Server, including servers mentioned in -Servers switch.
	
	.PARAMETER SCXAgents
		Linux/Unix Agents you want to gather data from, via Bash Script that is transmitted via ssh.
	
	.PARAMETER SCXMaintenanceUsername
		The SCX Maintenance Username to use for gathering with the Linux Data Collector.
	
	.PARAMETER SCXMonitoringUsername
		The SCX Monitoring Username to use for gathering with the Linux Data Collector.
	
	.PARAMETER SCXResourcePoolDisplayName
		The Linux/Unix Resource Pool(s) to gather SCX WinRM data.
	
	.PARAMETER SCXUsername
		The username you would like to use for SCX Agent SSH Authentication.
	
	.PARAMETER SCXWinRMCredentials
		Provide the WinRM Credentials to use for SCX WinRM querying.
	
	.PARAMETER SCXWinRMEnumerateAllClasses
		Enumerate all the WinRM classes to use for SCX WinRM querying.
	
	.PARAMETER SCXWinRMEnumerateSpecificClasses
		Enumerate specific (comma separated) WinRM classes to use for SCX WinRM querying.
	
	.PARAMETER Servers
		Set additional servers to run checks against. This can be Agents or Gateways, they have to be in the same domain at this time.
	
	.PARAMETER SkipBestPracticeAnalyzer
		Skip the Best Practice Analyzer gathering.
	
	.PARAMETER SkipConnectivityTests
		Skip the tests for remote accessibility, use this if you know your environment passes these tests. DO NOT USE IF YOU AREN'T SURE!
	
	.PARAMETER SkipGeneralInformation
		Skip the General Information file gathering.
	
	.PARAMETER SkipSQLQueries
		Skip the SQL Queries. This will leave you with much less data in the data collector. Other functions in the data collector may rely on the SQL Queries and may be missing data.
	
	.PARAMETER SQLLogs
		Gather SQL Logs from OperationsManager and DataWarehouse DB's.
	
	.PARAMETER SQLOnly
		Run only SQL Queries and Output to CSV.
	
	.PARAMETER SQLOnlyDW
		Internal Script Switch.
	
	.PARAMETER SQLOnlyOpsDB
		Internal Script Switch.
	
	.EXAMPLE
		This is an example of how you can gather data from 2 Agents and the Management Server(s); and gather as much data as possible:
		PS C:\> .\DataCollector.ps1 -Servers Agent1.contoso.com, Agent2.contoso.com -All
	
	.NOTES
		This script is intended for System Center Operations Manager Environments. This is currently in development by the SCEM Support Team with Microsoft.
		
		.AUTHOR
		Blake Drumm (blakedrumm@microsoft.com)
		
		.CONTRIBUTORS
		Kevin Holman (kevinhol)
		Tyson Paul (typaul)
		Lorne Sepaugh (lornesepaugh)
		Michael Kallhoff (mikallho)
		Bobby King (v-bking)
		Tiago Fernandes (tifernan)
		Alex Kremenetskiy (alexkre)
		Andy Desmond (andydesmond)
		Bryan Faul (v-bryanfaul)
		Jordan Stanhope (jstanhope)
		Brook Hudson (brhudso)
		Udish Mudiar (udmudiar)
	
	.LINK
		Blog Post:
		https://blakedrumm.com/blog/scom-data-collector/
		
		Download Link:
		https://aka.ms/SCOM-DataCollector
		
		Github Repo:
		https://github.com/blakedrumm/SCOM-Scripts-and-SQL
		
		.VERSION
		v4.0.4 - May 7th, 2024
#>
[CmdletBinding(HelpUri = 'https://blakedrumm.com/blog/scom-data-collector/')]
[OutputType([string])]
param
(
	[Parameter(Mandatory = $false,
			   Position = 1,
			   HelpMessage = 'Gather additional Event Logs. (Example: -AdditionalEventLogs Security)')]
	[array]$AdditionalEventLogs,
	[Parameter(Mandatory = $false,
			   Position = 2,
			   HelpMessage = 'Allows you to Specify all the Switches Available for use. (Except: MSInfo32)')]
	[switch]$All,
	[Parameter(Mandatory = $false,
			   Position = 3,
			   HelpMessage = 'This will allow you to not be prompted for anything.')]
	[Alias('yes')]
	[switch]$AssumeYes,
	[Parameter(Mandatory = $false,
			   Position = 4,
			   HelpMessage = 'Azure DevOps Build Pipeline switch to output the SDC Results file without any File Date or CaseNumber.',
			   DontShow = $true)]
	[Alias('bp')]
	[switch]$BuildPipeline,
	[Parameter(Mandatory = $false,
			   Position = 5,
			   HelpMessage = 'Add an Optional Case Number to the Output of the Zip File.')]
	[Alias('case')]
	[string]$CaseNumber,
	[Parameter(Mandatory = $false,
			   Position = 6,
			   HelpMessage = 'Check the Certificates for validity for SCOM use, output in TXT format.')]
	[Alias('cc')]
	[switch]$CheckCertificates,
	[Parameter(Position = 7,
			   HelpMessage = 'Check the group policy for each server listed in -Servers as well as any Management Servers and SQL Servers.')]
	[switch]$CheckGroupPolicy,
	[Parameter(Mandatory = $false,
			   Position = 8,
			   HelpMessage = 'Check SCOM Common Ports against every Management Server in Management Group and SQL Servers, as well as any -Servers listed.')]
	[switch]$CheckPorts,
	[Parameter(Mandatory = $false,
			   Position = 9,
			   HelpMessage = 'Check for TLS 1.2 Readiness, output in TXT format.')]
	[Alias('ct')]
	[switch]$CheckTLS,
	[Parameter(Mandatory = $false,
			   Position = 10,
			   HelpMessage = 'Export all Sealed/Unsealed MPs.')]
	[Alias('em')]
	[switch]$ExportMPs,
	[Parameter(Position = 12,
			   HelpMessage = 'Skip exporting the SCOM Management Server SCX Certificates.')]
	[Alias('sesc')]
	[switch]$ExportSCXCertificates,
	[Parameter(Position = 11,
			   HelpMessage = 'Export all Management Server Certificates.')]
	[Alias('emc')]
	[switch]$ExportMSCertificates,
	[Parameter(Mandatory = $false,
			   Position = 13,
			   HelpMessage = 'Generate a HTML Report Page { EXPERIMENTAL }')]
	[Alias('html')]
	[switch]$GenerateHTML,
	[Parameter(Position = 14,
			   HelpMessage = 'Gather the Registry / ConfigService.config Configuration of the Management Servers.')]
	[switch]$GetConfiguration,
	[Parameter(Mandatory = $false,
			   Position = 15,
			   HelpMessage = 'Gather Event Logs with the localemetadata to ensure that you are able to open the Event log from any machine.')]
	[Alias('gel')]
	[switch]$GetEventLogs,
	[Parameter(Mandatory = $false,
			   Position = 16,
			   HelpMessage = 'Gather software installed from Management Servers / Agents / Gateways.')]
	[switch]$GetInstalledSoftware,
	[Parameter(Position = 17)]
	[switch]$GetInstallLogs,
	[Parameter(Mandatory = $false,
			   Position = 18,
			   HelpMessage = 'Get Local Administrators and Logon Rights.')]
	[Alias('gls')]
	[switch]$GetLocalSecurity,
	[Parameter(Mandatory = $false,
			   Position = 19,
			   HelpMessage = 'A description of the GetNotificationSubscriptions parameter.')]
	[switch]$GetNotificationSubscriptions,
	[Parameter(Mandatory = $false,
			   Position = 20,
			   HelpMessage = 'A description of the GetRulesAndMonitors parameter.')]
	[Alias('gram')]
	[switch]$GetRulesAndMonitors,
	[Parameter(Mandatory = $false,
			   Position = 21,
			   HelpMessage = 'Get RunAs Accounts that are set on each Management Server.')]
	[Alias('graa')]
	[switch]$GetRunAsAccounts,
	[Parameter(Mandatory = $false,
			   Position = 22,
			   HelpMessage = 'Get SPN Configuration from Active Directory.')]
	[Alias('gs')]
	[switch]$GetSPN,
	[Parameter(Position = 23,
			   HelpMessage = 'Gathers User Roles and the configurations from SCOM.')]
	[switch]$GetUserRoles,
	[Parameter(Mandatory = $false,
			   Position = 24,
			   HelpMessage = 'Gathers Group Policy Results to verify Harmful Policies are not present, Generated in HTML and TXT Format.')]
	[Alias('gp')]
	[switch]$GPResult,
	[Parameter(Mandatory = $false,
			   Position = 25,
			   HelpMessage = 'Pull the least amount of data from SCOM.')]
	[switch]$LeastAmount,
	[Parameter(Mandatory = $false,
			   Position = 26,
			   HelpMessage = 'Only run data gathering against the Management Servers specified here.')]
	[Alias('ms')]
	[array]$ManagementServers,
	[Parameter(Mandatory = $false,
			   Position = 27,
			   HelpMessage = 'Export MSInfo32 for viewing in TXT Format.')]
	[Alias('mi32')]
	[switch]$MSInfo32,
	[Parameter(Position = 28,
			   HelpMessage = 'Internal Script Switch.')]
	[switch]$NoSQLPermission,
	[Parameter(Mandatory = $false,
			   Position = 29,
			   HelpMessage = 'Ping every Management Server, including servers mentioned in -Servers switch.')]
	[switch]$PingAll,
	[Parameter(Mandatory = $false,
			   Position = 30,
			   HelpMessage = 'Linux/Unix Agents you want to gather data from, via Bash Script that is transmitted via ssh.')]
	[Alias('LinuxAgents')]
	[Array]$SCXAgents,
	[Parameter(Position = 31,
			   HelpMessage = 'The SCX Maintenance Username to use for gathering with the Linux Data Collector.')]
	[string]$SCXMaintenanceUsername,
	[Parameter(Position = 32,
			   HelpMessage = 'The SCX Monitoring Username to use for gathering with the Linux Data Collector.')]
	[string]$SCXMonitoringUsername,
	[Parameter(Position = 33,
			   HelpMessage = 'The Linux/Unix Resource Pool to gather SCX WinRM data.')]
	[Alias('scxrp')]
	[string]$SCXResourcePoolDisplayName,
	[Parameter(Mandatory = $false,
			   Position = 34,
			   HelpMessage = 'The username you would like to use for SCX Agent SSH Authentication.')]
	[Alias('LinuxUsername')]
	[string]$SCXUsername,
	[Parameter(Position = 35,
			   HelpMessage = 'Provide the WinRM Credentials to use for SCX WinRM querying.')]
	[pscredential]$SCXWinRMCredentials,
	[Parameter(Position = 36,
			   HelpMessage = 'Enumerate all the WinRM classes to use for SCX WinRM querying.')]
	[switch]$SCXWinRMEnumerateAllClasses,
	[Parameter(Position = 37,
			   HelpMessage = 'Enumerate specific (comma separated) WinRM classes to use for SCX WinRM querying.')]
	[string[]]$SCXWinRMEnumerateSpecificClasses = @('SCX_UnixProcess', 'SCX_Agent', 'SCX_OperatingSystem'),
	[Parameter(Mandatory = $false,
			   Position = 38,
			   HelpMessage = 'Set additional servers to run checks against. This can be Agents or Gateways, they have to be in the same domain at this time.')]
	[Alias('s')]
	[Array]$Servers,
	[Parameter(Position = 39,
			   HelpMessage = 'Skip the Best Practice Analyzer gathering.')]
	[Alias('sbpa')]
	[switch]$SkipBestPracticeAnalyzer,
	[Parameter(Position = 40,
			   HelpMessage = 'Skip the tests for remote accessibility, use this if you know your environment passes these tests. DO NOT USE THIS IF YOU ARENT SURE!')]
	[Alias('sct')]
	[switch]$SkipConnectivityTests,
	[Parameter(Position = 41,
			   HelpMessage = 'Skip the General Information file gathering.')]
	[Alias('sgi')]
	[switch]$SkipGeneralInformation,
	[Parameter(Mandatory = $false,
			   Position = 42,
			   HelpMessage = 'Skip the SQL Queries. This will leave you with much less data in the data collector. Other functions in the data collector may rely on the SQL Queries and may be missing data.')]
	[Alias('NoSQLQueries')]
	[switch]$SkipSQLQueries,
	[Parameter(Position = 43,
			   HelpMessage = 'Gather SQL Logs from OperationsManager and DataWarehouse DBs.')]
	[switch]$SQLLogs,
	[Parameter(Mandatory = $false,
			   Position = 44,
			   HelpMessage = 'Run only SQL Queries and Output to CSV.')]
	[switch]$SQLOnly,
	[Parameter(Mandatory = $false,
			   Position = 45,
			   HelpMessage = 'Internal Script Switch.',
			   DontShow = $true)]
	[switch]$SQLOnlyDW,
	[Parameter(Mandatory = $false,
			   Position = 46,
			   HelpMessage = 'Internal Script Switch.',
			   DontShow = $true)]
	[switch]$SQLOnlyOpsDB
)
try
{
	$StartTime = "$(Get-Date -Format "MMMM dd, yyyy @ h:mm tt") $((Get-TimeZone -ErrorAction Stop).DisplayName)"
}
catch
{
	$StartTime = "$(Get-Date -Format "MMMM dd, yyyy @ h:mm tt") (unknown time zone)"
}

Get-Job -Name "getEvent*", "getPerf*" -ErrorAction SilentlyContinue | Stop-Job -ErrorAction SilentlyContinue | Out-Null
#Get the script path
$scriptname = $((Get-PSCallStack | Select-Object -First 1).Command)
[string]$ScriptPath = $PSScriptRoot
if (!$ScriptPath)
{
	#Running from Powershell ISE
	$ScriptPath = $pwd
}
$currentPath = $myinvocation.mycommand.definition
$OutputPath = "$ScriptPath\Output"
#$location = $MyInvocation.MyCommand.Path
Function Invoke-TimeStamp
{
	$TimeStamp = Get-Date -Format "MM/dd/yyyy hh:mm:ss tt"
	return "$TimeStamp - "
}

function Write-Console
{
	param
	(
		[string]$Text,
		$ForegroundColor,
		[switch]$NoNewLine
	)
	
	if ([Environment]::UserInteractive)
	{
		if ($ForegroundColor)
		{
			Write-Host $Text -ForegroundColor $ForegroundColor -NoNewLine:$NoNewLine
		}
		else
		{
			Write-Host $Text -NoNewLine:$NoNewLine
		}
	}
	else
	{
		Write-Output $Text
	}
}

if (!($SQLOnly -or $SQLOnlyDW -or $SQLOnlyOpsDB))
{
	Write-Console @"
===================================================================
==========================  Start of Script =======================
===================================================================
"@ -ForegroundColor DarkYellow
	$runningas = $null
	$runningas = [System.Security.Principal.WindowsIdentity]::GetCurrent().Name
	Write-Console "Script currently running as: " -ForegroundColor DarkGray -NoNewLine
	Write-Console $runningas -ForegroundColor Gray
	
	Write-Console "Attempting to run the following command to unblock the Powershell Scripts under the current folder:`nGet-ChildItem $ScriptPath -Recurse | Unblock-File" -ForegroundColor Gray; Get-ChildItem $ScriptPath -Recurse | Unblock-File | Out-Null
	$scriptout = [Array] @()
	try
	{
		[String]$Comp = Resolve-DnsName $env:COMPUTERNAME -Type A -ErrorAction Stop | Select-Object -Property Name -ExpandProperty Name
	}
	catch
	{
		[String]$Comp = $env:COMPUTERNAME
	}
	$checkingpermission = "Checking for elevated permissions..."
	$scriptout += $checkingpermission
	Write-Console $checkingpermission -ForegroundColor Gray
	# Gather the Parameters Passed to the script, we will use these to relaunch the script
	foreach ($psbp in $PSBoundParameters.GetEnumerator())
	{
		$ScriptPassedArgs += "-{0} {1} " -f $psbp.Key, [system.String]::Join(", ", $(($psbp.Value -replace "True", "") -replace "False", ""))
		Write-Verbose $("-{0} {1} " -f $psbp.Key, [system.String]::Join(", ", $(($psbp.Value -replace "True", "") -replace "False", "")))
	}
	$command = "-NoProfile -NoExit -Command cd '$ScriptPath';. '$ScriptPath\$scriptname' $ScriptPassedArgs"
	if (-NOT ([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole(`
[Security.Principal.WindowsBuiltInRole] "Administrator"))
	{
		$nopermission = "Insufficient permissions to run this script. Attempting to open the PowerShell script ($currentPath) as administrator."
		$scriptout += $nopermission
		Write-Warning $nopermission
		# We are not running "as Administrator" - so relaunch as administrator
		Start-Process powershell.exe ($command) -Verb RunAs
		break
	}
	else
	{
		$permissiongranted = " Currently running as administrator - proceeding with script execution..."
		Write-Console $permissiongranted -ForegroundColor Green
	}
	$currentUser = ([System.Security.Principal.WindowsIdentity]::GetCurrent().Name).split('\')[1]
	$omsdkUserOrig = (Get-CimInstance Win32_Service -Filter "Name='omsdk'" -ErrorAction SilentlyContinue).StartName -split '@'
	if ($omsdkUserOrig)
	{
		if ($omsdkUserOrig[1])
		{
			$omsdkUser = $omsdkUserOrig[1] + "\" + $omsdkUserOrig[0]
		}
		else
		{
			$omsdkUser = $omsdkUserOrig
		}
		$question = "the SDK account ($omsdkUser)"
	}
	else
	{
		$omsdkUserOrig = $false
		$question = "another user account"
	}
	
	if ($omsdkUserOrig -notmatch "$currentUser")
	{
		do
		{
			if ($AssumeYes)
			{
				$answer = "n"
			}
			else
			{
				$answer = Read-Host "`n[OPTIONAL]`n Would you like to run this script as $($question)? (Y/N)"
			}
		}
		until ($answer -eq "y" -or $answer -eq "n")
		if ($answer -eq "y")
		{
			$error.clear()
			try { $Credentials = Get-Credential -Message "Please provide credentials to run this script with" "$omsdkUser" }
			catch
			{
				Write-Warning "$error"
			}
			$error.clear()
			try
			{
				Start-Process powershell.exe ($command) -Credential $Credentials
				
			}
			catch
			{
				Write-Warning "Try again... $error"
				if ($error -match "The user name or password is incorrect")
				{
					try { $Credentials = Get-Credential -Message "Please provide credentials to run this script with" "$omsdkUser" }
					catch
					{
						Write-Warning "Exiting... $error"
					}
				}
			}
			exit 0
		}
		
	}
}

function Start-ScomDataCollector
{
	[CmdletBinding()]
	param
	(
		[Parameter(Mandatory = $false,
				   Position = 1,
				   HelpMessage = 'Gather additional Event Logs. (Example: -AdditionalEventLogs Security)')]
		[array]$AdditionalEventLogs,
		[Parameter(Mandatory = $false,
				   Position = 2,
				   HelpMessage = 'Allows you to Specify all the Switches Available for use. (Except: MSInfo32)')]
		[switch]$All,
		[Parameter(Mandatory = $false,
				   Position = 3,
				   HelpMessage = 'This will allow you to not be prompted for anything.')]
		[Alias('yes')]
		[switch]$AssumeYes,
		[Parameter(Mandatory = $false,
				   Position = 4,
				   HelpMessage = 'Azure DevOps Build Pipeline switch to output the SDC Results file without any File Date or CaseNumber.',
				   DontShow = $true)]
		[Alias('bp')]
		[switch]$BuildPipeline,
		[Parameter(Mandatory = $false,
				   Position = 5,
				   HelpMessage = 'Add an Optional Case Number to the Output of the Zip File.')]
		[Alias('case')]
		[string]$CaseNumber,
		[Parameter(Mandatory = $false,
				   Position = 6,
				   HelpMessage = 'Check the Certificates for validity for SCOM use, output in TXT format.')]
		[Alias('cc')]
		[switch]$CheckCertificates,
		[Parameter(Position = 7,
				   HelpMessage = 'Check the group policy for each server listed in -Servers as well as any Management Servers and SQL Servers.')]
		[switch]$CheckGroupPolicy,
		[Parameter(Mandatory = $false,
				   Position = 8,
				   HelpMessage = 'Check SCOM Common Ports against every Management Server in Management Group and SQL Servers, as well as any -Servers listed.')]
		[switch]$CheckPorts,
		[Parameter(Mandatory = $false,
				   Position = 9,
				   HelpMessage = 'Check for TLS 1.2 Readiness, output in TXT format.')]
		[Alias('ct')]
		[switch]$CheckTLS,
		[Parameter(Mandatory = $false,
				   Position = 10,
				   HelpMessage = 'Export all Sealed/Unsealed MPs.')]
		[Alias('em')]
		[switch]$ExportMPs,
		[Parameter(Position = 12,
				   HelpMessage = 'Skip exporting the SCOM Management Server SCX Certificates.')]
		[Alias('sesc')]
		[switch]$ExportSCXCertificates,
		[Parameter(Position = 11,
				   HelpMessage = 'Export all Management Server Certificates.')]
		[Alias('emc')]
		[switch]$ExportMSCertificates,
		[Parameter(Mandatory = $false,
				   Position = 13,
				   HelpMessage = 'Generate a HTML Report Page { EXPERIMENTAL }')]
		[Alias('html')]
		[switch]$GenerateHTML,
		[Parameter(Position = 14,
				   HelpMessage = 'Gather the Registry / ConfigService.config Configuration of the Management Servers.')]
		[switch]$GetConfiguration,
		[Parameter(Mandatory = $false,
				   Position = 15,
				   HelpMessage = 'Gather Event Logs with the localemetadata to ensure that you are able to open the Event log from any machine.')]
		[Alias('gel')]
		[switch]$GetEventLogs,
		[Parameter(Mandatory = $false,
				   Position = 16,
				   HelpMessage = 'Gather software installed from Management Servers / Agents / Gateways.')]
		[switch]$GetInstalledSoftware,
		[Parameter(Position = 17)]
		[switch]$GetInstallLogs,
		[Parameter(Mandatory = $false,
				   Position = 18,
				   HelpMessage = 'Get Local Administrators and Logon Rights.')]
		[Alias('gls')]
		[switch]$GetLocalSecurity,
		[Parameter(Mandatory = $false,
				   Position = 19,
				   HelpMessage = 'A description of the GetNotificationSubscriptions parameter.')]
		[switch]$GetNotificationSubscriptions,
		[Parameter(Mandatory = $false,
				   Position = 20,
				   HelpMessage = 'A description of the GetRulesAndMonitors parameter.')]
		[Alias('gram')]
		[switch]$GetRulesAndMonitors,
		[Parameter(Mandatory = $false,
				   Position = 21,
				   HelpMessage = 'Get RunAs Accounts that are set on each Management Server.')]
		[Alias('graa')]
		[switch]$GetRunAsAccounts,
		[Parameter(Mandatory = $false,
				   Position = 22,
				   HelpMessage = 'Get SPN Configuration from Active Directory.')]
		[Alias('gs')]
		[switch]$GetSPN,
		[Parameter(Position = 23,
				   HelpMessage = 'Gathers User Roles and the configurations from SCOM.')]
		[switch]$GetUserRoles,
		[Parameter(Mandatory = $false,
				   Position = 24,
				   HelpMessage = 'Gathers Group Policy Results to verify Harmful Policies are not present, Generated in HTML and TXT Format.')]
		[Alias('gp')]
		[switch]$GPResult,
		[Parameter(Mandatory = $false,
				   Position = 25,
				   HelpMessage = 'Pull the least amount of data from SCOM.')]
		[switch]$LeastAmount,
		[Parameter(Mandatory = $false,
				   Position = 26,
				   HelpMessage = 'Only run data gathering against the Management Servers specified here.')]
		[Alias('ms')]
		[array]$ManagementServers,
		[Parameter(Mandatory = $false,
				   Position = 27,
				   HelpMessage = 'Export MSInfo32 for viewing in TXT Format.')]
		[Alias('mi32')]
		[switch]$MSInfo32,
		[Parameter(Position = 28,
				   HelpMessage = 'Internal Script Switch.')]
		[switch]$NoSQLPermission,
		[Parameter(Mandatory = $false,
				   Position = 29,
				   HelpMessage = 'Ping every Management Server, including servers mentioned in -Servers switch.')]
		[switch]$PingAll,
		[Parameter(Mandatory = $false,
				   Position = 30,
				   HelpMessage = 'Linux/Unix Agents you want to gather data from, via Bash Script that is transmitted via ssh.')]
		[Alias('LinuxAgents')]
		[Array]$SCXAgents,
		[Parameter(Position = 31,
				   HelpMessage = 'The SCX Maintenance Username to use for gathering with the Linux Data Collector.')]
		[string]$SCXMaintenanceUsername,
		[Parameter(Position = 32,
				   HelpMessage = 'The SCX Monitoring Username to use for gathering with the Linux Data Collector.')]
		[string]$SCXMonitoringUsername,
		[Parameter(Position = 33,
				   HelpMessage = 'The Linux/Unix Resource Pool(s) to gather SCX WinRM data.')]
		[Alias('scxrp')]
		[string[]]$SCXResourcePoolDisplayName,
		[Parameter(Mandatory = $false,
				   Position = 34,
				   HelpMessage = 'The username you would like to use for SCX Agent SSH Authentication.')]
		[Alias('LinuxUsername')]
		[string]$SCXUsername,
		[Parameter(Position = 35,
				   HelpMessage = 'Provide the WinRM Credentials to use for SCX WinRM querying.')]
		[pscredential]$SCXWinRMCredentials,
		[Parameter(Position = 36,
				   HelpMessage = 'Enumerate all the WinRM classes to use for SCX WinRM querying.')]
		[switch]$SCXWinRMEnumerateAllClasses,
		[Parameter(Position = 37,
				   HelpMessage = 'Enumerate specific (comma separated) WinRM classes to use for SCX WinRM querying.')]
		[string[]]$SCXWinRMEnumerateSpecificClasses = @('SCX_UnixProcess', 'SCX_Agent', 'SCX_OperatingSystem'),
		[Parameter(Mandatory = $false,
				   Position = 38,
				   HelpMessage = 'Set additional servers to run checks against. This can be Agents or Gateways, they have to be in the same domain at this time.')]
		[Alias('s')]
		[Array]$Servers,
		[Parameter(Position = 39,
				   HelpMessage = 'Skip the Best Practice Analyzer gathering.')]
		[Alias('sbpa')]
		[switch]$SkipBestPracticeAnalyzer,
		[Parameter(Position = 40,
				   HelpMessage = 'Skip the tests for remote accessibility, use this if you know your environment passes these tests. DO NOT USE THIS IF YOU ARENT SURE!')]
		[Alias('sct')]
		[switch]$SkipConnectivityTests,
		[Parameter(Position = 41,
				   HelpMessage = 'Skip the General Information file gathering.')]
		[Alias('sgi')]
		[switch]$SkipGeneralInformation,
		[Parameter(Mandatory = $false,
				   Position = 42,
				   HelpMessage = 'Skip the SQL Queries. This will leave you with much less data in the data collector. Other functions in the data collector may rely on the SQL Queries and may be missing data.')]
		[Alias('NoSQLQueries')]
		[switch]$SkipSQLQueries,
		[Parameter(Position = 43,
				   HelpMessage = 'Gather SQL Logs from OperationsManager and DataWarehouse DBs.')]
		[switch]$SQLLogs,
		[Parameter(Mandatory = $false,
				   Position = 44,
				   HelpMessage = 'Run only SQL Queries and Output to CSV.')]
		[switch]$SQLOnly,
		[Parameter(Mandatory = $false,
				   Position = 45,
				   HelpMessage = 'Internal Script Switch.',
				   DontShow = $true)]
		[switch]$SQLOnlyDW,
		[Parameter(Mandatory = $false,
				   Position = 46,
				   HelpMessage = 'Internal Script Switch.',
				   DontShow = $true)]
		[switch]$SQLOnlyOpsDB
	)
	
	# Gather the Parameters Passed to the function
	$cmdName = $MyInvocation.InvocationName
	$paramList = (Get-Command -Name $cmdName).Parameters
	foreach ($key in $paramList.Keys)
	{
		$value = (Get-Variable $key -ErrorAction SilentlyContinue).Value
		if ($value -or $value -eq 0)
		{
			$FunctionPassedArgs += "-{0} {1} " -f $key, [system.String]::Join(", ", $(($value -replace "True", "") -replace "False", ""))
			Write-Verbose $("-{0} {1} " -f $key, [system.String]::Join(", ", $(($value -replace "True", "") -replace "False", "")))
		}
	}
	<#
	=================================================================================
	  SCOM Health SQL Query Collection Script
	=================================================================================
	 Constants section - modify stuff here:
	=================================================================================
	$script:OpsDB_SQLServer = "SQL2A.opsmgr.net"
	$OpsDB_SQLDBName =  "OperationsManager"
	$script:DW_SQLServer = "SQL2A.opsmgr.net"
	$DW_SQLDBName =  "OperationsManagerDW"
	=================================================================================
	 Begin MAIN script section
	=================================================================================
	#>
	#Clear-Host
	# Check if this is running on a SCOM Management Server
	# Get SQLServer info from Registry if so
	trap
	{
		#potential error code
		#use continue or break keywords
		$e = $_.Exception
		$line = $_.InvocationInfo.ScriptLineNumber
		$msg = $e.Message
		
		Write-Verbose "Caught Exception: $e :: Message: $msg :: at line: $line"
		"$(Invoke-TimeStamp)Caught Exception: $e :: Message: $msg :: at line: $line" | Out-File $OutputPath\Error.log -Append
	}
	Import-Module OperationsManager -ErrorAction SilentlyContinue
	IF (!(Test-Path $OutputPath))
	{
		Write-Console "Output folder not found.  Creating output folder...." -ForegroundColor Gray
		mkdir $OutputPath | out-null
	}
	else
	{
		Write-Console "Output folder found. Removing Existing Files...." -ForegroundColor Gray
		Get-CimInstance Win32_Process | Select-Object ProcessId, ProcessName, CommandLine | ForEach-Object{
			if ($_.CommandLine -like ("*$OutputPath*"))
			{
				Write-Console "Found process using the output folder, closing process: $($_.ProcessName)" -ForegroundColor Gray
				Stop-Process $_.ProcessId -Force -ErrorAction SilentlyContinue
			}
		}
		Remove-Item -Path $OutputPath -Recurse -Force | Out-Null
		Write-Console "Creating output folder...." -ForegroundColor Gray
		mkdir $OutputPath | out-null
		mkdir $OutputPath\CSV | out-null
	}
	if ($SCXAgents -and -NOT $SCXWinRMCredentials)
	{
		if ($SCXUsername)
		{
			$SCXWinRMCredentials = (Get-Credential $SCXUsername)
		}
		else
		{
			$SCXWinRMCredentials = (Get-Credential)
		}
	}
	$MSKey = "HKLM:\SOFTWARE\Microsoft\Microsoft Operations Manager\3.0\Server Management Groups"
	IF (Test-Path $MSKey)
	{
		# This is a management server.  Try to get the database values.
		$SCOMKey = "HKLM:\SOFTWARE\Microsoft\Microsoft Operations Manager\3.0\Setup"
		$SCOMData = Get-ItemProperty $SCOMKey
		$script:OpsDB_SQLServer = ($SCOMData).DatabaseServerName
		$script:OpsDB_SQLServerOriginal = $script:OpsDB_SQLServer
		$OpsDB_SQLDBName = ($SCOMData).DatabaseName
		$script:DW_SQLServer = ($SCOMData).DataWarehouseDBServerName
		$script:DW_SQLServerOriginal = $script:DW_SQLServer
		$DW_SQLDBName = ($SCOMData).DataWarehouseDBName
		$mgmtserver = 1
	}
	ELSE
	{
		if ($RemoteMGMTserver)
		{
			$ComputerName = $RemoteMGMTserver
		}
		else
		{
			do
			{
				$ComputerName = read-host "Please enter the name of a SCOM management server $env:userdomain\$env:USERNAME has permissions on"
			}
			until ($ComputerName)
		}
		$Hive = [Microsoft.Win32.RegistryHive]::LocalMachine
		$KeyPath = 'SOFTWARE\Microsoft\Microsoft Operations Manager\3.0\Setup'
		$OpsDBServer = 'DatabaseServerName'
		$OpsDBName = 'DatabaseName'
		$DWServer = 'DataWarehouseDBServerName'
		$DWDB = 'DataWarehouseDBName'
		$reg = [Microsoft.Win32.RegistryKey]::OpenRemoteBaseKey($Hive, $ComputerName)
		$key = $reg.OpenSubKey($KeyPath)
		$script:OpsDB_SQLServer = $key.GetValue($OpsDBServer)
		$script:OpsDB_SQLServerOriginal = $key.GetValue($OpsDBServer)
		$OpsDB_SQLDBName = $key.GetValue($OpsDBName)
		$script:DW_SQLServer = $key.GetValue($DWServer)
		$script:DW_SQLServerOriginal = $key.GetValue($DWServer)
		$DW_SQLDBName = $key.GetValue($DWDB)
	}
	if (!$script:OpsDB_SQLServer)
	{
		do
		{
			$script:OpsDB_SQLServer = read-host "Please enter the name of the Operations Manager SQL Database Server. (ex. SQL-2019\SCOM2019)"
		}
		until ($script:OpsDB_SQLServer)
		$script:OpsDB_SQLServerOriginal = $script:OpsDB_SQLServer
	}
	if (!$OpsDB_SQLDBName)
	{
		do
		{
			$OpsDBName = read-host "Please enter the name of the Operations Manager SQL Database Name. (ex. OperationsManager)"
		}
		until ($OpsDBName)
		$OpsDB_SQLDBName = $OpsDBName
	}
	if (!$script:DW_SQLServer)
	{
		do
		{
			$script:DW_SQLServer = read-host "Please enter the name of the Operations Manager Data Warehouse SQL Server Name. (ex. SQL-2019\SCOM2019)"
		}
		until ($script:DW_SQLServer)
		$script:DW_SQLServerOriginal = $script:DW_SQLServer
	}
	if (!$DW_SQLDBName)
	{
		do
		{
			$DW_SQLDBName = read-host "Please enter the name of the Operations Manager Data Warehouse SQL Database Name. (ex. OperationsManagerDW)"
		}
		until ($DW_SQLDBName)
	}
	if (!$SkipSQLQueries -or $SQLOnly)
	{
		. $ScriptPath`\Functions\SQL-Queries.ps1
		if (($SQLOnly -or $SQLOnlyDW -or $SQLOnlyOpsDB))
		{
			[System.Security.Principal.WindowsIdentity]::GetCurrent().Name
			Invoke-SQLQueries
			if ($SQLOnlyDW)
			{
				exit 0
			}
			if ($SQLOnlyOpsDB)
			{
				exit 0
			}
			write-output " "
			write-output "================================`n   Wrapping Up`n================================"
			Write-Console "Moving stuff around and zipping everything up for easy transport" -ForegroundColor Gray
			. $ScriptPath`\Functions\Wrapping-Up.ps1
			Invoke-WrapUp -BuildPipeline:$BuildPipeline
			Write-Console "`n---Script has completed!`n" -ForegroundColor Green -NoNewline
			Start-Sleep -Seconds 1
			Start-Process C:\Windows\explorer.exe -ArgumentList "/select, $script:destfile"
			break
		}
		else
		{
			Invoke-SQLQueries
		}
	}
	
	Write-Progress -Activity "Collection Running" -Status "Progress-> 1%" -PercentComplete 1
	
	#$TLSservers = import-csv $OutputPath\ManagementServers.csv
	if (!$script:ManagementServers)
	{
		try
		{
			$script:ManagementServers = Get-SCOMManagementServer -ErrorAction Stop | Where-Object { $_.IsGateway -eq $false } | Sort-Object DisplayName -Descending | Select-Object DisplayName -ExpandProperty DisplayName -Unique
		}
		catch
		{
			$script:ManagementServers = import-csv $OutputPath\ManagementServers.csv | Where-Object { $_.IsGateway -eq $false } | Sort-Object DisplayName -Descending | Select-Object DisplayName -ExpandProperty DisplayName -Unique
		}
	}
	if (-NOT ($script:ManagementServers))
	{
		"$(Invoke-TimeStamp)Unable to detect any Management Servers with the `'Get-SCOMManagementServer`' command and the SQL Query to return Management Servers. Setting the `$ManagementServer variable to $env:COMPUTERNAME (local machine)." | Out-File $OutputPath\Error.log -Append
		$script:ManagementServers = $env:COMPUTERNAME
	}
	Write-Progress -Activity "Collection Running" -Status "Progress-> 2%" -PercentComplete 2
	[string[]]$TLSservers = $script:ManagementServers
	
	[string[]]$TLSservers += ($script:DW_SQLServer.Split('\')[0]).Split(',')[0]
	
	[string[]]$TLSservers += ($script:OpsDB_SQLServer.Split('\')[0]).Split(',')[0]
	
	[string[]]$script:TestedTLSservers = @()
	if (!$SkipConnectivityTests)
	{
		$pathtestOpsMgr = Test-Path -Path $OutputPath\SQL_Primary_Replicas_OpsMgr.csv
		if ($pathtestOpsMgr)
		{
			$replicasCSV = import-csv $OutputPath\SQL_Primary_Replicas_OpsMgr.csv
			if ($replicasCSV.replica_server_name)
			{
				Foreach ($replica in $replicasCSV.replica_server_name)
				{
					[string[]]$TLSservers += ($replica.Split('\')[0]).Split(',')[0]
				}
			}
		}
		
		$pathtestDW = Test-Path -Path $OutputPath\SQL_Primary_Replicas_DW.csv
		if ($pathtestDW)
		{
			$dwreplicasCSV = import-csv $OutputPath\SQL_Primary_Replicas_DW.csv
			if ($dwreplicasCSV.replica_server_name)
			{
				Foreach ($replica in $dwreplicasCSV.replica_server_name)
				{
					[string[]]$TLSservers += ($replica.Split('\')[0]).Split(',')[0]
				}
			}
		}
		
		Write-Progress -Activity "Collection Running" -Status "Progress-> 3%" -PercentComplete 3
		if ($Servers)
		{
			$Servers = ($Servers.Split(",").Split(" ") -replace (" ", ""))
			$Servers = $Servers | Select-Object -Unique
			foreach ($Server in $Servers)
			{
				[string[]]$TLSservers += $Server
			}
		}
		[array]$DNSCheckedServers = $null
		[string[]]$TLSservers = $TLSservers | Select-Object -Unique | Where-Object { $null -ne $_ }
		Write-Progress -Activity "Collection Running" -Status "Progress-> 4%" -PercentComplete 4
		foreach ($server in $TLSservers)
		{
			try
			{
				[array]$DNSCheckedServers += ([System.Net.Dns]::GetHostByName(("$server"))).Hostname
			}
			catch
			{
				"$(Invoke-TimeStamp)Unable to Find DNS Hostname: $server - from $env:COMPUTERNAME - Not adding to list of Servers to Check." | Out-File $OutputPath\Error.log -Append
				Write-Console "Unable to Find DNS Hostname: $server - Not adding to list of Servers to Check." -ForegroundColor Red
			}
		}
		Write-Progress -Activity "Collection Running" -Status "Progress-> 5%" -PercentComplete 5
		[array]$DNSVerifiedServers = [array]$DNSCheckedServers | Select-Object -Unique | Sort-Object
		$DNSCount = ($DNSVerifiedServers).Count
		
		Write-Output " "
		Write-Output "================================`nTesting Connectivity to Servers (Count: $DNSCount)"
		foreach ($Rsrv in $DNSVerifiedServers)
		{
			$shareAccessible = $false
			Write-Console "  Testing $Rsrv" -ForegroundColor Gray
			$test = $null
			$test = test-path "filesystem::\\$Rsrv\c`$" -ErrorAction SilentlyContinue
			if ($test)
			{
				Write-Console "    Successfully Accessed Remote Share : \\$Rsrv\c`$" -ForegroundColor Green
				$shareAccessible = $true
			}
			else
			{
				"$(Invoke-TimeStamp)Access to \\$Rsrv\c`$ Failed from $($env:COMPUTERNAME)" | Out-File $OutputPath\Error.log -Append
				Write-Console "    Access to \\$Rsrv\c`$ Failed! Removing from Server Array! 
    Please verify that the server is online, and that your account has remote access to it.`n" -ForegroundColor Gray
				continue
			}
			$InvokeAbility = Invoke-Command -ErrorAction SilentlyContinue -ComputerName $Rsrv -ScriptBlock { return $true }
			if ($InvokeAbility)
			{
				Write-Console "    Successfully Executed Powershell Invoke Command : $Rsrv" -ForegroundColor Green
				if ($shareAccessible)
				{
					$script:TestedTLSservers += $Rsrv.Split(",")
				}
			}
			else
			{
				"$(Invoke-TimeStamp)Unable to Invoke-Commands against $Rsrv" | Out-File $OutputPath\Error.log -Append
				Write-Console "    Unable to Invoke-Commands for $Rsrv! Removing from Server Array! 
    Verify that you have PSRemoting turned on: Enable-PSRemoting`n" -ForegroundColor Gray
				continue
			}
		}
		$script:TestedTLSservers = $script:TestedTLSservers | Select-Object -Unique | Sort-Object
		$templist = @()
		foreach ($server in $script:TestedTLSservers)
		{
			foreach ($ManagementServer in $script:ManagementServers)
			{
				if ($server -match "^$ManagementServer")
				{
					$templist += $server
				}
			}
		}
		$OriginalManagementServers = $script:ManagementServers | Select-Object -Unique | Sort-Object
		$script:ManagementServers = $templist
	}
	else
	{
		$script:TestedTLSservers = $TLSservers | Select-Object -Unique
	}
	#region Linux Agent Gather Script
	if ($SCXAgents)
	{
		try
		{
			$UNIXAgentPools = (Import-Csv "$OutputPath\UNIX_Agents.csv" -ErrorAction Stop).ResourcePool | Select-Object -Unique
			$UNIXManagementServer = (Import-Csv "$OutputPath\ResourcePools.csv" -ErrorAction Stop | Where-Object { $_.ResourcePool -in $UNIXAgentPools -and $SCXResourcePools -contains $_.ResourcePool}).Member
		}
		catch
		{
			Write-Host "NOT FOUND"
			$UNIXManagementServer = $null
		}
		if ($UNIXManagementServer)
		{
			Write-Output " "
			Write-Output "================================`nGathering Linux Data Collector (UNIX/Linux)"
			. $ScriptPath`\Functions\Linux-DataCollector.ps1
			Start-LinuxDataCollector -Servers $SCXAgents -Username $SCXUsername -SCXMaintenanceUsername $SCXMaintenanceUsername -SCXMonitoringUsername $SCXMonitoringUsername
			
			Write-Output " "
			Write-Output "================================`nGathering SCX WinRM data (UNIX/Linux)"
			. $ScriptPath`\Functions\Linux-WinRM-Tests.ps1
			Write-Console "  Gathering Linux Agent Data from: $($SCXAgents -join ", ")" -ForegroundColor Green
			if ($SCXWinRMEnumerateAllClasses)
			{
				Invoke-SCXWinRMEnumeration -OriginServer $UNIXManagementServer -ComputerName $SCXAgents -Credential $SCXWinRMCredentials -EnumerateAllClasses -OutputType Text -OutputFile $OutputPath\SCX_WinRM_Queries -PassThru | Out-Null
			}
			else
			{
				Invoke-SCXWinRMEnumeration -OriginServer $UNIXManagementServer -ComputerName $SCXAgents -Credential $SCXWinRMCredentials -Classes $SCXWinRMEnumerateSpecificClasses -OutputType Text -OutputFile $OutputPath\SCX_WinRM_Queries -PassThru | Out-Null
			}
		}
		else
		{
			"$(Invoke-TimeStamp)Could not find any Management Servers associated with SCX Resource Pool(s): $SCXResourcePools" | Out-File $OutputPath\Error.log -Append
			Write-Warning "Could not find any Management Servers associated with SCX Resource Pool(s): $SCXResourcePools"
		}
	}
	#endregion Linux Agent Gather Script
	#region Least Amount
	if (!$LeastAmount)
	{
		Write-Progress -Activity "Collection Running" -Status "Progress-> 6%" -PercentComplete 6
		$error.clear()
		try
		{
			if ($GetRunAsAccounts)
			{
				Write-Output " "
				Write-Console "================================`nGathering RunAs Accounts"
				. $ScriptPath`\Functions\Get-RunasAccount.ps1
				Write-Console "  Gathering from: " -NoNewline -ForegroundColor Gray
				Write-Console $script:ManagementServers[0] -NoNewline -ForegroundColor Cyan
				Write-Progress -Activity "Collection Running" -Status "Progress-> 7%" -PercentComplete 7
				Get-SCOMRunasAccount -ManagementServer $script:ManagementServers[0]
				Write-Output " "
			}
		}
		catch
		{
			"$(Invoke-TimeStamp)Unable to gather RunAs Accounts due to error: $error" | Out-File $OutputPath\Error.log -Append
			Write-Warning "$error"
		}
		Write-Progress -Activity "Collection Running" -Status "Progress-> 8%" -PercentComplete 8
		$error.clear()
		try
		{
			if ($CheckCertificates)
			{
				Write-Output " "
				Write-Output "================================`nGathering and checking Certificates"
				. $ScriptPath`\Functions\Certificate-Check.ps1
				New-Item -ItemType Directory -Path "$OutputPath\Certificates" -Force -ErrorAction Stop | Out-Null
				Write-Progress -Activity "Collection Running" -Status "Progress-> 9%" -PercentComplete 9
				foreach ($CertChkSvr in $script:TestedTLSservers)
				{
					Invoke-SCOMCertificateChecker -Servers $CertChkSvr -OutputFile $OutputPath\Certificates\$CertChkSvr.CertificateInfo.txt
				}
			}
			if ($ExportMSCertificates)
			{
				Write-Output " "
				Write-Output "================================`nExporting Management Server Certificates"
				. $ScriptPath`\Functions\Export-SCOMMSCertificate.ps1
				Write-Progress -Activity "Collection Running" -Status "Progress-> 10%" -PercentComplete 10
				Export-SCOMMSCertificate -Servers $script:TestedTLSservers -ExportPath $OutputPath\Certificates
			}
		}
		catch
		{
			"$(Invoke-TimeStamp)Unable to gather SCOM Certificates due to error: $error" | Out-File $OutputPath\Error.log -Append
			Write-Warning "$error"
		}
		$error.clear()
		try
		{
			if ($GetInstalledSoftware)
			{
				Write-Output " "
				Write-Output "================================`nGathering Installed Software"
				. $ScriptPath`\Functions\Get-InstalledSoftware.ps1
				Write-Progress -Activity "Collection Running" -Status "Progress-> 11%" -PercentComplete 11
				# Get Installed Software
				$installedsoftware = Invoke-GetInstalledSoftware -Servers $script:TestedTLSservers
				$installedsoftware | Format-Table * -AutoSize | Out-String -Width 4096 | Out-File "$OutputPath\Installed-Software.txt"
				$installedsoftware | Export-Csv -Path "$OutputPath\Installed-Software.csv" -NoTypeInformation
			}
		}
		catch
		{
			"$(Invoke-TimeStamp)Unable to gather Installed Software due to error: $error" | Out-File $OutputPath\Error.log -Append
			Write-Warning "$error"
		}
		$error.clear()
		try
		{
			if ($GetSPN)
			{
				Write-Output " "
				Write-Output "================================`nGathering SPNs from Active Directory"
				. $ScriptPath`\Functions\Get-SPN.ps1
				Write-Progress -Activity "Collection Running" -Status "Progress-> 12%" -PercentComplete 12
				# Get SPNs from Active Directory
				Write-Console "  Running function to gather SPN Data" -ForegroundColor Gray -NoNewline
				try
				{
					$spnOutput1 = Get-SPN -ErrorAction Stop -ComputerName $TLSservers | Select-Object * -Unique | Where-Object { $_.ServiceClass -ne 'MSOMSdkSvc' } | Sort-Object -Property ComputerName, ServiceClass, whenChanged
					Write-Console "-" -ForegroundColor Green -NoNewline
				}
				catch
				{
					"$(Invoke-TimeStamp)Unable to gather SPN Output due to error: $($error[0])" | Out-File $OutputPath\Error.log -Append
					"Unable to gather SPN Output due to error: `n$($error[0])" | Out-File -FilePath $OutputPath\SPN-Output.txt -Force
				}
				try
				{
					$spnOutput2 = Get-SPN -ErrorAction Stop -ServiceClass MSOMSdkSvc | Select-Object * -Unique | Sort-Object -Property ComputerName, ServiceClass, whenChanged
					Write-Console "-" -ForegroundColor Green -NoNewline
				}
				catch
				{
					"$(Invoke-TimeStamp)Unable to gather SPN Output due to error: $($error[0])" | Out-File $OutputPath\Error.log -Append
					"Unable to gather SPN Output due to error: `n$($error[0])" | Out-File -FilePath $OutputPath\SPN-Output.txt -Force
				}
				if ($spnOutput1 -or $spnOutput2)
				{
					$spnFinal = ($spnOutput1, $spnOutput2) | Select-Object -Unique | Sort-Object ServiceClass, ComputerName
					$spnFinal | Format-Table * -AutoSize | Out-String -Width 4096 | Out-File -FilePath $OutputPath\SPN-Output.txt -Force
					$spnOutput1 | Export-Csv -Path $OutputPath\SPN-Output.csv -NoTypeInformation
					$spnOutput2 | Export-Csv -Path $OutputPath\SPN-Output.csv -NoTypeInformation -Append
				}
				
				Write-Console "> Completed!" -ForegroundColor Green
			}
		}
		catch
		{
			"$(Invoke-TimeStamp)Unable to gather SPN data due to error: $error" | Out-File $OutputPath\Error.log -Append
			Write-Warning "$error"
		}
		$error.clear()
		try
		{
			if ($CheckTLS)
			{
				Write-Output " "
				Write-Output "================================`nGathering TLS Data"
				. $ScriptPath`\Functions\Get-TLSRegKeys.ps1
				Write-Progress -Activity "Collection Running" -Status "Progress-> 13%" -PercentComplete 13
				# This will be updated with CipherSuite checks at some point
				Get-TLSRegistryKeys -Servers $script:TestedTLSservers |
				Out-File $OutputPath\TLS-RegistryKeys.txt
			}
		}
		catch
		{
			"$(Invoke-TimeStamp)Unable to gather TLS data due to error: $error" | Out-File $OutputPath\Error.log -Append
			Write-Warning "$error"
		}
		$error.clear()
		try
		{
			if ($GetConfiguration)
			{
				Write-Progress -Activity "Collection Running" -Status "Progress-> 14%" -PercentComplete 14
				Write-Output " "
				Write-Output "================================`nGathering Management Server Configuration"
				. $ScriptPath`\Functions\Get-Configuration.ps1
				Get-SCOMConfiguration -Servers $script:ManagementServers
			}
		}
		catch
		{
			"$(Invoke-TimeStamp)Unable to gather Configuration data due to error: $error" | Out-File $OutputPath\Error.log -Append
			Write-Warning "$error"
		}
		$error.clear()
		try
		{
			if ($GetEventLogs -or $AdditionalEventLogs)
			{
				Write-Output " "
				Write-Output "================================`nGathering Event Logs"
				. $ScriptPath`\Functions\Get-EventLog.ps1
				Write-Progress -Activity "Collection Running" -Status "Progress-> 16%" -PercentComplete 16
				if ((Test-Path -Path "$OutputPath\Event Logs") -eq $false)
				{
					Write-Console "  Creating Folder: $OutputPath\Event Logs" -ForegroundColor Gray
					mkdir "$OutputPath\Event Logs" | out-null
				}
				else
				{
					Write-Console "  Existing Folder Found: $OutputPath\Event Logs" -ForegroundColor Gray
					Remove-Item "$OutputPath\Event Logs" -Recurse | Out-Null
					Write-Console "   Deleting folder contents" -ForegroundColor Gray
					mkdir "$OutputPath\Event Logs" | out-null
					Write-Console "    Folder Created: $OutputPath\Event Logs" -ForegroundColor Gray
				}
				Write-Progress -Activity "Collection Running" -Status "Progress-> 18%" -PercentComplete 18
				foreach ($ElogServer in $script:TestedTLSservers)
				{
					
					if ($AdditionalEventLogs)
					{
						$Logs = "Application", "System", "Operations Manager", $AdditionalEventLogs
						Get-SCOMEventLogs -Servers $ELogServer -Logs $Logs
					}
					else
					{
						$Logs = "Application", "System", "Operations Manager"
						Get-SCOMEventLogs -Servers $ELogServer -Logs $Logs
					}
				}
				Write-Progress -Activity "Collection Running" -Status "Progress-> 20%" -PercentComplete 20
				Write-Output " "
			}
		}
		catch
		{
			"$(Invoke-TimeStamp)Unable to gather Event Log data due to error: $error" | Out-File $OutputPath\Error.log -Append
			Write-Warning "$error"
		}
		Write-Progress -Activity "Collection Running" -Status "Progress-> 22%" -PercentComplete 22
		$error.clear()
		try
		{
			if ($ExportMPs)
			{
				try
				{
					if ($mgmtserver -eq 1)
					{
						Write-Output "================================`nExporting Management Packs"
						. $ScriptPath`\Functions\Export-ManagementPack.ps1
						Write-Progress -Activity "Collection Running" -Status "Progress-> 23%" -PercentComplete 23
						Invoke-MPExport
    <#
        md $OutputPath\MPSealed | out-null
        try{
           (Get-SCOMManagementPack).where{$_.Sealed -eq $true} | Export-SCOMManagementPack -path $OutputPath\MPSealed
        }catch{
           
        }
    #>
						
					}
					else
					{
						Write-Warning "  Exporting Management Packs is only possible from a management server"
					}
				}
				catch
				{
					Write-Warning $_; "$(Invoke-TimeStamp)Unable to gather Event Log data due to error: $error" | Out-File $OutputPath\Error.log -Append
					Write-Warning "$error"
				}
			}
		}
		catch
		{
			"$(Invoke-TimeStamp)Unable to gather Event Log data due to error: $error" | Out-File $OutputPath\Error.log -Append
			Write-Warning "$error"
		}
		Write-Progress -Activity "Collection Running" -Status "Progress-> 24%" -PercentComplete 24
		$error.clear()
		try
		{
			if ($GetRulesAndMonitors)
			{
				Write-Output " "
				Write-Console "================================`nGathering Rules and Monitors"
				Write-Progress -Activity "Collection Running" -Status "Progress-> 25%" -PercentComplete 25
				. $ScriptPath`\Functions\Get-RulesAndMonitors.ps1
				Get-RulesAndMonitors -OutputDirectory $OutputPath -ManagementServer $script:ManagementServers[0]
				Write-Output " "
			}
		}
		catch
		{
			"$(Invoke-TimeStamp)Unable to gather Rules and Monitors data due to error: $error" | Out-File $OutputPath\Error.log -Append
			Write-Warning "$error"
		}
		Write-Progress -Activity "Collection Running" -Status "Progress-> 26%" -PercentComplete 26
		$error.clear()
		try
		{
			if ($GetLocalSecurity)
			{
				write-output " "
				Write-Console "====================================================================`nGathering the Local Security Policies & Local Administrators Group"
				. $ScriptPath`\Functions\Get-LocalUserAccountsRights.ps1
				Write-Progress -Activity "Collection Running" -Status "Progress-> 27%" -PercentComplete 27
				Get-LocalUserAccountsRights -Servers $script:TestedTLSservers
			}
		}
		catch
		{
			"$(Invoke-TimeStamp)Unable to gather Local Security / User Account Rights data due to error: $error" | Out-File $OutputPath\Error.log -Append
			Write-Warning "$error"
		}
		Write-Progress -Activity "Collection Running" -Status "Progress-> 30%" -PercentComplete 30
		$error.clear()
		try
		{
			if ($CheckPorts)
			{
				. $ScriptPath`\Functions\Test-SCOMPorts.ps1
				Write-Progress -Activity "Collection Running" -Status "Progress-> 32%" -PercentComplete 32
				Invoke-TestSCOMPorts -SourceServer $script:TestedTLSservers -DestinationServer $env:COMPUTERNAME -OutputFile $OutputPath\Port_Checker.txt -OutputType CSV, Text
			}
		}
		catch
		{
			"$(Invoke-TimeStamp)Unable to Test SCOM Ports due to error: $error" | Out-File $OutputPath\Error.log -Append
			Write-Warning "$error"
		}
		Write-Progress -Activity "Collection Running" -Status "Progress-> 34%" -PercentComplete 34
		$error.clear()
		try
		{
			if ($msinfo32)
			{
				write-output " "
				Write-Console "================================`nGathering MSInfo32"
				. $ScriptPath`\Functions\MsInfo32.ps1
				Write-Progress -Activity "Collection Running" -Status "Progress-> 36%" -PercentComplete 36
				Invoke-MSInfo32Gathering
			}
		}
		catch
		{
			"$(Invoke-TimeStamp)Unable to gather MSInfo32 data due to error: $error" | Out-File $OutputPath\Error.log -Append
			Write-Warning "$error"
		}
		$error.clear()
		try
		{
			if ($GetNotificationSubscriptions)
			{
				write-output " "
				Write-Console "================================`nGathering Notification Subscriptions"
				. $ScriptPath`\Functions\Get-SCOMNotificationSubscriptionDetails.ps1
				Write-Progress -Activity "Collection Running" -Status "Progress-> 37%" -PercentComplete 36
				Get-SCOMNotificationSubscriptionDetails -OutputFile $OutputPath\Notification_Subscriptions.txt
			}
		}
		catch
		{
			"$(Invoke-TimeStamp)Unable to Get Notification Subscriptions due to error: $error" | Out-File $OutputPath\Error.log -Append
			Write-Warning "$error"
		}
		Write-Progress -Activity "Collection Running" -Status "Progress-> 38%" -PercentComplete 38
		$error.clear()
		try
		{
			if ($SQLLogs)
			{
				$error.clear()
				try
				{
					Write-Progress -Activity "Collection Running" -Status "Progress-> 39%" -PercentComplete 39
					if (Test-Path $OutputPath\SQL_ErrorLogLocation_OpsDB.csv -ErrorAction Stop)
					{
						write-output " "
						Write-Console "================================`nGathering SQL Logs"
						
						mkdir "$OutputPath`\SQL Logs" | out-null
						$SQLOMLogLoc = Import-Csv $OutputPath\SQL_ErrorLogLocation_OpsDB.csv -ErrorAction Stop
						if ($script:DW_SQLServer -ne $script:OpsDB_SQLServer)
						{
							$SQLDWLogLoc = Import-Csv $OutputPath\SQL_ErrorLogLocation_DW.csv -ErrorAction Stop
						}
						else
						{
							$SQLDWLogLoc = $null
						}
						Write-Progress -Activity "Collection Running" -Status "Progress-> 40%" -PercentComplete 40
						$SQLOMLogLoc = ($SQLOMLogLoc).text
						$SQLOMLogLoc = $SQLOMLogLoc.split("'")[1]
						$SQLOMLogLoc = $SQLOMLogLoc.Replace(':', '$')
						$SQLOMLogLoc = $SQLOMLogLoc.replace("ERRORLOG", '*')
						if ($SQLDWLogLoc)
						{
							$SQLDWLogLoc = ($SQLDWLogLoc).text
							$SQLDWLogLoc = $SQLDWLogLoc.split("'")[1]
							$SQLDWLogLoc = $SQLDWLogLoc.Replace(':', '$')
							$SQLDWLogLoc = $SQLDWLogLoc.replace("ERRORLOG", '*')
							#$dest = "$locsrv" + "\$OutputPath"
						}
						Write-Progress -Activity "Collection Running" -Status "Progress-> 41%" -PercentComplete 41
						
						if ($script:OpsDB_SQLServer -ne $script:DW_SQLServer)
						{
							mkdir "$OutputPath`\SQL Logs\OperationsManager" | out-null
							mkdir "$OutputPath`\SQL Logs\DataWarehouse" | out-null
							Write-Console "  Copying " -NoNewline -ForegroundColor Cyan
							Write-Console "$OpsDB_SQLDBName" -NoNewline -ForegroundColor Magenta
							Write-Console " Database SQL Logs from " -NoNewline -ForegroundColor Cyan
							Write-Console "$script:OpsDB_SQLServer" -ForegroundColor Magenta
							Copy-Item -path \\$script:OpsDB_SQLServer\$SQLOMLogLoc -Destination "$OutputPath`\SQL Logs\OperationsManager" -Exclude *.MDMP, *.dmp, *.trc, *.txt | Out-Null # exclude *.trc *.dmp *.mdmp
							Write-Console "    Copying " -NoNewline -ForegroundColor Cyan
							Write-Console "$DW_SQLDBName" -NoNewline -ForegroundColor Magenta
							Write-Console " Database SQL Logs from " -NoNewline -ForegroundColor Cyan
							Write-Console "$script:DW_SQLServer" -NoNewline -ForegroundColor Magenta
							Copy-Item -path \\$script:DW_SQLServer\$SQLDWLogLoc -Destination "$OutputPath`\SQL Logs\DataWarehouse" -Exclude *.MDMP, *.dmp, *.trc, *.txt | Out-Null # exclude *.trc *.dmp *.mdmp
						}
						Write-Progress -Activity "Collection Running" -Status "Progress-> 42%" -PercentComplete 42
						if ($script:OpsDB_SQLServer -eq $script:DW_SQLServer)
						{
							Write-Console "  Copying " -NoNewline -ForegroundColor Cyan
							Write-Console "$OpsDB_SQLDBName" -NoNewline -ForegroundColor Magenta
							Write-Console " & " -NoNewline -ForegroundColor Cyan
							Write-Console "$DW_SQLDBName" -NoNewline -ForegroundColor Magenta
							Write-Console " Database SQL Logs from " -NoNewline -ForegroundColor Cyan
							Write-Console "$script:OpsDB_SQLServer" -ForegroundColor Magenta
							Copy-Item -path \\$script:OpsDB_SQLServer\$SQLOMLogLoc -Destination "$OutputPath`\SQL Logs\" | Out-Null
						}
						Write-Progress -Activity "Collection Running" -Status "Progress-> 43%" -PercentComplete 43
					}
				}
				catch
				{
					"$(Invoke-TimeStamp)Unable to Gather SQL Error Logs due to error: $error" | Out-File $OutputPath\Error.log -Append
				}
				
			}
		}
		catch
		{
			"$(Invoke-TimeStamp)Unable to Gather SQL Error Logs due to error: $error" | Out-File $OutputPath\Error.log -Append
		}
		Write-Progress -Activity "Collection Running" -Status "Progress-> 44%" -PercentComplete 44
		$error.clear()
		try
		{
			if ($GetInstallLogs)
			{
				Write-Output " "
				Write-Console "================================`nGathering Operations Manager Install Logs"
				. $ScriptPath`\Functions\Get-InstallLogs.ps1
				Write-Progress -Activity "Collection Running" -Status "Progress-> 46%" -PercentComplete 46
				Invoke-GetInstallLogs -Servers $script:TestedTLSservers
			}
		}
		catch
		{
			"$(Invoke-TimeStamp)Unable to gather SCOM Install Logs due to error: $error" | Out-File $OutputPath\Error.log -Append
			Write-Warning "$error"
		}
		Write-Progress -Activity "Collection Running" -Status "Progress-> 48%" -PercentComplete 48
		$error.clear()
		try
		{
			if ($GPResult)
			{
				write-output " "
				Write-Console "================================`nGathering Group Policy Result"
				foreach ($gpserver in $script:TestedTLSservers)
				{
					try
					{
						if ($gpserver -match $Comp)
						{
							mkdir -Path "$OutputPath`\GPResults" -Force | Out-Null
							Write-Console "  Gathering HTML Generated Output locally: `'" -NoNewLine -ForegroundColor Cyan
							Write-Console "$Comp" -NoNewLine -ForegroundColor Magenta
							Write-Console "`'" -ForegroundColor Cyan
							Start-Process -FilePath GPResult.exe -WorkingDirectory C:\Windows\System32 -ArgumentList "/H `"$OutputPath`\GPResults\$Comp`-GPResult.html`"" -ErrorAction Stop -Wait
							#gpresult /H "$OutputPath`\GPResults\$Comp`-GPResult.html"
							
							Write-Console "  Gathering Text Generated Output locally: `'" -NoNewLine -ForegroundColor Cyan
							Write-Console "$Comp" -NoNewLine -ForegroundColor Magenta
							Write-Console "`'" -ForegroundColor Cyan
							Start-Process -FilePath GPResult.exe -WorkingDirectory C:\Windows\System32 -ArgumentList "/Z" -ErrorAction Stop -Wait | Out-File -FilePath "$OutputPath`\GPResults\$Comp`-GPResult-Z.txt"
							#gpresult /Z | Out-File -FilePath "$OutputPath`\GPResults\$Comp`-GPResult-Z.txt"
						}
						else
						{
							Write-Console "  Gathering HTML Generated Output: `'" -NoNewLine -ForegroundColor Cyan
							Write-Console "$gpserver" -NoNewLine -ForegroundColor Magenta
							Write-Console "`'" -ForegroundColor Cyan
							Start-Process -FilePath GPResult.exe -WorkingDirectory C:\Windows\System32 -ArgumentList "/H `"$OutputPath`\GPResults\$gpserver`-GPResult.html`" /S $gpserver" -ErrorAction Stop -Wait
							#gpresult /H "$OutputPath`\GPResults\$gpserver`-GPResult.html" /S $gpserver
							
							Write-Console "  Gathering Text Generated Output: `'" -NoNewLine -ForegroundColor Cyan
							Write-Console "$gpserver" -NoNewLine -ForegroundColor Magenta
							Write-Console "`'" -ForegroundColor Cyan
							Start-Process -FilePath GPResult.exe -WorkingDirectory C:\Windows\System32 -ArgumentList "/Z /S $gpserver" -ErrorAction Stop -Wait | Out-File -FilePath "$OutputPath`\GPResults\$gpserver`-GPResult-Z.txt"
							#gpresult /Z /S $gpserver | Out-File -FilePath "$OutputPath`\GPResults\$gpserver`-GPResult-Z.txt"
						}
					}
					catch
					{
						Write-Warning $_
						continue
					}
					Write-Progress -Activity "Collection Running" -Status "Progress-> 58%" -PercentComplete 58
					
					
				}
			}
		}
		catch
		{
			"$(Invoke-TimeStamp)Unable to gather GPResult due to error: $error" | Out-File $OutputPath\Error.log -Append
			Write-Warning "$error"
		}
		$error.clear()
		try
		{
			if ($CheckGroupPolicy)
			{
				# Check Group Policy ability to Update
				write-output " "
				Write-Console "================================`nVerifying Group Policy Update / Gathering Results"
				. $ScriptPath`\Functions\Check-GroupPolicy.ps1
				Check-GroupPolicy -Servers $script:TestedTLSservers
				Write-Progress -Activity "Collection Running" -Status "Progress-> 59%" -PercentComplete 59
			}
		}
		catch
		{
			"$(Invoke-TimeStamp)Unable to update Group Policy due to error: $error" | Out-File $OutputPath\Error.log -Append
		}
		if ($GetUserRoles)
		{
			try
			{
				
				write-output " "
				Write-Console "================================`nGathering SCOM User Role Configuration"
				$UserRoles = $Null
				$UserRoles = @()
				$UserRoleList = Get-SCOMUserRole
				Write-Progress -Activity "Collection Running" -Status "Progress-> 60%" -PercentComplete 60
				Write-Console "  Processing User Role:  " -ForegroundColor Cyan
				foreach ($UserRole in $UserRoleList)
				{
					Write-Console "    $UserRole" -ForegroundColor Magenta
					$UserRoles += New-Object -TypeName psobject -Property @{
						Name	    = $UserRole.Name;
						DisplayName = $UserRole.DisplayName;
						Description = $UserRole.Description;
						Users	    = ($UserRole.Users -join "; ");
					}
				}
				Write-Progress -Activity "Collection Running" -Status "Progress-> 61%" -PercentComplete 61
				$UserRolesOutput = $UserRoles | Select-Object Name, DisplayName, Description, Users
				$UserRolesOutput | Out-File "$OutputPath`\UserRoles.txt" -Width 4096
				$UserRolesOutput | Export-CSV -Path "$OutputPath`\UserRoles.csv" -NoTypeInformation
			}
			catch
			{
				"$(Invoke-TimeStamp)Unable to gather User Role Information due to error: $($error[0])" | Out-File $OutputPath\Error.log -Append
				Write-Warning "$error"[0]
			}
		}
		
	}
	#endregion least amount
	
	#region Pending Management
	$error.clear()
	try
	{
		if (!$script:ManagementServers)
		{
			$script:ManagementServers = $OriginalManagementServers | Select-Object * -Unique
		}
		foreach ($ManagementServer in $script:ManagementServers)
		{
			if ($ManagementServer -notmatch $env:COMPUTERNAME)
			{
				$pendingMgmtCurrentServer = $script:ManagementServers[0]
				$pendingMgmt = Invoke-Command -ComputerName $script:ManagementServers[0] -ScriptBlock { Import-Module OperationsManager; return Get-SCOMPendingManagement }
				continue
			}
			else
			{
				$pendingMgmtCurrentServer = $env:COMPUTERNAME
				$pendingMgmt = Get-SCOMPendingManagement
				continue
			}
		}
	}
	catch
	{
		"$(Invoke-TimeStamp)Unable to gather Agents Pending Management due to error: $error" | Out-File $OutputPath\Error.log -Append
		Write-Verbose "$(Invoke-TimeStamp)Unable to gather Agents Pending Management due to error: $error"
	}
	
	Write-Progress -Activity "Collection Running" -Status "Progress-> 62%" -PercentComplete 62
	$error.clear()
	try
	{
		if ($pendingMgmt)
		{
			Write-Console "`n================================`nGathering Agent(s) Pending Management"
			$pendingCount = ($pendingMgmt).Count
			if ($pendingCount -ne 0)
			{
				"Current Count of Pending Management: " + $pendingCount | Out-File -FilePath "$OutputPath\Pending Management.txt" -ErrorAction Stop
				Write-Console "    Running Powershell Command: " -NoNewLine -ForegroundColor Cyan
				Write-Console "`n      Get-SCOMPendingManagement" -NoNewLine -ForegroundColor Magenta
				Write-Console " against" -NoNewLine -ForegroundColor Cyan
				Write-Console " $pendingMgmtCurrentServer" -NoNewLine -ForegroundColor Magenta
				Write-Console "-" -NoNewline -ForegroundColor Green
				do { Write-Console "-" -NoNewline -ForegroundColor Green; Start-Sleep 1 }
				while ($pendingMgmt | Out-File -Append -FilePath "$OutputPath\Pending Management.txt")
				Write-Console "> Command Execution Completed!`n" -NoNewline -ForegroundColor Green
			}
			else
			{
				Write-Console "    No Servers Pending Management" -ForegroundColor Magenta
			}
		}
	}
	catch
	{
		"$(Invoke-TimeStamp)Unable to gather Agents Pending Management due to error: $error" | Out-File $OutputPath\Error.log -Append
		Write-Verbose "$(Invoke-TimeStamp)Unable to gather Agents Pending Management due to error: $error"
	}
	#endregion Pending Management
	Write-Progress -Activity "Collection Running" -Status "Progress-> 64%" -PercentComplete 64
	Write-Output " "
	if (!$SkipGeneralInformation)
	{
		Write-Output "================================`nGathering System Center Operations Manager General Information"
		Write-Console "  Executing Function" -NoNewLine -ForegroundColor Cyan
		Write-Console "-" -NoNewline -ForegroundColor Green
		Write-Verbose "$(Invoke-TimeStamp)Loading General Info Function"
		. $ScriptPath`\Functions\General-Info.ps1
		Write-Progress -Activity "Collection Running" -Status "Progress-> 66%" -PercentComplete 66
		Write-Verbose "$(Invoke-TimeStamp)Executing General Info Function"
		Get-SCOMGeneralInfo -Servers $script:TestedTLSservers
		Write-Console "> Completed!`n" -NoNewline -ForegroundColor Green
		Write-Progress -Activity "Collection Running" -Status "Progress-> 97%" -PercentComplete 97
	}
	# Best Practices
	if (!$SkipBestPracticeAnalyzer)
	{
		Write-Verbose "$(Invoke-TimeStamp)Executing Best Practice Function"
		. $ScriptPath`\Functions\Get-BestPractices.ps1
		Write-Progress -Activity "Collection Running" -Status "Progress-> 98%" -PercentComplete 98
		Write-Output " "
		$error.clear()
		try
		{
			Write-Output "================================`nChecking Environment for Best Practices"
			Invoke-GetBestPractices -Servers $script:ManagementServers
		}
		catch
		{
			"$(Invoke-TimeStamp)Unable to gather Best Practices due to error: $error" | Out-File $OutputPath\Error.log -Append
			Write-Warning "$error"
		}
	}
	
	# Export SCOM SCX Certificates
	if ($ExportSCXCertificates)
	{
		Write-Progress -Activity "Collection Running" -Status "Progress-> 99%" -PercentComplete 99
		Write-Verbose "$(Invoke-TimeStamp)Executing Export SCOM SCX Certificates Function"
		. $ScriptPath`\Functions\Export-SCOMSCXCertificate.ps1
		
		$error.clear()
		try
		{
			New-Item -ItemType 'Directory' -Path "$OutputPath\Management Server SCX Certificates" -ErrorAction Stop | Out-Null
		}
		catch
		{
			"$(Invoke-TimeStamp)Unable to create the SCX Certificates folder due to error: $error" | Out-File $OutputPath\Error.log -Append
			Write-Warning "$error"
		}
		Write-Console "-" -NoNewline -ForegroundColor Green
		Write-Output " "
		$error.clear()
		try
		{
			Write-Output "`n================================`nGathering Management Server SCX Certificates"
			Write-Console "  Executing Function" -NoNewLine -ForegroundColor Cyan
			Write-Console "-" -NoNewline -ForegroundColor Green
			Export-SCXCertificate -OutputDirectory "$OutputPath\Management Server SCX Certificates" -ComputerName $script:ManagementServers
			Write-Console "-" -NoNewline -ForegroundColor Green
		}
		catch
		{
			"$(Invoke-TimeStamp)Unable to export the Management Server SCX Certificates due to error: $error" | Out-File $OutputPath\Error.log -Append
			Write-Warning "$error"
		}
		Write-Console "> Completed!`n" -NoNewline -ForegroundColor Green
	}
	
	
	# end Best Practices
	$error.clear()
	try
	{
		if ($GenerateHTML)
		{
			Write-Output "`n================================`nGenerating System Center Operations Manager Report Webpage"
			. $ScriptPath`\Functions\Report-Webpage.ps1
			Write-Console "  Generating Report Webpage to be viewed in a Web Browser" -NoNewLine -ForegroundColor Cyan
			Write-Console "-" -NoNewline -ForegroundColor Green
			$reportWebpageCompleted = Report-Webpage
			do { Write-Console "-" -NoNewline -ForegroundColor Green; Start-Sleep 1 }
			until ($reportWebpageCompleted)
			Write-Console "> Completed!`n" -NoNewline -ForegroundColor Green
		}
	}
	catch
	{
		"$(Invoke-TimeStamp)Unable to run HTML Report due to error: $error" | Out-File $OutputPath\Error.log -Append
		Write-Warning "$error"
	}
	write-output " "
	write-output "================================`n   Wrapping Up`n================================"
	Write-Console "Moving stuff around and zipping everything up for easy transport" -ForegroundColor Gray
	. $ScriptPath`\Functions\Wrapping-Up.ps1
	Invoke-WrapUp -BuildPipeline:$BuildPipeline
	Write-Progress -Activity "Collection Running" -Status "Progress-> 100%" -PercentComplete 100
	Write-Console "---Script has completed" -ForegroundColor Green -NoNewline
	$x = 1
	do { $x++; Write-Console "." -NoNewline -ForegroundColor Green; Start-Sleep -Millisecond 50 }
	until ($x -eq 4)
	Start-Process C:\Windows\explorer.exe -ArgumentList "/select, $script:destfile"
	exit 0
}

if ($BuildPipeline -or $CheckTLS -or $CheckCertificates -or $GetEventLogs -or $MSInfo32 -or $AssumeYes -or $ExportMPs -or $ExportMSCertificates -or $CaseNumber -or $Servers -or $GenerateHTML -or $GetRulesAndMonitors -or $GetRunAsAccounts -or $All -or $GPResult -or $SQLLogs -or $NoSQLPermission -or $SQLOnly -or $SQLOnlyOpsDB -or $SQLOnlyDW -or $CheckPorts -or $GetLocalSecurity -or $LeastAmount -or $GetNotificationSubscriptions -or $AdditionalEventLogs -or $GetInstalledSoftware -or $GetSPN -or $script:ManagementServers -or $SkipBestPracticeAnalyzer -or $SkipConnectivityTests -or $GetConfiguration -or $SkipGeneralInformation -or $ExportSCXCertificates -or $SkipSQLQueries -or $CheckGroupPolicy -or $GetInstallLogs -or $SCXAgents -or $SCXUsername -or $SCXMaintenanceUsername -or $SCXMonitoringUsername -or $SCXWinRMCredentials -or $SCXWinRMEnumerateAllClasses -or $SCXResourcePoolDisplayName -or $GetUserRoles -or $PingAll)
{
	if ($all)
	{
		if ($Servers)
		{
			if ($AssumeYes)
			{
				Start-ScomDataCollector -Servers $Servers -GetRulesAndMonitors -GetRunAsAccounts -CheckTLS -CheckCertificates -GetEventLogs -ExportMPs -ExportMSCertificates -GPResult -SQLLogs -CheckPorts -GetLocalSecurity -PingAll -AdditionalEventLogs $AdditionalEventLogs -GetInstalledSoftware -GetSPN -AssumeYes -ManagementServers:$ManagementServers -GetConfiguration -CheckGroupPolicy -GetInstallLogs -SkipConnectivityTests:$SkipConnectivityTests -ExportSCXCertificates:$ExportSCXCertificates -SCXResourcePoolDisplayName $SCXResourcePoolDisplayName -SkipBestPracticeAnalyzer:$SkipBestPracticeAnalyzer -SkipGeneralInformation:$SkipGeneralInformation -SkipSQLQueries:$SkipSQLQueries -MSInfo32:$MSInfo32 -GetUserRoles
			}
			else
			{
				Start-ScomDataCollector -Servers $Servers -GetRulesAndMonitors -GetRunAsAccounts -CheckTLS -CheckCertificates -GetEventLogs -ExportMPs -ExportMSCertificates -GPResult -SQLLogs -CheckPorts -GetLocalSecurity -PingAll -AdditionalEventLogs $AdditionalEventLogs -GetInstalledSoftware -GetSPN -ManagementServers:$ManagementServers -GetConfiguration -CheckGroupPolicy -GetInstallLogs -SkipConnectivityTests:$SkipConnectivityTests -ExportSCXCertificates:$ExportSCXCertificates -SkipBestPracticeAnalyzer:$SkipBestPracticeAnalyzer -SkipGeneralInformation:$SkipGeneralInformation -SkipSQLQueries:$SkipSQLQueries -MSInfo32:$MSInfo32 -GetUserRoles
			}
		}
		elseif ($SCXAgents)
		{
			if ($AssumeYes)
			{
				Start-ScomDataCollector -Servers $Servers -GetRulesAndMonitors -GetRunAsAccounts -CheckTLS -CheckCertificates -GetEventLogs -ExportMPs -ExportMSCertificates -GPResult -SQLLogs -CheckPorts -GetLocalSecurity -PingAll -AdditionalEventLogs $AdditionalEventLogs -GetInstalledSoftware -GetSPN -AssumeYes -ManagementServers:$ManagementServers -GetConfiguration -CheckGroupPolicy -GetInstallLogs -SkipConnectivityTests:$SkipConnectivityTests -ExportSCXCertificates:$ExportSCXCertificates -SkipBestPracticeAnalyzer:$SkipBestPracticeAnalyzer -SkipGeneralInformation:$SkipGeneralInformation -SkipSQLQueries:$SkipSQLQueries -SCXAgents $SCXAgents -SCXUsername $SCXUsername -SCXMaintenanceUsername $SCXMaintenanceUsername -SCXMonitoringUsername $SCXMonitoringUsername -SCXResourcePoolDisplayName $SCXResourcePoolDisplayName -MSInfo32:$MSInfo32 -SCXWinRMCredentials $SCXWinRMCredentials -SCXWinRMEnumerateSpecificClasses:$SCXWinRMEnumerateSpecificClasses -SCXWinRMEnumerateAllClasses:$SCXWinRMEnumerateAllClasses -GetUserRoles
			}
			else
			{
				Start-ScomDataCollector -Servers $Servers -GetRulesAndMonitors -GetRunAsAccounts -CheckTLS -CheckCertificates -GetEventLogs -ExportMPs -ExportMSCertificates -GPResult -SQLLogs -CheckPorts -GetLocalSecurity -PingAll -AdditionalEventLogs $AdditionalEventLogs -GetInstalledSoftware -GetSPN -ManagementServers:$ManagementServers -GetConfiguration -CheckGroupPolicy -GetInstallLogs -SkipConnectivityTests:$SkipConnectivityTests -ExportSCXCertificates:$ExportSCXCertificates -SkipBestPracticeAnalyzer:$SkipBestPracticeAnalyzer -SkipGeneralInformation:$SkipGeneralInformation -SkipSQLQueries:$SkipSQLQueries -SCXAgents $SCXAgents -SCXUsername $SCXUsername -SCXMaintenanceUsername $SCXMaintenanceUsername -SCXMonitoringUsername $SCXMonitoringUsername -SCXResourcePoolDisplayName $SCXResourcePoolDisplayName -MSInfo32:$MSInfo32 -SCXWinRMCredentials $SCXWinRMCredentials -SCXWinRMEnumerateSpecificClasses:$SCXWinRMEnumerateSpecificClasses -SCXWinRMEnumerateAllClasses:$SCXWinRMEnumerateAllClasses -GetUserRoles
			}
		}
		elseif ($AssumeYes)
		{
			Start-ScomDataCollector -GetRulesAndMonitors -GetRunAsAccounts -CheckTLS -CheckCertificates -GetEventLogs -ExportMPs -ExportMSCertificates -GPResult -SQLLogs -CheckPorts -GetLocalSecurity -PingAll -AdditionalEventLogs $AdditionalEventLogs -GetInstalledSoftware -GetSPN -AssumeYes -ManagementServers:$ManagementServers -GetConfiguration -CheckGroupPolicy -GetInstallLogs -SkipConnectivityTests:$SkipConnectivityTests -ExportSCXCertificates:$ExportSCXCertificates -SkipBestPracticeAnalyzer:$SkipBestPracticeAnalyzer -SkipGeneralInformation:$SkipGeneralInformation -SkipSQLQueries:$SkipSQLQueries -MSInfo32:$MSInfo32 -GetUserRoles
		}
		else
		{
			Start-ScomDataCollector -GetRulesAndMonitors -GetRunAsAccounts -CheckTLS -CheckCertificates -GetEventLogs -GPResult -ExportMPs -ExportMSCertificates -SQLLogs -CheckPorts -GetLocalSecurity -PingAll -AdditionalEventLogs $AdditionalEventLogs -GetInstalledSoftware -GetSPN -ManagementServers:$ManagementServers -GetConfiguration -CheckGroupPolicy -GetInstallLogs -SkipConnectivityTests:$SkipConnectivityTests -ExportSCXCertificates:$ExportSCXCertificates -SkipBestPracticeAnalyzer:$SkipBestPracticeAnalyzer -SkipGeneralInformation:$SkipGeneralInformation -SkipSQLQueries:$SkipSQLQueries -MSInfo32:$MSInfo32 -GetUserRoles
		}
		
	}
	else
	{
		Start-ScomDataCollector -Servers $Servers -GetRunAsAccounts:$GetRunAsAccounts -CheckTLS:$CheckTLS -CheckCertificates:$CheckCertificates -GetEventLogs:$GetEventLogs -GetUserRoles:$GetUserRoles -GetRulesAndMonitors:$GetRulesAndMonitors -GPResult:$GPResult -ManagementServers:$ManagementServers -MSInfo32:$MSInfo32 -SQLLogs:$SQLLogs -ExportMPs:$ExportMPs -ExportMSCertificates:$ExportMSCertificates -CaseNumber:$CaseNumber -GenerateHTML:$GenerateHTML -AssumeYes:$AssumeYes -NoSQLPermission:$NoSQLPermission -SQLOnly:$SQLOnly -SQLOnlyOpsDB:$SQLOnlyOpsDB -SQLOnlyDW:$SQLOnlyDW -CheckPorts:$CheckPorts -GetLocalSecurity:$GetLocalSecurity -PingAll:$PingAll -LeastAmount:$LeastAmount -GetNotificationSubscriptions:$GetNotificationSubscriptions -AdditionalEventLogs $AdditionalEventLogs -GetInstalledSoftware:$GetInstalledSoftware -GetSPN:$GetSPN -SkipConnectivityTests:$SkipConnectivityTests -ExportSCXCertificates:$ExportSCXCertificates -SkipBestPracticeAnalyzer:$SkipBestPracticeAnalyzer -SkipGeneralInformation:$SkipGeneralInformation -SkipSQLQueries:$SkipSQLQueries -GetConfiguration:$GetConfiguration -CheckGroupPolicy:$CheckGroupPolicy -GetInstallLogs:$GetInstallLogs -BuildPipeline:$BuildPipeline -SCXAgents $SCXAgents -SCXUsername $SCXUsername -SCXMaintenanceUsername $SCXMaintenanceUsername -SCXMonitoringUsername $SCXMonitoringUsername -SCXWinRMCredentials $SCXWinRMCredentials -SCXWinRMEnumerateSpecificClasses:$SCXWinRMEnumerateSpecificClasses -SCXWinRMEnumerateAllClasses:$SCXWinRMEnumerateAllClasses -SCXResourcePoolDisplayName $SCXResourcePoolDisplayName
	}
}
elseif (!$SQLOnly)
{
	#Start Built-in Menu
	. $ScriptPath`\Functions\Builtin-Menu.ps1
	Invoke-DataCollectorMenu
}
# or you can run the below to gather minimal data.
#Start-ScomDataCollector
$issueOccurred = "$(Invoke-TimeStamp)ISSUE: Something is wrong, Script has been stopped"
Write-Console $issueOccurred -ForegroundColor Yellow
$issueOccurred | Out-File $OutputPath\Error.log -Append
$x = 1
do { $x++; Write-Console "." -NoNewline -ForegroundColor Yellow; Start-Sleep 1 }
until ($x -eq 3)
Write-Output " "
Write-Warning "Exiting script..."
exit 1

<#
MIT License

Copyright (c) Blake Drumm

Permission is hereby granted, free of charge, to any person obtaining a copy
of this software and associated documentation files (the "Software"), to deal
in the Software without restriction, including without limitation the rights
to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
copies of the Software, and to permit persons to whom the Software is
furnished to do so, subject to the following conditions:

The above copyright notice and this permission notice shall be included in all
copies or substantial portions of the Software.

THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
SOFTWARE.
#>