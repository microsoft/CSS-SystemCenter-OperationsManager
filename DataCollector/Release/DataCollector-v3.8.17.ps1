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
		This will allow you to not be prompted for anything.
	
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
	
	.PARAMETER SCXPassword
		The password you would like to use for SCX Agent SSH Authentication.
	
	.PARAMETER SCXUsername
		The username you would like to use for SCX Agent SSH Authentication.
	
	.PARAMETER Servers
		Set additional servers to run checks against. This can be Agents or Gateways, they have to be in the same domain at this time.
	
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
		Kevin Holman
		Tyson Paul
		Michael Kallhoff (mikallho)
		Bobby King (v-bking)
		Tiago Fernandes (fernandes.tiago)
		Alex Kremenetskiy (alexkre)
		Andy Desmond (v-adesmond)
		Bryan Faul (v-bryanfaul)
		Jordan Stanhope (jstanhope)
		Brook Hudson (brook.hudson)
	
	.LINK
		Blog Post:
		https://blakedrumm.com/blog/scom-data-collector/
		
		Download Link:
		https://aka.ms/SCOM-DataCollector
		
		Github Repo:
		https://github.com/blakedrumm/SCOM-Scripts-and-SQL
		
		.VERSION
		v3.8.17 - November 15th, 2022
#>
[CmdletBinding()]
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
	[Parameter(Mandatory = $false,
			   Position = 11,
			   HelpMessage = 'Generate a HTML Report Page { EXPERIMENTAL }')]
	[Alias('html')]
	[switch]$GenerateHTML,
	[Parameter(Position = 12,
			   HelpMessage = 'Gather the Registry / ConfigService.config Configuration of the Management Servers.')]
	[switch]$GetConfiguration,
	[Parameter(Mandatory = $false,
			   Position = 13,
			   HelpMessage = 'Gather Event Logs with the localemetadata to ensure that you are able to open the Event log from any machine.')]
	[Alias('gel')]
	[switch]$GetEventLogs,
	[Parameter(Mandatory = $false,
			   Position = 14,
			   HelpMessage = 'Gather software installed from Management Servers / Agents / Gateways.')]
	[switch]$GetInstalledSoftware,
	[Parameter(Position = 15)]
	[switch]$GetInstallLogs,
	[Parameter(Mandatory = $false,
			   Position = 16,
			   HelpMessage = 'Get Local Administrators and Logon Rights.')]
	[Alias('gls')]
	[switch]$GetLocalSecurity,
	[Parameter(Mandatory = $false,
			   Position = 17,
			   HelpMessage = 'A description of the GetNotificationSubscriptions parameter.')]
	[switch]$GetNotificationSubscriptions,
	[Parameter(Mandatory = $false,
			   Position = 18,
			   HelpMessage = 'A description of the GetRulesAndMonitors parameter.')]
	[Alias('gram')]
	[switch]$GetRulesAndMonitors,
	[Parameter(Mandatory = $false,
			   Position = 19,
			   HelpMessage = 'Get RunAs Accounts that are set on each Management Server.')]
	[Alias('graa')]
	[switch]$GetRunAsAccounts,
	[Parameter(Mandatory = $false,
			   Position = 20,
			   HelpMessage = 'Get SPN Configuration from Active Directory.')]
	[Alias('gs')]
	[switch]$GetSPN,
	[Parameter(Position = 21,
			   HelpMessage = 'Gathers User Roles and the configurations from SCOM.')]
	[switch]$GetUserRoles,
	[Parameter(Mandatory = $false,
			   Position = 22,
			   HelpMessage = 'Gathers Group Policy Results to verify Harmful Policies are not present, Generated in HTML and TXT Format.')]
	[Alias('gp')]
	[switch]$GPResult,
	[Parameter(Mandatory = $false,
			   Position = 23,
			   HelpMessage = 'Pull the least amount of data from SCOM.')]
	[switch]$LeastAmount,
	[Parameter(Mandatory = $false,
			   Position = 24,
			   HelpMessage = 'Only run data gathering against the Management Servers specified here.')]
	[Alias('ms')]
	[array]$ManagementServers,
	[Parameter(Mandatory = $false,
			   Position = 25,
			   HelpMessage = 'Export MSInfo32 for viewing in TXT Format.')]
	[Alias('mi32')]
	[switch]$MSInfo32,
	[Parameter(Position = 26,
			   HelpMessage = 'Internal Script Switch.')]
	[switch]$NoSQLPermission,
	[Parameter(Mandatory = $false,
			   Position = 27,
			   HelpMessage = 'Ping every Management Server, including servers mentioned in -Servers switch.')]
	[switch]$PingAll,
	[Parameter(Mandatory = $false,
			   Position = 28,
			   HelpMessage = 'Linux/Unix Agents you want to gather data from, via Bash Script that is transmitted via ssh.')]
	[Alias('LinuxAgents')]
	[Array]$SCXAgents,
	[Parameter(Mandatory = $false,
			   Position = 29,
			   HelpMessage = 'The password you would like to use for SCX Agent SSH Authentication.')]
	[Alias('LinuxPassword')]
	[string]$SCXPassword,
	[Parameter(Mandatory = $false,
			   Position = 30,
			   HelpMessage = 'The username you would like to use for SCX Agent SSH Authentication.')]
	[Alias('LinuxUsername')]
	[string]$SCXUsername,
	[Parameter(Mandatory = $false,
			   Position = 31,
			   HelpMessage = 'Set additional servers to run checks against. This can be Agents or Gateways, they have to be in the same domain at this time.')]
	[Alias('s')]
	[Array]$Servers,
	[Parameter(Position = 32,
			   HelpMessage = 'Skip the tests for remote accessibility, use this if you know your environment passes these tests. DO NOT USE THIS IF YOU ARENT SURE!')]
	[Alias('sct')]
	[switch]$SkipConnectivityTests,
	[Parameter(Position = 33,
			   HelpMessage = 'Skip the General Information file gathering.')]
	[Alias('sgi')]
	[switch]$SkipGeneralInformation,
	[Parameter(Mandatory = $false,
			   Position = 34,
			   HelpMessage = 'Skip the SQL Queries. This will leave you with much less data in the data collector. Other functions in the data collector may rely on the SQL Queries and may be missing data.')]
	[Alias('NoSQLQueries')]
	[switch]$SkipSQLQueries,
	[Parameter(Position = 35,
			   HelpMessage = 'Gather SQL Logs from OperationsManager and DataWarehouse DBs.')]
	[switch]$SQLLogs,
	[Parameter(Mandatory = $false,
			   Position = 36,
			   HelpMessage = 'Run only SQL Queries and Output to CSV.')]
	[switch]$SQLOnly,
	[Parameter(Mandatory = $false,
			   Position = 37,
			   HelpMessage = 'Internal Script Switch.',
			   DontShow = $true)]
	[switch]$SQLOnlyDW,
	[Parameter(Mandatory = $false,
			   Position = 38,
			   HelpMessage = 'Internal Script Switch.',
			   DontShow = $true)]
	[switch]$SQLOnlyOpsDB
)
try
{
	$StartTime = "$(Get-Date -Format "MMMM dd, yyyy @ h:mm tt") $((Get-TimeZone -ErrorAction SilentlyContinue).DisplayName)"
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
$location = $MyInvocation.MyCommand.Path
Function Time-Stamp
{
	$TimeStamp = Get-Date -Format "MM/dd/yyyy hh:mm:ss tt"
	return "$TimeStamp - "
}

if (!($SQLOnly -or $SQLOnlyDW -or $SQLOnlyOpsDB))
{
	Write-Host @"
===================================================================
==========================  Start of Script =======================
===================================================================
"@ -ForegroundColor DarkYellow
	$runningas = $null
	$runningas = [System.Security.Principal.WindowsIdentity]::GetCurrent().Name
	Write-Host "Script currently running as: " -ForegroundColor DarkGray -NoNewLine
	Write-Host $runningas -ForegroundColor Gray
	$CSVFile = $ScriptPath
	
	
	$scriptout = [Array] @()
	[String]$Comp = Resolve-DnsName $env:COMPUTERNAME -Type A | Select-Object -Property Name -ExpandProperty Name
	$checkingpermission = "Checking for elevated permissions..."
	$scriptout += $checkingpermission
	Write-Host $checkingpermission -ForegroundColor Gray
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
		Write-Host $permissiongranted -ForegroundColor Green
	}
	$currentUser = ([System.Security.Principal.WindowsIdentity]::GetCurrent().Name).split('\')[1]
	$omsdkUserOrig = (Get-WmiObject Win32_Service -Filter "Name='omsdk'").StartName -split '@'
	if ($omsdkUserOrig)
	{
		$omsdkUserSplit = ($omsdkUserOrig)[0]
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
		$omsdkUserSplit = $currentUser
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
				$currentPathFormat = """$currentPath"""
				$answer = Read-Host "Would you like to run this script as $($question)? (Y/N)"
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
		[Parameter(Mandatory = $false,
				   Position = 11,
				   HelpMessage = 'Generate a HTML Report Page { EXPERIMENTAL }')]
		[Alias('html')]
		[switch]$GenerateHTML,
		[Parameter(Position = 12,
				   HelpMessage = 'Gather the Registry / ConfigService.config Configuration of the Management Servers.')]
		[switch]$GetConfiguration,
		[Parameter(Mandatory = $false,
				   Position = 13,
				   HelpMessage = 'Gather Event Logs with the localemetadata to ensure that you are able to open the Event log from any machine.')]
		[Alias('gel')]
		[switch]$GetEventLogs,
		[Parameter(Mandatory = $false,
				   Position = 14,
				   HelpMessage = 'Gather software installed from Management Servers / Agents / Gateways.')]
		[switch]$GetInstalledSoftware,
		[Parameter(Position = 15)]
		[switch]$GetInstallLogs,
		[Parameter(Mandatory = $false,
				   Position = 16,
				   HelpMessage = 'Get Local Administrators and Logon Rights.')]
		[Alias('gls')]
		[switch]$GetLocalSecurity,
		[Parameter(Mandatory = $false,
				   Position = 17,
				   HelpMessage = 'A description of the GetNotificationSubscriptions parameter.')]
		[switch]$GetNotificationSubscriptions,
		[Parameter(Mandatory = $false,
				   Position = 18,
				   HelpMessage = 'A description of the GetRulesAndMonitors parameter.')]
		[Alias('gram')]
		[switch]$GetRulesAndMonitors,
		[Parameter(Mandatory = $false,
				   Position = 19,
				   HelpMessage = 'Get RunAs Accounts that are set on each Management Server.')]
		[Alias('graa')]
		[switch]$GetRunAsAccounts,
		[Parameter(Mandatory = $false,
				   Position = 20,
				   HelpMessage = 'Get SPN Configuration from Active Directory.')]
		[Alias('gs')]
		[switch]$GetSPN,
		[Parameter(Position = 21,
				   HelpMessage = 'Gathers User Roles and the configurations from SCOM.')]
		[switch]$GetUserRoles,
		[Parameter(Mandatory = $false,
				   Position = 22,
				   HelpMessage = 'Gathers Group Policy Results to verify Harmful Policies are not present, Generated in HTML and TXT Format.')]
		[Alias('gp')]
		[switch]$GPResult,
		[Parameter(Mandatory = $false,
				   Position = 23,
				   HelpMessage = 'Pull the least amount of data from SCOM.')]
		[switch]$LeastAmount,
		[Parameter(Mandatory = $false,
				   Position = 24,
				   HelpMessage = 'Only run data gathering against the Management Servers specified here.')]
		[Alias('ms')]
		[array]$ManagementServers,
		[Parameter(Mandatory = $false,
				   Position = 25,
				   HelpMessage = 'Export MSInfo32 for viewing in TXT Format.')]
		[Alias('mi32')]
		[switch]$MSInfo32,
		[Parameter(Position = 26,
				   HelpMessage = 'Internal Script Switch.')]
		[switch]$NoSQLPermission,
		[Parameter(Mandatory = $false,
				   Position = 27,
				   HelpMessage = 'Ping every Management Server, including servers mentioned in -Servers switch.')]
		[switch]$PingAll,
		[Parameter(Mandatory = $false,
				   Position = 28,
				   HelpMessage = 'Linux/Unix Agents you want to gather data from, via Bash Script that is transmitted via ssh.')]
		[Alias('LinuxAgents')]
		[Array]$SCXAgents,
		[Parameter(Mandatory = $false,
				   Position = 29,
				   HelpMessage = 'The password you would like to use for SCX Agent SSH Authentication.')]
		[Alias('LinuxPassword')]
		[string]$SCXPassword,
		[Parameter(Mandatory = $false,
				   Position = 30,
				   HelpMessage = 'The username you would like to use for SCX Agent SSH Authentication.')]
		[Alias('LinuxUsername')]
		[string]$SCXUsername,
		[Parameter(Mandatory = $false,
				   Position = 31,
				   HelpMessage = 'Set additional servers to run checks against. This can be Agents or Gateways, they have to be in the same domain at this time.')]
		[Alias('s')]
		[Array]$Servers,
		[Parameter(Position = 32,
				   HelpMessage = 'Skip the tests for remote accessibility, use this if you know your environment passes these tests. DO NOT USE THIS IF YOU ARENT SURE!')]
		[Alias('sct')]
		[switch]$SkipConnectivityTests,
		[Parameter(Position = 33,
				   HelpMessage = 'Skip the General Information file gathering.')]
		[Alias('sgi')]
		[switch]$SkipGeneralInformation,
		[Parameter(Mandatory = $false,
				   Position = 34,
				   HelpMessage = 'Skip the SQL Queries. This will leave you with much less data in the data collector. Other functions in the data collector may rely on the SQL Queries and may be missing data.')]
		[Alias('NoSQLQueries')]
		[switch]$SkipSQLQueries,
		[Parameter(Position = 35,
				   HelpMessage = 'Gather SQL Logs from OperationsManager and DataWarehouse DBs.')]
		[switch]$SQLLogs,
		[Parameter(Mandatory = $false,
				   Position = 36,
				   HelpMessage = 'Run only SQL Queries and Output to CSV.')]
		[switch]$SQLOnly,
		[Parameter(Mandatory = $false,
				   Position = 37,
				   HelpMessage = 'Internal Script Switch.',
				   DontShow = $true)]
		[switch]$SQLOnlyDW,
		[Parameter(Mandatory = $false,
				   Position = 38,
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
	$OpsDB_SQLServer = "SQL2A.opsmgr.net"
	$OpsDB_SQLDBName =  "OperationsManager"
	$DW_SQLServer = "SQL2A.opsmgr.net"
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
		"$(Time-Stamp)Caught Exception: $e :: Message: $msg :: at line: $line" | Out-File $OutputPath\Error.log -Append
	}
	Import-Module OperationsManager -ErrorAction SilentlyContinue
	IF (!(Test-Path $OutputPath))
	{
		Write-Host "Output folder not found.  Creating folder...." -ForegroundColor Gray
		md $OutputPath | out-null
	}
	else
	{
		Write-Host "Output folder found. Removing Existing Files...." -ForegroundColor Gray
		Get-CimInstance Win32_Process | select ProcessId, ProcessName, CommandLine | foreach{
			if ($_.CommandLine -like ("*$OutputPath*"))
			{
				Write-Host "Found process using the output folder, closing process: $($_.ProcessName)" -ForegroundColor Gray
				Stop-Process $_.ProcessId -Force -ErrorAction SilentlyContinue
			}
		}
		rmdir -Path $OutputPath -Recurse | Out-Null
		Write-Host "Creating folder...." -ForegroundColor Gray
		md $OutputPath | out-null
		md $OutputPath\CSV | out-null
	}
	$MSKey = "HKLM:\SOFTWARE\Microsoft\Microsoft Operations Manager\3.0\Server Management Groups"
	IF (Test-Path $MSKey)
	{
		# This is a management server.  Try to get the database values.
		$SCOMKey = "HKLM:\SOFTWARE\Microsoft\Microsoft Operations Manager\3.0\Setup"
		$SCOMData = Get-ItemProperty $SCOMKey
		$global:OpsDB_SQLServer = ($SCOMData).DatabaseServerName
		$global:OpsDB_SQLServerOriginal = $OpsDB_SQLServer
		$OpsDB_SQLDBName = ($SCOMData).DatabaseName
		$global:DW_SQLServer = ($SCOMData).DataWarehouseDBServerName
		$global:DW_SQLServerOriginal = $DW_SQLServer
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
			$ComputerName = read-host "Please enter the name of a SCOM management server $env:userdomain\$env:USERNAME has permissions on"
		}
		$Hive = [Microsoft.Win32.RegistryHive]::LocalMachine
		$KeyPath = 'SOFTWARE\Microsoft\Microsoft Operations Manager\3.0\Setup'
		$OpsDBServer = 'DatabaseServerName'
		$OpsDBName = 'DatabaseName'
		$DWServer = 'DataWarehouseDBServerName'
		$DWDB = 'DataWarehouseDBName'
		$reg = [Microsoft.Win32.RegistryKey]::OpenRemoteBaseKey($Hive, $ComputerName)
		$key = $reg.OpenSubKey($KeyPath)
		$global:OpsDB_SQLServer = $key.GetValue($OpsDBServer)
		$global:OpsDB_SQLServerOriginal = $key.GetValue($OpsDBServer)
		$OpsDB_SQLDBName = $key.GetValue($OpsDBName)
		$global:DW_SQLServer = $key.GetValue($DWServer)
		$global:DW_SQLServerOriginal = $key.GetValue($DWServer)
		$DW_SQLDBName = $key.GetValue($DWDB)
	}
	if (!$global:OpsDB_SQLServer)
	{
		$global:OpsDB_SQLServer = read-host "Please enter the name of the Operations Manager SQL Database Server. (ex. SQL-2019\SCOM2019)"
		$global:OpsDB_SQLServerOriginal = $global:OpsDB_SQLServer
	}
	if (!$OpsDB_SQLDBName)
	{
		$OpsDBName = read-host "Please enter the name of the Operations Manager SQL Database Name. (ex. OperationsManager)"
		$OpsDB_SQLDBName = $OpsDBName
	}
	if (!$global:DW_SQLServer)
	{
		$global:DW_SQLServer = read-host "Please enter the name of the Operations Manager Data Warehouse SQL Server Name. (ex. SQL-2019\SCOM2019)"
		$DW_SQLServerOriginal = $global:DW_SQLServer
	}
	if (!$DW_SQLDBName)
	{
		$DWDB = read-host "Please enter the name of the Operations Manager Data Warehouse SQL Database Name. (ex. OperationsManagerDW)"
		$DW_SQLDBName = $DWServer
	}
	if (!$SkipSQLQueries -or $SQLOnly)
	{
		Function SQL-Queries
{
	trap
	{
		#potential error code
		#use continue or break keywords
		$e = $_.Exception
		$line = $_.InvocationInfo.ScriptLineNumber
		$msg = $e.Message
		
		Write-Verbose "Caught Exception: $e :: Message: $msg :: at line: $line"
		"$(Time-Stamp)Caught Exception: $e :: Message: $msg :: at line: $line" | Out-File $OutputPath\Error.log -Append
	}
	function Invoke-SqlCommand
	{
    <#
        .SYNOPSIS
            Executes an SQL statement. Executes using Windows Authentication unless the Username and Password are provided.

        .PARAMETER Server
            The SQL Server instance name.

        .PARAMETER Database
            The SQL Server database name where the query will be executed.

        .PARAMETER Timeout
            The connection timeout.

        .PARAMETER Connection
            The System.Data.SqlClient.SQLConnection instance used to connect.

        .PARAMETER Username
            The SQL Authentication Username.

        .PARAMETER Password
            The SQL Authentication Password.

        .PARAMETER CommandType
            The System.Data.CommandType value specifying Text or StoredProcedure.

        .PARAMETER Query
            The SQL query to execute.

         .PARAMETER Path
            The path to an SQL script.

        .PARAMETER Parameters
            Hashtable containing the key value pairs used to generate as collection of System.Data.SqlParameter.

        .PARAMETER As
            Specifies how to return the result.

            PSCustomObject
             - Returns the result set as an array of System.Management.Automation.PSCustomObject objects.
            DataSet
             - Returns the result set as an System.Data.DataSet object.
            DataTable
             - Returns the result set as an System.Data.DataTable object.
            DataRow
             - Returns the result set as an array of System.Data.DataRow objects.
            Scalar
             - Returns the first column of the first row in the result set. Should be used when a value with no column name is returned (i.e. SELECT COUNT(*) FROM Test.Sample).
            NonQuery
             - Returns the number of rows affected. Should be used for INSERT, UPDATE, and DELETE.

        .EXAMPLE
            PS C:\> Invoke-SqlCommand -Server "DATASERVER" -Database "Web" -Query "SELECT TOP 1 * FROM Test.Sample"

            datetime2         : 1/17/2013 8:46:22 AM
            ID                : 202507
            uniqueidentifier1 : 1d0cf1c0-9fb1-4e21-9d5a-b8e9365400fc
            bool1             : False
            datetime1         : 1/17/2013 12:00:00 AM
            double1           : 1
            varchar1          : varchar11
            decimal1          : 1
            int1              : 1

            Returned the first row as a System.Management.Automation.PSCustomObject.

        .EXAMPLE
            PS C:\> Invoke-SqlCommand -Server "DATASERVER" -Database "Web" -Query "SELECT COUNT(*) FROM Test.Sample" -As Scalar

            9544            
    #>
		[CmdletBinding(DefaultParameterSetName = "Default")]
		param (
			[Parameter(Mandatory = $true, Position = 0)]
			[string]$Server,
			[Parameter(Mandatory = $true, Position = 1)]
			[string]$Database,
			[Parameter(Mandatory = $false, Position = 2)]
			[int]$Timeout = 30,
			[System.Data.SqlClient.SQLConnection]$Connection,
			[string]$Username,
			[string]$Password,
			[System.Data.CommandType]$CommandType = [System.Data.CommandType]::Text,
			[string]$Query,
			[ValidateScript({ Test-Path -Path $_ })]
			[string]$Path,
			[hashtable]$Parameters,
			[ValidateSet("DataSet", "DataTable", "DataRow", "PSCustomObject", "Scalar", "NonQuery")]
			[string]$As = "PSCustomObject"
		)
		
		begin
		{
			if ($Path)
			{
				$Query = [System.IO.File]::ReadAllText("$((Resolve-Path -Path $Path).Path)")
			}
			else
			{
				if (-not $Query)
				{
					throw (New-Object System.ArgumentNullException -ArgumentList "Query", "The query statement is missing.")
				}
			}
			
			$createConnection = (-not $Connection)
			
			if ($createConnection)
			{
				$Connection = New-Object System.Data.SqlClient.SQLConnection
				if ($Username -and $Password)
				{
					$Connection.ConnectionString = "Server=$($Server);Database=$($Database);User Id=$($Username);Password=$($Password);"
				}
				else
				{
					$Connection.ConnectionString = "Server=$($Server);Database=$($Database);Integrated Security=SSPI;"
				}
				if ($PSBoundParameters.Verbose)
				{
					$Connection.FireInfoMessageEventOnUserErrors = $true
					$Connection.Add_InfoMessage([System.Data.SqlClient.SqlInfoMessageEventHandler] { Write-Verbose "$($_)" })
				}
			}
			
			if (-not ($Connection.State -like "Open"))
			{
				try { $Connection.Open() }
				catch [Exception] { throw $_ }
			}
		}
		
		process
		{
			$command = New-Object System.Data.SqlClient.SqlCommand ($query, $Connection)
			$command.CommandTimeout = $Timeout
			$command.CommandType = $CommandType
			if ($Parameters)
			{
				foreach ($p in $Parameters.Keys)
				{
					$command.Parameters.AddWithValue($p, $Parameters[$p]) | Out-Null
				}
			}
			
			$scriptBlock = {
				$result = @()
				$reader = $command.ExecuteReader()
				if ($reader)
				{
					$counter = $reader.FieldCount
					$columns = @()
					for ($i = 0; $i -lt $counter; $i++)
					{
						$columns += $reader.GetName($i)
					}
					
					if ($reader.HasRows)
					{
						while ($reader.Read())
						{
							$row = @{ }
							for ($i = 0; $i -lt $counter; $i++)
							{
								$row[$columns[$i]] = $reader.GetValue($i)
							}
							$result += [PSCustomObject]$row
						}
					}
				}
				$result
			}
			
			if ($As)
			{
				switch ($As)
				{
					"Scalar" {
						$scriptBlock = {
							$result = $command.ExecuteScalar()
							$result
						}
					}
					"NonQuery" {
						$scriptBlock = {
							$result = $command.ExecuteNonQuery()
							$result
						}
					}
					default {
						if ("DataSet", "DataTable", "DataRow" -contains $As)
						{
							$scriptBlock = {
								$ds = New-Object System.Data.DataSet
								$da = New-Object System.Data.SqlClient.SqlDataAdapter($command)
								$da.Fill($ds) | Out-Null
								switch ($As)
								{
									"DataSet" { $result = $ds }
									"DataTable" { $result = $ds.Tables }
									default { $result = $ds.Tables | ForEach-Object -Process { $_.Rows } }
								}
								$result
							}
						}
					}
				}
			}
			
			$result = Invoke-Command -ScriptBlock $ScriptBlock
			$command.Parameters.Clear()
		}
		
		end
		{
			if ($createConnection) { $Connection.Close() }
			Write-Verbose "$($result | Out-String)"
			return $result
		}
	}
	$InvokeSQLcmdFunction = [scriptblock]::Create(@"
  function Invoke-SqlCommand { ${Function:Invoke-SQLCommand} } 
"@)
	## strip fqdn etc...
	If ($global:OpsDB_SQLServerOriginal -like "*,*")
	{
		$global:OpsDB_SQLServer = $OpsDB_SQLServerOriginal.split(',')[0]
		$global:OpsDB_SQLServerPort = $OpsDB_SQLServerOriginal.split(',')[1]
		$global:DW_SQLServerInstance = $null
	}
	elseif ($global:OpsDB_SQLServerOriginal -like "*\*")
	{
		$global:OpsDB_SQLServer = $OpsDB_SQLServerOriginal.split('\')[0]
		$global:OpsDB_SQLServerInstance = $OpsDB_SQLServerOriginal.split('\')[1]
	}
	else
	{
		$global:OpsDB_SQLServerInstance = $null
		$global:OpsDB_SQLServerPort = $null
	}
	
	If ($global:DW_SQLServerOriginal -like "*,*")
	{
		$global:DW_SQLServer = $DW_SQLServerOriginal.split(',')[0]
		$global:DW_SQLServerPort = $DW_SQLServerOriginal.split(',')[1]
		$global:DW_SQLServerInstance = $null
	}
	elseif ($global:DW_SQLServerOriginal -like "*\*")
	{
		$global:DW_SQLServer = $DW_SQLServerOriginal.split('\')[0]
		$global:DW_SQLServerInstance = $DW_SQLServerOriginal.split('\')[1]
	}
	else
	{
		$global:DW_SQLServerInstance = $null
		$global:DW_SQLServerPort = $null
	}
	
	
	
	
	$Populated = 1
	
	## Verify variables are populated
	If ($OpsDB_SQLServer -eq $null)
	{
		write-output "OpsDBServer not found"
		$populated = 0
	}
	If ($DW_SQLServer -eq $null)
	{
		write-output "DataWarehouse server not found"
		$populated = 0
	}
	If ($OpsDB_SQLDBName -eq $null)
	{
		write-output "OpsDBName Not found"
		$populated = 0
	}
	If ($DW_SQLDBName -eq $null)
	{
		write-output "DWDBName not found"
		$populated = 0
	}
	if ($Populated = 0)
	{
		"At least some SQL Information not found, exiting script..."
    <# 
        insert Holman's method from the original script here, then remove the break found below
    #>
		break
	}
	## Hate this output. Want to change it, will eventually, doesnt pose a problem functionally though 
	## so thats a task for a later date. Want a table, not a list like that. 
	## Combine the objects into a single object and display via table.
	$color = "Cyan"
	Write-Output " "
	Write-Host "OpsDB Server        : $global:OpsDB_SQLServer" -ForegroundColor $color -NoNewline
	if ($OpsDB_SQLServerInstance)
	{
		Write-Host "\$OpsDB_SQLServerInstance" -ForegroundColor $color -NoNewline
	}
	if ($OpsDB_SQLServerPort)
	{
		Write-Host "`nOpsDB Server Port   : $OpsDB_SQLServerPort" -ForegroundColor $color -NoNewline
	}
	Write-Host "`nOpsDB Name          : $OpsDB_SQLDBName" -ForegroundColor $color
	Write-Output " "
	Write-Host "DWDB Server         : $($global:DW_SQLServer)" -ForegroundColor $color -NoNewline
	if ($global:DW_SQLServerInstance)
	{
		Write-Host "\$DW_SQLServerInstance" -ForegroundColor $color -NoNewline
	}
	if ($global:DW_SQLServerPort)
	{
		Write-Host "`nDWDB Server Port    : $DW_SQLServerPort" -ForegroundColor $color -NoNewline
	}
	Write-Host "`nDWDB Name           : $DW_SQLDBName" -ForegroundColor $color
	Write-Output " "
	
	if ($SQLOnlyOpsDB)
	{
		$AssumeYes = $true
	}
	elseif ($SQLOnlyDW)
	{
		$skipOpsDBQuery = $true
	}
	else
	{
		$skipOpsDBQuery = $false
	}
	
	if (!$skipOpsDBQuery)
	{
		if (!$AssumeYes)
		{
			do
			{
				
				$answer = Read-Host -Prompt "Do you want to continue with these values? (Y/N)"
				
			}
			until ($answer -eq "y" -or $answer -eq "n")
		}
		else { $answer = "y" }
		IF ($answer -eq "y")
		{
			Write-Host "Connecting to SQL Server...." -ForegroundColor DarkGreen
		}
		ELSE
		{
			do
			{
				
				$answer = Read-Host -Prompt "Do you want to attempt to continue without Queries to your SQL Server? (Y/N)"
				
			}
			until ($answer -eq "y" -or $answer -eq "n")
			if ($answer -eq "y")
			{
				Write-Warning "Be aware, this has not been implemented yet..."
				return
			}			
		}
		# Query the OpsDB Database
		[string]$currentuser = ([Environment]::UserDomainName + "\" + [Environment]::UserName)
		if (!$NoSQLPermission)
		{
			if (!$AssumeYes)
			{
				Write-Host "Currently Detecting User as: $currentuser"
				do
				{
					$answer2 = Read-Host -Prompt " Does the above user have the correct permissions to perform SQL Queries against OpsDB: $OpsDB_SQLServer`? (Y/N)"
				}
				until ($answer2 -eq "y" -or $answer2 -eq "n")
			}
			else { $answer2 = "y" }
		}
		else
		{
			$answer2 = "n"
		}
		if ($answer2 -eq "n")
		{
			do
			{
				$answer3 = Read-Host -Prompt "  Are you setup for `'SQL Credentials`' or `'Domain Credentials`' on OpsDB: $OpsDB_SQLServer`? (SQL/Domain)"
			}
			until ($answer3 -eq "SQL" -or $answer3 -eq "Domain")
			$SQLuser = Read-Host '   What is your username?'
			$SQLpass = Read-Host '   What is your password?' -AsSecureString
			do
			{
				$proceed = Read-Host "    Would you like to proceed with $SQLuser`? (Y/N)"
				if ($proceed -eq "n")
				{
					$SQLuser = $null
					$SQLuser = Read-Host '   What is your username?'
					$SQLpass = Read-Host '   What is your password?' -AsSecureString
				}
			}
			until ($proceed -eq "y")
		}
		else
		{ $answer2 = "y" }
		# Query the DW database
		if (!$NoSQLPermission)
		{
			if (!$AssumeYes)
			{
				do
				{
					$answer4 = Read-Host -Prompt " Does `'$currentuser`' have the correct permissions to perform SQL Queries against DW: $DW_SQLServer`? (Y/N)"
				}
				until ($answer4 -eq "y" -or $answer4 -eq "n")
			}
			else { $answer4 = "y" }
		}
		else
		{
			$answer4 = "n"
		}
		
		if ($answer4 -eq "n")
		{
			if ($SQLuser)
			{
				do
				{
					$answer6 = Read-Host -Prompt "  Would you like to use the same credentials as OpsDB for the DW Queries? `'$SQLuser`'? (Y/N)"
				}
				until ($answer6 -eq "y" -or $answer6 -eq "n")
				if ($answer6 -eq "y")
				{
					$SQLuser2 = $SQLuser
					$SQLpass2 = $SQLpass
					$answer5 = $answer3
				}
				else
				{
					do
					{
						$answer5 = Read-Host -Prompt "  Are you setup for `'SQL Credentials`' or `'Domain Credentials`' on DW: $DW_SQLServer`? (SQL/Domain)"
					}
					until ($answer5 -eq "SQL" -or $answer5 -eq "Domain")
					$SQLuser2 = Read-Host '    What is your username?'
					$SQLpass2 = Read-Host '    What is your password?' -AsSecureString
					do
					{
						$proceed2 = Read-Host "   Would you like to proceed with $SQLuser2`? (Y/N)"
						if ($proceed2 -eq "n")
						{
							$SQLuser2 = $null
							$SQLuser2 = Read-Host '    What is your username?'
							$SQLpass2 = Read-Host '    What is your password?' -AsSecureString
						}
					}
					until ($proceed2 -eq "y")
				}
			}
			else
			{
				do
				{
					$answer5 = Read-Host -Prompt "  Are you setup for `'SQL Credentials`' or `'Domain Credentials`' on DW: $DW_SQLServer`? (SQL/Domain)"
				}
				until ($answer5 -eq "SQL" -or $answer5 -eq "Domain")
				$SQLuser2 = Read-Host '    What is your username?'
				$SQLpass2 = Read-Host '    What is your password?' -AsSecureString
				do
				{
					$proceed2 = Read-Host "   Would you like to proceed with $SQLuser2`? (Y/N)"
					if ($proceed2 -eq "n")
					{
						$SQLuser2 = $null
						$SQLuser2 = Read-Host '    What is your username?'
						$SQLpass2 = Read-Host '    What is your password?' -AsSecureString
					}
				}
				until ($proceed2 -eq "y")
			}
		}
		if ($answer3 -eq "Domain")
		{
			$Credential = New-Object -TypeName System.Management.Automation.PSCredential -ArgumentList $SQLuser, $SQLpass
			$command = "-NoProfile -NoExit -Command cd '$ScriptPath';. '$ScriptPath\$scriptname' -SQLOnlyOpsDB; exit 0"
			Start-Process powershell.exe ($command) -Credential $Credential -Wait -NoNewWindow
			$job1 = $true
		}
		elseif ($answer2 -eq "y")
		{
			$SqlIntegratedSecurity = $true
		}
		elseif ($answer3 -eq "SQL")
		{
			$SqlIntegratedSecurity = $false
		}
		if (!$job1)
		{
			$QueriesPath = "$ScriptPath\queries\OpsDB"
			IF (!(Test-Path $QueriesPath))
			{
				Write-Warning "Path to query files not found ($QueriesPath).  Terminating...."
				break
			}
			Write-Host "`n================================"
			Write-Host "Starting SQL Query Gathering"
			Write-Host "Running SQL Queries against Operations Database"
			try
			{
				$timeout = 30
				if ($SqlIntegratedSecurity)
				{
					$initialCheck = Invoke-SqlCommand -Server $OpsDB_SQLServerOriginal -Database $OpsDB_SQLDBName -Query 'SELECT 1' -As DataRow -Timeout $timeout -ErrorAction Stop
				}
				else
				{
					$initialCheck = Invoke-SqlCommand -Server $OpsDB_SQLServerOriginal -Database $OpsDB_SQLDBName -Username $SQLuser -Password $SQLpass -Query 'SELECT 1' -As DataRow -Timeout $timeout -ErrorAction Stop
				}
				
				if ($initialCheck)
				{
					# 15 minute timeout for each query
					$timeout = 900
					$jobtimeout = 2100
				}
				else
				{
					Write-Warning "Cannot communicate with SQL DB, expect errors."
					"$(Time-Stamp)Cannot communicate with SQL DB, expect errors." | Out-File $OutputPath\Error.log -Append
				}
			}
			catch
			{
				Write-Warning $_
			}
			Write-Host " Current query timeout: $timeout seconds ($($timeout/60) minutes) \ Current query job timeout: $jobtimeout seconds ($($jobtimeout/60) minutes)" -ForegroundColor Gray
			Write-Host "  Looking for query files in: $QueriesPath" -ForegroundColor DarkGray
			$QueryFiles = Get-ChildItem -Path $QueriesPath -Filter "*.sql" ###BH - Remove Where for Filter left
			$QueryFilesCount = $QueryFiles.Count
			Write-Host "   Found ($QueryFilesCount) queries" -ForegroundColor Green
			FOREACH ($QueryFile in $QueryFiles)
			{
				try
				{
					$QueryFileName = ($QueryFile.Name).split('.')[0]
					[string]$OutputFileName = $OutputPath + "\" + $QueryFileName + ".csv"
					if ($SqlIntegratedSecurity)
					{
						$OpsScriptBlock = [scriptblock]::Create(@"
  Invoke-SqlCommand -Server $OpsDB_SQLServerOriginal -Database $OpsDB_SQLDBName -Path "$QueriesPath\$QueryFile" -As DataRow -Timeout $jobtimeout -ErrorAction Stop | Export-Csv -Path "$OutputFileName" -NoTypeInformation
"@)
						#This runs all queries with Perf in the name, as a job
						if ($QueryFileName -match 'Perf')
						{
							Write-Host "     Running query job: " -ForegroundColor Cyan -NoNewline
							Write-Host $QueryFile.Name -ForegroundColor Magenta
							Start-Job -Name "getPerf_Ops-$($QueryFile.Name)" -InitializationScript $InvokeSQLcmdFunction -ScriptBlock $OpsScriptBlock | Out-Null
						}
						elseif ($QueryFileName -match 'Event')
						{
							Write-Host "     Running query job: " -ForegroundColor Cyan -NoNewline
							Write-Host $QueryFile.Name -ForegroundColor Magenta
							Start-Job -Name "getEvent_Ops-$($QueryFile.Name)" -InitializationScript $InvokeSQLcmdFunction -ScriptBlock $OpsScriptBlock | Out-Null
						}
						else
						{
							Write-Host "     Running query: " -ForegroundColor Cyan -NoNewline
							Write-Host $QueryFile.Name -ForegroundColor Magenta
							Invoke-SqlCommand -Server $OpsDB_SQLServerOriginal -Database $OpsDB_SQLDBName -Path "$QueriesPath\$QueryFile" -As DataRow -Timeout $timeout -ErrorAction Stop | Export-Csv -Path "$OutputFileName" -NoTypeInformation
						}
						continue
					}
					else
					{
						$OpsScriptBlock = [scriptblock]::Create(@"
  Invoke-SqlCommand -Server $OpsDB_SQLServerOriginal -Database $OpsDB_SQLDBName -Username $SQLuser -Password $SQLpass -Path "$QueriesPath\$QueryFile" -As DataRow -Timeout $jobtimeout -ErrorAction Stop | Export-Csv -Path "$OutputFileName" -NoTypeInformation
"@)
						
						#This runs all queries with Perf in the name, as a job
						if ($QueryFileName -match 'Perf')
						{
							Write-Host "     Running query job: " -ForegroundColor Cyan -NoNewline
							Write-Host $QueryFile.Name -ForegroundColor Magenta
							Start-Job -Name "getPerf_Ops-$($QueryFile.Name)" -InitializationScript $InvokeSQLcmdFunction -ScriptBlock $OpsScriptBlock | Out-Null
						}
						elseif ($QueryFileName -match 'Event')
						{
							Write-Host "     Running query job: " -ForegroundColor Cyan -NoNewline
							Write-Host $QueryFile.Name -ForegroundColor Magenta
							Start-Job -Name "getEvent_Ops-$($QueryFile.Name)" -InitializationScript $InvokeSQLcmdFunction -ScriptBlock $OpsScriptBlock | Out-Null
						}
						else
						{
							Write-Host "     Running query: " -ForegroundColor Cyan -NoNewline
							Write-Host $QueryFile.Name -ForegroundColor Magenta
							Invoke-SqlCommand -Server $OpsDB_SQLServerOriginal -Database $OpsDB_SQLDBName -Username $SQLuser -Password $SQLpass -Path "$QueriesPath\$QueryFile" -As DataRow -Timeout $timeout -ErrorAction Stop | Export-Csv -Path "$OutputFileName" -NoTypeInformation
						}
						continue
					}
					#write-output "Writing output file" $OutputFileName
				}
				catch
				{
					Write-Host "       Error running SQL query: $QueryFileName
$_
" -ForegroundColor Red
					$_ | Export-Csv -Path "$OutputFileName" -NoTypeInformation
					"$(Time-Stamp)Error running SQL query: $QueryFileName `n$_" | Out-File $OutputPath\Error.log -Append
				}
				
			}
		}
	}
	
	if ($SQLOnlyOpsDB)
	{
		return
	}
	if ($SQLOnlyDW)
	{
		$AssumeYes = $true
	}
	# Query the DW database
	if ($answer5 -eq "Domain")
	{
		$Credential = New-Object -TypeName System.Management.Automation.PSCredential -ArgumentList $SQLuser2, $SQLpass2
		$command = "-NoProfile -NoExit -Command cd '$ScriptPath';. '$ScriptPath\$scriptname' -SQLOnlyDW; exit 0"
		Start-Process powershell.exe ($command) -Credential $Credential -Wait -NoNewWindow
		return
	}
	elseif ($answer4 -eq "y")
	{
		$SqlIntegratedSecurity = $true
	}
	elseif ($answer5 -eq "SQL")
	{
		$SqlIntegratedSecurity = $false
	}
	$QueriesPath = "$ScriptPath\queries\DW"
	IF (!(Test-Path $QueriesPath))
	{
		Write-Error "Path to query files not found ($QueriesPath).  Terminating...."
		"Path to query files not found ($QueriesPath).  Terminating...." | Out-File $OutputPath\Error.log -Append
		break
	}
	Write-Host "`n================================"
	Write-Host "Running SQL Queries against Data Warehouse"
	try
	{
		$timeout = 30
		if ($SqlIntegratedSecurity)
		{
			$initialCheck = Invoke-SqlCommand -Server $DW_SQLServerOriginal -Database $DW_SQLDBName -Query 'SELECT 1' -As DataRow -Timeout $timeout -ErrorAction Stop
		}
		else
		{
			$initialCheck = Invoke-SqlCommand -Server $DW_SQLServerOriginal -Database $DW_SQLDBName -Username $SQLuser2 -Password $SQLpass2 -Query 'SELECT 1' -As DataRow -Timeout $timeout -ErrorAction Stop
		}
		
		if ($initialCheck)
		{
			Write-Verbose "Initial Check:`n$initialCheck"
			# 15 minute timeout for each query
			$timeout = 900
			$jobtimeout = 2100
		}
		else
		{
			Write-Warning "Cannot communicate with SQL DB, expect errors."
		}
		
	}
	catch
	{
		Write-Warning $_
	}
	Write-Host " Current query timeout: $timeout seconds ($($timeout/60) minutes) \ Current query job timeout: $jobtimeout seconds ($($jobtimeout/60) minutes)" -ForegroundColor Gray
	Write-Host "  Gathering query files located here: $QueriesPath" -ForegroundColor DarkGray
	$QueryFiles = Get-ChildItem -Path $QueriesPath -Filter "*.sql" ###BH Remove Where for Filter left
	$QueryFilesCount = $QueryFiles.Count
	Write-Host "   Found ($QueryFilesCount) queries" -ForegroundColor Green
	FOREACH ($QueryFile in $QueryFiles)
	{
		try
		{
			$QueryFileName = ($QueryFile.Name).split('.')[0]
			$OutputFileName = $OutputPath + "\" + $QueryFileName + ".csv"
			if ($SqlIntegratedSecurity)
			{
				$DWScriptBlock = [scriptblock]::Create(@"
  Invoke-SqlCommand -Server $DW_SQLServerOriginal -Database $DW_SQLDBName -Path "$QueriesPath\$QueryFile" -As DataRow -Timeout $jobtimeout -ErrorAction Stop | Export-Csv -Path "$OutputFileName" -NoTypeInformation
"@)
				#This runs all queries with Perf in the name, as a job
				if ($QueryFileName -match 'Perf')
				{
					Write-Host "     Running query job: " -ForegroundColor Cyan -NoNewline
					Write-Host $QueryFile.Name -ForegroundColor Magenta
					Start-Job -Name "getPerf_DW-$($QueryFile.Name)" -InitializationScript $InvokeSQLcmdFunction -ScriptBlock $DWScriptBlock | Out-Null
				}
				elseif ($QueryFileName -match 'Event')
				{
					Write-Host "     Running query job: " -ForegroundColor Cyan -NoNewline
					Write-Host $QueryFile.Name -ForegroundColor Magenta
					Start-Job -Name "getEvent_DW-$($QueryFile.Name)" -InitializationScript $InvokeSQLcmdFunction -ScriptBlock $DWScriptBlock | Out-Null
				}
				else
				{
					Write-Host "     Running query: " -ForegroundColor Cyan -NoNewline
					Write-Host $QueryFile.Name -ForegroundColor Magenta
					Invoke-SqlCommand -Server $DW_SQLServerOriginal -Database $DW_SQLDBName -Path "$QueriesPath\$QueryFile" -As DataRow -Timeout $timeout -ErrorAction Stop | Export-Csv -Path "$OutputFileName" -NoTypeInformation
				}
				continue
			}
			else
			{
				$DWScriptBlock = [scriptblock]::Create(@"
  Invoke-SqlCommand -Server $DW_SQLServerOriginal -Database $DW_SQLDBName -Username $SQLuser2 -Password $SQLpass2 -Path "$QueriesPath\$QueryFile" -As DataRow -Timeout $jobtimeout -ErrorAction Stop | Export-Csv -Path "$OutputFileName" -NoTypeInformation
"@)
				#This runs all queries with Perf in the name, as a job
				if ($QueryFileName -match 'Perf')
				{
					Write-Host "     Running query job: " -ForegroundColor Cyan -NoNewline
					Write-Host $QueryFile.Name -ForegroundColor Magenta
					Start-Job -Name "getPerf_DW-$($QueryFile.Name)" -InitializationScript $InvokeSQLcmdFunction -ScriptBlock $DWScriptBlock | Out-Null
				}
				elseif ($QueryFileName -match 'Event')
				{
					Write-Host "     Running query job: " -ForegroundColor Cyan -NoNewline
					Write-Host $QueryFile.Name -ForegroundColor Magenta
					Start-Job -Name "getEvent_DW-$($QueryFile.Name)" -InitializationScript $InvokeSQLcmdFunction -ScriptBlock $DWScriptBlock | Out-Null
				}
				else
				{
					Write-Host "     Running query: " -ForegroundColor Cyan -NoNewline
					Write-Host $QueryFile.Name -ForegroundColor Magenta
					Invoke-SqlCommand -Server $DW_SQLServerOriginal -Database $DW_SQLDBName -Username $SQLuser2 -Password $SQLpass2 -Path "$QueriesPath\$QueryFile" -As DataRow -Timeout $timeout -ErrorAction Stop | Export-Csv -Path "$OutputFileName" -NoTypeInformation
				}
				continue
			}
		}
		catch
		{
			Write-Host "       Error running SQL query: $QueryFileName
$_
" -ForegroundColor Red
			"$(Time-Stamp)Error running SQL query: $QueryFileName - `n$_" | Out-File $OutputPath\Error.log -Append
			$_ | Export-Csv -Path "$OutputFileName" -NoTypeInformation
		}
	}
}

		if (($SQLOnly -or $SQLOnlyDW -or $SQLOnlyOpsDB))
		{
			[System.Security.Principal.WindowsIdentity]::GetCurrent().Name
			SQL-Queries
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
			Write-Host "Moving stuff around and zipping everything up for easy transport" -ForegroundColor Gray
			Function Wrap-Up
{
	param
	(
		[switch]$BuildPipeline
	)
	$jobstatus = $null
	$jobstatus = (Get-Job -Name "getEvent*", "getPerf*")
	foreach ($job in $jobstatus)
	{
		if ($job.State -eq 'Running')
		{
			Write-Host "`nWaiting for SQL Query `'$($job.Name -split "-" | Select-Object -Last 1)`' to finish gathering data." -ForegroundColor Gray -NoNewline
		}
		do
		{
			if ($job.State -eq 'Running')
			{
				Write-Host "." -ForegroundColor Gray -NoNewline
				sleep 5
			}
		}
		until ($job.State -ne 'Running')
	}
	Write-Host " "
	try
	{
		if (Test-Path $OutputPath\*.csv)
		{
			New-Item -Type Directory -Path $OutputPath\CSV -ErrorAction SilentlyContinue | out-null
			Move-Item $OutputPath\*.csv $OutputPath\CSV
		}
		if ((Get-ChildItem $OutputPath\CSV).Count -eq 0)
		{
			Remove-Item $OutputPath\CSV -Force -ErrorAction SilentlyContinue | out-null
		}
		$FolderNames = (Get-ChildItem "$OutputPath`\*.evtx" | Select-Object Name -ExpandProperty Name) | % { $_.split(".")[0] } | Select -Unique
		$FolderNames | % {
			$currentServer = $_
			mkdir "$OutputPath`\Event Logs\$currentServer" | Out-Null;
			mkdir "$OutputPath`\Event Logs\$currentServer`\localemetadata\" | Out-Null;
			$Eventlogs = Get-ChildItem "$OutputPath`\$currentServer`*.evtx"
			foreach ($eventlog in $Eventlogs)
			{
				Move-Item $eventlog -Destination "$OutputPath`\Event Logs\$currentServer" | Out-Null
			}
			
			$EventlogsMetadata = Get-ChildItem "$OutputPath`\$currentServer`*.mta"
			foreach ($eventlogmetadata in $EventlogsMetadata)
			{
				Move-Item $eventlogmetadata -Destination "$OutputPath`\Event Logs\$currentServer`\localemetadata\" | Out-Null
			}
		}
	}
	catch
	{
		Write-Warning $_
	}
	$fullfilepath = $OutputPath + '\datacollector-' + ((((Get-Content "$currentPath" | Select-String '.VERSION' -Context 1) | Select -First 1 $_.Context.PostContext) -split "`n")[2]).Trim().Split(" ")[0]
	#Write file to show script version in the SDC Results File.

	try
	{
		$EndTime = "$(Get-Date -Format "MMMM dd, yyyy @ h:mm tt") $((Get-TimeZone -ErrorAction SilentlyContinue).DisplayName)"
	}
	catch
	{
		$EndTime = "$(Get-Date -Format "MMMM dd, yyyy @ h:mm tt") (unknown time zone)"
	}
	@"
Script Running as User:
$env:USERDOMAIN\$env:USERNAME

Script Running on Server:
$env:COMPUTERNAME

Script Path:
$ScriptPath\$scriptname

Parameters Passed to Script:
$ScriptPassedArgs

Parameters Passed to Function:
$FunctionPassedArgs

Script execution started on date/time:
$StartTime

Script execution completed on date/time:
$EndTime
"@ | Out-File $fullfilepath -Force
	
	#Zip output
	$Error.Clear()
	Write-Host "Creating zip file of all output data." -ForegroundColor DarkCyan
	[Reflection.Assembly]::LoadWithPartialName("System.IO.Compression.FileSystem") | Out-Null
	[System.AppDomain]::CurrentDomain.GetAssemblies() | Out-Null
	$SourcePath = Resolve-Path $OutputPath
	[string]$filedate = (Get-Date).tostring("MM_dd_yyyy_hh-mm-tt")
	if ($CaseNumber)
	{
		[string]$destfilename = "SDC_Results_$CaseNumber_$filedate`.zip"
	}
	elseif ($BuildPipeline)
	{
		[string]$destfilename = "SDC_Results.zip"
	}
	else
	{
		[string]$destfilename = "SDC_Results_$filedate`.zip"
	}
	
	[string]$global:destfile = "$ScriptPath\$destfilename"
	IF (Test-Path $global:destfile)
	{
		#File exists from a previous run on the same day - delete it
		Write-Host "-Found existing zip file: $destfile.`n Deleting existing file." -ForegroundColor DarkGreen
		Remove-Item $global:destfile -Force
	}
	$compressionLevel = [System.IO.Compression.CompressionLevel]::Optimal
	$includebasedir = $false
	[System.IO.Compression.ZipFile]::CreateFromDirectory($SourcePath, $destfile, $compressionLevel, $includebasedir) | Out-Null
	IF ($Error)
	{
		Write-Error "Error creating zip file."
	}
	ELSE
	{
		Write-Host "-Cleaning up output directory." -ForegroundColor DarkCyan
		Remove-Item $OutputPath -Recurse
		Write-Host "--Saved zip file to: $global:destfile." -ForegroundColor Cyan
	}
}

			Wrap-Up -BuildPipeline:$BuildPipeline
			
			Write-Host "Script has completed!" -ForegroundColor Green -NoNewline
			Start-Sleep -Seconds 1
			Write-Output " "
			Write-Warning "Exiting script..."
			start C:\Windows\explorer.exe -ArgumentList "/select, $destfile"
			break
		}
		else
		{
			SQL-Queries
		}
	}
	
	$Populated = 1
	Write-Progress -Activity "Collection Running" -Status "Progress-> 1%" -PercentComplete 1
	
	#$TLSservers = import-csv $OutputPath\ManagementServers.csv
	if (!$ManagementServers)
	{
		try
		{
			$ManagementServers = Get-SCOMManagementServer -ErrorAction Stop | where { $_.IsGateway -eq $false } | Sort-Object DisplayName -Descending | Select-Object DisplayName -ExpandProperty DisplayName -Unique
		}
		catch
		{
			$ManagementServers = import-csv $OutputPath\ManagementServers.csv | where { $_.IsGateway -eq $false } | Sort-Object DisplayName -Descending | Select-Object DisplayName -ExpandProperty DisplayName -Unique
		}
	}
	if ($ManagementServers -eq $null)
	{
		"$(Time-Stamp)Unable to detect any Management Servers with the `'Get-SCOMManagementServer`' command and the SQL Query to return Management Servers. Setting the `$ManagementServer variable to $env:COMPUTERNAME (local machine)." | Out-File $OutputPath\Error.log -Append
		$ManagementServers = $env:COMPUTERNAME
	}
	Write-Progress -Activity "Collection Running" -Status "Progress-> 2%" -PercentComplete 2
	[string[]]$TLSservers = $ManagementServers
	
	[string[]]$TLSservers += ($global:DW_SQLServer.Split('\')[0]).Split(',')[0]
	
	[string[]]$TLSservers += ($global:OpsDB_SQLServer.Split('\')[0]).Split(',')[0]
	
	[string[]]$TestedTLSservers = @()
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
			$Servers = $Servers | select -Unique
			foreach ($Server in $Servers)
			{
				[string[]]$TLSservers += $Server
			}
		}
		[array]$DNSCheckedServers = $null
		[string[]]$TLSservers = $TLSservers | select -Unique | Where { $null -ne $_ }
		Write-Progress -Activity "Collection Running" -Status "Progress-> 4%" -PercentComplete 4
		foreach ($server in $TLSservers)
		{
			try
			{
				[array]$DNSCheckedServers += ([System.Net.Dns]::GetHostByName(("$server"))).Hostname
			}
			catch
			{
				"$(Time-Stamp)Unable to Find DNS Hostname: $server - from $env:COMPUTERNAME - Not adding to list of Servers to Check." | Out-File $OutputPath\Error.log -Append
				Write-Host "Unable to Find DNS Hostname: $server - Not adding to list of Servers to Check." -ForegroundColor Red
			}
		}
		Write-Progress -Activity "Collection Running" -Status "Progress-> 5%" -PercentComplete 5
		[array]$DNSVerifiedServers = [array]$DNSCheckedServers | select -Unique | Sort-Object
		$DNSCount = ($DNSVerifiedServers).Count
		
		Write-Output " "
		Write-Output "================================`nTesting Connectivity to Servers (Count: $DNSCount)"
		foreach ($Rsrv in $DNSVerifiedServers)
		{
			$shareAccessible = $false
			Write-Host "  Testing $Rsrv" -ForegroundColor Gray
			$test = $null
			$test = test-path "filesystem::\\$Rsrv\c`$" -ErrorAction SilentlyContinue
			if ($test)
			{
				Write-Host "    Successfully Accessed Remote Share : \\$Rsrv\c`$" -ForegroundColor Green
				$shareAccessible = $true
			}
			else
			{
				"$(Time-Stamp)Access to \\$Rsrv\c`$ Failed from $($env:COMPUTERNAME)" | Out-File $OutputPath\Error.log -Append
				Write-Host "    Access to \\$Rsrv\c`$ Failed! Removing from Server Array! 
    Please verify that the server is online, and that your account has remote access to it.`n" -ForegroundColor Gray
				continue
			}
			$InvokeAbility = Invoke-Command -ErrorAction SilentlyContinue -ComputerName $Rsrv -ScriptBlock { return $true }
			if ($InvokeAbility)
			{
				Write-Host "    Successfully Executed Powershell Invoke Command : $Rsrv" -ForegroundColor Green
				if ($shareAccessible)
				{
					$TestedTLSservers += $Rsrv.Split(",")
				}
			}
			else
			{
				"$(Time-Stamp)Unable to Invoke-Commands against $Rsrv" | Out-File $OutputPath\Error.log -Append
				Write-Host "    Unable to Invoke-Commands for $Rsrv! Removing from Server Array! 
    Verify that you have PSRemoting turned on: Enable-PSRemoting`n" -ForegroundColor Gray
				continue
			}
		}
		$TestedTLSservers = $TestedTLSservers | Select -Unique | Sort-Object
		$templist = @()
		foreach ($server in $TestedTLSservers)
		{
			foreach ($ManagementServer in $ManagementServers)
			{
				if ($server -match "^$ManagementServer")
				{
					$templist += $server
				}
			}
		}
		$OriginalManagementServers = $ManagementServers | Select -Unique | Sort-Object
		$ManagementServers = $templist
	}
	else
	{
		$TestedTLSservers = $TLSservers | Select-Object -Unique
	}
	#region Linux Agent Gather Script
	if ($SCXAgents)
	{
		Write-Output " "
		Write-Output "================================`nStarting SCX Agent Checker (Linux/Unix)"
		function Start-LinuxDataCollector
{
	param
	(
		[Array]$Servers,
		[String]$Username
	)
	# Last Updated: October 25th, 2022
	trap
	{
		#potential error code
		#use continue or break keywords
		$e = $_.Exception
		$line = $_.InvocationInfo.ScriptLineNumber
		$msg = $e.Message
		
		Write-Verbose "Caught Exception: $e :: Message: $msg :: at line: $line"
		"$(Time-Stamp)Caught Exception: $e :: Message: $msg :: at line: $line" | Out-File $OutputPath\Error.log -Append
	}
	try
	{
		Get-Command -Name 'ssh' -ErrorAction Stop | Out-Null
		Write-Host " Found 'ssh' executable on the server"
		$foundSSH = $true
	}
	catch
	{
		Write-Warning "Unable to detect SSH client installed, you will need to either include plink (https://www.chiark.greenend.org.uk/~sgtatham/putty/latest.html) in the SCOM Data Collector script folder, or you will need to install a SSH Client onto your machine and add it to the environmental variables so the 'ssh' command is accessible via Powershell.`n`nExiting.."
		#potential error code
		#use continue or break keywords
		$e = $_.Exception
		$line = $_.InvocationInfo.ScriptLineNumber
		$msg = $e.Message
		
		Write-Verbose "Caught Exception: $e :: Message: $msg :: at line: $line"
		"$(Time-Stamp)Caught Exception: $e :: Message: $msg :: at line: $line" | Out-File $OutputPath\Error.log -Append
		return
	}
	if (!$foundSSH)
	{
		try
		{
			Write-Host "  Testing to verify if the Plink executable is present."
			Test-Path "$ScriptPath\plink.exe" -ErrorAction Stop | Out-Null
		}
		catch
		{
			Write-Host "  Unable to locate plink.exe. Skipping Linux Data Collector gathering."
			"$(Time-Stamp)Unable to locate plink.exe. Skipping Linux Data Collector gathering." | Out-File $OutputPath\Error.log -Append
			break
		}
	}
	
	
	$ScomLinuxDataCollectorScript = @'
#! /bin/bash
#About:
#   This script is written for data collection from Linux machines which can help in troubleshooting SCOM UNIX/LINUX Agent (SCXAgent)
#Original Author :
#   Udish Mudiar, Microsoft Customer Service Support Professional
#Modified by :
#   Blake Drumm, Microsoft Customer Service Support Professional
#Feedback :
#   Email udmudiar@microsoft.com
#   Or the engineer you are working with


help()
{
    printf "\nAbout:\n\tThis shell script is used to collect basic information about the Operating System and SCOM Linux (SCX) Agent"
    printf "\n\tThis is a read -r only script and does not make any changes to the system."
    printf "\n\nUsage: [OPTIONS]"
    printf "\n  Options:"
    printf "\n    -o  OutputPath : Specify the location where the data would be collected. If not specified the script will collect the data in the current working directory."
    printf "\n\n    -m  SCXMaintenanceAccount : Specify the SCX Maintenance Account. This will be used to check the sudo privilege for the account."
    printf "\n\n    -n  SCXMonitoringAccount : Specify the SCX Monitoring Account. This will be used to check the sudo privilege for the account.\n"
}

check_distro(){
    printf "Checking distro. The script will proceed only for supported distro.....\n"
    printf "Checking distro. The script will proceed only for supported distro.....\n" >> "${path}"/scxdatacollector.log
    if [ "$(uname)" = 'Linux' ]; then
        printf "\tDistro is Linux. Continuing.....\n"
        printf "\tDistro is Linux. Continuing.....\n" >> "${path}"/scxdatacollector.log
    #elif [ condition ]; then
         # else if body
    else
        printf "\tDistro is not Linux (Detected: %s). Exiting.....\n" "$(uname)"
        printf "\tDistro is not Linux (Detected: %s). Exiting.....\n" "$(uname)" >> "${path}"/scxdatacollector.log
        exit
    fi
}

check_parameters(){
    #checking the number of parameters passed
    #we expect either 1 or 2 parameters which are the SCOM maintenance and monitoring account
    #if the parameters passed are greater than 2 then it is advised that you recheck the SCOM Run As Account and Profiles for streamlining your configuration.
    #you can refer to he below blog:
    # https://udishtech.com/how-to-configure-sudoers-file-for-scom-monitoring/
    if [ $# == 1 ]; then
        printf "The argument for sudo is: $1.....\n"
        printf "The argument for sudo is: $1.....\n" >> "${path}"/scxdatacollector.log
        create_dir "${path}/SCOMLinuxDataCollectorData/sudo"
        check_sudo_permission "$1"
    elif [ $# == 2 ]; then
        printf "The arguments for sudo are : $1 and $2.....\n"
        printf "The arguments for sudo are : $1 and $2.....\n" >> "${path}"/scxdatacollector.log
        create_dir "${path}/SCOMLinuxDataCollectorData/sudo"
        check_sudo_permission "$1" "$2"
    elif [ -z "${maint}" ] && [ -z "${mon}" ]; then
        printf "No SCOM Maintenance and Monitoring Account passed. Not collecting sudo details for the users....\n"
        printf "No SCOM Maintenance and Monitoring Account passed. Not collecting sudo details for the users....\n" >> "${path}"/scxdatacollector.log
        read -r -p 'Do you want to stop the script and rerun with the SCOM Accounts (Y/N)? ' response
       if [[ "${response}" == "Y" ]]; then
           printf "Exiting script....\n"
           exit 3
       elif [[ "${response}" == "N" ]]; then
            printf "Continuing script. But not collecting sudo details for the users....\n"
            printf "Continuing script. But not collecting sudo details for the users....\n" >> "${path}"/scxdatacollector.log
       fi
    fi
}

check_dir() {
    pwd=$(pwd)
    printf "Logs will be created in the output directory i.e. %s .....\n" "${path}"
    printf "Logs will be created in the output directory i.e. %s .....\n" "${path}" >> "${path}"/scxdatacollector.log
    printf "Creating the directory structure to store the data from the collector.....\n"
    printf "Creating the directory structure to store the data from the collector.....\n" >> "${path}"/scxdatacollector.log

    if [ -d "${path}/SCOMLinuxDataCollectorData" ]; then
        printf "\tPath %s/SCOMLinuxDataCollectorData is present. Removing and recreating the directory.....\n" "${path}"
        printf "\tPath %s/SCOMLinuxDataCollectorData is present. Removing and recreating the directory.....\n" "${path}" >> "${path}"/scxdatacollector.log
        rm -rf "${path}"/SCOMLinuxDataCollectorData
        create_dir "${path}/SCOMLinuxDataCollectorData"
    else
        printf "\tPath ${pwd} is not present in the current working directory. Creating the directory.....\n"
        printf "\tPath ${pwd} is not present in the current working directory. Creating the directory.....\n" >> "${path}"/scxdatacollector.log
        create_dir "${path}/SCOMLinuxDataCollectorData"
    fi

    create_dir "${path}/SCOMLinuxDataCollectorData/logs"
    create_dir "${path}/SCOMLinuxDataCollectorData/certs"
    create_dir "${path}/SCOMLinuxDataCollectorData/network"
    create_dir "${path}/SCOMLinuxDataCollectorData/scxdirectorystructure"
    create_dir "${path}/SCOMLinuxDataCollectorData/pam"
    create_dir "${path}/SCOMLinuxDataCollectorData/scxprovider"
    create_dir "${path}/SCOMLinuxDataCollectorData/configfiles"
    create_dir "${path}/SCOMLinuxDataCollectorData/tlscheck"
}

create_dir(){
    if [ -d "$1" ]; then
        printf "\tPath $1 exists. No action needed......\n"
        printf "\tPath $1 exists. No action needed......\n" >> "${path}"/scxdatacollector.log
    else
        printf "\tPath $1 does not exists. Proceed with creation.....\n"
        printf "\tPath $1 does not exists. Proceed with creation.....\n" >> "${path}"/scxdatacollector.log
        mkdir -p "$1"
    fi
}

collect_os_details() {
    printf "Collecting OS Details.....\n"
    printf "\nCollecting OS Details.....\n" >> "${path}"/scxdatacollector.log
    collect_host_name
    collect_os_version
    collect_system_logs sudo
    collect_compute
    collect_disk_space
    collect_network_details
    collect_openssl_details
    collect_openssh_details sudo
    collect_crypto_details
    check_kerberos_enabled
    collect_selinux_details
    collect_env_variable
    collect_other_config_files sudo   
}

collect_host_name() {
    printf "\tCollecting HostName Details.....\n"
    printf "\tCollecting Hostname Details.....\n" >> "${path}"/scxdatacollector.log
    printf "\n******HOSTNAME******"  > "${path}"/SCOMLinuxDataCollectorData/OSDetails.txt
    hostname >> "${path}"/SCOMLinuxDataCollectorData/OSDetails.txt
    #below is what SCOM check while creating the self-signed certificate as CN
    printf "\n******HOSTNAME FOR CERTS******"  >> "${path}"/SCOMLinuxDataCollectorData/OSDetails.txt
    nslookuphostname=$(nslookup "$(hostname)" | grep '^Name:' | awk '{print $2}' | grep "$(hostname)")
    if [ "${nslookuphostname}" ]; then
        printf "${nslookuphostname}" >> "${path}"/SCOMLinuxDataCollectorData/OSDetails.txt
    else
        printf "Unable to resolve hostname from nslookup....." >> "${path}"/SCOMLinuxDataCollectorData/OSDetails.txt
    fi
}

collect_os_version(){
    printf "\tCollecting OS Details.....\n"
    printf "\tCollecting OS Details.....\n" >> "${path}"/scxdatacollector.log
    printf "\n******OS VERSION******"  >> "${path}"/SCOMLinuxDataCollectorData/OSDetails.txt
	releasedata=$(cat /etc/*release)
	releaseversion=$(printf "$releasedata" | grep -Po '(?<=PRETTY_NAME=")[^"]*')
	printf "\t  Detected: ${releaseversion}"
    printf "$releasedata" >> "${path}"/SCOMLinuxDataCollectorData/OSDetails.txt
}

collect_compute(){
    printf "\n\tCollecting Memory and CPU for omi processes.....\n"
    printf "\tCollecting Memory and CPU for omi processes.....\n" >> "${path}"/scxdatacollector.log
    printf "\n******MEM AND CPU FOR OMISERVER PROCESS******"  >> "${path}"/SCOMLinuxDataCollectorData/OSDetails.txt
    ps -C omiserver -o %cpu,%mem,cmd >> "${path}"/SCOMLinuxDataCollectorData/OSDetails.txt
    printf "\n******MEM AND CPU FOR OMIENGINE PROCESS******"  >> "${path}"/SCOMLinuxDataCollectorData/OSDetails.txt
    ps -C omiengine -o %cpu,%mem,cmd >> "${path}"/SCOMLinuxDataCollectorData/OSDetails.txt
    printf "\n******MEM AND CPU FOR OMIAGENT PROCESSES******"  >> "${path}"/SCOMLinuxDataCollectorData/OSDetails.txt
    ps -C omiagent -o %cpu,%mem,cmd >> "${path}"/SCOMLinuxDataCollectorData/OSDetails.txt
}

collect_openssl_details() {
    printf "\tCollecting Openssl & Openssh Details.....\n"
    printf "\tCollecting Openssl & Openssh Details.....\n" >> "${path}"/scxdatacollector.log
    printf "\n******OPENSSL & OPENSSH VERSION******"  >> "${path}"/SCOMLinuxDataCollectorData/OSDetails.txt
    ssh -V  >> "${path}"/SCOMLinuxDataCollectorData/OSDetails.txt  2>&1
}

collect_openssh_details(){
    printf "\tCollecting SSH Details.....\n"
    printf "\tCollecting SSH Details.....\n" >> "${path}"/scxdatacollector.log
    #checking Kex settings in sshd. We are interested in the sshd server settings.
    printf "\n******SSH DETAILS******"  >> "${path}"/SCOMLinuxDataCollectorData/OSDetails.txt
    printf "\n******KEY EXCHANGE ALGORITHIM (KEX) DETAILS******"  >> "${path}"/SCOMLinuxDataCollectorData/OSDetails.txt
    $1 sshd -T | grep -E ^kexalgorithms >> "${path}"/SCOMLinuxDataCollectorData/OSDetails.txt
    printf "\n******CIPHERS DETAILS******"  >> "${path}"/SCOMLinuxDataCollectorData/OSDetails.txt
    $1 sshd -T | grep ciphers>> "${path}"/SCOMLinuxDataCollectorData/OSDetails.txt
    printf "\n******MACS DETAILS******"  >> "${path}"/SCOMLinuxDataCollectorData/OSDetails.txt
    $1 sshd -T | grep macs >> "${path}"/SCOMLinuxDataCollectorData/OSDetails.txt
    printf "\n******HOST KEY ALGORITHIMS DETAILS******"  >> "${path}"/SCOMLinuxDataCollectorData/OSDetails.txt
    $1 sshd -T | grep keyalgorithms >> "${path}"/SCOMLinuxDataCollectorData/OSDetails.txt
	#copy the sshd configuration file
    echo -e "\n******Copying sshd config file******"  >> "${path}"/SCOMLinuxDataCollectorData/OSDetails.txt
    $1 cp -f /etc/ssh/sshd_config  "${path}"/SCOMLinuxDataCollectorData/configfiles/sshd_config_copy
}

collect_disk_space(){
    printf "\tCollecting the file system usage.....\n"
    printf "\tCollecting the file system usage.....\n" >> "${path}"/scxdatacollector.log
    printf "\n******FILE SYSTEM DETAILS******"  >> "${path}"/SCOMLinuxDataCollectorData/OSDetails.txt
    df -h >> "${path}"/SCOMLinuxDataCollectorData/OSDetails.txt
}

check_kerberos_enabled(){
    #This is not a full proof method as there are 3rd party tools who uses different ways to enable Kerb auth. Need more testing.
    printf "\tChecking if Kerberos Authentication is enabled. This might not be 100%% accurate....\n"
    printf "\tChecking if Kerberos Authentication is enabled. This might not be 100%% accurate....\n" >> "${path}"/scxdatacollector.log
    if [ -f "/etc/krb5.conf" ]; then
        isKerb=$(cat /etc/krb5.conf | grep -E "^default_realm" | wc -l)
        if [ "${isKerb}" = 1 ]; then
            printf "\t  Kerberos Authentication is enabled. This might not be 100%% accurate....\n"
            printf "\t  Kerberos Authentication is enabled. This might not be 100%% accurate....\n" >> "${path}"/scxdatacollector.log
        else
            printf "\t  Kerberos Authentication is not enabled. This might not be 100%% accurate....\n"
            printf "\t  Kerberos Authentication is not enabled. This might not be 100%% accurate....\n" >> "${path}"/scxdatacollector.log
        fi
    else
        printf "\t  Kerberos Authentication is not enabled. This might not be 100%% accurate....\n"
        printf "\t  Kerberos Authentication is not enabled. This might not be 100%% accurate....\n" >> "${path}"/scxdatacollector.log
    fi
}

collect_network_details(){
    printf "\tCollecting the network details.....\n"
    printf "\tCollecting the network details.....\n" >> "${path}"/scxdatacollector.log
    printf "\n******IP ADDRESS DETAILS******"  >> "${path}"/SCOMLinuxDataCollectorData/network/ipdetails
    ip addr show >> "${path}"/SCOMLinuxDataCollectorData/network/ipdetails
    printf "\n******NETSTAT DETAILS******"  >> "${path}"/SCOMLinuxDataCollectorData/network/ipdetails
    #netstat is a deprecated utility.
    #netstat -anp >> ${path}/SCOMLinuxDataCollectorData/network/netstatdetails
    ss >> "${path}"/SCOMLinuxDataCollectorData/network/netstatdetails
}

check_sudo_permission(){
    account_1=$(/bin/echo "$1")
    account_2=$(/bin/echo "$2")
   if (( $# == 1 )); then
        printf "Checking the sudo permissions for the account ${account_1}...\n"
        printf "Checking the sudo permissions for the account ${account_1}.....\n" >> "${path}"/scxdatacollector.log
        create_dir "${path}/SCOMLinuxDataCollectorData/sudo"
        printf "******SUDO DETAILS FOR ${account_1}*****\n" > "${path}"/SCOMLinuxDataCollectorData/sudo/"${account_1}"
        sudo -l -U "${account_1}" >> "${path}"/SCOMLinuxDataCollectorData/sudo/"${account_1}"
   elif (( $# == 2 )); then
        printf "Checking the sudo permissions for the account ${account_1} and ${account_2}...\n"
        printf "Checking the sudo permissions for the account ${account_1} and ${account_2}...\n" >> "${path}"/scxdatacollector.log
        create_dir "${path}/SCOMLinuxDataCollectorData/sudo"
        printf "******SUDO DETAILS FOR %s*****\n" "${account_1}" > "${path}"/SCOMLinuxDataCollectorData/sudo/"${account_1}"
        sudo -l -U "${account_1}" >> "${path}"/SCOMLinuxDataCollectorData/sudo/"${account_1}"
        printf "******SUDO DETAILS FOR %s*****\n" "${account_2}" > "${path}"/SCOMLinuxDataCollectorData/sudo/"${account_2}"
        sudo -l -U "${account_2}" >> "${path}"/SCOMLinuxDataCollectorData/sudo/"${account_2}"
   fi
}

collect_crypto_details(){
    printf "\tCollecting Crypto details.....\n"
    printf "\tCollecting Crypto details.....\n" >> "${path}"/scxdatacollector.log
    if [ "$(which update-crypto-policie 2>/dev/null)" ]; then
        printf "\t\t Crypto binary found. Collecting the status....\n" >> "${path}"/scxdatacollector.log
        printf "*****CRYPTO SETTINGS******\n" >> "${path}"/SCOMLinuxDataCollectorData/OSDetails.txt
        update-crypto-policies --show >> "${path}"/SCOMLinuxDataCollectorData/OSDetails.txt
    else
        printf "\t\t Crypto binary not found....\n" >> "${path}"/scxdatacollector.log
    fi
}

collect_selinux_details(){
    printf "\tCollecting SELinux details.....\n"
    printf "\tCollecting SELinux details.....\n" >> "${path}"/scxdatacollector.log
    if [ "$(which sestatus 2>/dev/null)" ]; then
        printf "\t\t SELinux is installed. Collecting the status....\n" >> "${path}"/scxdatacollector.log
        printf "\n*****SELinux SETTINGS******\n" >> "${path}"/SCOMLinuxDataCollectorData/OSDetails.txt
        sestatus >> "${path}"/SCOMLinuxDataCollectorData/OSDetails.txt
    else
        printf "\t\t SELinux is not installed....\n" >> "${path}"/scxdatacollector.log
    fi
}

collect_env_variable(){
    printf "\tCollecting env variable for the current user: $(whoami).....\n"
    printf "\tCollecting env variable for the current user: $(whoami).....\n" >> "${path}"/scxdatacollector.log
    env >> "${path}"/SCOMLinuxDataCollectorData/configfiles/env
}

collect_system_logs(){
    printf "\n\tCollecting system logs. Might take sometime. Hang On....."
    printf "\tCollecting system logs. Might take sometime. Hang On....." >> "${path}"/scxdatacollector.log
    #only copying the latest logs from the archive.
    if [ -f "/var/log/messages" ]; then
        printf "\n\t\tFile /var/log/messages exists. Copying the file messages" >> "${path}"/scxdatacollector.log
        $1 cp -f /var/log/messages "${path}"/SCOMLinuxDataCollectorData/logs/messages_copy
    else
        printf "\n\t\tFile /var/log/messages doesn't exists. No action needed" >> "${path}"/scxdatacollector.log 
    fi
    if [ -f "/var/log/secure" ]; then
        printf "\n\t\tFile /var/log/secure exists. Copying the file secure" >> "${path}"/scxdatacollector.log
        $1 cp -f /var/log/secure "${path}"/SCOMLinuxDataCollectorData/logs/secure_copy
    else
        printf "\n\t\tFile /var/log/secure doesn't exists. No action needed" >> "${path}"/scxdatacollector.log   
    fi
    if [ -f "/var/log/auth" ]; then
        printf "\n\t\tFile /var/log/auth exists. Copying the file auth" >> "${path}"/scxdatacollector.log
        $1 cp -f /var/log/auth "${path}"/SCOMLinuxDataCollectorData/logs/auth_copy
    else
        printf "\n\t\tFile /var/log/auth doesn't exists. No action needed" >> "${path}"/scxdatacollector.log  
    fi  
}

collect_other_config_files(){
    printf "\tCollecting other config files.....\n"
    printf "\tCollecting /etc/resolv.conf and /etc/hosts config files......\n" >> "${path}"/scxdatacollector.log
    $1 cp -f /etc/resolv.conf "${path}"/SCOMLinuxDataCollectorData/configfiles/resolv.conf_copy
    $1 cp -f /etc/hosts "${path}"/SCOMLinuxDataCollectorData/configfiles/hosts_copy
}

detect_installer(){
    # If DPKG lives here, assume we use that. Otherwise we use RPM.
    printf "Checking installer should be rpm or dpkg.....\n" >> "${path}"/scxdatacollector.log
    type dpkg > /dev/null 2>&1
    if [ $? -eq 0 ]; then
        installer=dpkg
        printf "\tFound dpkg installer....\n" >> "${path}"/scxdatacollector.log
        check_scx_installed $installer "$1"
    else
        installer=rpm
        printf "\tFound rpm installer......\n" >> "${path}"/scxdatacollector.log
        check_scx_installed $installer "$1"
    fi
}

check_scx_installed(){
    printf "Checking if SCX is installed.....\n"
    printf "Checking if SCX is installed.....\n" >> "${path}"/scxdatacollector.log
    #we will check if the installer is rpm or dpkg and based on that run the package command.
    if [ "$installer" = "rpm" ]; then
        scx=$(rpm -qa scx 2>/dev/null)
        if [ "$scx" ]; then
            printf "\tSCX package is installed. Collecting SCX details.....\n"
            printf "\tSCX package is installed. Collecting SCX details.....\n" >> "${path}"/scxdatacollector.log
            #calling function to gather more information about SCX
            collect_scx_details "$2"
        else
            printf "\tSCX package is not installed. Not collecting any further details.....\n" >> "${path}"/scxdatacollector.log
        fi
    #we will assume if not rpm then dpkg.
    else
        scx=$(dpkg -s scx 2>/dev/null)
        if [ "$scx" ]; then
            printf "\tSCX package is installed. Collecting SCX details.....\n"
            printf "\tSCX package is installed. Collecting SCX details.....\n" >> "${path}"/scxdatacollector.log
            #calling function to gather more information about SCX
            collect_scx_details "$2"
        else
            printf "\tSCX package is not installed. Not collecting any further details.....\n" >> "${path}"/scxdatacollector.log
        fi
    fi


}

collect_scx_details(){
    scxversion=$(scxadmin -version)
    scxstatus=$(scxadmin -status)
    #netstat is a deprecated utility
    #netstat=`netstat -anp | grep :1270`
    netstat=$(ss -lp | grep -E ":opsmgr|:1270")
    omiprocesses=$(ps -ef | grep [o]mi | grep -v grep)
    omidstatus=$(systemctl status omid)
    printf "*****SCX VERSION******\n" > "${path}"/SCOMLinuxDataCollectorData/SCXDetails.txt
    printf "${scxversion}\n" >> "${path}"/SCOMLinuxDataCollectorData/SCXDetails.txt
    printf "*****SCX STATUS******\n" >> "${path}"/SCOMLinuxDataCollectorData/SCXDetails.txt
    printf "${scxstatus}\n" >> "${path}"/SCOMLinuxDataCollectorData/SCXDetails.txt
    printf "*****SCX PORT STATUS******\n" >> "${path}"/SCOMLinuxDataCollectorData/SCXDetails.txt
    printf "${netstat}\n" >> "${path}"/SCOMLinuxDataCollectorData/SCXDetails.txt
    printf "*****OMI PROCESSES******\n" >> "${path}"/SCOMLinuxDataCollectorData/SCXDetails.txt
    printf "${omiprocesses}\n" >> "${path}"/SCOMLinuxDataCollectorData/SCXDetails.txt
    printf "*****OMID STATUS******\n" >> "${path}"/SCOMLinuxDataCollectorData/SCXDetails.txt
    printf "${omidstatus}\n" >> "${path}"/SCOMLinuxDataCollectorData/SCXDetails.txt

    #unable to figure out the redirection for now
    #if the omiserver is stopped then we need to check the status by running the utility
    #omiserverstatus=`/opt/omi/bin/omiserver`
    #printf "omiserver status:\n $omiserverstatus\n" >> ${path}/scxdatacollector.log

    #*****************************************
    #*********SCX FUNCTION CALLS**************
    #*****************************************
    collect_scx_config_files
    collect_omi_scx_logs
    collect_omi_scx_certs
    collect_scx_directories_structure "$1"
    collect_omi_pam
    collect_scx_provider_status
    check_omi_core_files
    check_scx_omi_log_rotation
    test_tls_with_omi
}

collect_scx_config_files(){
    printf "\tCopying config files.....\n"
    printf "\tCopying config files.....\n" >> "${path}"/scxdatacollector.log
    cp -f /etc/opt/omi/conf/omiserver.conf "${path}"/SCOMLinuxDataCollectorData/configfiles/omiserver.conf_copy
}

collect_omi_scx_logs(){
    printf "\tCollecting details of OMI and SCX logs.....\n"
    printf "\tCollecting details of OMI and SCX logs.....\n" >> "${path}"/scxdatacollector.log
    omilogsetting=$(cat /etc/opt/omi/conf/omiserver.conf | grep -i loglevel)
    printf "*****OMI LOG SETTINGS******\n" >> "${path}"/SCOMLinuxDataCollectorData/SCXDetails.txt
    printf "$omilogsetting \n" >> "${path}"/SCOMLinuxDataCollectorData/SCXDetails.txt
    scxlogsetting=$(scxadmin -log-list)
    printf "*****SCX LOG SETTINGS******\n" >> "${path}"/SCOMLinuxDataCollectorData/SCXDetails.txt
    printf "$scxlogsetting \n" >> "${path}"/SCOMLinuxDataCollectorData/SCXDetails.txt

    printf "\tCopying OMI and SCX logs. Might take sometime. Hang On....\n"
    printf "\tCopying OMI and SCX logs. Might take sometime. Hang On....\n" >> "${path}"/scxdatacollector.log
    count1=$(ls -1 /var/opt/omi/log/*.log  2>/dev/null | wc -l)
    if [ "${count1}" != 0 ]; then
      printf "\t\tFound .log files in path /var/opt/omi/log. Copying the logs.. \n" >> "${path}"/scxdatacollector.log
      cp -f /var/opt/omi/log/*.log "${path}"/SCOMLinuxDataCollectorData/logs
    else
      printf "\t\tNo .log files found in path /var/opt/omi/log. No action needed....\n" >> "${path}"/scxdatacollector.log
    fi

    count2=$(ls -1 /var/opt/omi/log/*.trc  2>/dev/null | wc -l)
    if [ "${count2}" != 0 ]; then
        printf "\t\tFound .trc files in path /var/opt/omi/log. Copying the logs.. \n" >> "${path}"/scxdatacollector.log
        cp -f /var/opt/omi/log/*.trc "${path}"/SCOMLinuxDataCollectorData/logs
    else
        printf "\t\tNo .trc files found in path /var/opt/omi/log. No action needed.... \n" >> "${path}"/scxdatacollector.log
    fi

    count3=$(ls -1 /var/opt/microsoft/scx/log/*.log  2>/dev/null | wc -l)
    if [ "${count3}" != 0 ]; then
        printf "\t\tFound .log files in path /var/opt/microsoft/scx/log/*.log. Copying the logs.. \n" >> "${path}"/scxdatacollector.log
        cp -f /var/opt/microsoft/scx/log/*.log "${path}"/SCOMLinuxDataCollectorData/logs
    else
        printf "\t\tNo .log files found in path /var/opt/microsoft/scx/log/*.log. No action needed.... \n" >> "${path}"/scxdatacollector.log
    fi
}

collect_omi_scx_certs(){
    printf "\tCollecting SCX cert details.....\n"
    printf "\tCollecting SCX cert details.....\n" >> "${path}"/scxdatacollector.log

    #checking omi certs
    if [ -d "/etc/opt/omi/ssl/" ]; then
      printf "\t \tPath /etc/opt/omi/ssl exists. Dumping details.....\n" >> "${path}"/scxdatacollector.log
      #dumping the list of files as the soft links can be broken at times of the permissions might be messed
      printf "\n******OMI CERTS STRUCTURE******\n" >> "${path}"/SCOMLinuxDataCollectorData/certs/certlist.txt
      ls -l /etc/opt/omi/ssl/ >> "${path}"/SCOMLinuxDataCollectorData/certs/certlist.txt

      cert=$(ls /etc/opt/omi/ssl/)
      omipubliccertsoftlink=$(find /etc/opt/omi/ssl | grep omi.pem)

      #checking the omi.pem
        if [ -f "${omipubliccertsoftlink}" ]; then
            printf "\t\tomi public cert exists.....\n" >> "${path}"/scxdatacollector.log
        else
            printf "\t\tomi public cert does not exists.....\n" >> "${path}"/scxdatacollector.log
        fi
    else
      printf "\t\tPath /etc/opt/omi/ssl does not exists.....\n" >> "${path}"/scxdatacollector.log
    fi

    #checking scx certs
    if [ -d "/etc/opt/microsoft/scx/ssl/" ]; then
        printf "\t\tPath /etc/opt/microsoft/scx/ssl/ exists. Dumping details.....\n" >> "${path}"/scxdatacollector.log
        printf "\n******SCX CERT STRUCTURE******\n" >> "${path}"/SCOMLinuxDataCollectorData/certs/certlist.txt
        ls -l /etc/opt/microsoft/scx/ssl/ >> "${path}"/SCOMLinuxDataCollectorData/certs/certlist.txt

        scxpubliccertsoftlink=$(find /etc/opt/microsoft/scx/ssl | grep scx.pem)
        #checking the scx.pem
        #dumping scx.pem as SCOM uses it.
        if [ -f "${scxpubliccertsoftlink}" ]; then
            printf "\t\tscx public cert exists..Dumping details.....\n" >> "${path}"/scxdatacollector.log
            openssl x509 -in /etc/opt/microsoft/scx/ssl/scx.pem -text > "${path}"/SCOMLinuxDataCollectorData/certs/certdetails_long.txt
            openssl x509 -noout -in /etc/opt/microsoft/scx/ssl/scx.pem  -subject -issuer -dates > "${path}"/SCOMLinuxDataCollectorData/certs/certdetails_short.txt
        else
            printf "\t\tscx public cert does not exists.....\n" >> "${path}"/scxdatacollector.log
        fi
    else
        printf "\t\tPath /etc/opt/microsoft/scx/ssl/ does not exists.....\n" >> "${path}"/scxdatacollector.log
    fi
}

collect_scx_directories_structure(){
    printf "\tCollecting SCX DirectoryStructure.....\n"
    printf "\tCollecting SCX DirectoryStructure.....\n" >> "${path}"/scxdatacollector.log
    $1 ls -lR /var/opt/microsoft/ >> "${path}"/SCOMLinuxDataCollectorData/scxdirectorystructure/var-opt-microsoft
    $1 ls -lR /var/opt/omi >> "${path}"/SCOMLinuxDataCollectorData/scxdirectorystructure/var-opt-omi
    $1 ls -lR /opt/omi/ >> "${path}"/SCOMLinuxDataCollectorData/scxdirectorystructure/opt-omi
    $1 ls -lR /etc/opt/microsoft/ >> "${path}"/SCOMLinuxDataCollectorData/scxdirectorystructure/etc-opt-microsoft
    $1 ls -lR /etc/opt/omi >> "${path}"/SCOMLinuxDataCollectorData/scxdirectorystructure/etc-opt-omi
}

collect_omi_pam(){
    printf "\tCollecting omi PAM details.....\n"
    printf "\tCollecting omi PAM details.....\n" >> "${path}"/scxdatacollector.log
    if [ -f /etc/opt/omi/conf/pam.conf ]; then
        # PAM configuration file found; use that
        cp -f /etc/opt/omi/conf/pam.conf "${path}"/SCOMLinuxDataCollectorData/pam/pam.conf
    elif [ -f /etc/pam.d/omi ]; then
        cp -f /etc/pam.d/omi "${path}"/SCOMLinuxDataCollectorData/pam/omi
    fi
}

collect_scx_provider_status(){
   printf "\tCollecting SCX Provider Details.....\n"
   printf "\tCollecting SCX Provider Detail.....\n" >> "${path}"/scxdatacollector.log
   if [ -d "/etc/opt/omi/conf/omiregister" ]; then
      printf "\t\tomiregister directory found. Collecting more details.....\n" >> "${path}"/scxdatacollector.log
      cp /etc/opt/omi/conf/omiregister/root-scx/* "${path}"/SCOMLinuxDataCollectorData/scxprovider
   else
      printf "\t\tomiregister directory not found......\n" >> "${path}"/scxdatacollector.log
   fi

   printf "\t\tQuery the omi cli and dumping details for one class from each identity (root, req, omi).....\n" >> "${path}"/scxdatacollector.log
   #We can think of dumping all the classes information if required.
   #However, we need to keep in mind if the provider is hung then we have to kill the query after sometime. That logic has to be built later.
   /opt/omi/bin/omicli ei root/scx SCX_UnixProcess >> "${path}"/SCOMLinuxDataCollectorData/scxprovider/scxproviderstatus
   /opt/omi/bin/omicli ei root/scx SCX_Agent >> "${path}"/SCOMLinuxDataCollectorData/scxprovider/scxproviderstatus
   /opt/omi/bin/omicli ei root/scx SCX_OperatingSystem >> "${path}"/SCOMLinuxDataCollectorData/scxprovider/scxproviderstatus
}

check_omi_core_files(){
   printf "\tCheck for core files in SCX directory /var/opt/omi/run/.....\n"
   printf "\tCheck for core files in SCX directory /var/opt/omi/run/......\n" >> "${path}"/scxdatacollector.log

   corefilescount=$(ls -1 /var/opt/omi/run/core* 2>/dev/null | wc -l)
    if [ "${corefilescount}" != 0 ]; then
      printf "\t\tFound core files in path /var/opt/omi/run/. Copying the core files.. \n" >> "${path}"/scxdatacollector.log
      cp -f /var/opt/omi/run/core* "${path}"/SCOMLinuxDataCollectorData/logs
    else
      printf "\t\tNo core files found in path /var/opt/omi/run/. No action needed....\n" >> "${path}"/scxdatacollector.log
    fi
}

check_scx_omi_log_rotation(){
    printf "\tChecking the log rotation configuration for omi and scx.....\n"
    printf "\tChecking the log rotation configuration for omi and scx......\n" >> "${path}"/scxdatacollector.log
    if [ -f "/etc/opt/omi/conf/omilogrotate.conf" ]; then
        printf "\tFound omilogrotate.conf in path /etc/opt/omi/conf. Copying the file.. \n" >> "${path}"/scxdatacollector.log
        cp -f /etc/opt/omi/conf/omilogrotate.conf  "${path}"/SCOMLinuxDataCollectorData/configfiles/omilogrotate.conf_copy
    else
        printf "\tNot found omilogrotate.conf in path /etc/opt/omi/conf...... \n" >> "${path}"/scxdatacollector.log
    fi
    if [ -f "/etc/opt/microsoft/scx/conf/logrotate.conf" ]; then
        printf "\tFound logrotate.conf in path /etc/opt/microsoft/scx/conf. Copying the file.. \n" >> "${path}"/scxdatacollector.log
        cp -f /etc/opt/microsoft/scx/conf/logrotate.conf  "${path}"/SCOMLinuxDataCollectorData/configfiles/scxlogrotate.conf_copy
    else
        printf "\tNot found omilogrotate.conf in path /etc/opt/microsoft/scx/conf. Copying the file.. \n" >> "${path}"/scxdatacollector.log
    fi 
}

test_tls_with_omi(){
    printf "\tTesting TLS 1.0, 1.1 and 1.2 on port 1270 locally. Might take sometime. Hang On.........\n"
    printf "\tTesting TLS 1.0, 1.1 and 1.2 on port 1270 locally. Might take sometime. Hang On..........\n" >> "${path}"/scxdatacollector.log
    openssl s_client -connect localhost:1270 -tls1 < /dev/null > "${path}"/SCOMLinuxDataCollectorData/tlscheck/tls1 2> /dev/null
    openssl s_client -connect localhost:1270 -tls1_1 < /dev/null > "${path}"/SCOMLinuxDataCollectorData/tlscheck/tls1.1 2> /dev/null
    openssl s_client -connect localhost:1270 -tls1_2 < /dev/null > "${path}"/SCOMLinuxDataCollectorData/tlscheck/tls1.2 2> /dev/null
}

archive_logs () {
   printf "\nSuccessfully completed the SCOM Linux Data Collector.....\n" >> "${path}"/scxdatacollector.log
   if [ -f "${path}/SCOMLinuxDataCollectorData.tar.gz" ]; then
      printf "\nFile SCOMLinuxDataCollectorData.tar.gz already exist. Cleaning up before new archive.....\n"
      printf "\nFile SCOMLinuxDataCollectorData.tar.gz already exist. Cleaning up before new archive.....\n"  >> "${path}"/scxdatacollector.log
      rm -rf "${path}"/SCOMLinuxDataCollectorData.tar.gz

   fi
   printf "Moving the scxdatacollector.log file to SCOMLinuxDataCollectorData.\n"
   printf "Moving the scxdatacollector.log file to SCOMLinuxDataCollectorData. Archiving and zipping SCOMLinuxDataCollectorData. Clean up other data....\n" >> "${path}"/scxdatacollector.log
   echo -e "\n $(date) Successfully completed the SCOM Linux Data Collector steps. Few steps remaining....\n" >> "${path}"/scxdatacollector.log
   mv "${path}"/scxdatacollector.log "${path}"/SCOMLinuxDataCollectorData
   printf "Archiving and zipping SCOMLinuxDataCollectorData.\n"
   tar -cf "${path}"/SCOMLinuxDataCollectorData.tar "${path}"/SCOMLinuxDataCollectorData

   gzip "${path}"/SCOMLinuxDataCollectorData.tar
   printf "Clean up other data....\n"
   rm -rf "${path}"/SCOMLinuxDataCollectorData.tar
   rm -rf "${path}"/SCOMLinuxDataCollectorData
}

#this function fetches the maximum information
sub_main_root(){
    check_dir "$path"
    collect_os_details
	if [ ! -n "$maint" ] || [ ! -n "$mon" ]; then
		check_sudo_permission "$maint" "$mon"
	else
		check_sudo_permission "$(whoami)"
	fi
    detect_installer
    #This has to be the last function call in the script
    archive_logs
}

#this function fetches the less information
sub_main_non_root(){
    check_dir "$path"
    collect_os_details
	if [ ! -n "$maint" ] || [ ! -n "$mon" ]; then
		check_sudo_permission "$maint" "$mon"
	else
		check_sudo_permission "$(whoami)"
	fi
    detect_installer sudo
    #This has to be the last function call in the script
    archive_logs
}

main(){
    printf "+++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++\n"
    #clearing the scxdatacollector.log file to start with
    #using sudo out-of-box even if the user is root to avoid permission denied on the intial log file creation.
    sudo printf "" > "${path}"/scxdatacollector.log    

    if [ ! -n "${path}"  ]; then
        printf "Log Collection Path is NULL. Setting Path to current working directory......\n"
        printf "Log Collection Path is NULL. Setting Path to current working directory......\n" >> "${path}"/scxdatacollector.log
        path=$(pwd)
    fi

    #Currently supporting SCX 2016+ versions
    printf "Starting the SCOM Linux Data Collector.....\nDisclaimer: Currently supporting SCX 2016+ versions\n"
    printf "$(date)Starting the SCOM Linux Data Collector.....\n" > "${path}"/scxdatacollector.log
    printf "The arguments passed are: \n Path = ${path} \n Maint = ${maint} \n Mon = ${mon} \n"
    printf "The arguments passed are: \n Path = ${path} \n Maint = ${maint} \n Mon = ${mon} \n" >> "${path}"/scxdatacollector.log

    #checking the distro. Will only continue in supported distro
    check_distro

    #fetching the user under which the script is running.
    user="$(whoami)"
    printf "Script is running under user: ${user}.....\n"
    printf "Script is running under user: ${user}.....\n" >> "${path}"/scxdatacollector.log
    if [ "$user"=='root' ]; then
         printf "\tUser is root. Collecting maximum information.....\n"
         sub_main_root "$path" "$maint" "$mon"
    else
         printf "\tUser is non root. Collecting information based on the level of privilege.....\n"
         sub_main_non_root "$path" "$maint" "$mon"
    fi
}

############################################################
# Script execution starts from here.                       #
############################################################


############################################################
# Process the input options. Add options as needed.        #
############################################################
# Get the options
while getopts "ho:m:n:" option; do
   case $option in
      h) # display Help
         help
         exit;;
      o) # Enter log collection path
         path=$OPTARG
         ;;
      m) # Enter log collection path
         maint=$OPTARG
         ;;
      n) # Enter log collection path
         mon=$OPTARG
         ;;
     \?) # Invalid option
         printf "Error: Invalid option - Run help (-h) for full parameters"
         exit;;
   esac
done

#function calls
        main "$path" "$maint" "$mon"

printf "\nSuccessfully completed the SCOM Linux Data Collector.....\n"
printf "+++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++\n"
'@
	function Out-FileUtf8
	{
	<#
.SYNOPSIS
    A replacement for Out-File using UTF-8 encoding without a BOM.
.DESCRIPTION
    Allows to write text content via pipe or via parameter to a text file.
    The text file is UTF-8 encoded but no BOM is written at the beginning of the file.
    Line breaks are normalized, by default to [Environment]::NewLine (CRLF) on windows.
    But the new line separator can be specified with the -NewLine parameter.
    The resulting file always ends with a line break.
    Content piped into the command is streamed into the file one line at a time.
    With a sensible maximum line length, text files of arbitrary size can be written.
.NOTES
    A lot of tools from the UNIX world do not support the BOM
    of UTF-8 encoded text files. Therefore, files written
    with Out-File -Encoding UTF8 provoke errors when consumed by these tools.
    The Out-FileUtf8 command is a replacement for
    the standard Out-File and writes UTF-8 files without a BOM.
    WARNING: Cancelling this Cmdlet with Ctrl+C will leave the file handle
    to the target file open until the PowerShell process exits.
.EXAMPLE
    Get-Content file1.txt -Encoding UTF8 | Out-FileUtf8 file2.txt
    Reads an UTF-8 encoded text file (possibly without BOM)
    and writes its content to another UTF-8 encoded text file
    without BOM and with line breaks normalized to [Environment]::NewLine.
.EXAMPLE
    Get-Content original.txt -Encoding UTF8 | select -First 100 | Out-FileUtf8 head.txt
    Reads the first 100 lines of original.txt and writes them to head.txt.
.EXAMPLE
    Get-Content windows.txt | Out-FileUtf8 unix.txt -NewLine "`n"
    Converts a text file, encoded in UTF-8 with BOM and arbitrary line breaks
    to UTF-8 without BOM and UNIX line breaks (LF).
.PARAMETER FilePath
    A path to the target file.
    The file can exist or not, but the directory of the file must exist.
    If the file exists it is truncated, unless the -Append switch is activated.
.PARAMETER Append
    A switch to append the content to an existing file, instead of truncating it.
.PARAMETER NewLine
    A string to use as line separator.
    Line separators are always normalized.
    The default value is [System.Environment]::NewLine.
    For UNIX conform files, use "`n".
.PARAMETER Width
    A maximum with for written lines.
    If a line is longer then the specified width, the rest is truncated not wrapped.
.PARAMETER NoClobber
    Prevents the command from overriding an existing file.
    If -NoClobber is used together with -Append, the content is appended to the file.
.PARAMETER InputObject
    If the text content is not piped into the cmdlet,
    then it must be passed with this parameter.
#>
		
		[CmdletBinding()]
		param (
			[Parameter(Mandatory, Position = 0)]
			[string]$FilePath,
			[Parameter(ValueFromPipeline)]
			$InputObject,
			[switch]$Append,
			[string]$NewLine = [Environment]::NewLine,
			[int]$Width = 0,
			[switch]$NoClobber
		)
		
		begin
		{
			# If the given path is relative, use the current location
			# from the PowerShell-Context to make it absolute.
			if (![IO.Path]::IsPathRooted($FilePath))
			{
				$FilePath = [IO.Path]::Combine($PWD, $FilePath)
				Write-Verbose "Build absolute target path: $FilePath"
			}
			$Utf8WithoutBom = New-Object System.Text.UTF8Encoding $false
			if ($Append) { Write-Verbose "Appending to target file." }
			if (!$Append -and $NoClobber -and (Test-Path $FilePath))
			{
				Write-Error "The target file already exists."
				exit 1
			}
			if (!$Append -and !(Test-Path $FilePath)) { Write-Verbose "Truncating target file. " }
			$w = New-Object System.IO.StreamWriter @($FilePath, $Append, $Utf8WithoutBom)
			if (!$w) { exit 1 }
			Write-Verbose "Stream writer open."
			$n = 0
			$s = 0
			if ($Width) { Write-Verbose "Truncating all lines to the length of $Width." }
		}
		
		process
		{
			foreach ($line in $InputObject)
			{
				$n++
				# normalize line breaks
				$line = $line.Replace("`r`n", "`n").Replace("`r", "`n")
				# convert line breaks
				if ($Width)
				{
					[string[]]$lines = $line.Split("`n") | % { $_.Substring(0, $Width) }
					# count line breaks inside of the string
					$n += $lines.Length - 1
					$line = [string]::Join($NewLine, $lines)
				}
				else
				{
					# count line breaks inside of the string
					$n += $line.Length - $line.Replace("`n", "").Length
					$line = $line.Replace("`n", $NewLine)
				}
				$w.Write($line)
				$w.Write($NewLine)
				$s += $line.Length + $NewLine.Length
			}
		}
		
		end
		{
			Write-Verbose "$s chars written."
			Write-Verbose "$n lines written."
			$w.Close()
			Write-Verbose "Stream writer closed."
		}
	}
	
	try
	{
		$ScomLinuxDataCollectorScript | Out-FileUtf8 -FilePath "$ScriptPath\SCOMLinuxDataCollector.sh" -ErrorAction Stop
	}
	catch
	{
		Write-Host "  Unable to create / write to the following path: '$ScriptPath\SCOMLinuxDataCollector.sh'"
		"$(Time-Stamp)Unable to create / write to the following path: '$ScriptPath\SCOMLinuxDataCollector.sh' :: Caught Exception: $e :: Message: $msg :: at line: $line" | Out-File $OutputPath\Error.log -Append
	}
	foreach ($LinuxServer in $Servers)
	{
        # TAKE INTO CONSIDERATION - DIFFERENT SSH PORT 
		Write-Host "  Copying script to remote Unix/Linux server: $LinuxServer"

        scp -o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null "$ScriptPath\SCOMLinuxDataCollector.sh" $Username`@$LinuxServer`:/tmp
        Write-Host "  Attempting to run script to remote server: $LinuxServer"
        ssh $Username`@$LinuxServer 'chmod +x SCOMLinuxDataCollector.sh; ./tmp/SCOMLinuxDataCollector.sh'
	}
	
}

		Start-LinuxDataCollector -Servers $SCXAgents -Username $SCXUsername -Password $SCXPassword
	}
	#endregion Linux Agent Gather Script
	#region Least Amount
	if (!$LeastAmount)
	{
		Write-Progress -Activity "Collection Running" -Status "Progress-> 6%" -PercentComplete 6
		try
		{
			if ($GetRunAsAccounts)
			{
				Write-Output " "
				Write-Host "================================`nGathering RunAs Accounts"
				function Get-SCOMRunasAccount
{
	param ($ManagementServer)
	#=======================================================
	# Get all SCOM RunAs Accounts and their Profiles Script
	# v 1.1
	#=======================================================
	
	# Constants section - make changes here
	#=======================================================
	$OutPathTXT = "$OutputPath\RunAsAccountInfo.txt"
	$OutPathCSV = "$OutputPath\RunAsAccountInfo.csv"
	#=======================================================
	
	#Set Empty Profile Associated Text
	$strAccountNotAssignedToProfile = "No Profile Associated"
	
	#Set Variable to empty
	$AccountDataArray = @()
	
	# Load Modules and Connect to SCOM
	Import-Module "OperationsManager"
	$MGConnection = New-SCOMManagementGroupConnection -ComputerName $ManagementServer
	$MGModule = Get-SCOMManagementGroup
	
	# Load Assembly and define ManagementGroup Object
	$CoreDLL = "Microsoft.EnterpriseManagement.Core"
	[reflection.assembly]::LoadWithPartialName($CoreDLL) | out-null
	$MG = New-Object Microsoft.EnterpriseManagement.EnterpriseManagementGroup($ManagementServer)
	
	
	#Process HealthService based Action Accounts Section
	#=======================================================
	FOREACH ($RunAsProfile in (Get-SCOMRunAsProfile))
	{
		IF ($RunAsProfile.DisplayName -eq $null)
		{
			$ProfileName = $RunAsProfile.Name
		}
		ELSE
		{
			$ProfileName = $RunAsProfile.DisplayName
		}
		# get Health Service array associated with the profile
		$HSRef = $MGModule.GetMonitoringSecureDataHealthServiceReferenceBySecureReferenceId($RunAsProfile.ID)
		FOREACH ($HS in $HSRef)
		{
			$TargetName = (Get-SCOMClassInstance -Id $HS.HealthServiceId).Displayname
			$MonitoringData = $HS.GetMonitoringSecureData()
			$tempAccount = New-Object pscustomobject
			$tempAccount | Add-Member -MemberType NoteProperty -Name RunAsAccountName -Value $MonitoringData.name
			$tempAccount | Add-Member -MemberType NoteProperty -Name Domain -Value $MonitoringData.domain
			$tempAccount | Add-Member -MemberType NoteProperty -Name Username -Value $MonitoringData.username
			$tempAccount | Add-Member -MemberType NoteProperty -Name AccountType -Value $MonitoringData.SecureDataType
			$tempAccount | Add-Member -MemberType NoteProperty -Name ProfileName -Value $ProfileName
			$tempAccount | Add-Member -MemberType NoteProperty -Name TargetID -Value $HS.HealthServiceId.Guid.ToString()
			$tempAccount | Add-Member -MemberType NoteProperty -Name TargetName -Value $TargetName
			$AccountDataArray += $tempAccount
		}
	}
	#=======================================================
	# End Process HealthService based Action Accounts Section
	
	
	
	#Process all RunAsAccounts targeted at other targets
	#=======================================================
	#Get all RunAsAccounts 
	$colAccounts = $mg.Security.GetSecureData() | sort-object Name
	
	#Loop through each RunAs account
	FOREACH ($account in $colAccounts)
	{
		#All credits for the next 20 lines goes to Mihai
		$secStorId = $account.SecureStorageId
		$stringBuilder = New-Object System.Text.StringBuilder
		FOREACH ($byte in $secStorId)
		{
			$stringBuilder.Append($byte.ToString("X2")) | Out-Null
		}
		$MPCriteria = "Value='{0}'" -f $stringBuilder.ToString()
		$moc = New-Object Microsoft.EnterpriseManagement.Configuration.ManagementPackOverrideCriteria($MPCriteria)
		$overrides = $mg.Overrides.GetOverrides($moc)
		
		IF ($overrides.Count -eq 0)
		{
			$ProfileName = "No Profile Assigned"
			$tempAccount = New-Object pscustomobject
			$tempAccount | Add-Member -MemberType NoteProperty -Name RunAsAccountId -Value $account.id
			$tempAccount | Add-Member -MemberType NoteProperty -Name RunAsAccountName -Value $account.name
			$tempAccount | Add-Member -MemberType NoteProperty -Name Domain -Value $account.domain
			$tempAccount | Add-Member -MemberType NoteProperty -Name Username -Value $account.username
			$tempAccount | Add-Member -MemberType NoteProperty -Name AccountType -Value $account.SecureDataType
			$tempAccount | Add-Member -MemberType NoteProperty -Name ProfileName -Value $ProfileName
			$tempAccount | Add-Member -MemberType NoteProperty -Name TargetID -Value "NULL"
			$tempAccount | Add-Member -MemberType NoteProperty -Name TargetName -Value "NULL"
			$AccountDataArray += $tempAccount
		}
		ELSE
		{
			FOREACH ($override in $overrides)
			{
				IF ($override.ContextInstance -eq $null)
				{
					$TargetID = $override.Context.id.Guid.ToString()
					$TargetClass = Get-SCOMClass -Id $TargetID
					IF ($TargetClass.DisplayName -eq $null)
					{
						$TargetName = $TargetClass.Name
					}
					ELSE
					{
						$TargetName = $TargetClass.DisplayName
					}
				}
				ELSE
				{
					$TargetID = $override.ContextInstance.Guid.ToString()
					$TargetClassInstance = Get-SCOMClassinstance -Id $TargetID
					IF ($TargetClassInstance.DisplayName -eq $null)
					{
						$TargetName = $TargetClassInstance.Name
					}
					ELSE
					{
						$TargetName = $TargetClassInstance.DisplayName
					}
				}
				$secRef = $mg.Security.GetSecureReference($override.SecureReference.Id)
				IF ($secRef.DisplayName -eq $null)
				{
					$ProfileName = $secRef.Name
				}
				ELSE
				{
					$ProfileName = $secRef.DisplayName
				}
				
				$tempAccount = New-Object pscustomobject
				$tempAccount | Add-Member -MemberType NoteProperty -Name RunAsAccountId -Value $account.id
				$tempAccount | Add-Member -MemberType NoteProperty -Name RunAsAccountName -Value $account.name
				$tempAccount | Add-Member -MemberType NoteProperty -Name Domain -Value $account.domain
				$tempAccount | Add-Member -MemberType NoteProperty -Name Username -Value $account.username
				$tempAccount | Add-Member -MemberType NoteProperty -Name AccountType -Value $account.SecureDataType
				$tempAccount | Add-Member -MemberType NoteProperty -Name ProfileName -Value $ProfileName
				$tempAccount | Add-Member -MemberType NoteProperty -Name TargetID -Value $TargetID
				$tempAccount | Add-Member -MemberType NoteProperty -Name TargetName -Value $TargetName
				$AccountDataArray += $tempAccount
			}
		} #This ends the for each override loop
	}
	#=======================================================
	# End Process all RunAsAccounts targeted at other targets
	
	# Sort by RunAsAccountName
	$AccountData = $AccountDataArray | Sort-Object RunAsAccountName
	
	# Output to the console for testing
	# $AccountDataArray | FT
	
	# Output to CSV
	$AccountData | ft * -AutoSize | Out-String -Width 4096 | Out-File $OutPathTXT
	$AccountData | Sort-Object RunAsAccountName | Export-CSV $OutPathCSV -NoTypeInformation
}

				Write-Host "  Gathering from: " -NoNewline -ForegroundColor Gray
				Write-Host $ManagementServers[0] -NoNewline -ForegroundColor Cyan
				Write-Progress -Activity "Collection Running" -Status "Progress-> 7%" -PercentComplete 7
				Get-SCOMRunasAccount -ManagementServer $ManagementServers[0]
				Write-Output " "
			}
		}
		catch
		{
			"$(Time-Stamp)Unable to gather RunAs Accounts due to Error: $($error[0])" | Out-File $OutputPath\Error.log -Append
			Write-Warning $error[0]
		}
		Write-Progress -Activity "Collection Running" -Status "Progress-> 8%" -PercentComplete 8
		try
		{
			if ($CheckCertificates)
			{
				Write-Output " "
				Write-Output "================================`nStarting Certificate Checker"
				function Certificate-Check
{
<#
	.SYNOPSIS
		System Center Operations Manager - Certificate Checker
	
	.DESCRIPTION
		The steps for configuring certificates in System Center Operations Manager are numerous and one can easily get them confused.
		I see posts to the newsgroups and discussion lists regularly trying to troubleshoot why certificate authentication is not working, perhaps for a workgroup machine or gateway.
		Sometimes it takes 3 or 4 messages back and forth before I or anyone else can diagnose what the problem actually is but once this is finally done we can suggest how to fix the problem.
		
		In an attempt to make this diagnosis stage easier I put together a PowerShell script that automatically checks installed certificates for the needed properties and configuration.
		If you think everything is set up correctly but the machines just won't communicate, try running this script on each computer and it will hopefully point you to the issue.
		I have tried to provide useful knowledge for fixing the problems.
		
		This script was originally designed for stand-alone PowerShell 1.0 - it does not require the OpsMgr PowerShell snapins.
		Technet Article: https://gallery.technet.microsoft.com/scriptcenter/Troubleshooting-OpsMgr-27be19d3
	
	.PARAMETER All
		Check All Certificates in Local Machine Store.
	
	.PARAMETER OutputFile
		Where to Output the File (txt, log, etc) for Script Execution.
	
	.PARAMETER SerialNumber
		Check a specific Certificate serial number in the Local Machine Personal Store. Not reversed.
	
	.PARAMETER Servers
		Each Server you want to Check SCOM Certificates on.
	
	.EXAMPLE
		Check All Certificates on 4 Servers and outputting the results to C:\Temp\Output.txt:
		PS C:\> .\Check-SCOMCertificates.ps1 -Servers ManagementServer1, ManagementServer2.contoso.com, Gateway.contoso.com, Agent1.contoso.com -All -OutputFile C:\Temp\Output.txt
	
	.EXAMPLE
		Check for a specific Certificate serialnumber in the Local Machine Personal Certificate store:
		PS C:\> .\Check-SCOMCertificates.ps1 -SerialNumber 1f00000008c694dac94bcfdc4a000000000008
	
	.EXAMPLE
		Check all certificates on the local machine:
		PS C:\> .\Check-SCOMCertificates.ps1 -All
	
	.NOTES
		Update 09/2022 (Blake Drumm, https://github.com/blakedrumm/ )
		Fixed bug introduced in last update. Certificates are checked correctly now.
	
		Update 09/2022 (Blake Drumm, https://github.com/blakedrumm/ )
		Added ability to gather issuer. Fixed bug in output.

		Update 03/2022 (Blake Drumm, https://github.com/blakedrumm/ )
		Major Update / alot of changes to how this script acts remotely and locally and added remoting abilites that are much superior to previous versions
		
		Update 02/2022 (Blake Drumm, https://github.com/blakedrumm/ )
		Fix some minor bugs and do some restructuring
		
		Update 01/2022 (Blake Drumm, https://github.com/blakedrumm/ )
		The script will now allow an -SerialNumber parameter so you can only gather the certificate you are expecting.
		
		Update 06/2021 (Blake Drumm, https://github.com/v-bldrum/ )
		The Script will now by default only check every Certificate only if you have the -All Switch. Otherwise it will just check the certificate Serial Number (Reversed) that is present in the Registry.
		
		Update 11/2020 (Blake Drumm, https://github.com/v-bldrum/ )
		Shows Subject Name instead of Issuer for each Certificate Checked.
		
		Update 08/2020 (Blake Drumm, https://github.com/v-bldrum/ )
		Fixed formatting in output.
		
		Update 06/2020 (Blake Drumm, https://github.com/v-bldrum/ )
		Added ability to OutputFile script to file.
		
		Update 2017.11.17 (Tyson Paul, https://blogs.msdn.microsoft.com/tysonpaul/ )
		Fixed certificate SerialNumber parsing error.
		
		Update 7/2009
		Fix for workgroup machine subjectname validation
		
		Update 2/2009
		Fixes for subjectname validation
		Typos
		Modification for CA chain validation
		Adds needed check for MachineKeyStore property on the private key
		
		Original Publish Date 1/2009
		(Lincoln Atkinson?, https://blogs.technet.microsoft.com/momteam/author/latkin/ )
#>
	[CmdletBinding()]
	[OutputType([string])]
	param
	(
		[Parameter(Mandatory = $false,
				   Position = 1,
				   HelpMessage = 'Check All Certificates in Local Machine Store.')]
		[Switch]$All,
		[Parameter(Mandatory = $false,
				   Position = 2,
				   HelpMessage = 'Where to Output the Text Log for Script.')]
		[String]$OutputFile,
		[Parameter(Mandatory = $false,
				   Position = 3,
				   HelpMessage = 'Check a specific Certificate serial number in the Local Machine Personal Store. Not reversed.')]
		[ValidateScript({ (Get-ChildItem cert:\LocalMachine\my\).SerialNumber })]
		[string]$SerialNumber,
		[Parameter(Mandatory = $false,
				   Position = 4,
				   HelpMessage = 'Each Server you want to Check SCOM Certificates on.')]
		[Array]$Servers
	)
	begin
	{
		#region CheckPermission
		$checkingpermission = "Checking for elevated permissions..."
		$MainScriptOutput = @()
		Write-Host $checkingpermission -ForegroundColor Gray
		$MainScriptOutput += $checkingpermission
		if (-NOT ([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole(`
[Security.Principal.WindowsBuiltInRole] "Administrator"))
		{
			$nopermission = "Insufficient permissions to run this script. Open the PowerShell console as an administrator and run this script again."
			$MainScriptOutput += $nopermission
			Write-Warning $nopermission
			Start-Sleep 5
			break
		}
		else
		{
			$permissiongranted = " Currently running as administrator - proceeding with script execution..."
			$MainScriptOutput += $permissiongranted
			Write-Host $permissiongranted -ForegroundColor Green
		}
		#endregion CheckPermission
		Function Time-Stamp
		{
			
			$TimeStamp = Get-Date -Format "MM/dd/yyyy hh:mm:ss tt"
			return $TimeStamp
		}
		function Inner-SCOMCertCheck
		{
			[OutputType([string])]
			param
			(
				[Parameter(Mandatory = $false,
						   Position = 1,
						   HelpMessage = 'Check All Certificates in Local Machine Store.')]
				[Switch]$All,
				[Parameter(Mandatory = $false,
						   Position = 2,
						   HelpMessage = 'Where to Output the Text Log for Script.')]
				[String]$OutputFile,
				[Parameter(Mandatory = $false,
						   Position = 3,
						   HelpMessage = 'Check a specific Certificate serial number in the Local Machine Personal Store. Not reversed.')]
				[string]$SerialNumber,
				[Parameter(Mandatory = $false,
						   Position = 4,
						   HelpMessage = 'Each Server you want to Check SCOM Certificates on.')]
				[Array]$Servers
			)
			
			Function Time-Stamp
			{
				
				$TimeStamp = Get-Date -Format "MM/dd/yyyy hh:mm:ss tt"
				return $TimeStamp
			}
			$out = @()
			$out += "`n" + @"
$(Time-Stamp) : Starting Script

"@
			# Consider all certificates in the Local Machine "Personal" store
			$certs = [Array] (Get-ChildItem cert:\LocalMachine\my\)
			$text1 = "Running against server: $env:COMPUTERNAME"
			$out += "`n" + $text1
			Write-Host $text1 -ForegroundColor Cyan
			if ($certs -eq $null)
			{
				$text2 = @"
    There are no certificates in the Local Machine `"Personal`" store.
    This is where the client authentication certificate should be imported.
    Check if certificates were mistakenly imported to the Current User
    `"Personal`" store or the `"Operations Manager`" store.
"@
				Write-Host $text2 -ForegroundColor Red
				$out += "`n" + $text2
				break
			}
			$x = 0
			$a = 0
			$alreadyCheckedThis = $false
			if ($All)
			{
				$FoundCount = "Found: $($certs.Count) certificates"
				$out += "`n" + $FoundCount
				Write-Host $FoundCount
				$text3 = "Verifying each certificate."
				$out += "`n" + $text3
				Write-Host $text3
			}
			foreach ($cert in $certs)
			{
				$x++
				$x = $x
				#If the serialnumber argument is present
				if ($SerialNumber)
				{
					if ($SerialNumber -ne $cert.SerialNumber)
					{
						$a++
						$a = $a
						$NotPresentCount = $a
						continue
					}
					$All = $true
				}
				if (!$All)
				{
					$certSerial = $cert.SerialNumber
					$certSerialReversed = [System.String]("")
					-1 .. -19 | ForEach-Object { $certSerialReversed += $certSerial[2 * $_] + $certSerial[2 * $_ + 1] }
					if (! (Test-Path "HKLM:\SOFTWARE\Microsoft\Microsoft Operations Manager\3.0\Machine Settings"))
					{
						$text36 = "Serial Number is not written to registry"
						$out += "`n" + $text36
						Write-Host $text36 -BackgroundColor Red -ForegroundColor Black
						$text37 = @"
    The certificate serial number is not written to registry.
    Need to run MomCertImport.exe
"@
						$out += "`n" + $text37
						Write-Host $text37
						$pass = $false
						break
					}
					else
					{
						$regKeys = get-itemproperty -path "HKLM:\SOFTWARE\Microsoft\Microsoft Operations Manager\3.0\Machine Settings"
						if ($regKeys.ChannelCertificateSerialNumber -eq $null)
						{
							$text36 = "Serial Number is not written to registry"
							$out += "`n" + $text36
							Write-Host $text36 -BackgroundColor Red -ForegroundColor Black
							$text37 = @"
    The certificate serial number is not written to registry.
    Need to run MomCertImport.exe
"@
							$out += "`n" + $text37
							Write-Host $text37
							$pass = $false
							break
						}
						else
						{
							$regSerial = ""
							$regKeys.ChannelCertificateSerialNumber | ForEach-Object { $regSerial += $_.ToString("X2") }
							if ($regSerial -eq "" -or $null) { $regSerial = "`{Empty`}" }
							if ($regSerial -ne $($certSerialReversed -Join (" ")))
							{
								continue
							}
						}
					}
				}
				$certificateReversed = -1 .. - $($cert.SerialNumber.Length) | ForEach-Object { $cert.SerialNumber[2 * $_] + $cert.SerialNumber[2 * $_ + 1] }
				$text4 = @"
=====================================================================================================================
$(if (!$SerialNumber -and $All) { "($x`/$($certs.Count)) " })Examining Certificate

`tSubject: "$($cert.Subject)" $(if ($cert.FriendlyName) { "`n`n`tFriendly name: $($cert.FriendlyName)" })

`tIssued by: $(($cert.Issuer -split ',' | Where-Object { $_ -match "CN=|DC=" }).Replace("CN=", '').Replace("DC=", '').Trim() -join '.')

`tSerial Number: "$($cert.SerialNumber)"

`tSerial Number Reversed: $($certificateReversed)
=====================================================================================================================
"@
				Write-Host $text4
				$out += "`n" + "`n" + $text4
				
				$pass = $true
				
				# Check subjectname
				
				$pass = &{
					$fqdn = $env:ComputerName
					$fqdn += "." + [DirectoryServices.ActiveDirectory.Domain]::GetComputerDomain().Name
					trap [DirectoryServices.ActiveDirectory.ActiveDirectoryObjectNotFoundException]
					{
						# Not part of a domain
						continue;
					}
					$fqdnRegexPattern = "CN=" + $fqdn.Replace(".", "\.") + '(,.*)?$'
					if (!($cert.SubjectName.Name -match $fqdnRegexPattern))
					{
						$text5 = "Certificate Subjectname Mismatch"
						$out += "`n" + $text5
						Write-Host $text5 -BackgroundColor Red -ForegroundColor Black
						
						$text6 = @"
    The Subjectname of this certificate does not match the FQDN of this machine.
		Actual: $($cert.SubjectName.Name)
		Expected (case insensitive): CN=$fqdn
"@
						$out += "`n" + $text6
						Write-Host $text6
						$false
					}
					else { $true; $text7 = "Certificate Subjectname is Good"; $out += "`n" + $text7; Write-Host $text7 -BackgroundColor Green -ForegroundColor Black }
				}
				
				# Verify private key
				
				if (!($cert.HasPrivateKey))
				{
					$text8 = "Private Key Missing"
					$out += "`n" + $text8
					Write-Host $text8 -BackgroundColor Red -ForegroundColor Black
					$text9 = @"
    This certificate does not have a private key.
    Verify that proper steps were taken when installing this cert.
"@
					$out += "`n" + $text9
					Write-Host $text9
					$pass = $false
				}
				elseif (!($cert.PrivateKey.CspKeyContainerInfo.MachineKeyStore))
				{
					$text10 = "Private Key not issued to Machine Account"
					$out += "`n" + $text10
					Write-Host $text10 -BackgroundColor Red -ForegroundColor Black
					$text11 = @"
    This certificate's private key is not issued to a machine account.
		One possible cause of this is that the certificate
		was issued to a user account rather than the machine,
		then copy/pasted from the Current User store to the Local
		Machine store.  A full export/import is required to switch
		between these stores.
"@
					$out += "`n" + $text11
					Write-Host $text11
					$pass = $false
				}
				else { $text12 = "Private Key is Good"; $out += "`n" + $text12; Write-Host $text12 -BackgroundColor Green -ForegroundColor Black }
				
				# Check expiration dates
				
				if (($cert.NotBefore -gt [DateTime]::Now) -or ($cert.NotAfter -lt [DateTime]::Now))
				{
					$text13 = "Expiration Out-of-Date"
					$out += "`n" + $text13
					Write-Host $text13 -BackgroundColor Red -ForegroundColor Black
					$text14 = @"
    This certificate is not currently valid.
    It will be valid between $($cert.NotBefore) and $($cert.NotAfter)
"@
					$out += "`n" + $text14
					Write-Host $text14
					$pass = $false
				}
				else
				{
					$text15 = @"
Expiration
    Not Expired: (valid from $($cert.NotBefore) thru $($cert.NotAfter))
"@
					$out += "`n" + $text15
					Write-Host $text15 -BackgroundColor Green -ForegroundColor Black
				}
				
				
				# Enhanced key usage extension
				
				$enhancedKeyUsageExtension = $cert.Extensions | Where-Object { $_.ToString() -match "X509EnhancedKeyUsageExtension" }
				if ($enhancedKeyUsageExtension -eq $null)
				{
					$text16 = "Enhanced Key Usage Extension Missing"
					$out += "`n" + $text16
					Write-Host $text16 -BackgroundColor Red -ForegroundColor Black
					$text17 = "    No enhanced key usage extension found."
					$out += "`n" + $text17
					Write-Host $text17
					$pass = $false
				}
				else
				{
					$usages = $enhancedKeyUsageExtension.EnhancedKeyUsages
					if ($usages -eq $null)
					{
						$text18 = "Enhanced Key Usage Extension Missing"
						$out += "`n" + $text18
						Write-Host $text18 -BackgroundColor Red -ForegroundColor Black
						$text19 = "    No enhanced key usages found."
						$out += "`n" + $text19
						Write-Host $text19
						$pass = $false
					}
					else
					{
						$srvAuth = $cliAuth = $false
						foreach ($usage in $usages)
						{
							if ($usage.Value -eq "1.3.6.1.5.5.7.3.1") { $srvAuth = $true }
							if ($usage.Value -eq "1.3.6.1.5.5.7.3.2") { $cliAuth = $true }
						}
						if ((!$srvAuth) -or (!$cliAuth))
						{
							$text20 = "Enhanced Key Usage Extension Issue"
							$out += "`n" + $text20
							Write-Host $text20 -BackgroundColor Red -ForegroundColor Black
							$text21 = @"
    Enhanced key usage extension does not meet requirements.
    Required EKUs are 1.3.6.1.5.5.7.3.1 and 1.3.6.1.5.5.7.3.2
    EKUs found on this cert are:
"@
							$out += "`n" + $text21
							Write-Host $text21
							$usages | ForEach-Object{ $text22 = "      $($_.Value)"; $out += "`n" + $text22; Write-Host $text22 }
							$pass = $false
						}
						else
						{
							$text23 = @"
Enhanced Key Usage Extension is Good
"@;
							$out += "`n" + $text23; Write-Host $text23 -BackgroundColor Green -ForegroundColor Black
						}
					}
				}
				
				# KeyUsage extension
				
				$keyUsageExtension = $cert.Extensions | Where-Object { $_.ToString() -match "X509KeyUsageExtension" }
				if ($keyUsageExtension -eq $null)
				{
					$text24 = "Key Usage Extensions Missing"
					$out += "`n" + $text24
					Write-Host $text24 -BackgroundColor Red -ForegroundColor Black
					$text25 = @"
    No key usage extension found.
    A KeyUsage extension matching 0xA0 (Digital Signature, Key Encipherment)
    or better is required.
"@
					$out += "`n" + $text25
					Write-Host $text25
					$pass = $false
				}
				else
				{
					$usages = $keyUsageExtension.KeyUsages
					if ($usages -eq $null)
					{
						$text26 = "Key Usage Extensions Missing"
						$out += "`n" + $text26
						Write-Host $text26 -BackgroundColor Red -ForegroundColor Black
						$text27 = @"
    No key usages found.
    A KeyUsage extension matching 0xA0 (DigitalSignature, KeyEncipherment)
    or better is required.
"@
						$out += "`n" + $text27
						Write-Host $text27
						$pass = $false
					}
					else
					{
						if (($usages.value__ -band 0xA0) -ne 0xA0)
						{
							$text28 = "Key Usage Extensions Issue"
							$out += "`n" + $text28
							Write-Host $text28 -BackgroundColor Red -ForegroundColor Black
							$text29 = @"
    Key usage extension exists but does not meet requirements.
    A KeyUsage extension matching 0xA0 (Digital Signature, Key Encipherment)
    or better is required.
    KeyUsage found on this cert matches:
    $usages"
"@
							$out += "`n" + $text29
							Write-Host $text29
							$pass = $false
						}
						else { $text30 = "Key Usage Extensions are Good"; $out += "`n" + $text30; Write-Host $text30 -BackgroundColor Green -ForegroundColor Black }
					}
				}
				
				# KeySpec
				
				$keySpec = $cert.PrivateKey.CspKeyContainerInfo.KeyNumber
				if ($keySpec -eq $null)
				{
					$text31 = "KeySpec Missing / Not Found"
					$out += "`n" + $text31
					Write-Host $text31 -BackgroundColor Red -ForegroundColor Black
					$text32 = "    Keyspec not found.  A KeySpec of 1 is required"
					$out += "`n" + $text32
					Write-Host $text32
					$pass = $false
				}
				elseif ($keySpec.value__ -ne 1)
				{
					$text33 = "KeySpec Incorrect"
					$out += "`n" + $text33
					Write-Host $text33 -BackgroundColor Red -ForegroundColor Black
					$text34 = @"
    Keyspec exists but does not meet requirements.
    A KeySpec of 1 is required.
    KeySpec for this cert: $($keySpec.value__)
"@
					$out += "`n" + $text34
					Write-Host $text34
					$pass = $false
				}
				else { $text35 = "KeySpec is Good"; $out += "`n" + $text35; Write-Host $text35 -BackgroundColor Green -ForegroundColor Black }
				
				
				# Check that serial is written to proper reg
				
				$certSerial = $cert.SerialNumber
				$certSerialReversed = [System.String]("")
				-1 .. -19 | ForEach-Object { $certSerialReversed += $certSerial[2 * $_] + $certSerial[2 * $_ + 1] }
				
				if (! (Test-Path "HKLM:\SOFTWARE\Microsoft\Microsoft Operations Manager\3.0\Machine Settings"))
				{
					$text36 = "Serial Number is not written to the registry"
					$out += "`n" + $text36
					Write-Host $text36 -BackgroundColor Red -ForegroundColor Black
					$text37 = @"
    The certificate serial number is not written to registry.
    Need to run MomCertImport.exe
"@
					$out += "`n" + $text37
					Write-Host $text37
					$pass = $false
				}
				else
				{
					$regKeys = get-itemproperty -path "HKLM:\SOFTWARE\Microsoft\Microsoft Operations Manager\3.0\Machine Settings"
					if ($regKeys.ChannelCertificateSerialNumber -eq $null)
					{
						$text38 = "Serial Number is not written to the registry"
						$out += "`n" + $text38
						Write-Host $text38 -BackgroundColor Red -ForegroundColor Black
						$text39 = @"
    The certificate serial number is not written to registry.
    Need to run MomCertImport.exe
"@
						$out += "`n" + $text39
						Write-Host $text39
						$pass = $false
					}
					else
					{
						$regSerial = ""
						$regKeys.ChannelCertificateSerialNumber | ForEach-Object { $regSerial += $_.ToString("X2") }
						if ($regSerial -eq "" -or $null) { $regSerial = "`{Empty`}" }
						if ($regSerial -ne $certSerialReversed)
						{
							$text40 = "Serial Number (mismatch) written to the registry"
							$out += "`n" + $text40
							Write-Host $text40 -BackgroundColor Red -ForegroundColor Black
							$text41 = @"
    The serial number written to the registry does not match this certificate
    Expected registry entry: $certSerialReversed
    Actual registry entry:   $regSerial
"@
							$out += "`n" + $text41
							Write-Host $text41
							$pass = $false
						}
						else { $text42 = "Serial Number is written to the registry"; $out += "`n" + $text42; Write-Host $text42 -BackgroundColor Green -ForegroundColor Black }
					}
				}
				
<#
	Check that the cert's issuing CA is trusted (This is not technically required
				as it is the remote machine cert's CA that must be trusted.  Most users leverage
	the same CA for all machines, though, so it's worth checking
				#>
				$chain = new-object Security.Cryptography.X509Certificates.X509Chain
				$chain.ChainPolicy.RevocationMode = 0
				if ($chain.Build($cert) -eq $false)
				{
					$text43 = "Certification Chain Issue"
					$out += "`n" + $text43
					Write-Host $text43 -BackgroundColor Red -ForegroundColor Black
					$text44 = @"
    The following error occurred building a certification chain with this certificate:
    $($chain.ChainStatus[0].StatusInformation)
    This is an error if the certificates on the remote machines are issued
    from this same CA - $($cert.Issuer)
    Please ensure the certificates for the CAs which issued the certificates configured
    on the remote machines are installed to the Local Machine Trusted Root Authorities
    store on this machine. (certlm.msc)
"@
					$out += "`n" + $text44
					Write-Host $text44 -ForegroundColor Yellow
					$pass = $false
				}
				else
				{
					$rootCaCert = $chain.ChainElements | Select-Object -property Certificate -last 1
					$localMachineRootCert = Get-ChildItem cert:\LocalMachine\Root | Where-Object { $_ -eq $rootCaCert.Certificate }
					if ($localMachineRootCert -eq $null)
					{
						$text45 = "Certification Chain Root CA Missing"
						$out += "`n" + $text45
						Write-Host $text45 -BackgroundColor Red -ForegroundColor Black
						$text46 = @"
    This certificate has a valid certification chain installed, but
    a root CA certificate verifying the issuer $($cert.Issuer)
    was not found in the Local Machine Trusted Root Authorities store.
    Make sure the proper root CA certificate is installed there, and not in
    the Current User Trusted Root Authorities store. (certlm.msc)
"@
						$out += "`n" + $text46
						Write-Host $text46 -ForegroundColor Yellow
						$pass = $false
					}
					else
					{
						$text47 = "Certification Chain looks Good"
						$out += "`n" + $text47
						Write-Host $text47 -BackgroundColor Green -ForegroundColor Black
						$text48 = @"
    There is a valid certification chain installed for this cert,
    but the remote machines' certificates could potentially be issued from
    different CAs.  Make sure the proper CA certificates are installed
    for these CAs.
"@
						$out += "`n" + $text48
						Write-Host $text48
					}
					
				}
				
				
				if ($pass)
				{
					$text49 = "`n*** This certificate is properly configured and imported for System Center Operations Manager ***"; $out += "`n" + $text49; Write-Host $text49 -ForegroundColor Green
				}
				else
				{
					$text49 = "`n*** This certificate is NOT properly configured for System Center Operations Manager ***"; $out += "`n" + $text49; Write-Host $text49 -ForegroundColor White -BackgroundColor Red
				}
				$out += "`n" + " " # This is so there is white space between each Cert. Makes it less of a jumbled mess.
			}
			if ($certs.Count -eq $NotPresentCount)
			{
				$text49 = "Unable to locate any certificates on this server that match the criteria specified OR the serial number in the registry does not match any certificates present."; $out += "`n" + $text49; Write-Host $text49 -ForegroundColor Red
			}
			$out += "`n" + @"

$(Time-Stamp) : Script Completed
"@
			Write-Verbose "$out"
			return $out
		}
		$InnerCheckSCOMCertificateFunctionScript = "function Inner-SCOMCertCheck { ${function:Inner-SCOMCertCheck} }"
	}
	PROCESS
	{
		#region Function
		function Check-SCOMCertificate
		{
			[OutputType([string])]
			[CmdletBinding()]
			param
			(
				[Parameter(Mandatory = $false,
						   Position = 1,
						   HelpMessage = 'Check All Certificates in Local Machine Store.')]
				[Switch]$All,
				[Parameter(Mandatory = $false,
						   Position = 2,
						   HelpMessage = 'Where to Output the Text Log for Script.')]
				[String]$OutputFile,
				[Parameter(Mandatory = $false,
						   Position = 3,
						   HelpMessage = 'Check a specific Certificate serial number in the Local Machine Personal Store. Not reversed.')]
				[string]$SerialNumber,
				[Parameter(Mandatory = $false,
						   Position = 4,
						   HelpMessage = 'Each Server you want to Check SCOM Certificates on.')]
				[Array]$Servers
			)
			if ($null -eq $Servers) { $Servers = $env:COMPUTERNAME }
			else
			{
				$Servers = ($Servers.Split(",").Split(" ") -replace (" ", ""))
				$Servers = $Servers | Select-Object -Unique
			}
			foreach ($server in $Servers)
			{
				$startofline = @" 

========================================================
Certificate Checker

"@
				Write-Host '========================================================'
				Write-Host @"
Certificate Checker

"@
				$MainScriptOutput += $startofline
				if ($server -ne $env:COMPUTERNAME)
				{
					$MainScriptOutput += Invoke-Command -ComputerName $server -ArgumentList $InnerCheckSCOMCertificateFunctionScript, $All, $SerialNumber -ScriptBlock {
						Param ($script,
							$All,
							$SerialNumber,
							$VerbosePreference)
						. ([ScriptBlock]::Create($script))
						return Inner-SCOMCertCheck -All:$All -SerialNumber $SerialNumber
						
					} -ErrorAction SilentlyContinue
				}
				else
				{
					if ($VerbosePreference.value__ -ne 0)
					{
						$MainScriptOutput += Inner-SCOMCertCheck -Servers $Servers -All:$All -SerialNumber:$SerialNumber -Verbose -ErrorAction SilentlyContinue
					}
					else
					{
						$MainScriptOutput += Inner-SCOMCertCheck -Servers $Servers -All:$All -SerialNumber:$SerialNumber -ErrorAction SilentlyContinue
					}
					
				}
			}
			if ($OutputFile)
			{
				$MainScriptOutput | Out-File $OutputFile -Width 4096
				#Start-Process C:\Windows\explorer.exe -ArgumentList "/select, $OutputFile"
			}
			#return $out
			continue
		}
		#endregion Function
		#region DefaultActions
		if ($Servers -or $OutputFile -or $All -or $SerialNumber)
		{
			Check-SCOMCertificate -Servers $Servers -OutputFile $OutputFile -All:$All -SerialNumber:$SerialNumber
		}
		else
		{
			# Modify line 755 if you want to change the default behavior when running this script through Powershell ISE
			#
			# Examples: 
			# Check-SCOMCertificate -SerialNumber 1f00000008c694dac94bcfdc4a000000000008
			# Check-SCOMCertificate -All
			# Check-SCOMCertificate -All -OutputFile C:\Temp\Certs-Output.txt
			# Check-SCOMCertificate -Servers MS01, MS02
			Check-SCOMCertificate
		}
		#endregion DefaultActions
	}
}

				New-Item -ItemType Directory -Path "$OutputPath\Certificates" -Force -ErrorAction Stop | Out-Null
				Write-Progress -Activity "Collection Running" -Status "Progress-> 9%" -PercentComplete 9
				foreach ($CertChkSvr in $TestedTLSservers)
				{
					Certificate-Check -Servers $CertChkSvr -Output $OutputPath\Certificates\$CertChkSvr.CertificateInfo.txt
				}
			}
		}
		catch
		{
			"$(Time-Stamp)Unable to gather SCOM Certificates due to Error: $($error[0])" | Out-File $OutputPath\Error.log -Append
			Write-Warning $error[0]
		}
		try
		{
			if ($GetInstalledSoftware)
			{
				Write-Output " "
				Write-Output "================================`nGathering Installed Software"
				function Get-InstalledSoftware
{
	param
	(
		[Parameter(Position = 0)]
		[string[]]$Servers = $env:COMPUTERNAME
	)
	function Inner-InstalledSoftware
	{
		# Add additional property InstallDateObj that will hold the parsed DateTime object
		$Installed_Software = @()
		# Get 64bit installed software
		$Installed_Software += Get-ItemProperty HKLM:\Software\Wow6432Node\Microsoft\Windows\CurrentVersion\Uninstall\* | Select-Object  DisplayName, DisplayVersion, Publisher, InstallDate, InstallDateObj, @{ Name = 'Architecture'; Expression = { '64bit' } }
		$Installed_Software += Get-ItemProperty HKLM:\Software\Microsoft\Windows\CurrentVersion\Uninstall\* | Select-Object  DisplayName, DisplayVersion, Publisher, InstallDate, InstallDateObj, @{ Name = 'Architecture'; Expression = { '32bit' } }
		
		$TheDate = (([datetime]::Now))
     	<# Try to parse dates.
		$Installed_Software.ForEach({
				
				# add more formats if you need
				[string[]]$formats = @("yyyyMMdd", "MM/dd/yyyy")
				
				$installDate = $_.InstallDate
				$installedDateObj = $null;
				$formats.ForEach({
						[DateTime]$dt = New-Object DateTime; if ([datetime]::TryParseExact($installDate, $_, [System.Globalization.CultureInfo]::InvariantCulture, [System.Globalization.DateTimeStyles]::None, [ref]$dt))
						{
							$installedDateObj = $dt
						} 
					});
				$_.InstallDateObj = $installedDateObj
			})
		#>
		$Installed_recently = @()
		$Installed_recently = $Installed_Software | Where { ($_.DisplayName -ne $null) } # -or ($(try{($TheDate - $_.InstallDateObj).Days -le $Days}catch{$Test = $true}))) }
		$array = @()
		if ($Installed_recently.Count -gt 0)
		{
			foreach ($software in $Installed_recently)
			{
				$array += [pscustomobject]@{
					'Installed Software' = $software.DisplayName;
					#'Software Version'   = [version]$software.DisplayVersion;
					'Software Version'   = $software.DisplayVersion;
					'Publisher'		     = $software.Publisher;
					'Install Date'	     = $(try { [Datetime]::ParseExact($software.InstallDate, 'yyyyMMdd', $null) | Get-Date -UFormat "%m/%d/%Y" }
						catch { })
					Architecture		 = $software.Architecture;
					ComputerName		 = $env:COMPUTERNAME
				}
			}
		}
		else
		{
			$array += [pscustomobject]@{
				'Installed Software' = 'Nothing found.';
				'Software Version'   = $null;
				'Publisher'		     = $null;
				'Install Date'	     = $null;
				Architecture		 = $null;
				ComputerName		 = $env:COMPUTERNAME
			}
		}
		return $array
	}
	$finalout = @()
	Write-Host "  Running the Function to gather Installed Software on:`n" -NoNewline -ForegroundColor Gray
	foreach ($server in $Servers)
	{
		Write-Host "    $server" -NoNewline -ForegroundColor Cyan
		if ($server -match $env:COMPUTERNAME)
		{
			Write-Host '-' -NoNewline -ForegroundColor Green
			$finalout += Inner-InstalledSoftware
			Write-Host "> Completed!`n" -NoNewline -ForegroundColor Green
		}
		else
		{
			$finalout += Invoke-Command -ComputerName $server -ScriptBlock ${Function:Inner-InstalledSoftware}
			Write-Host '-' -NoNewline -ForegroundColor Green
			Write-Host "> Completed!`n" -NoNewline -ForegroundColor Green
		}
	}
	return $finalout | Select-Object 'Installed Software', 'Software Version', 'Publisher', 'Install Date', 'Architecture', 'ComputerName' | Sort-Object -Property @{ Expression = 'ComputerName'; Descending = $false }, @{ Expression = 'Install Date'; Descending = $false }, @{ Expression = 'Software Version'; Descending = $true }
}

				Write-Progress -Activity "Collection Running" -Status "Progress-> 10%" -PercentComplete 10
				# Get Installed Software
				$installedsoftware = Get-InstalledSoftware -Servers $TestedTLSservers
				$installedsoftware | ft * -AutoSize | Out-String -Width 4096 | Out-File "$OutputPath\Installed-Software.txt"
				$installedsoftware | Export-Csv -Path "$OutputPath\Installed-Software.csv" -NoTypeInformation
			}
		}
		catch
		{
			"$(Time-Stamp)Unable to gather Installed Software due to Error: $($error[0])" | Out-File $OutputPath\Error.log -Append
			Write-Warning $error[0]
		}
		try
		{
			if ($GetSPN)
			{
				Write-Output " "
				Write-Output "================================`nGathering SPNs from Active Directory"
				function Get-SPN
{
	## Active Directory: PowerShell Function to Get Service Principal Names (SPNs) ##
	# Checked on 11/23/2021
	## Resource: https://gallery.technet.microsoft.com/scriptcenter/Get-SPN-Get-Service-3bd5524a
	
<#
    .SYNOPSIS
        This function will retrieve Service Principal Names (SPNs), with filters for computer name, service type, and port/instance

    .DESCRIPTION
        Get Service Principal Names

        Output includes:
            ComputerName - SPN Host
            Specification - SPN Port (or Instance)
            ServiceClass - SPN Service Class (MSSQLSvc, HTTP, etc.)
            sAMAccountName - sAMAccountName for the AD object with a matching SPN
            SPN - Full SPN string

    .PARAMETER ComputerName
        One or more hostnames to filter on.  Default is *

    .PARAMETER ServiceClass
        Service class to filter on.
        
        Examples:
            HOST
            MSSQLSvc
            TERMSRV
            RestrictedKrbHost
            HTTP

    .PARAMETER Specification
        Filter results to this specific port or instance name

    .PARAMETER SPN
        If specified, filter explicitly and only on this SPN.  Accepts Wildcards.

    .PARAMETER Domain
        If specified, search in this domain. Use a fully qualified domain name, e.g. contoso.org

        If not specified, we search the current user's domain

    .EXAMPLE
        Get-Spn -ServiceClass MSSQLSvc
        
        #This command gets all MSSQLSvc SPNs for the current domain
    
    .EXAMPLE
        Get-Spn -ComputerName SQLServer54, SQLServer55
        
        #List SPNs associated with SQLServer54, SQLServer55
    
    .EXAMPLE
        Get-SPN -SPN http*

        #List SPNs maching http*
    
    .EXAMPLE
        Get-SPN -ComputerName SQLServer54 -Domain Contoso.org

        # List SPNs associated with SQLServer54 in contoso.org

    .NOTES 
        Adapted from
            http://www.itadmintools.com/2011/08/list-spns-in-active-directory-using.html
            http://poshcode.org/3234
        Version History 
            v1.0   - Chad Miller - Initial release 
            v1.1   - ramblingcookiemonster - added parameters to specify service type, host, and specification
            v1.1.1 - ramblingcookiemonster - added parameterset for explicit SPN lookup, added ServiceClass to results

    .FUNCTIONALITY
        Active Directory             
#>
	
	[cmdletbinding(DefaultParameterSetName = 'Parse')]
	param (
		[Parameter(Position = 0,
				   ValueFromPipeline = $true,
				   ValueFromPipelineByPropertyName = $true,
				   ParameterSetName = 'Parse')]
		[string[]]$ComputerName = "*",
		[Parameter(ParameterSetName = 'Parse')]
		[string]$ServiceClass = "*",
		[Parameter(ParameterSetName = 'Parse')]
		[string]$Specification = "*",
		[Parameter(ParameterSetName = 'Explicit')]
		[string]$SPN,
		[string]$Domain
	)
	BEGIN
	{
		#Set up domain specification, borrowed from PyroTek3
		#https://github.com/PyroTek3/PowerShell-AD-Recon/blob/master/Find-PSServiceAccounts
		if (-not $Domain)
		{
			$ADDomainInfo = [System.DirectoryServices.ActiveDirectory.Domain]::GetCurrentDomain()
			$Domain = $ADDomainInfo.Name
		}
		$DomainDN = "DC=" + $Domain -Replace ("\.", ',DC=')
		$DomainLDAP = "LDAP://$DomainDN"
		Write-Verbose "Search root: $DomainLDAP"
		
		#Filter based on service type and specification.  For regexes, convert * to .*
		if ($PsCmdlet.ParameterSetName -like "Parse")
		{
			$ServiceFilter = If ($ServiceClass -eq "*") { ".*" }
			else { $ServiceClass }
			$SpecificationFilter = if ($Specification -ne "*") { ".$Domain`:$specification" }
			else { "*" }
		}
		else
		{
			#To use same logic as 'parse' parameterset, set these variables up...
			$ComputerName = @("*")
			$Specification = "*"
		}
		
		#Set up objects for searching
		$SearchRoot = [ADSI]$DomainLDAP
		$searcher = New-Object System.DirectoryServices.DirectorySearcher
		$searcher.SearchRoot = $SearchRoot
		$searcher.PageSize = 1000
	}
	PROCESS
	{
		#Loop through all the computers and search!
		foreach ($computer in $ComputerName)
		{
			#Set filter - Parse SPN or use the explicit SPN parameter
			if ($PsCmdlet.ParameterSetName -like "Parse")
			{
				$filter = "(servicePrincipalName=$ServiceClass/$computer$SpecificationFilter)"
			}
			else
			{
				$filter = "(servicePrincipalName=$SPN)"
			}
			$searcher.Filter = $filter
			
			Write-Verbose "Searching for SPNs with filter $filter"
			foreach ($result in $searcher.FindAll())
			{
				
				$account = $result.GetDirectoryEntry()
				foreach ($servicePrincipalName in $account.servicePrincipalName.Value)
				{
					#Regex will capture computername and port/instance
					if ($servicePrincipalName -match "^(?<ServiceClass>$ServiceFilter)\/(?<computer>[^\.|^:]+)[^:]*(:{1}(?<port>\w+))?$")
					{
						
						#Build up an object, get properties in the right order, filter on computername
						New-Object psobject -property @{
							ComputerName = $matches.computer
							ServiceClass = $matches.ServiceClass
							sAMAccountName = $($account.sAMAccountName)
							distinguishedName = $($account.distinguishedName)
							whenChanged  = $($account.whenChanged)
							SPN		     = $servicePrincipalName
						} |
						Select-Object ComputerName, ServiceClass, sAMAccountName, distinguishedName, whenChanged, SPN #|
						#To get results that match parameters, filter on comp and spec
						#Where-Object { $_.ComputerName -like $computer -and $_.Specification -like $Specification }
					}
				}
			}
		}
	}
}

				Write-Progress -Activity "Collection Running" -Status "Progress-> 11%" -PercentComplete 11
				# Get SPNs from Active Directory
				Write-Host "  Running function to gather SPN Data" -ForegroundColor Gray -NoNewline
				try
				{
					$spnOutput1 = Get-SPN -ErrorAction Stop -ComputerName $TLSservers | Select * -Unique | Where { $_.ServiceClass -ne 'MSOMSdkSvc' } | Sort-Object -Property ComputerName, ServiceClass, whenChanged
					Write-Host "-" -ForegroundColor Green -NoNewline
				}
				catch
				{
					"$(Time-Stamp)Unable to gather SPN Output due to Error: $($error[0])" | Out-File $OutputPath\Error.log -Append
					"Unable to gather SPN Output due to Error: `n$($error[0])" | Out-File -FilePath $OutputPath\SPN-Output.txt -Force
				}
				try
				{
					$omsdkServiceAccount = ((Get-WmiObject Win32_service -ErrorAction SilentlyContinue).where{ $_.name -eq 'omsdk' }).StartName
					if ($omsdkServiceAccount -eq 'LocalMachine')
					{
						continue
					}
					else
					{
						$spnOutput2 = Get-SPN -ErrorAction Stop -ServiceClass MSOMSdkSvc | Select * -Unique | Sort-Object -Property ComputerName, ServiceClass, whenChanged
					}
					
					Write-Host "-" -ForegroundColor Green -NoNewline
				}
				catch
				{
					"$(Time-Stamp)Unable to gather SPN Output due to Error: $($error[0])" | Out-File $OutputPath\Error.log -Append
					"Unable to gather SPN Output due to Error: `n$($error[0])" | Out-File -FilePath $OutputPath\SPN-Output.txt -Force
				}
				if ($spnOutput1 -or $spnOutput2)
				{
					$spnFinal = ($spnOutput1, $spnOutput2) | Select-Object -Unique | Sort-Object ServiceClass, ComputerName
					$spnFinal | ft * -AutoSize | Out-String -Width 4096 | Out-File -FilePath $OutputPath\SPN-Output.txt -Force
					$spnOutput1 | Export-Csv -Path $OutputPath\SPN-Output.csv -NoTypeInformation
					$spnOutput2 | Export-Csv -Path $OutputPath\SPN-Output.csv -NoTypeInformation -Append
				}
				
				Write-Host "> Completed!" -ForegroundColor Green
			}
		}
		catch
		{
			"$(Time-Stamp)Unable to gather SPN data due to Error: $($error[0])" | Out-File $OutputPath\Error.log -Append
			Write-Warning $error[0]
		}
		try
		{
			if ($CheckTLS)
			{
				Write-Output " "
				Write-Output "================================`nStarting TLS Checker"
				Function Get-TLSRegistryKeys
{
	[CmdletBinding()]
	Param
	(
		[string[]]$Servers
	)
	if (!$Servers)
	{
		$Servers = $env:COMPUTERNAME
	}
	$Servers = $Servers | Sort-Object
	Write-Host "  Accessing Registry on:`n" -NoNewline -ForegroundColor Gray
	$scriptOut = $null
	function Inner-TLSRegKeysFunction
	{
		[CmdletBinding()]
		param ()
		$finalData = @()
		$LHost = $env:computername
		$ProtocolList = "TLS 1.0", "TLS 1.1", "TLS 1.2"
		$ProtocolSubKeyList = "Client", "Server"
		$DisabledByDefault = "DisabledByDefault"
		$Enabled = "Enabled"
		$registryPath = "HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\"
		Write-Output "Path`n----`n$registryPath"
		foreach ($Protocol in $ProtocolList)
		{
			foreach ($key in $ProtocolSubKeyList)
			{
				Write-Host "-" -NoNewline -ForegroundColor Green
				#Write-Host "Checking for $protocol\$key"
				$currentRegPath = $registryPath + $Protocol + "\" + $key
				$IsDisabledByDefault = @()
				$IsEnabled = @()
				$localresults = @()
				if (!(Test-Path $currentRegPath))
				{
					$IsDisabledByDefault = "Null"
					$IsEnabled = "Null"
				}
				else
				{
					$IsDisabledByDefault = (Get-ItemProperty -Path $currentRegPath -Name $DisabledByDefault -ea 0).DisabledByDefault
					if ($IsDisabledByDefault -eq 4294967295)
					{
						$IsDisabledByDefault = "0xffffffff"
					}
					if ($IsDisabledByDefault -eq $null)
					{
						$IsDisabledByDefault = "DoesntExist"
					}
					$IsEnabled = (Get-ItemProperty -Path $currentRegPath -Name $Enabled -ea 0).Enabled
					if ($IsEnabled -eq 4294967295)
					{
						$isEnabled = "0xffffffff"
					}
					if ($IsEnabled -eq $null)
					{
						$IsEnabled = "DoesntExist"
					}
				}
				$localresults = "PipeLineKickStart" | select @{ n = 'Server'; e = { $LHost } },
															 @{ n = 'Protocol'; e = { $Protocol } },
															 @{ n = 'Type'; e = { $key } },
															 @{ n = 'DisabledByDefault'; e = { ($IsDisabledByDefault).ToString().Replace('0', 'False').Replace('1', 'True') } },
															 @{ n = 'IsEnabled'; e = { ($IsEnabled).ToString().Replace('0', 'False').Replace('1', 'True') } }
				$finalData += $localresults
			}
		}
		$results += $finaldata | select -Property * -ExcludeProperty PSComputerName, RunspaceId, PSShowComputerName | ft * -AutoSize
		$CrypKey1 = "HKLM:\SOFTWARE\Microsoft\.NETFramework\v4.0.30319"
		$CrypKey2 = "HKLM:\SOFTWARE\WOW6432Node\Microsoft\.NETFramework\v4.0.30319"
		$Strong = "SchUseStrongCrypto"
		$Crypt1 = (Get-ItemProperty -Path $CrypKey1 -Name $Strong -ea 0).SchUseStrongCrypto
		If ($crypt1 -eq 1)
		{
			$Crypt1 = $true
		}
		else
		{
			$Crypt1 = $False
		}
		$crypt2 = (Get-ItemProperty -Path $CrypKey2 -Name $Strong -ea 0).SchUseStrongCrypto
		if ($crypt2 -eq 1)
		{
			$Crypt2 = $true
		}
		else
		{
			$Crypt2 = $False
		}
		$DefaultTLSVersions = (Get-ItemProperty -Path $CrypKey1 -Name $Strong -ea 0).SystemDefaultTlsVersions
		If ($DefaultTLSVersions -eq 1)
		{
			$DefaultTLSVersions = $true
		}
		else
		{
			$DefaultTLSVersions = $False
		}
		$DefaultTLSVersions64 = (Get-ItemProperty -Path $CrypKey2 -Name $Strong -ea 0).SystemDefaultTlsVersions
		if ($DefaultTLSVersions64 -eq 1)
		{
			$DefaultTLSVersions64 = $true
		}
		else
		{
			$DefaultTLSVersions64 = $False
		}
		##  ODBC : https://www.microsoft.com/en-us/download/details.aspx?id=50420
		##  OLEDB : https://docs.microsoft.com/en-us/sql/connect/oledb/download-oledb-driver-for-sql-server?view=sql-server-ver15
		[string[]]$data = (Get-WmiObject -Class Win32_Product | Where-Object { $_.Name -like "*sql*" }).name
		$odbcOutput = $data | where { $_ -like "Microsoft ODBC Driver *" } # Need to validate version
		$odbc = @()
		foreach ($driver in $odbcOutput)
		{
			Write-Host '-' -NoNewline -ForegroundColor Green
			if ($driver -match "11|13|17|18")
			{
				Write-Verbose "FOUND $driver"
				$odbc += "$driver (Good)"
			}
			elseif ($driver)
			{
				Write-Verbose "FOUND $driver"
				$odbc += "$driver"
			}
			else
			{
				$odbc = "Not Found."
			}
		}
		$odbc = $odbc -split "`n" | Out-String -Width 2048
		$oledb = $data | where { $_ -like "Microsoft OLE DB Driver*" }
		if ($oledb)
		{
			Write-Verbose "Found: $oledb"
			$OLEDB_Output = @()
			foreach ($software in $oledb)
			{
				if ($software -eq 'Microsoft OLE DB Driver 19 for SQL Server')
				{
					$OLEDB_Output += "$software - $((Get-ItemProperty HKLM:\SOFTWARE\Microsoft\MSOLEDBSQL19).InstalledVersion) (Good)"
				}
				elseif ($software -eq 'Microsoft OLE DB Driver for SQL Server')
				{
					$OLEDB_Output += "$software - $((Get-ItemProperty HKLM:\SOFTWARE\Microsoft\MSOLEDBSQL).InstalledVersion) (Good)"
				}
				else
				{
					$OLEDB_Output += "$software - $((Get-ItemProperty HKLM:\SOFTWARE\Microsoft\MSOLEDBSQL*).InstalledVersion) (Good)"
				}
			}
		}
		else
		{
			$OLEDB = "Not Found."
		}
		foreach ($Protocol in $ProtocolList)
		{
			Write-Host '-' -NoNewline -ForegroundColor Green
			foreach ($key in $ProtocolSubKeyList)
			{
				#Write-Host "Checking for $protocol\$key"
				$currentRegPath = $registryPath + $Protocol + "\" + $key
				$IsDisabledByDefault = @()
				$IsEnabled = @()
				$localresults = @()
				if (!(Test-Path $currentRegPath))
				{
					$IsDisabledByDefault = "Null"
					$IsEnabled = "Null"
				}
				else
				{
					$IsDisabledByDefault = (Get-ItemProperty -Path $currentRegPath -Name $DisabledByDefault -ea 0).DisabledByDefault
					if ($IsDisabledByDefault -eq 4294967295)
					{
						$IsDisabledByDefault = "0xffffffff"
					}
					if ($IsDisabledByDefault -eq $null)
					{
						$IsDisabledByDefault = "DoesntExist"
					}
					$IsEnabled = (Get-ItemProperty -Path $currentRegPath -Name $Enabled -ea 0).Enabled
					if ($IsEnabled -eq 4294967295)
					{
						$isEnabled = "0xffffffff"
					}
					if ($IsEnabled -eq $null)
					{
						$IsEnabled = "DoesntExist"
					}
				}
				$localresults = "PipeLineKickStart" | select @{ n = 'Server'; e = { $LHost } },
															 @{ n = 'Protocol'; e = { $Protocol } },
															 @{ n = 'Type'; e = { $key } },
															 @{ n = 'DisabledByDefault'; e = { ($IsDisabledByDefault).ToString().Replace('0', 'False').Replace('1', 'True') } },
															 @{ n = 'IsEnabled'; e = { ($IsEnabled).ToString().Replace('0', 'False').Replace('1', 'True') } }
				$finalData += $localresults
			}
		}
		### Check if SQL Client is installed 
		$RegPath = "HKLM:SOFTWARE\Microsoft\SQLNCLI11"
		IF (Test-Path $RegPath)
		{
			[string]$SQLClient11VersionString = (Get-ItemProperty $RegPath)."InstalledVersion"
			[version]$SQLClient11Version = [version]$SQLClient11VersionString
		}
		[version]$MinSQLClient11Version = [version]"11.4.7001.0"
		Write-Host '-' -NoNewline -ForegroundColor Green
		$SQLClientProgramVersion = $data | where { $_ -like "Microsoft SQL Server 2012 Native Client" } # Need to validate version
		IF ($SQLClient11Version -ge $MinSQLClient11Version)
		{
			Write-Verbose "SQL Client - is installed and version: ($SQLClient11VersionString) and greater or equal to the minimum version required: (11.4.7001.0)"
			$SQLClient = "$SQLClientProgramVersion $SQLClient11Version (Good)"
		}
		ELSEIF ($SQLClient11VersionString)
		{
			Write-Verbose "SQL Client - is installed and version: ($SQLClient11VersionString) but below the minimum version of (11.4.7001.0)."
			$SQLClient = "$SQLClientProgramVersion $SQLClient11VersionString (Below minimum)"
		}
		ELSE
		{
			Write-Verbose "    SQL Client - is NOT installed."
			$SQLClient = "Not Found."
		}
		###################################################
		# Test .NET Framework version on ALL servers
		# Get version from registry
		$NetVersion = @()
		$RegPath = "HKLM:\SOFTWARE\Microsoft\NET Framework Setup\NDP\v4\Full\"
		$ReleaseRegValues = (Get-ItemProperty $RegPath)
		foreach ($ReleaseRegValue in $ReleaseRegValues)
		{
            <#
			# Interpret .NET version
			[string]$VersionString = switch ($ReleaseRegValue)
			{
				"378389" { ".NET Framework 4.5" }
				"378675" { ".NET Framework 4.5.1" }
				"378758" { ".NET Framework 4.5.1" }
				"379893" { ".NET Framework 4.5.2" }
				"393295" { ".NET Framework 4.6" }
				"393297" { ".NET Framework 4.6" }
				"394254" { ".NET Framework 4.6.1" }
				"394271" { ".NET Framework 4.6.1" }
				"394802" { ".NET Framework 4.6.2" }
				"394806" { ".NET Framework 4.6.2" }
				"460798" { ".NET Framework 4.7" }
				"460805" { ".NET Framework 4.7" }
				"461308" { ".NET Framework 4.7.1" }
				"461310" { ".NET Framework 4.7.1" }
				"461814" { ".NET Framework 4.7.2" }
				"461808" { ".NET Framework 4.7.2" }
				"461814" { ".NET Framework 4.7.2" }
				"528040" { ".NET Framework 4.8" }
				"528372" { ".NET Framework 4.8" }
				"528049" { ".NET Framework 4.8" }
				"528449" { ".NET Framework 4.8" }
				default { "Unknown .NET version: $ReleaseRegValue" }
			}
            #>
			Write-Host '-' -NoNewline -ForegroundColor Green
			# Check if version is 4.6 or higher
			IF ($ReleaseRegValue.Release -ge 393295)
			{
				Write-Verbose ".NET version is 4.6 or later (Detected: $($ReleaseRegValue.Version)) (Good)"
				$NetVersion += ".NET Framework $($ReleaseRegValue.Version) (Good)"
			}
			ELSE
			{
				Write-Verbose ".NET version is NOT 4.6 or later (Detected: $ReleaseRegValue.Version) (Bad)"
				$NetVersion += ".NET Framework $($ReleaseRegValue.Version) (Does not match required version, .NET 4.6 ATLEAST is required)"
			}
		}
		$SChannelLogging = Get-ItemProperty 'HKLM:\System\CurrentControlSet\Control\SecurityProviders\SCHANNEL' -Name EventLogging | Select-Object EventLogging -ExpandProperty EventLogging
		$SChannelSwitch = switch ($SChannelLogging)
		{
			1 { '0x0001 - Log error messages. (Default)' }
			2 { '0x0002 - Log warnings. (Modified)' }
			3 { '0x0003 - Log warnings and error messages. (Modified)' }
			4 { '0x0004 - Log informational and success events. (Modified)' }
			5 { '0x0005 - Log informational, success events and error messages. (Modified)' }
			6 { '0x0006 - Log informational, success events and warnings. (Modified)' }
			7 { '0x0007 - Log informational, success events, warnings, and error messages (all log levels). (Modified)' }
			0 { '0x0000 - Do not log. (Modified)' }
			default { "$SChannelLogging - Unknown Log Level Possibly Misconfigured. (Modified)" }
		}
		try
		{
			Write-Host '-' -NoNewline -ForegroundColor Green
			$odbcODBCDataSources = Get-ItemProperty 'HKLM:\SOFTWARE\ODBC\ODBC.INI\ODBC Data Sources' -ErrorAction Stop | Select-Object OpsMgrAC -ExpandProperty OpsMgrAC -ErrorAction Stop
		}
		catch { $odbcODBCDataSources = 'Not Found.' }
		try
		{
			$odbcOpsMgrAC = Get-ItemProperty 'HKLM:\SOFTWARE\ODBC\ODBC.INI\OpsMgrAC' -ErrorAction Stop | Select-Object Driver -ExpandProperty Driver -ErrorAction Stop
		}
		catch { $odbcOpsMgrAC = 'Not Found.' }
		try
		{
			$SSLCiphers = ((Get-ItemProperty 'HKLM:\SOFTWARE\Policies\Microsoft\Cryptography\Configuration\SSL\00010002').Functions).Split(",") | Sort-Object | Out-String
		}
		catch { $SSLCiphers = 'Not Found' }
		try
		{
			$FIPS = Get-ItemProperty "HKLM:\System\CurrentControlSet\Control\LSA\FIPSAlgorithmPolicy" | Select Enabled, PSPath
		}
		catch
		{
			$FIPS = 'PipelineKickstart' | Select @{ n = 'Enabled'; e = { 'Not Found.' } }, @{ n = 'PSPath'; e = { 'HKLM:\System\CurrentControlSet\Control\LSA\FIPSAlgorithmPolicy' } }
		}
		$additional = ('PipeLineKickStart' | Select @{ n = 'SchUseStrongCrypto'; e = { $Crypt1 } },
													@{ n = 'SchUseStrongCrypto_WOW6432Node'; e = { $Crypt2 } },
													@{ n = 'FIPS Enabled'; e = { ($FIPS.Enabled).ToString().Replace("0", "False").Replace("1", "True") } },
													@{ n = 'DefaultTLSVersions'; e = { $DefaultTLSVersions } },
													@{ n = 'DefaultTLSVersions_WOW6432Node'; e = { $DefaultTLSVersions64 } },
													@{ n = 'OLEDB'; e = { $OLEDB_Output -split "`n" | Out-String -Width 2048 } },
													@{ n = 'ODBC'; e = { $odbc } },
													@{ n = 'ODBC (ODBC Data Sources\OpsMgrAC)'; e = { $odbcODBCDataSources } },
													@{ n = 'ODBC (OpsMgrAC\Driver)'; e = { $odbcOpsMgrAC } },
													@{ n = 'SQLClient'; e = { $SQLClient } },
													@{ n = '.NetFramework'; e = { $NetVersion -split "`n" | Out-String -Width 2048 } },
													@{ n = 'SChannel Logging'; e = { $SChannelSwitch } },
													@{ n = 'SSL Cipher Suites'; e = { $SSLCiphers } }
		)
		$results += $additional | select -Property * -ExcludeProperty PSComputerName, RunspaceId, PSShowComputerName
		$results += "====================================================="
		return $results
	}
	foreach ($server in $servers)
	{
		Write-Host "     $server" -NoNewline -ForegroundColor Cyan
		if ($server -notcontains $env:COMPUTERNAME)
		{
			$InnerTLSRegKeysFunctionScript = "function Inner-TLSRegKeysFunction { ${function:Inner-TLSRegKeysFunction} }"
			$scriptOut += (Invoke-Command -ComputerName $server -ArgumentList $InnerTLSRegKeysFunctionScript, $VerbosePreference -ScriptBlock {
					Param ($script,
						$VerbosePreference)
					. ([ScriptBlock]::Create($script))
					Write-Host "-" -NoNewLine -ForegroundColor Green
					if ($VerbosePreference -eq 'Continue')
					{
						return Inner-TLSRegKeysFunction -Verbose
					}
					else
					{
						return Inner-TLSRegKeysFunction
					}
				} -HideComputerName | Out-String) -replace "RunspaceId.*", ""
			Write-Host "> Completed!`n" -NoNewline -ForegroundColor Green
		}
		else
		{
			Write-Host "-" -NoNewLine -ForegroundColor Green
			if ($VerbosePreference -eq 'Continue')
			{
				$scriptOut += Inner-TLSRegKeysFunction -Verbose
			}
			else
			{
				$scriptOut += Inner-TLSRegKeysFunction
			}
			Write-Host "> Completed!`n" -NoNewline -ForegroundColor Green
		}
	}
	$scriptOut | Out-String -Width 4096
}

				Write-Progress -Activity "Collection Running" -Status "Progress-> 12%" -PercentComplete 12
				# This will be updated with CipherSuite checks at some point
				Get-TLSRegistryKeys -Servers $TestedTLSservers |
				Out-File $OutputPath\TLS-RegistryKeys.txt
			}
		}
		catch
		{
			"$(Time-Stamp)Unable to gather TLS data due to Error: $($error[0])" | Out-File $OutputPath\Error.log -Append
			Write-Warning $error[0]
		}
		try
		{
			if ($GetConfiguration)
			{
				Write-Progress -Activity "Collection Running" -Status "Progress-> 13%" -PercentComplete 13
				Write-Output " "
				Write-Output "================================`nStarting Management Server Configuration Gather"
				Function Get-SCOMConfiguration
{
	[cmdletbinding()]
	param (
		[string[]]$Servers
	)
	<#
	Check Registry Keys for:
	HKLM:\SYSTEM\CurrentControlSet\services\HealthService
	HKLM:\SOFTWARE\Microsoft\Microsoft Operations Manager\3.0
	HKLM:\SOFTWARE\Microsoft\System Center\2010
	HKLM:\SOFTWARE\Microsoft\System Center Operations Manager\12

	this also gathers the following file:
	ConfigService.config
	#>
	#Remove-Item -Recurse -Path "$OutputPath\Management Server Config\*" -ErrorAction SilentlyContinue
	trap
	{
		#potential error code
		#use continue or break keywords
		$e = $_.Exception
		$line = $_.InvocationInfo.ScriptLineNumber
		$msg = $e.Message
		
		Write-Verbose "Caught Exception: $e :: Message: $msg :: at line: $line"
		"$(Time-Stamp)Caught Exception: $e :: Message: $msg :: at line: $line" | Out-File $OutputPath\Error.log -Append
	}
	function Inner-CheckSCOMConfiguration
	{
		param
		(
			[switch]$Remote,
			[switch]$Local,
			[string]$Server
		)
		
		try
		{
			$installpath = $null
			$success = $false
			if ($Remote)
			{
				$remoteConfigFile = $null
				$remoteConfigFile = Invoke-Command -ErrorAction Stop -ComputerName $Server {
					$installpath = (Get-ItemProperty -path "HKLM:\SOFTWARE\Microsoft\Microsoft Operations Manager\3.0\Setup" -ErrorAction SilentlyContinue).InstallDirectory
					$configFile = Get-Content "$installpath\ConfigService.config"
					return $configFile
				}
				if ($remoteConfigFile)
				{
					$remoteConfigFile | Out-File -FilePath "$OutputPath\Management Server Config\$server-ConfigService.config"
				}
			}
			
			if ($Local)
			{
				$localConfigFile = $null
				$installpath = (Get-ItemProperty -path "HKLM:\SOFTWARE\Microsoft\Microsoft Operations Manager\3.0\Setup" -ErrorAction SilentlyContinue).InstallDirectory
				if ($installpath)
				{
					$localConfigFile = Get-Content "$installpath\ConfigService.config"
				}
				if ($localConfigFile)
				{
					$localConfigFile | Out-File -FilePath "$OutputPath\Management Server Config\$server-ConfigService.config"
				}
			}
			
			Write-Host "    $server" -NoNewline -ForegroundColor Cyan
			Write-Host "-" -NoNewline -ForegroundColor Green
			if ($Remote)
			{
				$HealthService = Invoke-Command -ComputerName $Server { return ((Get-ChildItem 'HKLM:\SYSTEM\CurrentControlSet\services\HealthService' -Recurse | Get-ItemProperty | Select-Object * -ExcludeProperty PSChildName, PSProvider, PSDrive | Out-String -Width 4096).Replace("Microsoft.PowerShell.Core\Registry::", "").Replace('PSPath', "Registry Path") -replace "PSParentPath(.*)", "`n================================================================================================`n") } -ErrorAction SilentlyContinue
				$HealthService | Out-File -FilePath "$OutputPath\Management Server Config\HealthService\$server.txt"
				Write-Host "-" -NoNewline -ForegroundColor Green
				$OpsMgr = Invoke-Command -ComputerName $Server { return (Get-ChildItem 'HKLM:\SOFTWARE\Microsoft\Microsoft Operations Manager\3.0' -Recurse | Get-ItemProperty | Out-String -Width 4096).Replace("Microsoft.PowerShell.Core\Registry::", "").Replace('PSPath', 'Registry Path') -Replace "PSParentPath(.*)", "" -Replace "PSChildName(.*)", "" -Replace "PSProvider(.*)", "=================================================================" }
				$OpsMgr | Out-File -FilePath "$OutputPath\Management Server Config\Operations Manager - 3.0\$server.txt"
				Write-Host "-" -NoNewline -ForegroundColor Green
				$SystemCenter2010 = Invoke-Command -ComputerName $Server { return (Get-ChildItem 'HKLM:\SOFTWARE\Microsoft\System Center\2010' -Recurse | Get-ItemProperty | Out-String -Width 4096).Replace("Microsoft.PowerShell.Core\Registry::", "").Replace('PSPath', 'Registry Path') -Replace "PSParentPath(.*)", "" -Replace "PSChildName(.*)", "" -Replace "PSProvider(.*)", "=================================================================" }
				$SystemCenter2010 | Out-File -FilePath "$OutputPath\Management Server Config\System Center - 2010\$server.txt"
				Write-Host "-" -NoNewline -ForegroundColor Green
				$SystemCenterOperationsManager = Invoke-Command -ComputerName $Server { return (Get-ChildItem 'HKLM:\SOFTWARE\Microsoft\System Center Operations Manager\12' -Recurse | Get-ItemProperty | Select-Object * -ExcludeProperty PSChildName, PSProvider, PSDrive | Out-String -Width 4096).Replace("Microsoft.PowerShell.Core\Registry::", "").Replace('PSPath', "Registry Path") -replace "PSParentPath(.*)", "`n================================================================================================`n" }
				$SystemCenterOperationsManager | Out-File -FilePath "$OutputPath\Management Server Config\System Center Operations Manager - 12\$server.txt"
				
				Write-Host "> Done!" -ForegroundColor Green
			}
			elseif ($Local)
			{
				$HealthService = ((Get-ChildItem 'HKLM:\SYSTEM\CurrentControlSet\services\HealthService' -Recurse | Get-ItemProperty | Select-Object * -ExcludeProperty PSChildName, PSProvider, PSDrive | Out-String -Width 4096).Replace("Microsoft.PowerShell.Core\Registry::", "").Replace('PSPath', "Registry Path") -replace "PSParentPath(.*)", "`n================================================================================================`n")
				$HealthService | Out-File -FilePath "$OutputPath\Management Server Config\HealthService\$server.txt"
				Write-Host "-" -NoNewline -ForegroundColor Green
				$OpsMgr = (Get-ChildItem 'HKLM:\SOFTWARE\Microsoft\Microsoft Operations Manager\3.0' -Recurse | Get-ItemProperty | Out-String -Width 4096).Replace("Microsoft.PowerShell.Core\Registry::", "").Replace('PSPath', 'Registry Path') -Replace "PSParentPath(.*)", "" -Replace "PSChildName(.*)", "" -Replace "PSProvider(.*)", "================================================================="
				$OpsMgr | Out-File -FilePath "$OutputPath\Management Server Config\Operations Manager - 3.0\$server.txt"
				Write-Host "-" -NoNewline -ForegroundColor Green
				$SystemCenter2010 = (Get-ChildItem 'HKLM:\SOFTWARE\Microsoft\System Center\2010' -Recurse | Get-ItemProperty | Out-String -Width 4096).Replace("Microsoft.PowerShell.Core\Registry::", "").Replace('PSPath', 'Registry Path') -Replace "PSParentPath(.*)", "" -Replace "PSChildName(.*)", "" -Replace "PSProvider(.*)", "================================================================="
				$SystemCenter2010 | Out-File -FilePath "$OutputPath\Management Server Config\System Center - 2010\$server.txt"
				Write-Host "-" -NoNewline -ForegroundColor Green
				$SystemCenterOperationsManager = (Get-ChildItem 'HKLM:\SOFTWARE\Microsoft\System Center Operations Manager\12' -Recurse | Get-ItemProperty | Select-Object * -ExcludeProperty PSChildName, PSProvider, PSDrive | Out-String -Width 4096).Replace("Microsoft.PowerShell.Core\Registry::", "").Replace('PSPath', "Registry Path") -replace "PSParentPath(.*)", "`n================================================================================================`n"
				$SystemCenterOperationsManager | Out-File -FilePath "$OutputPath\Management Server Config\System Center Operations Manager - 12\$server.txt"
				
				Write-Host "> Done!" -ForegroundColor Green
			}
		}
		catch
		{
			"Unable to gather the configuration due to connectivity issues." | Out-File -FilePath "$OutputPath\Management Server Config\$server`-Unable-to-Connect.txt"
			#potential error code
			#use continue or break keywords
			$e = $_.Exception
			$line = $_.InvocationInfo.ScriptLineNumber
			$msg = $e.Message
			
			Write-Verbose "Caught Exception: $e :: Message: $msg :: at line: $line"
			"$(Time-Stamp)Caught Exception: $e :: Message: $msg :: at line: $line" | Out-File $OutputPath\Error.log -Append
		}
	}
	New-Item -ItemType Directory -Path "$OutputPath\Management Server Config\HealthService" -ErrorAction Stop | Out-Null
	New-Item -ItemType Directory -Path "$OutputPath\Management Server Config\Operations Manager - 3.0" -ErrorAction Stop | Out-Null
	New-Item -ItemType Directory -Path "$OutputPath\Management Server Config\System Center - 2010" -ErrorAction Stop | Out-Null
	New-Item -ItemType Directory -Path "$OutputPath\Management Server Config\System Center Operations Manager - 12" -ErrorAction Stop | Out-Null
	Write-Host "  Gathering Configuration from:" -ForegroundColor Gray
	foreach ($server in $Servers)
	{
		try
		{
			if ($server -ne $env:COMPUTERNAME)
			{
				Inner-CheckSCOMConfiguration -Remote -Server $server
			}
			else
			{
				Inner-CheckSCOMConfiguration -Local -Server $server
			}
			
		}
		catch
		{
			#potential error code
			#use continue or break keywords
			$e = $_.Exception
			$line = $_.InvocationInfo.ScriptLineNumber
			$msg = $e.Message
			
			Write-Verbose "Caught Exception: $e :: Message: $msg :: at line: $line"
			"$(Time-Stamp)Caught Exception: $e :: Message: $msg :: at line: $line" | Out-File $OutputPath\Error.log -Append
		}
	}
}

				Get-SCOMConfiguration -Servers $ManagementServers
			}
		}
		catch
		{
			"$(Time-Stamp)Unable to gather Configuration data due to Error: $($error[0])" | Out-File $OutputPath\Error.log -Append
			Write-Warning $error[0]
		}
		Write-Progress -Activity "Collection Running" -Status "Progress-> 14%" -PercentComplete 14
		try
		{
			if ($GetEventLogs -or $AdditionalEventLogs)
			{
				Write-Output " "
				Write-Output "================================`nStarting Event Log Gathering"
				Function Get-SCOMEventLogs
{
	[cmdletbinding()]
	param (
		[String[]]$Servers,
		[String[]]$Logs = ("Application", "System", "Operations Manager")
	)
	trap
	{
		#potential error code
		#use continue or break keywords
		$e = $_.Exception
		$line = $_.InvocationInfo.ScriptLineNumber
		$msg = $e.Message
		
		Write-Verbose "Caught Exception: $e :: Message: $msg :: at line: $line"
		"$(Time-Stamp)Caught Exception: $e :: Message: $msg :: at line: $line" | Out-File $OutputPath\Error.log -Append
	}
	foreach ($server in $servers)
	{
		Write-Output " "
		foreach ($log in $logs)
		{
			$originalLogName = $log
			if ($log -like "*/*")
			{
				$log = $log.Replace("/", "-")
			}
			If ($Comp -match $server)
			{
				# If running locally do the below
				Write-Host "    Locally " -NoNewline -ForegroundColor DarkCyan
				Write-Host "Exporting Event Log " -NoNewline -ForegroundColor Cyan
				Write-Host "on " -NoNewline -ForegroundColor DarkCyan
				Write-Host "$server " -NoNewline -ForegroundColor Cyan
				Write-Host ": " -NoNewline -ForegroundColor DarkCyan
				Write-Host "$originalLogName" -NoNewline -ForegroundColor Cyan
				$fileCheck = test-path "c:\windows\Temp\$server.$log.evtx"
				if ($fileCheck -eq $true)
				{
					Remove-Item "c:\windows\Temp\$server.$log.evtx" -Force
				}
				Write-Host "-" -NoNewline -ForegroundColor Green;
				$eventcollect = wevtutil epl $originalLogName "c:\windows\Temp\$server.$log.evtx"; wevtutil al "c:\windows\Temp\$server.$log.evtx"
				do { Write-Host "-" -NoNewline -ForegroundColor Green; sleep 1 }
				while ($eventcollect)
				Write-Host "> Collected Events`n" -NoNewline -ForegroundColor Green
				try
				{
					Write-Host "     Locally moving files using Move-Item" -NoNewline -ForegroundColor DarkCyan
					$movelocalevtx = Move-Item "C:\Windows\temp\$server.$log.evtx" $ScriptPath\output -force -ErrorAction Stop; Move-Item "C:\Windows\temp\localemetadata\*.mta" $ScriptPath\output -force -ErrorAction Stop
					Write-Host "-" -NoNewline -ForegroundColor Green
					do { Write-Host "-" -NoNewline -ForegroundColor Green; sleep 1 }
					while ($movelocalevtx | Out-Null)
					Write-Host "> Transfer Completed!" -NoNewline -ForegroundColor Green
					Write-Output " "
					continue
				}
				catch
				{
					Write-Warning $_
				}
				try
				{
					Write-Host "     Locally moving files using Robocopy" -NoNewline -ForegroundColor DarkCyan
					Robocopy "C:\Windows\temp" "$ScriptPath\output" "$server.$log.evtx" /MOVE /R:2 /W:10 | Out-Null
					Robocopy "C:\Windows\temp\localemetadata" "$ScriptPath\output" "*.MTA" /MOVE /R:2 /W:10 | Out-Null
					Write-Host "      Transfer Completed!" -NoNewline -ForegroundColor Green
					Write-Output " "
					continue
				}
				catch
				{
					Write-Warning $_
				}
			}
			else
			{
				# If not the Computer Running this Script, do the below.
				$eventlog_ispresent = Get-EventLog -LogName * -ComputerName $server | Where { $_.Log -eq $log }
				if ($eventlog_ispresent)
				{
					Write-Host "    Remotely " -NoNewline -ForegroundColor DarkCyan
					Write-Host "Exporting Event Log " -NoNewline -ForegroundColor Cyan
					Write-Host "on " -NoNewline -ForegroundColor DarkCyan
					Write-Host "$server " -NoNewline -ForegroundColor Cyan
					Write-Host ": " -NoNewline -ForegroundColor DarkCyan
					Write-Host "$log" -NoNewline -ForegroundColor Cyan
					Write-Host "-" -NoNewline -ForegroundColor Green
					try
					{
						Invoke-Command -ComputerName $server {
							
							
							$localAdmin = ([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole] "Administrator")
							if ($localadmin) { $LA = "$true" }
							else { $LA = "$false" }
							
							
							$fileCheck = test-path "c:\windows\Temp\$using:server.$using:log.evtx"
							if ($fileCheck -eq $true)
							{
								Remove-Item "c:\windows\Temp\$using:server.$using:log.evtx" -Force
							}
							Write-Host "-" -NoNewline -ForegroundColor Green
							if ($la -eq $true)
							{
								try
								{
									$eventcollect = wevtutil epl $using:originalLogName "c:\windows\Temp\$using:server.$using:log.evtx"; wevtutil al "c:\windows\Temp\$using:server.$using:log.evtx"
									do { Write-Host "-" -NoNewline -ForegroundColor Green; sleep 1 }
									while ($eventcollect)
									Write-Host "> Collected Events" -NoNewline -ForegroundColor Green
								}
								catch
								{
									Write-Warning $_
									continue
								}
							}
							Write-Output " "
							continue
						}
					}
					catch { Write-Warning $_ }
					try
					{
						Write-Host "     Transferring using Move-Item" -NoNewLine -ForegroundColor DarkCyan
						$moveevents = Move-Item "\\$server\c$\windows\temp\$server.$log.evtx" $ScriptPath\output -force -ErrorAction Stop; Move-Item "\\$server\c$\windows\temp\localemetadata\*.mta" $ScriptPath\output -force -ErrorAction Stop
						Write-Host "-" -NoNewline -ForegroundColor Green
						do { Write-Host "-" -NoNewline -ForegroundColor Green; sleep 1 }
						while ($moveevents)
						Write-Host "> Transfer Completed!" -NoNewline -ForegroundColor Green
						Write-Output " "
						continue
					}
					catch
					{
						Write-Warning $_
					}
					try
					{
						Write-Host "     Transferring using Robocopy" -NoNewline -ForegroundColor DarkCyan
						Robocopy "\\$server\c$\windows\temp" "$ScriptPath\output" "$server.$log.evtx" /MOVE /R:2 /W:10 | Out-Null
						Robocopy "\\$server\c$\windows\temp\localemetadata" "$ScriptPath\output" "*.MTA" /MOVE /R:2 /W:10 | Out-Null
						Write-Host "      Transfer Completed!" -NoNewline -ForegroundColor Green
						continue
					}
					catch
					{
						Write-Warning $_
					}
				}
			}
		}
	}
}

				Write-Progress -Activity "Collection Running" -Status "Progress-> 16%" -PercentComplete 16
				if ((Test-Path -Path "$OutputPath\Event Logs") -eq $false)
				{
					Write-Host "  Creating Folder: $OutputPath\Event Logs" -ForegroundColor Gray
					md "$OutputPath\Event Logs" | out-null
				}
				else
				{
					Write-Host "  Existing Folder Found: $OutputPath\Event Logs" -ForegroundColor Gray
					Remove-Item "$OutputPath\Event Logs" -Recurse | Out-Null
					Write-Host "   Deleting folder contents" -ForegroundColor Gray
					md "$OutputPath\Event Logs" | out-null
					Write-Host "    Folder Created: $OutputPath\Event Logs" -ForegroundColor Gray
				}
				Write-Progress -Activity "Collection Running" -Status "Progress-> 18%" -PercentComplete 18
				foreach ($ElogServer in $TestedTLSservers)
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
			"$(Time-Stamp)Unable to gather Event Log data due to Error: $($error[0])" | Out-File $OutputPath\Error.log -Append
			Write-Warning $error[0]
		}
		Write-Progress -Activity "Collection Running" -Status "Progress-> 22%" -PercentComplete 22
		try
		{
			if ($ExportMPs)
			{
				try
				{
					if ($mgmtserver = 1)
					{
						Write-Output "================================`nStarting Management Pack Export"
						Function MP-Export
{
	if ((Test-Path -Path "$OutputPath\Unsealed Management Packs") -eq $false)
	{
		Write-Host "  Creating Folder: $OutputPath\Unsealed Management Packs" -ForegroundColor Gray
		md "$OutputPath\Unsealed Management Packs" | Out-Null
	}
	else
	{
		Write-Host "  Existing Folder Found: $OutputPath\Unsealed Management Packs" -ForegroundColor Gray
		Remove-Item "$OutputPath\Unsealed Management Packs" -Recurse | Out-Null
		Write-Host "   Deleting folder contents" -ForegroundColor Gray
		md "$OutputPath\Unsealed Management Packs" | out-null
		Write-Host "    Folder Created: $OutputPath\Unsealed Management Packs" -ForegroundColor Gray
	}
	
	try
	{
		Get-SCOMManagementPack | Where{ $_.Sealed -eq $false } | Export-SCOMManagementPack -path "$OutputPath\Unsealed Management Packs" | out-null
		Write-Host "    Completed Exporting Unsealed Management Packs" -ForegroundColor Green
	}
	catch
	{
		#potential error code
		#use continue or break keywords
		$e = $_.Exception
		$line = $_.InvocationInfo.ScriptLineNumber
		$msg = $e.Message
		
		Write-Warning "Caught Exception: $e :: Message: $msg :: at line: $line"
		"$(Time-Stamp)Caught Exception: $e :: Message: $msg :: at line: $line" | Out-File $OutputPath\Error.log -Append
	}
	
	if ((Test-Path -Path "$OutputPath\Sealed Management Packs") -eq $false)
	{
		Write-Host "  Creating Folder: $OutputPath\Sealed Management Packs" -ForegroundColor Gray
		md "$OutputPath\Sealed Management Packs" | Out-Null
	}
	else
	{
		Write-Host "  Existing Folder Found: $OutputPath\Sealed Management Packs" -ForegroundColor Gray
		Remove-Item "$OutputPath\Sealed Management Packs" -Recurse | Out-Null
		Write-Host "   Deleting folder contents" -ForegroundColor Gray
		md "$OutputPath\Sealed Management Packs" | out-null
		Write-Host "    Folder Created: $OutputPath\Sealed Management Packs" -ForegroundColor Gray
	}
	
	try
	{
		Get-SCOMManagementPack | Where{ $_.Sealed -eq $true } | Export-SCOMManagementPack -path "$OutputPath\Sealed Management Packs" | out-null
		Write-Host "    Completed Exporting Sealed Management Packs" -ForegroundColor Green
	}
	catch
	{
		#potential error code
		#use continue or break keywords
		$e = $_.Exception
		$line = $_.InvocationInfo.ScriptLineNumber
		$msg = $e.Message
		
		Write-Warning "Caught Exception: $e :: Message: $msg :: at line: $line"
		"$(Time-Stamp)Caught Exception: $e :: Message: $msg :: at line: $line" | Out-File $OutputPath\Error.log -Append
	}
}

						Write-Progress -Activity "Collection Running" -Status "Progress-> 23%" -PercentComplete 23
						MP-Export
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
					Write-Warning $_; "$(Time-Stamp)Unable to gather Event Log data due to Error: $_" | Out-File $OutputPath\Error.log -Append
					Write-Warning $error[0]
				}
			}
		}
		catch
		{
			"$(Time-Stamp)Unable to gather Event Log data due to Error: $($error[0])" | Out-File $OutputPath\Error.log -Append
			Write-Warning $error[0]
		}
		Write-Progress -Activity "Collection Running" -Status "Progress-> 24%" -PercentComplete 24
		try
		{
			if ($GetRulesAndMonitors)
			{
				Write-Output " "
				Write-Host "================================`nGathering Rules and Monitors"
				Write-Progress -Activity "Collection Running" -Status "Progress-> 25%" -PercentComplete 25
				Function Get-RulesAndMonitors
{
	#=================================================================================
	#  Get all Rule and Monitors from SCOM and their properties
	#
	#  Author: Kevin Holman
	#  Modified by: Blake Drumm
	#  Modified Date: 3/3/2022
	#  v1.5
	#=================================================================================
	param ($ManagementServer,
		$OutputDirectory)
	
	
	Write-Verbose "Starting Script to get all rules and monitors in SCOM"
	
	# Parameters section
	#=================================================================================
	IF ($ManagementServer -notmatch "^$ENV:COMPUTERNAME")
	{
		$ManagementServerName = $ManagementServer
		Write-Verbose "    Connecting to Remote SCOM Management Server..."
	}
	ELSE
	{
		$ManagementServerName = "localhost"
		Write-Verbose "    Connecting to local SCOM Management Server..."
	}
	#=================================================================================
	
	
	# Begin MAIN script section
	#=================================================================================
	
	IF (!(Test-Path $OutputDirectory))
	{
		Write-Host "Output folder not found for ($OutputDirectory).  Creating folder..."
		md $OutputDirectory
	}
	Write-Verbose "Output path is ($OutputDirectory)"
	
	# Connect to SCOM
	Write-Verbose "Connecting to SCOM Management Server ($ManagementServerName)..."
	$MG = Get-SCOMManagementGroup -ComputerName $ManagementServerName
	
	#Set output array object to empty
	$RulesAndMonitorsObj = @()
	$RuleReport = @()
	$MonitorReport = @()
	# Begin Rules section
	#=========================
	try
	{
		#Get all the SCOM Rules
		Write-Host "  Gathering all Rules in SCOM..." -ForegroundColor Green
		$Rules = Get-SCOMRule
		Write-Host "   Found $($Rules.Count) rules" -ForegroundColor Gray
		#Create a hashtable of all the SCOM classes for faster retreival based on Class ID
		$Classes = Get-SCOMClass
		$ClassHT = @{ }
		FOREACH ($Class in $Classes)
		{
			$ClassHT.Add("$($Class.Id)", $Class)
		}
		
		#Get GenerateAlert WriteAction module
		$HealthMP = Get-SCOMManagementPack -Name "System.Health.Library"
		$AlertWA = $HealthMP.GetModuleType("System.Health.GenerateAlert")
		$AlertWAID = $AlertWA.Id
		
		Write-Host "    Gathering Properties from each Rule..." -ForegroundColor Green
		$Error.Clear()
		FOREACH ($Rule in $Rules)
		{
			[string]$RuleDisplayName = $Rule.DisplayName
			[string]$RuleName = $Rule.Name
			[string]$RuleID = $Rule.Id
			[string]$TargetDisplayName = ($ClassHT.($Rule.Target.Id.Guid)).DisplayName
			[string]$TargetName = ($ClassHT.($Rule.Target.Id.Guid)).Name
			[string]$Category = $Rule.Category
			[string]$Enabled = $Rule.Enabled
			IF ($Enabled -eq "onEssentialMonitoring") { $Enabled = "TRUE" }
			IF ($Enabled -eq "onStandardMonitoring") { $Enabled = "TRUE" }
			$MP = $Rule.GetManagementPack()
			[string]$MPDisplayName = $MP.DisplayName
			[string]$MPName = $Rule.ManagementPackName
			[string]$RuleDS = $Rule.DataSourceCollection.TypeID.Identifier.Path
			[string]$Description = $Rule.Description
			
			#WriteAction Section
			$GenAlert = $false
			$AlertDisplayName = ""
			$AlertPriority = ""
			$AlertSeverity = ""
			$WA = $Rule.writeactioncollection
			
			#Inspect each WA module to see if it contains a System.Health.GenerateAlert module
			FOREACH ($WAModule in $WA)
			{
				$WAId = $WAModule.TypeId.Id
				IF ($WAId -eq $AlertWAID)
				{
					#this rule generates alert using System.Health.GenerateAlert module
					$GenAlert = $true
					#Get the module configuration
					[string]$WAModuleConfig = $WAModule.Configuration
					#Assign the module configuration the XML type and encapsulate it to make it easy to retrieve values
					[xml]$WAModuleConfigXML = "<Root>" + $WAModuleConfig + "</Root>"
					$WAXMLRoot = $WAModuleConfigXML.Root
					#Check to see if there is an AlertMessageID
					IF ($WAXMLRoot.AlertMessageId)
					{
						#AlertMessageId Exists
						#Get the Alert Display Name from the AlertMessageID
						$AlertName = $WAXMLRoot.AlertMessageId.Split('"')[1]
						IF (!($AlertName))
						{
							$AlertName = $WAXMLRoot.AlertMessageId.Split("'")[1]
						}
						$AlertDisplayName = $MP.GetStringResource($AlertName).DisplayName
					}
					ELSE
					{
						#AlertMessageId Does Not exist.  This is an odd condition where some MPs do not provide this.
						#Attempt to Get the Alert Display Name from the WAXML
						IF ($WAXMLRoot.AlertName)
						{
							$AlertDisplayName = $WAXMLRoot.AlertName
						}
						ELSE
						{
							#We failed to find the Alert Display Name from the AlertMessageId or from the Write Action XML.  Set this to EMPTY value.
							$AlertDisplayName = "EMPTY"
						}
					}
					#Get Alert Priority and Severity
					$AlertPriority = $WAXMLRoot.Priority
					$AlertPriority = switch ($AlertPriority)
					{
						"0" { "Low" }
						"1" { "Medium" }
						"2" { "High" }
					}
					$AlertSeverity = $WAXMLRoot.Severity
					$AlertSeverity = switch ($AlertSeverity)
					{
						"0" { "Information" }
						"1" { "Warning" }
						"2" { "Critical" }
					}
				}
				ELSE
				{
					#need to detect if it's using a Custom Composite WA which contains System.Health.GenerateAlert module
					$WASource = $MG.GetMonitoringModuleType($WAId)
					
					#Check each write action member modules in the customized write action module...
					FOREACH ($Item in $WASource.WriteActionCollection)
					{
						$ItemId = $Item.TypeId.Id
						IF ($ItemId -eq $AlertWAId)
						{
							$GenAlert = $true
							#Get the module configuration
							[string]$WAModuleConfig = $WAModule.Configuration
							#Assign the module configuration the XML type and encapsulate it to make it easy to retrieve values
							[xml]$WAModuleConfigXML = "<Root>" + $WAModuleConfig + "</Root>"
							$WAXMLRoot = $WAModuleConfigXML.Root
							#Check to see if there is an AlertMessageID
							IF ($WAXMLRoot.AlertMessageId)
							{
								#AlertMessageId Exists
								#Get the Alert Display Name from the AlertMessageID
								$AlertName = $WAXMLRoot.AlertMessageId.Split('"')[1]
								IF (!($AlertName))
								{
									$AlertName = $WAXMLRoot.AlertMessageId.Split("'")[1]
								}
								$AlertDisplayName = $MP.GetStringResource($AlertName).DisplayName
							}
							ELSE
							{
								#AlertMessageId Does Not exist.  This is an odd condition where some MPs do not provide this.
								#Attempt to Get the Alert Display Name from the WAXML
								IF ($WAXMLRoot.AlertName)
								{
									$AlertDisplayName = $WAXMLRoot.AlertName
								}
								ELSE
								{
									#We failed to find the Alert Display Name from the AlertMessageId or from the Write Action XML.  Set this to EMPTY value.
									$AlertDisplayName = "EMPTY"
								}
							}
							#Get Alert Priority and Severity
							$AlertPriority = $WAXMLRoot.Priority
							$AlertPriority = switch ($AlertPriority)
							{
								"0" { "Low" }
								"1" { "Medium" }
								"2" { "High" }
							}
							$AlertSeverity = $WAXMLRoot.Severity
							$AlertSeverity = switch ($AlertSeverity)
							{
								"0" { "Information" }
								"1" { "Warning" }
								"2" { "Critical" }
							}
						}
					}
				}
			}
			
			#Create generic object and assign values  
			$obj = New-Object -TypeName psobject
			$obj | Add-Member -Type NoteProperty -Name "ID" -Value $RuleID
			$obj | Add-Member -Type NoteProperty -Name "WorkFlowType" -Value "Rule"
			$obj | Add-Member -Type NoteProperty -Name "DisplayName" -Value $RuleDisplayName
			$obj | Add-Member -Type NoteProperty -Name "Name" -Value $RuleName
			$obj | Add-Member -Type NoteProperty -Name "TargetDisplayName" -Value $TargetDisplayName
			$obj | Add-Member -Type NoteProperty -Name "TargetName" -Value $TargetName
			$obj | Add-Member -Type NoteProperty -Name "Category" -Value $Category
			$obj | Add-Member -Type NoteProperty -Name "Enabled" -Value $Enabled
			$obj | Add-Member -Type NoteProperty -Name "Alert" -Value $GenAlert
			$obj | Add-Member -Type NoteProperty -Name "AlertName" -Value $AlertDisplayName
			$obj | Add-Member -Type NoteProperty -Name "AlertPriority" -Value $AlertPriority
			$obj | Add-Member -Type NoteProperty -Name "AlertSeverity" -Value $AlertSeverity
			$obj | Add-Member -Type NoteProperty -Name "MPDisplayName" -Value $MPDisplayName
			$obj | Add-Member -Type NoteProperty -Name "MPName" -Value $MPName
			$obj | Add-Member -Type NoteProperty -Name "RuleDataSource" -Value $RuleDS
			$obj | Add-Member -Type NoteProperty -Name "MonitorClassification" -Value ""
			$obj | Add-Member -Type NoteProperty -Name "MonitorType" -Value ""
			$obj | Add-Member -Type NoteProperty -Name "Description" -Value $Description
			$RuleReport += $obj
		}
		Write-Host "     Generating Rules (CSV and TXT) at ($OutputDirectory)..." -ForegroundColor Magenta
		$RuleReport | Format-List * | Out-File $OutputDirectory\Rules.txt
		$RuleReport | Export-Csv $OutputDirectory\Rules.csv -NoTypeInformation
		
	}
	catch
	{
		#potential error code
		#use continue or break keywords
		$e = $_.Exception
		$line = $_.InvocationInfo.ScriptLineNumber
		$msg = $e.Message
		
		Write-Verbose "Caught Exception: $e :: Message: $msg :: at line: $line"
		"$(Time-Stamp)Caught Exception: $e :: Message: $msg :: at line: $line" | Out-File $OutputPath\Error.log -Append
	}
	#=========================
	# End Rules section
	Write-Host " "
	# Begin Monitors section
	#=========================
	try
	{
		#Get all the SCOM Monitors
		Write-Host "  Gathering all Monitors in SCOM..." -ForegroundColor Green
		$Monitors = Get-SCOMMonitor
		Write-Host "   Found $($Monitors.Count) monitors" -ForegroundColor Gray
		#Loop through each monitor and get properties
		Write-Host "    Gathering Properties from each Monitor..." -ForegroundColor Green
		FOREACH ($Monitor in $Monitors)
		{
			[string]$MonitorDisplayName = $Monitor.DisplayName
			[string]$MonitorName = $Monitor.Name
			[string]$MonitorID = $Monitor.Id
			[string]$TargetDisplayName = ($ClassHT.($Monitor.Target.Id.Guid)).DisplayName
			[string]$TargetName = ($ClassHT.($Monitor.Target.Id.Guid)).Name
			[string]$Category = $Monitor.Category
			[string]$Enabled = $Monitor.Enabled
			IF ($Enabled -eq "onEssentialMonitoring") { $Enabled = "TRUE" }
			IF ($Enabled -eq "onStandardMonitoring") { $Enabled = "TRUE" }
			$MP = $Monitor.GetManagementPack()
			[string]$MPDisplayName = $MP.DisplayName
			[string]$MPName = $MP.Name
			[string]$MonitorClassification = $Monitor.XmlTag
			[string]$MonitorType = $Monitor.TypeID.Identifier.Path
			[string]$Description = $Monitor.Description
			
			# Get the Alert Settings for the Monitor
			$AlertSettings = $Monitor.AlertSettings
			$GenAlert = ""
			$AlertDisplayName = ""
			$AlertSeverity = ""
			$AlertPriority = ""
			$AutoResolve = ""
			
			IF (!($AlertSettings))
			{
				$GenAlert = $false
			}
			ELSE
			{
				$GenAlert = $true
				#Get the Alert Display Name from the AlertMessageID and MP
				$AlertName = $AlertSettings.AlertMessage.Identifier.Path
				$AlertDisplayName = $MP.GetStringResource($AlertName).DisplayName
				$AlertSeverity = $AlertSettings.AlertSeverity
				IF ($AlertSeverity -eq "MatchMonitorHealth") { $AlertSeverity = $AlertSettings.AlertOnState }
				IF ($AlertSeverity -eq "Error") { $AlertSeverity = "Critical" }
				$AlertPriority = $AlertSettings.AlertPriority
				IF ($AlertPriority -eq "Normal") { $AlertPriority = "Medium" }
				$AutoResolve = $AlertSettings.AutoResolve
			}
			
			#Create generic object and assign values  
			$obj = New-Object -TypeName psobject
			$obj | Add-Member -Type NoteProperty -Name "ID" -Value $MonitorID
			$obj | Add-Member -Type NoteProperty -Name "WorkFlowType" -Value "Monitor"
			$obj | Add-Member -Type NoteProperty -Name "DisplayName" -Value $MonitorDisplayName
			$obj | Add-Member -Type NoteProperty -Name "Name" -Value $MonitorName
			$obj | Add-Member -Type NoteProperty -Name "TargetDisplayName" -Value $TargetDisplayName
			$obj | Add-Member -Type NoteProperty -Name "TargetName" -Value $TargetName
			$obj | Add-Member -Type NoteProperty -Name "Category" -Value $Category
			$obj | Add-Member -Type NoteProperty -Name "Enabled" -Value $Enabled
			$obj | Add-Member -Type NoteProperty -Name "Alert" -Value $GenAlert
			$obj | Add-Member -Type NoteProperty -Name "AlertName" -Value $AlertDisplayName
			$obj | Add-Member -Type NoteProperty -Name "AlertPriority" -Value $AlertPriority
			$obj | Add-Member -Type NoteProperty -Name "AlertSeverity" -Value $AlertSeverity
			$obj | Add-Member -Type NoteProperty -Name "MPDisplayName" -Value $MPDisplayName
			$obj | Add-Member -Type NoteProperty -Name "MPName" -Value $MPName
			$obj | Add-Member -Type NoteProperty -Name "RuleDataSource" -Value ""
			$obj | Add-Member -Type NoteProperty -Name "MonitorClassification" -Value $MonitorClassification
			$obj | Add-Member -Type NoteProperty -Name "MonitorType" -Value $MonitorType
			$obj | Add-Member -Type NoteProperty -Name "Description" -Value $Description
			$MonitorReport += $obj
		}
		
		Write-Host "     Generating Monitors (CSV and TXT) at ($OutputDirectory)..." -ForegroundColor Magenta
		$MonitorReport | Format-List * | Out-File $OutputDirectory\Monitors.txt
		$MonitorReport | Export-Csv $OutputDirectory\Monitors.csv -NoTypeInformation
	}
	catch
	{
		#potential error code
		#use continue or break keywords
		$e = $_.Exception
		$line = $_.InvocationInfo.ScriptLineNumber
		$msg = $e.Message
		
		Write-Verbose "Get-RulesAndMonitors - Caught Exception: $e :: Message: $msg :: at line: $line"
		"$(Time-Stamp)Get-RulesAndMonitors - Caught Exception: $e :: Message: $msg :: at line: $line" | Out-File $OutputPath\Error.log -Append
	}
	#=========================
	# End Monitors section
	#End of Script
}

				Get-RulesAndMonitors -OutputDirectory $OutputPath -ManagementServer $ManagementServers[0]
				Write-Output " "
			}
		}
		catch
		{
			"$(Time-Stamp)Unable to gather Rules and Monitors data due to Error: $($error[0])" | Out-File $OutputPath\Error.log -Append
			Write-Warning $error[0]
		}
		Write-Progress -Activity "Collection Running" -Status "Progress-> 26%" -PercentComplete 26
		try
		{
			if ($GetLocalSecurity)
			{
				write-output " "
				Write-Host "====================================================================`nGathering the Local Security Policies & Local Administrators Group"
				function Get-LocalUserAccountsRights
{
	param
	(
		[Parameter(Mandatory = $false,
				   Position = 1)]
		[array]$Servers
	)
	trap
	{
		#potential error code
		#use continue or break keywords
		$e = $_.Exception
		$line = $_.InvocationInfo.ScriptLineNumber
		$msg = $e.Message
		
		Write-Verbose "Caught Exception: $e :: Message: $msg :: at line: $line"
		"$(Time-Stamp)Caught Exception: $e :: Message: $msg :: at line: $line" | Out-File $OutputPath\Error.log -Append
	}
	if (!$Servers)
	{
		$Servers = $env:COMPUTERNAME
	}
	
	function Inner-LocalAdministrators
	{
		$members = net localgroup administrators |
		where { $_ -AND $_ -notmatch "command completed successfully" } |
		select -skip 4
		
		$dtable = New-Object System.Data.DataTable
		$dtable.Columns.Add("ComputerName", "System.String") | Out-Null
		$dtable.Columns.Add("Group", "System.String") | Out-Null
		$dtable.Columns.Add("Members", "System.String") | Out-Null
		
		foreach ($member in $members)
		{
			Write-Host "-" -ForegroundColor DarkCyan -NoNewline
			$nRow = $dtable.NewRow()
			$nRow.ComputerName = $env:COMPUTERNAME
			$nRow.Group = "Administrators"
			$nRow.Members = $member
			
			$dtable.Rows.Add($nRow)
		}
		return $dtable
	}
	Write-Host "  Gathering Local Administrators:" -ForegroundColor DarkCyan
	$localadmin = @()
	$localAdministratorsScriptBlock = (get-item Function:Inner-LocalAdministrators).ScriptBlock
	foreach ($Server in $Servers)
	{
		Write-Host "   $Server" -ForegroundColor Cyan -NoNewline
		if ($Server -match $env:COMPUTERNAME)
		{
			Write-Host "-" -ForegroundColor DarkCyan -NoNewline
			$localadmin += Inner-LocalAdministrators
		}
		else
		{
			Write-Host "-" -ForegroundColor DarkCyan -NoNewline
			$localadmin += Invoke-Command -ComputerName $Server -ScriptBlock $localAdministratorsScriptBlock -HideComputerName | Select * -ExcludeProperty RunspaceID, PSShowComputerName, PSComputerName | Sort-Object -Property @{ Expression = "ComputerName"; Descending = $False }, @{ Expression = "Members"; Descending = $False }
		}
		Write-Host "> " -ForegroundColor DarkCyan -NoNewline
		Write-Host 'Complete!' -ForegroundColor Green
	}
	Write-Host " "
	New-Item -ItemType Directory -Path "$OutputPath\Local Administrators Group" -Force -ErrorAction Stop | Out-Null
	$localadmin | Export-CSV $OutputPath\Server_LocalAdministratorsGroup.csv -NoTypeInformation
	$localadmin | Out-String -Width 4096 | Out-File "$OutputPath\Local Administrators Group\LocalAdministratorsGroup.txt"
	Write-Host "  Gathering Local User Rights Assignment:" -ForegroundColor DarkCyan
	$localrights = @()
	function Inner-UserSecurityRights
	{
		# The better version of this function is located here: https://github.com/blakedrumm/SCOM-Scripts-and-SQL/blob/master/Powershell/General%20Functions/Get-UserRights.ps1
		# Full blog post here: https://blakedrumm.com/blog/set-and-check-user-rights-assignment/
		function Get-SecurityPolicy
		{
			#requires -version 2
			
			# Fail script if we can't find SecEdit.exe
			$SecEdit = Join-Path ([Environment]::GetFolderPath([Environment+SpecialFolder]::System)) "SecEdit.exe"
			if (-not (Test-Path $SecEdit))
			{
				Write-Error "File not found - '$SecEdit'" -Category ObjectNotFound
				return
			}
			
			# LookupPrivilegeDisplayName Win32 API doesn't resolve logon right display
			# names, so use this hashtable
			$UserLogonRights = @{
				"SeBatchLogonRight"				    = "Log on as a batch job"
				"SeDenyBatchLogonRight"			    = "Deny log on as a batch job"
				"SeDenyInteractiveLogonRight"	    = "Deny log on locally"
				"SeDenyNetworkLogonRight"		    = "Deny access to this computer from the network"
				"SeDenyRemoteInteractiveLogonRight" = "Deny log on through Remote Desktop Services"
				"SeDenyServiceLogonRight"		    = "Deny log on as a service"
				"SeInteractiveLogonRight"		    = "Allow log on locally"
				"SeNetworkLogonRight"			    = "Access this computer from the network"
				"SeRemoteInteractiveLogonRight"	    = "Allow log on through Remote Desktop Services"
				"SeServiceLogonRight"			    = "Log on as a service"
			}
			
			# Create type to invoke LookupPrivilegeDisplayName Win32 API
			$Win32APISignature = @'
[DllImport("advapi32.dll", SetLastError=true)]
public static extern bool LookupPrivilegeDisplayName(
  string systemName,
  string privilegeName,
  System.Text.StringBuilder displayName,
  ref uint cbDisplayName,
  out uint languageId
);
'@
			$AdvApi32 = Add-Type advapi32 $Win32APISignature -Namespace LookupPrivilegeDisplayName -PassThru
			
			# Use LookupPrivilegeDisplayName Win32 API to get display name of privilege
			# (except for user logon rights)
			function Get-PrivilegeDisplayName
			{
				param (
					[String]$name
				)
				$displayNameSB = New-Object System.Text.StringBuilder 1024
				$languageId = 0
				$ok = $AdvApi32::LookupPrivilegeDisplayName($null, $name, $displayNameSB, [Ref]$displayNameSB.Capacity, [Ref]$languageId)
				if ($ok)
				{
					$displayNameSB.ToString()
				}
				else
				{
					# Doesn't lookup logon rights, so use hashtable for that
					if ($UserLogonRights[$name])
					{
						$UserLogonRights[$name]
					}
					else
					{
						$name
					}
				}
			}
			# Outputs list of hashtables as a PSObject
			function Out-Object
			{
				param (
					[System.Collections.Hashtable[]]$hashData
				)
				$order = @()
				$result = @{ }
				$hashData | ForEach-Object {
					$order += ($_.Keys -as [Array])[0]
					$result += $_
				}
				$out = New-Object PSObject -Property $result | Select-Object $order
				return $out
			}
			
			# Translates a SID in the form *S-1-5-... to its account name;
			function Get-AccountName
			{
				param (
					[String]$principal
				)
				try
				{
					$sid = New-Object System.Security.Principal.SecurityIdentifier($principal.Substring(1))
					$sid.Translate([Security.Principal.NTAccount])
				}
				catch { $principal }
			}
			
			$TemplateFilename = Join-Path ([IO.Path]::GetTempPath()) ([IO.Path]::GetRandomFileName())
			$LogFilename = Join-Path ([IO.Path]::GetTempPath()) ([IO.Path]::GetRandomFileName())
			$StdOut = & $SecEdit /export /cfg $TemplateFilename /areas USER_RIGHTS /log $LogFilename
			if ($LASTEXITCODE -eq 0)
			{
				$dtable = $null
				$dtable = New-Object System.Data.DataTable
				$dtable.Columns.Add("Privilege", "System.String") | Out-Null
				$dtable.Columns.Add("PrivilegeName", "System.String") | Out-Null
				$dtable.Columns.Add("Principal", "System.String") | Out-Null
				$dtable.Columns.Add("ComputerName", "System.String") | Out-Null
				Select-String '^(Se\S+) = (\S+)' $TemplateFilename | Foreach-Object {
					Write-Host "-" -ForegroundColor DarkCyan -NoNewline
					$Privilege = $_.Matches[0].Groups[1].Value
					$Principals = $_.Matches[0].Groups[2].Value -split ','
					foreach ($Principal in $Principals)
					{
						$nRow = $dtable.NewRow()
						$nRow.Privilege = $Privilege
						$nRow.PrivilegeName = Get-PrivilegeDisplayName $Privilege
						$nRow.Principal = Get-AccountName $Principal
						$nRow.ComputerName = $env:COMPUTERNAME
						
						$dtable.Rows.Add($nRow)
					}
					return $dtable
					
				}
			}
			else
			{
				$OFS = ""
				Write-Error "$StdOut"
			}
			Remove-Item $TemplateFilename, $LogFilename -ErrorAction SilentlyContinue
		}
		return Get-SecurityPolicy
	}
	$localUserSecurityRightsScriptBlock = (get-item Function:Inner-UserSecurityRights).ScriptBlock
	foreach ($Server in $Servers)
	{
		Write-Host "   $Server" -ForegroundColor Cyan -NoNewline
		if ($Server -match "^$env:COMPUTERNAME")
		{
			Write-Host "-" -ForegroundColor DarkCyan -NoNewline
			$localrights += Inner-UserSecurityRights
		}
		else
		{
			Write-Host "-" -ForegroundColor DarkCyan -NoNewline
			$localrights += Invoke-Command -ComputerName $Server -ScriptBlock $localUserSecurityRightsScriptBlock -HideComputerName | Select * -ExcludeProperty RunspaceID, PSShowComputerName, PSComputerName -Unique
		}
		Write-Host "> " -ForegroundColor DarkCyan -NoNewline
		Write-Host 'Complete!' -ForegroundColor Green
	}
	New-Item -ItemType Directory -Path "$OutputPath\Local User Rights" -Force -ErrorAction Stop | Out-Null
	# Export CSV
	$localrights | Select-Object Privilege, PrivilegeName, Principal, ComputerName -Unique | Export-CSV $OutputPath\Server_UserRightsAssignment.csv -NoTypeInformation
	# Export TXT
	$localrights | Select-Object Privilege, PrivilegeName, Principal, ComputerName -Unique | Format-Table -AutoSize | Out-String -Width 4096 | Out-File "$OutputPath\Local User Rights\UserRightsAssignment.txt"
}

				Write-Progress -Activity "Collection Running" -Status "Progress-> 27%" -PercentComplete 27
				Get-LocalUserAccountsRights -Servers $TestedTLSservers
			}
		}
		catch
		{
			"$(Time-Stamp)Unable to gather Local Security / User Account Rights data due to Error: $($error[0])" | Out-File $OutputPath\Error.log -Append
			Write-Warning $error[0]
		}
		Write-Progress -Activity "Collection Running" -Status "Progress-> 30%" -PercentComplete 30
		try
		{
			if ($CheckPorts)
			{
				function Test-SCOMPorts
{
	param
	(
		[Parameter(Mandatory = $false,
				   Position = 1)]
		[array]$SourceServer,
		[Parameter(Mandatory = $true,
				   ValueFromPipeline = $true,
				   Position = 2)]
		[array]$DestinationServer,
		[Parameter(Position = 3)]
		[string]$OutputFile,
		[Parameter(Position = 4)]
		[ValidateSet("Text", "CSV", "Table")]
		[string[]]$OutputType
	)
	<#
	.SYNOPSIS
		Test the ports SCOM Uses with Test-NetConnection Automatically.
	
	.DESCRIPTION
		This script tests the ports for SCOM.
	
	.PARAMETER SourceServer
		A description of the SourceServer parameter.
	
	.PARAMETER DestinationServer
		A description of the DestinationServer parameter.
	
	.PARAMETER OutputFile
		A description of the OutputFile parameter.
	
	.PARAMETER OutputType
		A description of the OutputType parameter.
	
	.PARAMETER Servers
		An array of Servers, or alternatively you can pipe in objects from Get-SCOMAgent or Get-SCOMManagementServer.
	
	.EXAMPLE
		PS C:\> Get-SCOMAgent | Where {$_.Name -match "IIS-server"} | .\Test-SCOMPorts
		PS C:\> Get-SCOMManagementServer | .\Test-SCOMPorts
		PS C:\> .\Test-SCOMPorts -Servers Agent1.contoso.com, SQL-Server.contoso.com
	
	.NOTES
		.AUTHOR
		Blake Drumm (blakedrumm@microsoft.com)
		.LAST MODIFIED
		08/04/2021
		
		https://www.stefanroth.net/2013/10/08/powershell-4-0-checking-scom-required-ports/
#>
	if ($OutputFile)
	{
		if (!$OutputType)
		{
			$OutputType = 'Text'
		}
	}
	else
	{
		if ($OutputType -eq 'Text')
		{
			$OutputFile = "$PSScriptRoot`\SCOM-Port-Checker.txt"
		}
		elseif ($OutputType -eq 'CSV')
		{
			$OutputFile = "$PSScriptRoot`\SCOM-Port-Checker.csv"
		}
	}
	if (!$SourceServer)
	{
		$SourceServer = $env:COMPUTERNAME
	}
	if ($DestinationServer -match 'Microsoft.EnterpriseManagement.Administration.ManagementServer')
	{
		$DestinationServer = $DestinationServer.DisplayName
	}
	elseif ($DestinationServer -match 'Microsoft.EnterpriseManagement.Administration.AgentManagedComputer')
	{
		$DestinationServer = $DestinationServer.DisplayName
	}
	else
	{
		$DestinationServer = $DestinationServer
	}
	Write-Output " "
	Write-Output @"
================================
Starting SCOM Port Checker
"@
Write-Host "  Running function:"
	function Check-SCOMPorts
	{
		param
		(
			[Parameter(Mandatory = $true,
					   Position = 0)]
			[array]$DestinationServer,
			[Parameter(Mandatory = $false,
					   Position = 1)]
			[array]$SourceServer
		)
		$payload = $null
		$payload = @()
		Write-Host "    $env:COMPUTERNAME" -ForegroundColor Cyan -NoNewLine
		$ports = @{
			"Management Server / Agent Port"   = 5723;
			"Web Console / Console Port"	   = 5724;
			"Connector Framework Source Port"  = 51905;
			"ACS Forwarder Port"			   = 51909;
			"AEM Port"						   = 51906;
			"SQL Server (Default) Port"	       = 1433;
			"SSH Port"						   = 22;
			"WS-MAN Port"					   = 1270;
			"Web Console (HTTP) Port"		   = 80;
			"Web Console (HTTPS) Port"		   = 443;
			"SNMP (Get) Port"				   = 161;
			"SNMP (Trap) Port"				   = 162
			
			"Remote Procedure Call (DCOM/RPC)" = 135;
			#"NetBIOS (Name Services UDP)"  = 137;
			#"NetBIOS (Datagram Services UDP)"  = 138;
			"NetBIOS (Session Services)"	   = 139;
			"SMB Over IP (Direct TCP/IP)"	   = 445;
			#"Private/Dynamic Range (Beginning)" = 49152;
			#"Private/Dynamic Range (Middle)" = 57343;
			#"Private/Dynamic Range (End)" = 65535;
		}
		foreach ($server in $DestinationServer)
		{
			ForEach ($port in $ports.GetEnumerator())
			{
				$tcp = $null
				$tcp = Test-NetConnection -Computername $server -Port $port.Value -WarningAction SilentlyContinue
				Write-Host '-' -ForegroundColor Green -NoNewline
				Switch ($($tcp.TcpTestSucceeded))
				{
					True { $payload += new-object psobject -property @{ Availability = 'Up'; 'Service Name' = $($port.Name); Port = $($port.Value); SourceServer = $env:COMPUTERNAME; DestinationServer = $server } }
					
					False { $payload += new-object psobject -property @{ Availability = 'Down'; 'Service Name' = $($port.Name); Port = $($port.Value); SourceServer = $env:COMPUTERNAME; DestinationServer = $server } }
				}
			}
			
		}
		Write-Host '> Complete!' -ForegroundColor Green
		return $payload
	}
	$sb = (get-item Function:Check-SCOMPorts).ScriptBlock
	foreach ($source in $SourceServer)
	{
		if ($source -match $env:COMPUTERNAME)
		{
			$scriptout += Check-SCOMPorts -SourceServer $source -DestinationServer $DestinationServer
		}
		else
		{
			$scriptout += Invoke-Command -ComputerName $source -ScriptBlock $sb -ArgumentList ( ,$DestinationServer)
		}
		
	}
	
	$finalout = $scriptout | select 'Service Name', SourceServer, Port, Availability, DestinationServer | Sort-Object -Property @{
		expression = 'SourceServer'
		descending = $false
	}, @{
		expression = 'DestinationServer'
		descending = $false
	}, @{
		expression = 'Port'
		descending = $false
	}
	if ($OutputType -eq 'CSV')
	{
		#Write-Host "Output to " -NoNewline -ForegroundColor Gray
		#Write-Host $OutputFile -NoNewline -ForegroundColor Cyan
		$finalout | Export-Csv -Path $OutputFile -NoTypeInformation
	}
	elseif ($OutputType -eq 'Text')
	{
		#Write-Host "Output to " -NoNewline -ForegroundColor Gray
		#Write-Host $OutputFile -NoNewline -ForegroundColor Cyan
		$finalout | ft * | Out-File $OutputFile
	}
	elseif ($OutputType -eq 'Table')
	{
		$finalout | ft *
	}
}

				Write-Progress -Activity "Collection Running" -Status "Progress-> 32%" -PercentComplete 32
				Test-SCOMPorts -SourceServer $TestedTLSservers -DestinationServer $env:COMPUTERNAME -OutputFile $OutputPath\Port_Checker.txt
			}
		}
		catch
		{
			"$(Time-Stamp)Unable to Test SCOM Ports due to Error: $($error[0])" | Out-File $OutputPath\Error.log -Append
			Write-Warning $error[0]
		}
		Write-Progress -Activity "Collection Running" -Status "Progress-> 34%" -PercentComplete 34
		try
		{
			if ($msinfo32)
			{
				write-output " "
				Write-Host "================================`nStarting MSInfo32 reporting"
				Function MSInfo32-Gathering 
{
	if ((Test-Path -Path "$OutputPath\MSInfo32") -eq $false)
		{
			md $OutputPath\MSInfo32 | out-null
		}
		else
		{
			Remove-Item $OutputPath\MSInfo32 -Recurse
		}
		try
		{
			$TestedTLSservers | % { $serv = $_; Write-Host "    Gathering MSInfo32 from: " -NoNewline; Write-Host "$serv" -ForegroundColor Cyan; Start-Process "msinfo32.exe" -ArgumentList "/report `"$OutputPath\MSInfo32\$_.msinfo32.txt`" /computer $serv" -NoNewWindow -Wait; $serv = $null; }
		}
		catch
		{
			Write-Warning "     Issue gathering MSInfo32 with this command: msinfo32.exe /report `"C:\Windows\Temp\$serv.msinfo32.txt`" /computer $serv"
			$sessions = New-PSSession -ComputerName $TestedTLSservers
			Invoke-Command -Session $sessions {
				$Name = $env:COMPUTERNAME
				$FileName = "$name" + ".msinfo32.txt"
				#msinfo32 /report "c:\windows\Temp\$FileName"
				msinfo32 /report "c:\windows\Temp\$FileName"
				$runtime = 6
				$Run = 1
				while ($Run -eq 1)
				{
					$running = $null
					$running = get-process msinfo32 -ea SilentlyContinue
					if ($running)
					{
						Write-Host "    MSInfo32 is still running on $name. Pausing 1 minute, and rechecking..."
						start-sleep -Seconds 60
						$run = 1
						$runtime = $runtime - 1
						if ($runtime -lt 1)
						{
							Write-Warning "    MSInfo32 process on $name appears hung, killing process"
							get-process msinfo32 | kill
							$run = 0
						}
					}
					else
					{
						$run = 0
					}
				}
			}
			Write-Host "    Completed on $name" -ForegroundColor
			Get-PSSession | Remove-PSSession
			write-Output " "
			Write-output "Moving MSInfo32 Reports to $env:COMPUTERNAME"
			foreach ($rserv in $TestedTLSservers)
			{
				Write-output " Retrieving MSInfo32 Report from $rserv"
				Move-Item "\\$rserv\c$\windows\Temp\*.msinfo32.txt" "$OutputPath\MSInfo32"
				Write-Host "    Completed Retrieving MSInfo32 Report from $rserv" -ForegroundColor Green
			}
		}
}

				Write-Progress -Activity "Collection Running" -Status "Progress-> 36%" -PercentComplete 36
				MSInfo32-Gathering
			}
		}
		catch
		{
			"$(Time-Stamp)Unable to gather MSInfo32 data due to Error: $($error[0])" | Out-File $OutputPath\Error.log -Append
			Write-Warning $error[0]
		}
		try
		{
			if ($GetNotificationSubscriptions)
			{
				write-output " "
				Write-Host "================================`nGathering Notification Subscriptions"
				function Get-SCOMNotificationSubscriptionDetails
{
	param
	(
		[Parameter(Mandatory = $false)]
		[string]$OutputFile
	)
	#Originally found here: https://blog.topqore.com/export-scom-subscriptions-using-powershell/
	# Located here: https://github.com/blakedrumm/SCOM-Scripts-and-SQL/blob/master/Powershell/Get-SCOMNotificationSubscriptionDetails.ps1
	# Modified by: Blake Drumm (blakedrumm@microsoft.com)
	# Date Modified: 08/03/2021
	$finalstring = $null
	$subs = $null
	$subs = Get-SCOMNotificationSubscription | Sort-Object
	$subcount = 0
	Write-Host "  Gathering Notification Subscription Details from " -ForegroundColor Gray -NoNewline
    Write-Host $env:COMPUTERNAME -ForegroundColor Cyan
	foreach ($sub in $subs)
	{
		$subcount = $subcount
		$subcount++
		#empty all the variables
		$monitor = $null
		$rule = $null
		$Instance = $null
		$Desc = $null
		$classid = $null
		$groupid = $null
		$class = $null
		$Group = $null
		$Name = $sub.DisplayName
		$finalstring += "`n`n==========================================================`n"
		$MainObject = New-Object PSObject
		$MainObject | Add-Member -MemberType NoteProperty -Name 'Subscription Name' -Value $Name
		$MainObject | Add-Member -MemberType NoteProperty -Name 'Subscription Enabled' -Value $sub.Enabled
		$MainObject | Add-Member -MemberType NoteProperty -Name 'Subscription Description' -Value $sub.Description
		$MainObject | Add-Member -MemberType NoteProperty -Name ' ' -Value "`n-------- Subscription Criteria --------"
		$tempcriteria = $null
		$templatesub = $sub.Configuration.Criteria
		$expression = $templatesub | Select-Xml -XPath "//SimpleExpression" | foreach { $_.node.InnerXML }
		$val = Select-Xml -Content $templatesub -XPath "//Value" | foreach { $_.node.InnerXML }
		$operators = Select-Xml -Content $templatesub -XPath "//Operator" | foreach { $_.node.InnerXML }
		$properties = Select-Xml -Content $templatesub -XPath "//Property" | foreach { $_.node.InnerXML }
		$i = 0
		do
		{
			foreach ($property in $properties)
			{
				if ($property -eq "ProblemId")
				{
					$monitor = (Get-SCOMMonitor -Id $($val | Select-Object -Index $i)).DisplayName
					$tempcriteria += "  " + ($i + 1) + ") Raised by Monitor: $monitor" + "`n"
				}
				elseif ($property -eq "RuleId")
				{
					$rule = (Get-SCOMRule -Id $($val | Select-Object -Index $i)).DisplayName
					$tempcriteria += "  " + ($i + 1) + ") Raised by Rule: $rule" + "`n"
				}
				elseif ($property -eq "BaseManagedEntityId")
				{
					$Instance = (Get-SCOMClassInstance -Id $($val | Select-Object -Index $i)).DisplayName
					$tempcriteria += "  " + ($i + 1) + ") Raised by Instance: $Instance" + "`n"
				}
				elseif ($property -eq "Severity")
				{
					$verbose_severity = switch ($($val | Select-Object -Index $i))
					{
						'0' { 'Informational' }
						'1' { 'Warning' }
						'2' { 'Critical' }
						Default { $($val | Select-Object -Index $i) }
					}
					$tempcriteria += "  " + ($i + 1) + ") " + $property + " " + $($operators | Select-Object -Index $i) + " " + $verbose_severity + "`n"
				}
				elseif ($property -eq "Priority")
				{
					$tempcriteria += "  " + ($i + 1) + ") $property $($operators | Select-Object -Index $i) $($val | Select-Object -Index $i) `n"
				}
				elseif ($property -eq "ResolutionState")
				{
					$tempcriteria += "  " + ($i + 1) + ") $property $($operators | Select-Object -Index $i) $($val | Select-Object -Index $i) `n"
				}
				elseif ($property -eq "AlertDescription")
				{
					$tempcriteria += "  " + ($i + 1) + ") $property $($operators | Select-Object -Index $i) $($val | Select-Object -Index $i) `n"
				}
				elseif ($property -eq "AlertName")
				{
					$tempcriteria += "  " + ($i + 1) + ") $property $($operators | Select-Object -Index $i) $($val | Select-Object -Index $i) `n"
				}
				else
				{
					$tempcriteria += "  " + ($i + 1) + ") $property $($operators | Select-Object -Index $i) $($val | Select-Object -Index $i) `n"
				}
				$i++
				continue
			}
		}
		until ($i -eq $val.Count)
		#$MainObject | Add-Member -MemberType NoteProperty -Name ("Criteria ") -Value 
		$MainObject | Add-Member -MemberType NoteProperty -Name 'Criteria' -Value ($tempcriteria + "`n-------- Subscription Scope --------")
		
		#Check for class/group
		$i = 0
		$classid = $sub.Configuration.MonitoringClassIds
		$groupid = $sub.Configuration.MonitoringObjectGroupIds
		if ($classid -ne $null)
		{
			$class = Get-SCOMClass -Id $classid
		}
		if ($groupid -ne $null)
		{
			$Group = Get-SCOMGroup -Id $groupid
		}
		if ($class -and !$Group)
		{
			$classStr = ''
			for ($i = 1; $i -le $class.Count; $i++)
			{
				$classStr += "`n `r $i) " + $class[$i - 1].DisplayName
			}
			$MainObject | Add-Member -MemberType NoteProperty -Name "Raised by an instance of a specific class" -Value $classStr
		}
		if ($group -and !$class)
		{
			$groupStr = ''
			for ($i = 1; $i -le $Group.Count; $i++)
			{
				$groupStr += "`n `r $i) " + $Group[$i - 1].DisplayName
			}
			$MainObject | Add-Member -MemberType NoteProperty -Name "Raised by an instance of a specific group" -Value $groupStr
		}
		if ($class -and $Group)
		{
			$groupStr = ''
			Foreach ($targetgroup in $Group)
			{
				$groupStr += $targetgroup.DisplayName.Split(", ")
			}
			
			$classStr = ''
			
			Foreach ($targetclass in $Class)
			{
				$classStr += $targetclass.DisplayName.Split(", ")
			}
			$MainObject | Add-Member -MemberType NoteProperty -Name "Raised by an instance of a specific group" -Value $groupStr
			$MainObject | Add-Member -MemberType NoteProperty -Name "Raised by an instance of a specific class" -Value $classStr
		}
		
		$MainObject | Add-Member -MemberType NoteProperty -Name '   ' -Value "`n`n-------- Subscriber Information --------"
		$subscribers = $sub.ToRecipients
		$i = 0
		foreach ($subscriber in $subscribers)
		{
			$i = $i
			$i++
			$MainObject | Add-Member -MemberType NoteProperty -Name "Subscriber Name | $i" -Value $subscriber.Name
			(97 .. (97 + 25)).ForEach({ [array]$abc += [char]$_ })
			$number = 0
			foreach ($protocol in $subscriber.Devices.Protocol)
			{
				$protocoltype = switch ($protocol)
				{
					'SIP' { 'Instant Message (IM)' }
					{ $_ -like 'Cmd*' } { 'Command' }
					'SMTP' { 'E-Mail (SMTP)' }
					'SMS' { 'Text Message (SMS)' }
					Default { $protocol }
				}
				$number++
				$MainObject | Add-Member -MemberType NoteProperty -Name "   Channel Type | $i$($abc | Select-Object -Index $($number))" -Value $protocoltype
				$MainObject | Add-Member -MemberType NoteProperty -Name "   Subscriber Address Name | $i$($abc[$number])" -Value $($subscriber.Devices.Name | Select-Object -Index $($number - 1))
				$MainObject | Add-Member -MemberType NoteProperty -Name "   Subscriber Address Destination | $i$($abc[$number])" -Value $($subscriber.Devices.Address | Select-Object -Index $($number - 1))
			}
		}
		$i = 0
		$MainObject | Add-Member -MemberType NoteProperty -Name '     ' -Value "`n`n-------- Channel Information --------"
		foreach ($action in $sub.Actions)
		{
			$i = $i
			$i++
			$MainObject | Add-Member -MemberType NoteProperty -Name ("       Channel Name | $i") -Value ($action.Displayname)
			$MainObject | Add-Member -MemberType NoteProperty -Name ("       ID | $i") -Value ($action.ID)
			$MainObject | Add-Member -MemberType NoteProperty -Name ("       Channel Description | $i") -Value ($action.description)
			if ($action.Endpoint -like "Smtp*")
			{
				#Get the SMTP channel endpoint
				$MainObject | Add-Member -MemberType NoteProperty -Name ("       Primary SMTP Server | $i") -Value ($action.Endpoint.PrimaryServer.Address)
				$MainObject | Add-Member -MemberType NoteProperty -Name ("       Primary SMTP Port | $i") -Value ($action.Endpoint.PrimaryServer.PortNumber)
				$MainObject | Add-Member -MemberType NoteProperty -Name ("       Primary SMTP Authentication Type | $i") -Value ($action.Endpoint.PrimaryServer.AuthenticationType)
				$MainObject | Add-Member -MemberType NoteProperty -Name ("       Primary SMTP ExternalEmailProfile | $i") -Value ($action.Endpoint.PrimaryServer.ExternalEmailProfile)
				$MainObject | Add-Member -MemberType NoteProperty -Name ("       Secondary SMTP Server | $i") -Value ($action.Endpoint.SecondaryServers.Address)
				$MainObject | Add-Member -MemberType NoteProperty -Name ("       Secondary SMTP Port | $i") -Value ($action.Endpoint.SecondaryServers.PortNumber)
				$MainObject | Add-Member -MemberType NoteProperty -Name ("       Secondary SMTP Authentication Type | $i") -Value ($action.Endpoint.SecondaryServers.AuthenticationType)
				$MainObject | Add-Member -MemberType NoteProperty -Name ("       Secondary SMTP ExternalEmailProfile | $i") -Value ($action.Endpoint.SecondaryServers.ExternalEmailProfile)
				$MainObject | Add-Member -MemberType NoteProperty -Name ("       From | $i") -Value ($action.From)
				$MainObject | Add-Member -MemberType NoteProperty -Name ("       Subject | $i") -Value ($action.Subject)
				$MainObject | Add-Member -MemberType NoteProperty -Name ("       Endpoint | $i") -Value ($action.Endpoint)
				$MainObject | Add-Member -MemberType NoteProperty -Name ("       Body Encoding | $i") -Value ($action.BodyEncoding)
				$MainObject | Add-Member -MemberType NoteProperty -Name ("       Reply To | $i") -Value ($action.ReplyTo)
				$MainObject | Add-Member -MemberType NoteProperty -Name ("       Headers | $i") -Value ($action.Headers)
				$MainObject | Add-Member -MemberType NoteProperty -Name ("       Is Body HTML? | $i") -Value ($action.IsBodyHtml)
				$MainObject | Add-Member -MemberType NoteProperty -Name ("       Body | $i") -Value ($action.body)
			}
			elseif ($action.RecipientProtocol -like "Cmd*")
			{
				$MainObject | Add-Member -MemberType NoteProperty -Name ("       Application Name | $i") -Value ($action.ApplicationName)
				$MainObject | Add-Member -MemberType NoteProperty -Name ("       Working Directory | $i") -Value ($action.WorkingDirectory)
				$MainObject | Add-Member -MemberType NoteProperty -Name ("       Command Line | $i") -Value ($action.CommandLine)
				$MainObject | Add-Member -MemberType NoteProperty -Name ("       Timeout | $i") -Value ($action.Timeout)
			}
			elseif ($action.Endpoint -like "Im*")
			{
				$MainObject | Add-Member -MemberType NoteProperty -Name ("       Name | $i") -Value ($action.Name)
				$MainObject | Add-Member -MemberType NoteProperty -Name ("       Encoding | $i") -Value ($action.Encoding)
				$MainObject | Add-Member -MemberType NoteProperty -Name ("       Body | $i") -Value ($action.WorkingDirectory)
				$MainObject | Add-Member -MemberType NoteProperty -Name ("       Content Type | $i") -Value ($action.ContentType)
				$MainObject | Add-Member -MemberType NoteProperty -Name ("       Endpoint Primary Server | $i") -Value ($action.Endpoint.PrimaryServer.Address)
				$MainObject | Add-Member -MemberType NoteProperty -Name ("       Endpoint Return Address | $i") -Value ($action.Endpoint.PrimaryServer.UserUri)
			}
			elseif ($action.Endpoint -like "Sms*")
			{
				$MainObject | Add-Member -MemberType NoteProperty -Name ("       Name | $i") -Value ($action.Name)
				$MainObject | Add-Member -MemberType NoteProperty -Name ("       Encoding | $i") -Value ($action.Encoding)
				$MainObject | Add-Member -MemberType NoteProperty -Name ("       Body | $i") -Value ($action.WorkingDirectory)
				$MainObject | Add-Member -MemberType NoteProperty -Name ("       Content Type | $i") -Value ($action.ContentType)
				$MainObject | Add-Member -MemberType NoteProperty -Name ("       Endpoint Primary Device | $i") -Value ($action.Endpoint.PrimaryDevice)
				$MainObject | Add-Member -MemberType NoteProperty -Name ("       Endpoint Secondary Device | $i") -Value ($action.Endpoint.SecondaryDevices | Out-String -Width 2048)
				$MainObject | Add-Member -MemberType NoteProperty -Name ("       Endpoint Device Enumeration Interval Seconds | $i") -Value ($action.Endpoint.DeviceEnumerationIntervalSeconds)
				$MainObject | Add-Member -MemberType NoteProperty -Name ("       Endpoint Primary Device Switch Back Interval Seconds | $i") -Value ($action.Endpoint.PrimaryDeviceSwitchBackIntervalSeconds)
			}
		}
		$finalstring += $MainObject | Out-String -Width 4096
		
	}
	if($OutputFile)
	{
		$finalstring | Out-File $OutputFile
	}
	else
	{
		$finalstring
	}
}

				Write-Progress -Activity "Collection Running" -Status "Progress-> 37%" -PercentComplete 36
				Get-SCOMNotificationSubscriptionDetails -OutputFile $OutputPath\Notification_Subscriptions.txt
			}
		}
		catch
		{
			"$(Time-Stamp)Unable to Get Notification Subscriptions due to Error: $($error[0])" | Out-File $OutputPath\Error.log -Append
			Write-Warning $error[0]
		}
		Write-Progress -Activity "Collection Running" -Status "Progress-> 38%" -PercentComplete 38
		try
		{
			if ($SQLLogs)
			{
				try
				{
					Write-Progress -Activity "Collection Running" -Status "Progress-> 39%" -PercentComplete 39
					if (Test-Path $OutputPath\SQL_ErrorLogLocation_OpsDB.csv)
					{
						write-output " "
						Write-Host "================================`nGathering SQL Logs"
						
						md "$OutputPath`\SQL Logs" | out-null
						$SQLOMLogLoc = Import-Csv $OutputPath\SQL_ErrorLogLocation_OpsDB.csv
						if ($DW_SQLServer -ne $opsdb_SQLServer)
						{
							$SQLDWLogLoc = Import-Csv $OutputPath\SQL_ErrorLogLocation_DW.csv
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
						
						if ($OpsDB_SQLServer -ne $DW_SQLServer)
						{
							md "$OutputPath`\SQL Logs\OperationsManager" | out-null
							md "$OutputPath`\SQL Logs\DataWarehouse" | out-null
							Write-Host "  Copying " -NoNewline -ForegroundColor Cyan
							Write-Host "$OpsDB_SQLDBName" -NoNewline -ForegroundColor Magenta
							Write-Host " Database SQL Logs from " -NoNewline -ForegroundColor Cyan
							Write-Host "$OpsDB_SQLServer" -ForegroundColor Magenta
							copy -path \\$OpsDB_SQLServer\$SQLOMLogLoc -Destination "$OutputPath`\SQL Logs\OperationsManager" -Exclude *.MDMP, *.dmp, *.trc | Out-Null # exclude *.trc *.dmp *.mdmp
							Write-Host "    Copying " -NoNewline -ForegroundColor Cyan
							Write-Host "$DW_SQLDBName" -NoNewline -ForegroundColor Magenta
							Write-Host " Database SQL Logs from " -NoNewline -ForegroundColor Cyan
							Write-Host "$DW_SQLServer" -NoNewline -ForegroundColor Magenta
							copy -path \\$DW_SQLServer\$SQLDWLogLoc -Destination "$OutputPath`\SQL Logs\DataWarehouse" -Exclude *.MDMP, *.dmp, *.trc | Out-Null # exclude *.trc *.dmp *.mdmp
						}
						Write-Progress -Activity "Collection Running" -Status "Progress-> 42%" -PercentComplete 42
						if ($OpsDB_SQLServer -eq $DW_SQLServer)
						{
							Write-Host "  Copying " -NoNewline -ForegroundColor Cyan
							Write-Host "$OpsDB_SQLDBName" -NoNewline -ForegroundColor Magenta
							Write-Host " & " -NoNewline -ForegroundColor Cyan
							Write-Host "$DW_SQLDBName" -NoNewline -ForegroundColor Magenta
							Write-Host " Database SQL Logs from " -NoNewline -ForegroundColor Cyan
							Write-Host "$OpsDB_SQLServer" -ForegroundColor Magenta
							copy -path \\$OpsDB_SQLServer\$SQLOMLogLoc -Destination "$OutputPath`\SQL Logs\" | Out-Null
						}
						Write-Progress -Activity "Collection Running" -Status "Progress-> 43%" -PercentComplete 43
					}
				}
				catch
				{
					Write-Warning 'Unable to locate the Log Location from SQL Query.'
					Write-Warning $error[0]
				}
				
			}
		}
		catch
		{
			"$(Time-Stamp)Unable to Gather SQL Error Logs due to Error: $($error[0])" | Out-File $OutputPath\Error.log -Append
		}
		Write-Progress -Activity "Collection Running" -Status "Progress-> 44%" -PercentComplete 44
		try
		{
			if ($GetInstallLogs)
			{
				Write-Output " "
				Write-Host "================================`nGathering Operations Manager Install Logs"
				Function Get-InstallLogs
{
	param
	(
		[Parameter(Position = 0)]
		[string[]]$Servers = $env:COMPUTERNAME
	)
	BEGIN
	{
		#region Install Log Inner Function
		function Inner-InstallLog
		{
			try
			{
				# Grab all users AppData SCOM Logs
				$LocalSCOMLogs = Get-Item "C:\Users\*\AppData\Local\SCOM\Logs" -ErrorAction Stop
				Remove-Item -Path "$env:TEMP\SCOM-DataCollector-InstallLogs\" -Recurse -Force -ErrorAction SilentlyContinue
				if ($LocalSCOMLogs)
				{
					# Parse through each path found
					foreach ($path in $LocalSCOMLogs)
					{
						Write-Verbose "Path FullName: $($path.FullName)"
						$founduser = $path.FullName.split("\")[2]
						Write-Verbose "Found User: $founduser"
						# Parse through each user found
						foreach ($user in $founduser)
						{
							# Remote any old data
							Remove-Item -Path "$env:TEMP\SCOM-DataCollector-InstallLogs\$user\*" -Recurse -Force -ErrorAction SilentlyContinue
							
							Copy-Item $path "$env:TEMP\SCOM-DataCollector-InstallLogs\$user" -Recurse -Force -ErrorAction Stop | Out-Null
						}
					}
				}
			}
			catch
			{
				return "function:Inner-InstallLog - $($Error[0])"
			}
			return "$env:TEMP\SCOM-DataCollector-InstallLogs\"
		}
		#endregion Install Log Inner Function
		New-Item -ItemType Directory -Path "$OutputPath\Install Logs\AppData Install Logs" -Force -ErrorAction SilentlyContinue | Out-Null
		$OutputDirectory = "$OutputPath\Install Logs\AppData Install Logs"
		Write-Verbose "  Gathering Install Logs from:"
		$InnerInstallLogFunctionScript = "function Inner-InstallLog { ${Function:Inner-InstallLog} }"
		$RemotePath = "\\$env:COMPUTERNAME\$($OutputPath.Replace(':', '$'))"
	}
	PROCESS
	{
		foreach ($server in $Servers)
		{
			Write-Host "  $server" -NoNewline -ForegroundColor Cyan
			$serverPath = "$OutputPath\Install Logs\AppData Install Logs\$server"
			New-Item -ItemType Directory -Path $serverPath -Force -ErrorAction SilentlyContinue | Out-Null
			if ($server -match $env:COMPUTERNAME)
			{
				Write-Host '-' -NoNewline -ForegroundColor Green
				try
				{
					$finalout += Inner-InstallLog -ErrorAction Stop
					if ($finalout -like "function:Inner-InstallLog*")
					{
						Write-Verbose "$(Time-Stamp)function:Get-InstallLogs - Local - $server - $($error[0])"
						"$(Time-Stamp)function:Get-InstallLogs - Local - $server - $($error[0])" | Out-File $OutputPath\Error.log -Append
					}
					Copy-Item "\\$server\$($finalout.Replace(':', '$'))\*" $serverPath -Force -Recurse -ErrorAction Stop
					Remove-Item "\\$server\$($finalout.Replace(':', '$'))\*" -Recurse -Force -ErrorAction SilentlyContinue
				}
				catch
				{
					Write-Verbose "$(Time-Stamp)function:Get-InstallLogs - Local - $server - $($error[0])"
					"$(Time-Stamp)function:Get-InstallLogs - Local - $server - $($error[0])" | Out-File $OutputPath\Error.log -Append
					
				}
				Write-Host "> Completed!`n" -NoNewline -ForegroundColor Green
			}
			else
			{
				try
				{
					$remoteOutput += Invoke-Command -ComputerName $server -ArgumentList $InnerInstallLogFunctionScript -ScriptBlock {
						Param ($script)
						. ([ScriptBlock]::Create($script))
						return Inner-InstallLog
					} -ErrorAction Stop
					if ($remoteOutput -like "function:Inner-InstallLog*")
					{
						Write-Verbose "$(Time-Stamp)function:Get-InstallLogs - Remote - $server - $($error[0])"
						"$(Time-Stamp)function:Get-InstallLogs - Remote - $server - $($error[0])" | Out-File $OutputPath\Error.log -Append
					}
					Copy-Item "\\$server\$($remoteOutput.Replace(':', '$'))\*" $serverPath -Force -Recurse -ErrorAction Stop
					Remove-Item "\\$server\$($remoteOutput.Replace(':', '$'))\*" -Recurse -Force -ErrorAction SilentlyContinue
				}
				catch
				{
					Write-Verbose "$(Time-Stamp)function:Get-InstallLogs - Remote - $server - $($error[0])"
					"$(Time-Stamp)function:Get-InstallLogs - Remote - $server - $($error[0])" | Out-File $OutputPath\Error.log -Append
				}
				
				Write-Host '-' -NoNewline -ForegroundColor Green
				Write-Host "> Completed!`n" -NoNewline -ForegroundColor Green
			}
		}
	}
	END
	{
		Write-Verbose "$(Time-Stamp)End of 'Get-InstallLogs'"
	}
}

				Write-Progress -Activity "Collection Running" -Status "Progress-> 46%" -PercentComplete 46
				Get-InstallLogs -Servers $TestedTLSservers
			}
		}
		catch
		{
			"$(Time-Stamp)Unable to gather SCOM Install Logs due to Error: $($error[0])" | Out-File $OutputPath\Error.log -Append
			Write-Warning $error[0]
		}
		Write-Progress -Activity "Collection Running" -Status "Progress-> 48%" -PercentComplete 48
		try
		{
			if ($GPResult)
			{
				write-output " "
				Write-Host "================================`nGathering Group Policy Result"
				foreach ($gpserver in $TestedTLSservers)
				{
					try
					{
						if ($gpserver -match $Comp)
						{
							mkdir -Path "$OutputPath`\GPResults" -Force | Out-Null
							Write-Host "  Gathering HTML Generated Output locally: `'" -NoNewLine -ForegroundColor Cyan
							Write-Host "$Comp" -NoNewLine -ForegroundColor Magenta
							Write-Host "`'" -ForegroundColor Cyan
							Start-Process -FilePath GPResult.exe -WorkingDirectory C:\Windows\System32 -ArgumentList "/H `"$OutputPath`\GPResults\$Comp`-GPResult.html`"" -ErrorAction Stop -Wait
							#gpresult /H "$OutputPath`\GPResults\$Comp`-GPResult.html"
							
							Write-Host "  Gathering Text Generated Output locally: `'" -NoNewLine -ForegroundColor Cyan
							Write-Host "$Comp" -NoNewLine -ForegroundColor Magenta
							Write-Host "`'" -ForegroundColor Cyan
							Start-Process -FilePath GPResult.exe -WorkingDirectory C:\Windows\System32 -ArgumentList "/Z" -ErrorAction Stop -Wait | Out-File -FilePath "$OutputPath`\GPResults\$Comp`-GPResult-Z.txt"
							#gpresult /Z | Out-File -FilePath "$OutputPath`\GPResults\$Comp`-GPResult-Z.txt"
						}
						else
						{
							Write-Host "  Gathering HTML Generated Output: `'" -NoNewLine -ForegroundColor Cyan
							Write-Host "$gpserver" -NoNewLine -ForegroundColor Magenta
							Write-Host "`'" -ForegroundColor Cyan
							Start-Process -FilePath GPResult.exe -WorkingDirectory C:\Windows\System32 -ArgumentList "/H `"$OutputPath`\GPResults\$gpserver`-GPResult.html`" /S $gpserver" -ErrorAction Stop -Wait
							#gpresult /H "$OutputPath`\GPResults\$gpserver`-GPResult.html" /S $gpserver
							
							Write-Host "  Gathering Text Generated Output: `'" -NoNewLine -ForegroundColor Cyan
							Write-Host "$gpserver" -NoNewLine -ForegroundColor Magenta
							Write-Host "`'" -ForegroundColor Cyan
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
			"$(Time-Stamp)Unable to gather GPResult due to Error: $($error[0])" | Out-File $OutputPath\Error.log -Append
			Write-Warning $error[0]
		}
		try
		{
			if ($CheckGroupPolicy)
			{
				# Check Group Policy ability to Update
				write-output " "
				Write-Host "================================`nVerifying Group Policy Update / Gathering Results"
				Function Check-GroupPolicy
{
	[CmdletBinding()]
	Param
	(
		[string[]]$Servers
	)
	function Invoke-GPCheck
	{
		Write-Host "  Checking / Updating Group Policy on $env:COMPUTERNAME`:" -NoNewline -ForegroundColor Gray
		$out = @"
================================================
$env:COMPUTERNAME
"@
        Write-Host "-" -NoNewLine -ForegroundColor Green
		$out += Get-Service gpsvc | Out-String -Width 2048
        Write-Host "-" -NoNewLine -ForegroundColor Green
        $expectedresult = @"
Updating policy...



Computer Policy update has completed successfully.

User Policy update has completed successfully.




"@
        $gp = (gpupdate | Out-String)
        if($gp -eq $expectedresult)
        {
            $out += "Group Policy is updating correctly`n"
        }
        else
        {
            $out += $gp
        }
        Write-Host "-" -NoNewLine -ForegroundColor Green
		$out += (Get-EventLog -LogName 'System' -Source 'Microsoft-Windows-GroupPolicy' -Newest 2) | ft EventID, Message, UserName, TimeWritten, EntryType -AutoSize | Out-String -Width 4096
        Write-Host "> Completed!" -ForegroundColor Green
		return $out
	}
	$finalout = $null
	foreach ($server in $servers)
	{
		if ($Comp -ne $server)
		{
			$finalout += Invoke-Command -ComputerName $server -ScriptBlock ${function:Invoke-GPCheck}
		}
		else
		{
			$finalout += Invoke-GPCheck
		}
	}
	$finalout | Out-File -FilePath "$OutputPath\GP-Check.txt"
}

				Check-GroupPolicy -Servers $TestedTLSservers
				Write-Progress -Activity "Collection Running" -Status "Progress-> 59%" -PercentComplete 59
			}
		}
		catch
		{
			"$(Time-Stamp)Unable to update Group Policy due to Error: $($error[0])" | Out-File $OutputPath\Error.log -Append
		}
		if ($GetUserRoles)
		{
			try
			{
				
				write-output " "
				Write-Host "================================`nGathering SCOM User Role Configuration"
				$UserRoles = $Null
				$UserRoles = @()
				$UserRoleList = Get-SCOMUserRole
				Write-Progress -Activity "Collection Running" -Status "Progress-> 60%" -PercentComplete 60
				Write-Host "  Processing User Role:  " -ForegroundColor Cyan
				foreach ($UserRole in $UserRoleList)
				{
					Write-Host "    $UserRole" -ForegroundColor Magenta
					$UserRoles += New-Object -TypeName psobject -Property @{
						Name = $UserRole.Name;
						DisplayName = $UserRole.DisplayName;
						Description = $UserRole.Description;
						Users = ($UserRole.Users -join "; ");
					}
				}
				Write-Progress -Activity "Collection Running" -Status "Progress-> 61%" -PercentComplete 61
				$UserRolesOutput = $UserRoles | Select-Object Name, DisplayName, Description, Users
				$UserRolesOutput | Out-File "$OutputPath`\UserRoles.txt" -Width 4096
				$UserRolesOutput | Export-CSV -Path "$OutputPath`\UserRoles.csv" -NoTypeInformation
			}
			catch
			{
				"$(Time-Stamp)Unable to gather User Role Information due to Error: $($error[0])" | Out-File $OutputPath\Error.log -Append
				Write-Warning $error[0]
			}
		}
		
	}
	#endregion least amount
	
	#region Pending Management
	try
	{
		if (!$ManagementServers)
		{
			$ManagementServers = $OriginalManagementServers | Select * -Unique
		}
		foreach ($ManagementServer in $ManagementServers)
		{
			if ($ManagementServer -notmatch $env:COMPUTERNAME)
			{
				$pendingMgmtCurrentServer = $ManagementServers[0]
				$pendingMgmt = Invoke-Command -ComputerName $ManagementServers[0] -ScriptBlock { Import-Module OperationsManager; return Get-SCOMPendingManagement }
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
		"$(Time-Stamp)Unable to gather Agents Pending Management due to Error: $($error[0])" | Out-File $OutputPath\Error.log -Append
		Write-Verbose "$(Time-Stamp)Unable to gather Agents Pending Management due to Error: $($error[0])"
	}
	
	Write-Progress -Activity "Collection Running" -Status "Progress-> 62%" -PercentComplete 62
	try
	{
		if ($pendingMgmt)
		{
			Write-Host "`n================================`nGathering Agent(s) Pending Management"
			$pendingCount = ($pendingMgmt).Count
			if ($pendingCount -ne 0)
			{
				"Current Count of Pending Management: " + $pendingCount | Out-File -FilePath "$OutputPath\Pending Management.txt"
				Write-Host "    Running Powershell Command: " -NoNewLine -ForegroundColor Cyan
				Write-Host "`n      Get-SCOMPendingManagement" -NoNewLine -ForegroundColor Magenta
				Write-Host " against" -NoNewLine -ForegroundColor Cyan
				Write-Host " $pendingMgmtCurrentServer" -NoNewLine -ForegroundColor Magenta
				Write-Host "-" -NoNewline -ForegroundColor Green
				do { Write-Host "-" -NoNewline -ForegroundColor Green; sleep 1 }
				while ($pendingMgmt | Out-File -Append -FilePath "$OutputPath\Pending Management.txt")
				Write-Host "> Command Execution Completed!`n" -NoNewline -ForegroundColor Green
			}
			else
			{
				Write-Host "    No Servers Pending Management" -ForegroundColor Magenta
			}
		}
	}
	catch
	{
		"$(Time-Stamp)Unable to gather Agents Pending Management due to Error: $($error[0])" | Out-File $OutputPath\Error.log -Append
		Write-Verbose "$(Time-Stamp)Unable to gather Agents Pending Management due to Error: $($error[0])"
	}
	#endregion Pending Management
	Write-Progress -Activity "Collection Running" -Status "Progress-> 64%" -PercentComplete 64
	Write-Output " "
	if (!$SkipGeneralInformation)
	{
		Write-Output "================================`nGathering System Center Operations Manager General Information"
		Write-Host "  Executing Function" -NoNewLine -ForegroundColor Cyan
		Write-Host "-" -NoNewline -ForegroundColor Green
		Write-Verbose "$(Time-Stamp)Loading General Info Function"
		function Get-SCOMGeneralInfo
{
	#Last modified: October 24th, 2022
	param
	(
		[cmdletbinding()]
		[Parameter(Position = 1)]
		[array]$Servers
	)
	trap
	{
		#potential error code
		#use continue or break keywords
		$e = $_.Exception
		$line = $_.InvocationInfo.ScriptLineNumber
		$msg = $e.Message
		
		Write-Verbose "$(Time-Stamp)Caught Exception: $e :: Message: $msg :: at line: $line"
		"$(Time-Stamp)Caught Exception: $e :: Message: $msg :: at line: $line" | Out-File $OutputPath\Error.log -Append
	}
	Write-Verbose "$(Time-Stamp)Loading Product Version"
	function Get-ProductVersion
{
	param
	(
		[Parameter(Mandatory = $true,
				   Position = 1)]
		[ValidateSet('SCOM', 'SQL', 'SSRS')]
		[string]$Product,
		[Parameter(Mandatory = $true,
				   Position = 2)]
		[string]$BuildVersion
	)
	
	#Last Updated SQL Server List on: August 25th, 2022
	#Last Updated SCOM Version List on: November 15th, 2022
	#Last Updated SSRS Version List on: August 25th, 2022
	
	if ($Product -eq 'SCOM')
	{
		$Output = switch ($BuildVersion)
		{
    <# 
       System Center Operations Manager 2022 Versions
    #>
	
			'10.22.1032.0'  { "SCOM 2022 RTM - 1.6.10-2	/ August 2022" } #SCX Agent
			'10.22.1024.0'  { "SCOM 2022 RTM - 1.6.9-2 / August 2022" } #SCX Agent
			'10.22.1019.0'  { "SCOM 2022 RTM - 1.6.9-0 / August 2022" } #SCX Agent
			'10.22.10056.0' { "SCOM 2022 RTM / 2022 March 14" } #Agent
			'10.22.10118.0' { "SCOM 2022 RTM / 2022 March 14" }
    <# 
       System Center Operations Manager 2019 Versions
    #>
			'10.19.1158.0'  { "Update Rollup 4 - OMI Vulnerability Fix - 1.6.10-2 / August 2022" } #SCX Agent
			'10.19.1150.0'  { "SCOM 2019 Update Rollup 4 - 1.6.10-1 / June 2022" } #SCX Agent
			'10.19.10200.0' { "SCOM 2019 Update Rollup 4 / June 2022" } #Agent
			'10.19.10569.0' { "SCOM 2019 Update Rollup 4 / June 2022" }
			'10.19.1147.0'  { "SCOM 2019 Update Rollup 3 - Hotfix Oct 2021 for SCOM 2019 - 1.6.8-1 / 2021 October" } #SCX Agent
			'10.19.10185.0' { "SCOM 2019 Update Rollup 3 - Hotfix Oct 2021 for SCOM 2019 / 2021 October" } #Agent
			'10.19.10552.0' { "SCOM 2019 Update Rollup 3 - Hotfix Oct 2021 for SCOM 2019 / 2021 October" }
			'10.19.10550.0' { "SCOM 2019 Update Rollup 3 - Hotfix for Web Console / 2021 October" }
			'10.19.1138.0'  { "SCOM 2019 Update Rollup 3 - 1.6.8-0 / 2021 March 31" } #SCX Agent
			'10.19.10177.0' { "SCOM 2019 Update Rollup 3 / 2021 March 31" } #Agent
			'10.19.10505.0' { "SCOM 2019 Update Rollup 3 / 2021 March 31" }
			'10.19.1123.0'  { "SCOM 2019 Update Rollup 2 - 1.6.6-0 / 2020 August 4" } #SCX Agent
			'10.19.10153.0' { "SCOM 2019 Update Rollup 2 / 2020 August 4" } #Agent
			'10.19.10407.0' { "SCOM 2019 Update Rollup 2 / 2020 August 4" }
			'10.19.10349.0' { "SCOM 2019 Update Rollup 1 - Hotfix for Alert Management / 2020 April 1" }
			'10.19.1082.0'  { "SCOM 2019 Update Rollup 1 - 1.6.4-7 / 2020 February 4" } #SCX Agent
			'10.19.10140.0' { "SCOM 2019 Update Rollup 1 / 2020 February 4" } #Agent
			'10.19.10311.0' { "SCOM 2019 Update Rollup 1 / 2020 February 4" }
			'10.19.1008.0'  { "SCOM 2019 RTM - 1.6.3-793 / 2019 March 14" } #SCX Agent
			'10.19.10014.0' { "SCOM 2019 RTM / 2019 March 14" } #Agent
			'10.19.10050.0' { "SCOM 2019 RTM / 2019 March 14" }
			'10.19.10003.0' { "SCOM 2019 Technical Preview / 2018 December" }
    <# 
       System Center Operations Manager 2016 Versions
    #>
			'8.0.11057.0' { "SCOM 2016 Update Rollup 10 / 2020 November 19" } #Agent
			'7.2.12324.0' { "SCOM 2016 Update Rollup 10 / 2020 November 19" }
			'8.0.11049.0' { "SCOM 2016 Update Rollup 9 / 2020 March 24" } #Agent	
			'7.2.12265.0' { "SCOM 2016 Update Rollup 9 / 2020 March 24" }
			'8.0.11037.0' { "SCOM 2016 Update Rollup 8 / 2019 September 24" } #Agent
			'7.2.12213.0' { "SCOM 2016 Update Rollup 8 / 2019 September 24" }
			'8.0.11025.0' { "SCOM 2016 Update Rollup 7 / 2019 April 23" } #Agent
			'7.2.12150.0' { "SCOM 2016 Update Rollup 7 / 2019 April 23" }
			'8.0.11004.0' { "SCOM 2016 Update Rollup 6 / 2018 October 23" } #Agent
			'7.2.12066.0' { "SCOM 2016 Update Rollup 6 / 2018 October 23" }
			'8.0.10990.0' { "SCOM 2016 Update Rollup 5 / 2018 April 25" } #Agent
			'7.2.12016.0' { "SCOM 2016 Update Rollup 5 / 2018 April 25" }
			'8.0.10977.0' { "SCOM 2016 Update Rollup 4 / 2017 October 23" } #Agent	
			'7.2.11938.0' { "SCOM 2016 Update Rollup 4 / 2017 October 23" }
			'8.0.10970.0' { "SCOM 2016 Update Rollup 3 / 2017 May 23" } #Agent
			'7.2.11878.0' { "SCOM 2016 Update Rollup 3 / 2017 May 23" }
			'8.0.10949.0' { "SCOM 2016 Update Rollup 2 / 2017 February 22" } #Agent
			'7.2.11822.0' { "SCOM 2016 Update Rollup 2 / 2017 February 22" }
			'7.2.11759.0' { "SCOM 2016 Update Rollup 1 / 2016 October 13" }
			'8.0.10918.0' { "SCOM 2016 RTM / 2016 September 26" } #Agent
			'7.2.11719.0' { "SCOM 2016 RTM / 2016 September 26" }
			'7.2.11469.0' { "SCOM 2016 Technical Preview 5 / 2016 April" }
			'7.2.11257.0' { "SCOM 2016 Technical Preview 4 / 2016 July" }
			'7.2.11125.0' { "SCOM 2016 Technical Preview 3 / 2016 July" }
			'7.2.11097.0' { "SCOM 2016 Technical Preview 2 / 2016 June" }
			'7.2.10015.0' { "SCOM 2016 Technical Preview / 2016 " }
    <# 
       System Center Operations Manager Semi-Annual Channel (SAC) Versions
    #>
			'8.0.13067.0' { "Version 1807 / 2018 July 24" } #Agent
			'7.3.13261.0' { "Version 1807 / 2018 July 24" }
			'8.0.13053.0' { "Version 1801 / 2018 February 8" } #Agent
			'7.3.13142.0' { "Version 1801 / 2018 February 8" }
			'7.3.13040.0' { "Version 1711 (preview) / 2017 November 9" }
   <# 
      System Center Operations Manager 2012 R2 Versions
   #>
			'7.1.10305.0' 	 { "SCOM 2012 R2 Update Rollup 14 / 2017 November 28" } #Agent	
			'7.1.10226.1387' { "SCOM 2012 R2 Update Rollup 14 / 2017 November 28" }
			'7.1.10302.0' 	 { "SCOM 2012 R2 Update Rollup 13 / 2017 May 23" } #Agent
			'7.1.10226.1360' { "SCOM 2012 R2 Update Rollup 13 / 2017 May 23" }
			'7.1.10292.0' 	 { "SCOM 2012 R2 Update Rollup 12 / 2017 January 24" } #Agent
			'7.1.10226.1304' { "SCOM 2012 R2 Update Rollup 12 / 2017 January 24" }
			'7.1.10285.0' 	 { "SCOM 2012 R2 Update Rollup 11 / 2016 August 30" } #Agent
			'7.1.10226.1239' { "SCOM 2012 R2 Update Rollup 11 / 2016 August 30" }
			'7.1.10268.0'  	 { "SCOM 2012 R2 Update Rollup 9 / 2016 January 26" } #Agent
			'7.1.10226.1177' { "SCOM 2012 R2 Update Rollup 9 / 2016 January 26" }
			'7.1.10241.0' 	 { "SCOM 2012 R2 Update Rollup 8 / 2015 October 27" } #Agent
			'7.1.10226.1118' { "SCOM 2012 R2 Update Rollup 8 / 2015 October 27" }
			'7.1.10229.0' 	 { "SCOM 2012 R2 Update Rollup 7 / 2015 August 11" } #Agent
			'7.1.10226.1090' { "SCOM 2012 R2 Update Rollup 7 / 2015 August 11" }
			'7.1.10218.0'	 { "SCOM 2012 R2 Update Rollup 6 / 2015 April 28" } #Agent
			'7.1.10226.1064' { "SCOM 2012 R2 Update Rollup 6 / 2015 April 28" }
			'7.1.10213.0' 	 { "SCOM 2012 R2 Update Rollup 5 / 2015 February 10" } #Agent
			'7.1.10226.1052' { "SCOM 2012 R2 Update Rollup 5 / 2015 February 10" }
			'7.1.10211.0' 	 { "SCOM 2012 R2 Update Rollup 4 / 2014 October 28" } #Agent
			'7.1.10226.1046' { "SCOM 2012 R2 Update Rollup 4 / 2014 October 28" }
			'7.1.10204.0'	 { "SCOM 2012 R2 Update Rollup 3 / 2014 July 29" } #Agent
			'7.1.10226.1037' { "SCOM 2012 R2 Update Rollup 3 / 2014 July 29" }
			'7.1.10195.0'	 { "SCOM 2012 R2 Update Rollup 2 / 2014 April 23" } #Agent
			'7.1.10226.1015' { "SCOM 2012 R2 Update Rollup 2 / 2014 April 23" }
			'7.1.10188.0'	 { "SCOM 2012 R2 Update Rollup 1 / 2014 January 27" } #Agent
			'7.1.10226.1011' { "SCOM 2012 R2 Update Rollup 1 / 2014 January 27" }
			'7.1.10184.0'	 { "SCOM 2012 R2 RTM / 2013 October 22" } #Agent
			'7.1.10226.0'	 { "SCOM 2012 R2 RTM / 2013 October 22" }
   <# 
      System Center Operations Manager 2012 SP1 Versions
   #>
			'7.0.9538.1136' { "SCOM 2012 SP1 Update Rollup 10 / 2015 August 11" }
			'7.0.9538.1126' { "SCOM 2012 SP1 Update Rollup 9 / 2015 February 10" }
			'7.0.9538.1123' { "SCOM 2012 SP1 Update Rollup 8 / 2014 October 28" }
			'7.0.9538.1117' { "SCOM 2012 SP1 Update Rollup 7 / 2014 July 29" }
			'7.0.9538.1109' { "SCOM 2012 SP1 Update Rollup 6 / 2014 April 23" }
			'7.0.9538.1106' { "SCOM 2012 SP1 Update Rollup 5 / 2014 January 27" }
			'7.0.9538.1084' { "SCOM 2012 SP1 Update Rollup 4 / 2013 October 21" }
			'7.0.9538.1069' { "SCOM 2012 SP1 Update Rollup 3 / 2013 July 23" }
			'7.0.9538.1047' { "SCOM 2012 SP1 Update Rollup 2 / 2013 April 08" }
			'7.0.9538.1005' { "SCOM 2012 SP1 Update Rollup 1 / 2013 January 8" }
			
			'7.0.9538.0' { "SCOM 2012 SP1" }
   <# 
      System Center Operations Manager 2012 Versions
   #>
			'7.0.8289.0' { "SCOM 2012 Beta / 2011 July" }
			'7.0.8560.0' { "SCOM 2012 RTM" }
			
			'7.0.8560.1021' { "SCOM 2012 Update Rollup 1 / 2012 May 07" }
			'7.0.8560.1027' { "SCOM 2012 Update Rollup 2 / 2012 July 24" }
			'7.0.8560.1036' { "SCOM 2012 Update Rollup 3 / 2012 October 08" }
			'7.0.8560.1048' { "SCOM 2012 Update Rollup 8 / 2015 August 11" }
			# If nothing else found then default to version number
			default { "Unknown Version" }
		}
		return $Output
	}
	elseif ($Product -eq 'SQL')
	{
		$Output = switch ($BuildVersion)
		{
			"16.0.700.4" { "Microsoft SQL Server 2022 Community Technology Public Preview 2.1 (CTP 2.1) / 2022-07-27" }
			"16.0.600.9" { "Microsoft SQL Server 2022 Community Technology Public Preview 2.0 (CTP 2.0) / 2022-05-24" }
			"16.0.500.2" { "Microsoft SQL Server 2022 Community Technology Preview 1.5 (CTP 1.5) / " }
			"16.0.400.2" { "Microsoft SQL Server 2022 Community Technology Preview 1.4 (CTP 1.4) / " }
			"16.0.300.4" { "Microsoft SQL Server 2022 Community Technology Preview 1.3 (CTP 1.3) / " }
			"16.0.200.2" { "Microsoft SQL Server 2022 Community Technology Preview 1.2 (CTP 1.2) / " }
			"16.0.101.1" { "Microsoft SQL Server 2022 Community Technology Preview 1.1 (CTP 1.1) / " }
			"16.0.100.4" { "Microsoft SQL Server 2022 Community Technology Preview 1.0 (CTP 1.0) / 2021-12-07" }
			"15.0.4249.2" { "Cumulative Update 17 (CU17) For SQL Server 2019 / 2022-08-11" }
			"15.0.4236.7" { "Security Update For SQL Server 2019 CU16: June 14, 2022 / 2022-06-14" }
			"15.0.4223.1" { "Cumulative Update 16 (CU16) For SQL Server 2019 / 2022-04-18" }
			"15.0.4198.2" { "Cumulative Update 15 (CU15) For SQL Server 2019 / 2022-01-27" }
			"15.0.4188.2" { "Cumulative Update 14 (CU14) For SQL Server 2019 / 2021-11-22" }
			"15.0.4178.1" { "Cumulative Update 13 (CU13) For SQL Server 2019 / 2021-10-05" }
			"15.0.4153.1" { "Cumulative Update 12 (CU12) For SQL Server 2019 / 2021-08-04" }
			"15.0.4138.2" { "Cumulative Update 11 (CU11) For SQL Server 2019 / 2021-06-10" }
			"15.0.4123.1" { "Cumulative Update 10 (CU10) For SQL Server 2019 / 2021-04-06" }
			"15.0.4102.2" { "Cumulative Update 9 (CU9) For SQL Server 2019 / 2021-02-11" }
			"15.0.4083.2" { "Security Update For SQL Server 2019 CU8: January 12, 2021 / 2021-01-12" }
			"15.0.4073.23" { "Cumulative Update 8 (CU8) For SQL Server 2019 / 2020-10-01" }
			"15.0.4063.15" { "Cumulative Update 7 (CU7) For SQL Server 2019 / 2020-09-02" }
			"15.0.4053.23" { "Cumulative Update 6 (CU6) For SQL Server 2019 / 2020-08-04" }
			"15.0.4043.16" { "Cumulative Update 5 (CU5) For SQL Server 2019 / 2020-06-22" }
			"15.0.4033.1" { "Cumulative Update 4 (CU4) For SQL Server 2019 / 2020-03-31" }
			"15.0.4023.6" { "Cumulative Update 3 (CU3) For SQL Server 2019 / 2020-03-12" }
			"15.0.4013.40" { "Cumulative Update 2 (CU2) For SQL Server 2019 / 2020-02-13" }
			"15.0.4003.23" { "Cumulative Update 1 (CU1) For SQL Server 2019 / 2020-01-07" }
			"15.0.2095.3" { "Security Update For SQL Server 2019 GDR: June 14, 2022 / 2022-06-14" }
			"15.0.2090.38" { "Security Update For SQL Server 2019 GDR: February 8, 2022 / 2022-02-08" }
			"15.0.2080.9" { "Security Update For SQL Server 2019 GDR: January 12, 2021 / 2021-01-12" }
			"15.0.2070.41" { "Servicing Update (GDR1) For SQL Server 2019 RTM / 2019-11-04" }
			"15.0.2000.5" { "Microsoft SQL Server 2019 RTM / 2019-11-04" }
			"15.0.1900.47" { "Microsoft SQL Server 2019 Release Candidate Refresh For Big Data Clusters Only (RC1.1) / 2019-08-29" }
			"15.0.1900.25" { "Microsoft SQL Server 2019 Release Candidate 1 (RC1) / 2019-08-21" }
			"15.0.1800.32" { "Microsoft SQL Server 2019 Community Technology Preview 3.2 (CTP 3.2) / 2019-07-24" }
			"15.0.1700.37" { "Microsoft SQL Server 2019 Community Technology Preview 3.1 (CTP 3.1) / 2019-06-26" }
			"15.0.1600.8" { "Microsoft SQL Server 2019 Community Technology Preview 3.0 (CTP 3.0) / 2019-05-22" }
			"15.0.1500.28" { "Microsoft SQL Server 2019 Community Technology Preview 2.5 (CTP 2.5) / 2019-04-23" }
			"15.0.1400.75" { "Microsoft SQL Server 2019 Community Technology Preview 2.4 (CTP 2.4) / 2019-03-26" }
			"15.0.1300.359" { "Microsoft SQL Server 2019 Community Technology Preview 2.3 (CTP 2.3) / 2019-03-01" }
			"15.0.1200.24" { "Microsoft SQL Server 2019 Community Technology Preview 2.2 (CTP 2.2) / 2018-12-11" }
			"15.0.1100.94" { "Microsoft SQL Server 2019 Community Technology Preview 2.1 (CTP 2.1) / 2018-11-06" }
			"15.0.1000.34" { "Microsoft SQL Server 2019 Community Technology Preview 2.0 (CTP 2.0) / 2018-09-24" }
			"14.0.3451.2" { "Cumulative Update 30 (CU30) For SQL Server 2017 / 2022-07-13" }
			"14.0.3445.2" { "Security Update For SQL Server 2017 CU29: June 14, 2022 / 2022-06-14" }
			"14.0.3436.1" { "Cumulative Update 29 (CU29) For SQL Server 2017 / 2022-03-30" }
			"14.0.3430.2" { "Cumulative Update 28 (CU28) For SQL Server 2017 / 2022-01-13" }
			"14.0.3421.10" { "Cumulative Update 27 (CU27) For SQL Server 2017 / 2021-10-27" }
			"14.0.3411.3" { "Cumulative Update 26 (CU26) For SQL Server 2017 / 2021-09-14" }
			"14.0.3401.7" { "Cumulative Update 25 (CU25) For SQL Server 2017 / 2021-07-12" }
			"14.0.3391.2" { "Cumulative Update 24 (CU24) For SQL Server 2017 / 2021-05-10" }
			"14.0.3381.3" { "Cumulative Update 23 (CU23) For SQL Server 2017 / 2021-02-24" }
			"14.0.3370.1" { "Security Update For SQL Server 2017 CU22: January 12, 2021 / 2021-01-12" }
			"14.0.3356.20" { "Cumulative Update 22 (CU22) For SQL Server 2017 / 2020-09-10" }
			"14.0.3335.7" { "Cumulative Update 21 (CU21) For SQL Server 2017 / 2020-07-01" }
			"14.0.3294.2" { "Cumulative Update 20 (CU20) For SQL Server 2017 / 2020-04-07" }
			"14.0.3281.6" { "Cumulative Update 19 (CU19) For SQL Server 2017 / 2020-02-05" }
			"14.0.3257.3" { "Cumulative Update 18 (CU18) For SQL Server 2017 / 2019-12-09" }
			"14.0.3238.1" { "Cumulative Update 17 (CU17) For SQL Server 2017 / 2019-10-08" }
			"14.0.3223.3" { "Cumulative Update 16 (CU16) For SQL Server 2017 / 2019-08-01" }
			"14.0.3208.1" { "On-Demand Hotfix Update Package 2 For SQL Server 2017 Cumulative Update 15 (CU15) / 2019-07-09" }
			"14.0.3192.2" { "Security Update For SQL Server 2017 CU15: July 9, 2019 / 2019-07-09" }
			"14.0.3164.1" { "On-Demand Hotfix Update Package For SQL Server 2017 Cumulative Update 15 (CU15) / 2019-06-20" }
			"14.0.3162.1" { "Cumulative Update 15 (CU15) For SQL Server 2017 / 2019-05-24" }
			"14.0.3103.1" { "Security Update For SQL Server 2017 Cumulative Update 14 (CU14): May 14, 2019 / 2019-05-14" }
			"14.0.3076.1" { "Cumulative Update 14 (CU14) For SQL Server 2017 / 2019-03-25" }
			"14.0.3049.1" { "On-Demand Hotfix Update Package For SQL Server 2017 Cumulative Update 13 (CU13) / 2019-01-08" }
			"14.0.3048.4" { "Cumulative Update 13 (CU13) For SQL Server 2017 / 2018-12-18" }
			"14.0.3045.24" { "Cumulative Update 12 (CU12) For SQL Server 2017 / 2018-10-24" }
			"14.0.3038.14" { "Cumulative Update 11 (CU11) For SQL Server 2017 / 2018-09-21" }
			"14.0.3037.1" { "Cumulative Update 10 (CU10) For SQL Server 2017 / 2018-08-27" }
			"14.0.3035.2" { "Security Update For The Remote Code Execution Vulnerability In SQL Server 2017 CU: August 14, 2018 / 2018-08-14" }
			"14.0.3030.27" { "Cumulative Update 9 (CU9) For SQL Server 2017 / 2018-07-18" }
			"14.0.3029.16" { "Cumulative Update 8 (CU8) For SQL Server 2017 / 2018-06-21" }
			"14.0.3026.27" { "Cumulative Update 7 (CU7) For SQL Server 2017 / 2018-05-23" }
			"14.0.3025.34" { "Cumulative Update 6 (CU6) For SQL Server 2017 / 2018-04-19" }
			"14.0.3023.8" { "Cumulative Update 5 (CU5) For SQL Server 2017 / 2018-03-20" }
			"14.0.3022.28" { "Cumulative Update 4 (CU4) For SQL Server 2017 / 2018-02-17" }
			"14.0.3015.40" { "Cumulative Update 3 (CU3) For SQL Server 2017 - Security Advisory ADV180002 / 2018-01-04" }
			"14.0.3008.27" { "Cumulative Update 2 (CU2) For SQL Server 2017 / 2017-11-28" }
			"14.0.3006.16" { "Cumulative Update 1 (CU1) For SQL Server 2017 / 2017-10-23" }
			"14.0.2042.3" { "Security Update For SQL Server 2017 GDR: June 14, 2022 / 2022-06-14" }
			"14.0.2037.2" { "Security Update For SQL Server 2017 GDR: January 12, 2021 / 2021-01-12" }
			"14.0.2027.2" { "Security Update For SQL Server 2017 GDR: July 9, 2019 / 2019-07-09" }
			"14.0.2014.14" { "Security Update For SQL Server 2017 GDR: May 14, 2019 / 2019-05-14" }
			"14.0.2002.14" { "Security Update For The Remote Code Execution Vulnerability In SQL Server 2017 GDR: August 14, 2018 / 2018-08-14" }
			"14.0.2000.63" { "Security Update For SQL Server 2017 GDR: January 3, 2018 - Security Advisory ADV180002 / 2018-01-03" }
			"14.0.1000.169" { "Microsoft SQL Server 2017 RTM / 2017-10-02" }
			"14.0.900.75" { "Microsoft SQL Server 2017 Release Candidate 2 (RC2) (Linux Support; Codename Helsinki) / 2017-08-02" }
			"14.0.800.90" { "Microsoft SQL Server 2017 Release Candidate 1 (RC1) (Linux Support; Codename Helsinki) / 2017-07-17" }
			"14.0.600.250" { "Microsoft SQL Server 2017 Community Technical Preview 2.1 (CTP2.1) (Linux Support; Codename Helsinki) / 2017-05-17" }
			"14.0.500.272" { "Microsoft SQL Server 2017 Community Technical Preview 2.0 (CTP2.0) (Linux Support; Codename Helsinki) / 2017-04-19" }
			"14.0.405.198" { "Microsoft SQL Server Vnext Community Technology Preview 1.4 (CTP1.4) (Linux Support; Codename Helsinki) / 2017-03-17" }
			"14.0.304.138" { "Microsoft SQL Server Vnext Community Technology Preview 1.3 (CTP1.3) (Linux Support; Codename Helsinki) / 2017-02-17" }
			"14.0.200.24" { "Microsoft SQL Server Vnext Community Technology Preview 1.2 (CTP1.2) (Linux Support; Codename Helsinki) / 2017-01-20" }
			"14.0.100.187" { "Microsoft SQL Server Vnext Community Technology Preview 1.1 (CTP1.1) (Linux Support; Codename Helsinki) / 2016-12-16" }
			"14.0.1.246" { "Microsoft SQL Server Vnext Community Technology Preview 1 (CTP1) (Linux Support; Codename Helsinki) / 2016-11-16" }
			"13.0.7016.1" { "Security Update For SQL Server 2016 SP3 Azure Connect Feature Pack: June 14, 2022 / 2022-06-14" }
			"13.0.7000.253" { "Azure Connect Feature Pack For SQL Server 2016 Service Pack 3 / 2022-05-19" }
			"13.0.6419.1" { "Security Update For SQL Server 2016 SP3 GDR: June 14, 2022 / 2022-06-14" }
			"13.0.6404.1" { "On-Demand Hotfix Update Package For SQL Server 2016 Service Pack 3 (SP3) / 2021-10-27" }
			"13.0.6300.2" { "Microsoft SQL Server 2016 Service Pack 3 (SP3) / 2021-09-15" }
			"13.0.5893.48" { "Security Update For SQL Server 2016 SP2 CU17: June 14, 2022 / 2022-06-14" }
			"13.0.5888.11" { "Cumulative Update 17 (CU17) For SQL Server 2016 Service Pack 2 / 2021-03-29" }
			"13.0.5882.1" { "Cumulative Update 16 (CU16) For SQL Server 2016 Service Pack 2 / 2021-02-11" }
			"13.0.5865.1" { "Security Update For SQL Server 2016 SP2 CU15: January 12, 2021 / 2021-01-12" }
			"13.0.5850.14" { "Cumulative Update 15 (CU15) For SQL Server 2016 Service Pack 2 / 2020-09-28" }
			"13.0.5830.85" { "Cumulative Update 14 (CU14) For SQL Server 2016 Service Pack 2 / 2020-08-06" }
			"13.0.5820.21" { "Cumulative Update 13 (CU13) For SQL Server 2016 Service Pack 2 / 2020-05-28" }
			"13.0.5698.0" { "Cumulative Update 12 (CU12) For SQL Server 2016 Service Pack 2 / 2020-02-25" }
			"13.0.5622.0" { "Security Update For SQL Server 2016 SP2 CU11: February 11, 2020 / 2020-02-11" }
			"13.0.5598.27" { "Cumulative Update 11 (CU11) For SQL Server 2016 Service Pack 2 / 2019-12-09" }
			"13.0.5492.2" { "Cumulative Update 10 (CU10) For SQL Server 2016 Service Pack 2 / 2019-10-08" }
			"13.0.5479.0" { "4515435 Cumulative Update 9 (CU9) For SQL Server 2016 Service Pack 2 / 2019-09-30" }
			"13.0.5426.0" { "Cumulative Update 8 (CU8) For SQL Server 2016 Service Pack 2 / 2019-07-31" }
			"13.0.5382.0" { "On-Demand Hotfix Update Package 2 For SQL Server 2016 Service Pack 2 (SP2) Cumulative Update 7 (CU7) / 2019-07-09" }
			"13.0.5366.0" { "Security Update For SQL Server 2016 SP2 CU7 GDR: July 9, 2019 / 2019-07-09" }
			"13.0.5343.1" { "On-Demand Hotfix Update Package For SQL Server 2016 Service Pack 2 (SP2) Cumulative Update 7 (CU7) / 2019-06-24" }
			"13.0.5337.0" { "Cumulative Update 7 (CU7) For SQL Server 2016 Service Pack 2 / 2019-05-22" }
			"13.0.5292.0" { "Cumulative Update 6 (CU6) For SQL Server 2016 Service Pack 2 / 2019-03-19" }
			"13.0.5270.0" { "On-Demand Hotfix Update Package For SQL Server 2016 SP2 CU5 / 2019-02-14" }
			"13.0.5264.1" { "Cumulative Update 5 (CU5) For SQL Server 2016 Service Pack 2 / 2019-01-23" }
			"13.0.5239.0" { "On-Demand Hotfix Update Package 2 For SQL Server 2016 SP2 CU4 / 2018-12-21" }
			"13.0.5233.0" { "Cumulative Update 4 (CU4) For SQL Server 2016 Service Pack 2 / 2018-11-13" }
			"13.0.5221.0" { "FIX: Assertion Error Occurs When You Restart The SQL Server 2016 Database / 2018-10-09" }
			"13.0.5221.0" { "FIX: '3414' And '9003' Errors And A .Pmm Log File Grows Large In SQL Server 2016 / 2018-10-09" }
			"13.0.5216.0" { "Cumulative Update 3 (CU3) For SQL Server 2016 Service Pack 2 / 2018-09-21" }
			"13.0.5201.2" { "Security Update For The Remote Code Execution Vulnerability In SQL Server 2016 SP2 CU: August 19, 2018 / 2018-08-19" }
			"13.0.5161.0" { "Security Update For The Remote Code Execution Vulnerability In SQL Server 2016 SP2 CU: August 14, 2018 / 2018-08-14" }
			"13.0.5153.0" { "Cumulative Update 2 (CU2) For SQL Server 2016 Service Pack 2 / 2018-07-17" }
			"13.0.5149.0" { "Cumulative Update 1 (CU1) For SQL Server 2016 Service Pack 2 / 2018-05-30" }
			"13.0.5108.50" { "Security Update For SQL Server 2016 SP2 GDR: June 14, 2022 / 2022-06-14" }
			"13.0.5103.6" { "Security Update For SQL Server 2016 SP2 GDR: January 12, 2021 / 2021-01-12" }
			"13.0.5102.14" { "Security Update For SQL Server 2016 SP2 GDR: February 11, 2020 / 2020-02-11" }
			"13.0.5101.9" { "Security Update For SQL Server 2016 SP2 GDR: July 9, 2019 / 2019-07-09" }
			"13.0.5081.1" { "Security Update For The Remote Code Execution Vulnerability In SQL Server 2016 SP2 GDR: August 14, 2018 / 2018-08-14" }
			"13.0.5026.0" { "Microsoft SQL Server 2016 Service Pack 2 (SP2) / 2018-04-24" }
			"13.0.4604.0" { "Security Update For SQL Server 2016 SP1 CU15 GDR: July 9, 2019 / 2019-07-09" }
			"13.0.4577.0" { "On-Demand Hotfix Update Package For SQL Server 2016 Service Pack 1 (SP1) Cumulative Update 15 (CU15) / 2019-06-20" }
			"13.0.4574.0" { "Cumulative Update 15 (CU15) For SQL Server 2016 Service Pack 1 / 2019-05-16" }
			"13.0.4560.0" { "Cumulative Update 14 (CU14) For SQL Server 2016 Service Pack 1 / 2019-03-19" }
			"13.0.4550.1" { "Cumulative Update 13 (CU13) For SQL Server 2016 Service Pack 1 / 2019-01-23" }
			"13.0.4541.0" { "Cumulative Update 12 (CU12) For SQL Server 2016 Service Pack 1 / 2018-11-13" }
			"13.0.4531.0" { "FIX: The 'Modification_Counter' In DMV Sys.Dm_Db_Stats_Properties Shows Incorrect Value When Partitions Are Merged Through ALTER PARTITION In SQL Server 2016 / 2018-09-27" }
			"13.0.4528.0" { "Cumulative Update 11 (CU11) For SQL Server 2016 Service Pack 1 / 2018-09-18" }
			"13.0.4522.0" { "Security Update For The Remote Code Execution Vulnerability In SQL Server 2016 SP1 CU: August 14, 2018 / 2018-08-14" }
			"13.0.4514.0" { "Cumulative Update 10 (CU10) For SQL Server 2016 Service Pack 1 / 2018-07-16" }
			"13.0.4502.0" { "Cumulative Update 9 (CU9) For SQL Server 2016 Service Pack 1 / 2018-05-30" }
			"13.0.4477.0" { "On-Demand Hotfix Update Package For SQL Server 2016 SP1 / 2018-06-02" }
			"13.0.4474.0" { "Cumulative Update 8 (CU8) For SQL Server 2016 Service Pack 1 / 2018-03-19" }
			"13.0.4466.4" { "Cumulative Update 7 (CU7) For SQL Server 2016 Service Pack 1 - Security Advisory ADV180002 / 2018-01-04" }
			"13.0.4457.0" { "Cumulative Update 6 (CU6) For SQL Server 2016 Service Pack 1 / 2017-11-21" }
			"13.0.4451.0" { "Cumulative Update 5 (CU5) For SQL Server 2016 Service Pack 1 / 2017-09-18" }
			"13.0.4446.0" { "Cumulative Update 4 (CU4) For SQL Server 2016 Service Pack 1 / 2017-08-08" }
			"13.0.4435.0" { "Cumulative Update 3 (CU3) For SQL Server 2016 Service Pack 1 / 2017-05-15" }
			"13.0.4422.0" { "Cumulative Update 2 (CU2) For SQL Server 2016 Service Pack 1 / 2017-03-22" }
			"13.0.4411.0" { "Cumulative Update 1 (CU1) For SQL Server 2016 Service Pack 1 / 2017-01-18" }
			"13.0.4259.0" { "Security Update For SQL Server 2016 SP1 GDR: July 9, 2019 / 2019-07-09" }
			"13.0.4224.16" { "Security Update For The Remote Code Execution Vulnerability In SQL Server 2016 SP1 GDR: August 22, 2018 / 2018-08-22" }
			"13.0.4223.10" { "Security Update For The Remote Code Execution Vulnerability In SQL Server 2016 SP1 GDR: August 14, 2018 / 2018-08-14" }
			"13.0.4210.6" { "Description Of The Security Update For SQL Server 2016 SP1 GDR: January 3, 2018 - Security Advisory ADV180002 / 2018-01-03" }
			"13.0.4206.0" { "Security Update For SQL Server 2016 Service Pack 1 GDR: August 8, 2017 / 2017-08-08" }
			"13.0.4202.2" { "GDR Update Package For SQL Server 2016 SP1 / 2016-12-16" }
			"13.0.4199.0" { "Important Update For SQL Server 2016 SP1 Reporting Services / 2016-11-23" }
			"13.0.4001.0" { "Microsoft SQL Server 2016 Service Pack 1 (SP1) / 2016-11-16" }
			"13.0.2218.0" { "Description Of The Security Update For SQL Server 2016 CU: January 6, 2018 - Security Advisory ADV180002 / 2018-01-06" }
			"13.0.2216.0" { "Cumulative Update 9 (CU9) For SQL Server 2016 / 2017-11-21" }
			"13.0.2213.0" { "Cumulative Update 8 (CU8) For SQL Server 2016 / 2017-09-18" }
			"13.0.2210.0" { "Cumulative Update 7 (CU7) For SQL Server 2016 / 2017-08-08" }
			"13.0.2204.0" { "Cumulative Update 6 (CU6) For SQL Server 2016 / 2017-05-15" }
			"13.0.2197.0" { "Cumulative Update 5 (CU5) For SQL Server 2016 / 2017-03-21" }
			"13.0.2193.0" { "Cumulative Update 4 (CU4) For SQL Server 2016 / 2017-01-18" }
			"13.0.2190.2" { "On-Demand Hotfix Update Package For SQL Server 2016 CU3 / 2016-12-16" }
			"13.0.2186.6" { "Cumulative Update 3 (CU3) For SQL Server 2016 / 2016-11-08" }
			"13.0.2186.6" { "MS16-136: Description Of The Security Update For SQL Server 2016 CU: November 8, 2016 / 2016-11-08" }
			"13.0.2170.0" { "On-Demand Hotfix Update Package For SQL Server 2016 CU2 / 2016-11-01" }
			"13.0.2169.0" { "On-Demand Hotfix Update Package For SQL Server 2016 CU2 / 2016-10-26" }
			"13.0.2164.0" { "Cumulative Update 2 (CU2) For SQL Server 2016 / 2016-09-22" }
			"13.0.2149.0" { "Cumulative Update 1 (CU1) For SQL Server 2016 / 2016-07-26" }
			"13.0.1745.2" { "Description Of The Security Update For SQL Server 2016 GDR: January 6, 2018 - Security Advisory ADV180002 / 2018-01-06" }
			"13.0.1742.0" { "Security Update For SQL Server 2016 RTM GDR: August 8, 2017 / 2017-08-08" }
			"13.0.1728.2" { "GDR Update Package For SQL Server 2016 RTM / 2016-12-16" }
			"13.0.1722.0" { "MS16-136: Description Of The Security Update For SQL Server 2016 GDR: November 8, 2016 / 2016-11-08" }
			"13.0.1711.0" { "Processing A Partition Causes Data Loss On Other Partitions After The Database Is Restored In SQL Server 2016 (1200) / 2016-08-17" }
			"13.0.1708.0" { "Critical Update For SQL Server 2016 MSVCRT Prerequisites / 2016-06-03" }
			"13.0.1601.5" { "Microsoft SQL Server 2016 RTM / 2016-06-01" }
			"13.0.1400.361" { "Microsoft SQL Server 2016 Release Candidate 3 (RC3) / 2016-04-15" }
			"13.0.1300.275" { "Microsoft SQL Server 2016 Release Candidate 2 (RC2) / 2016-04-01" }
			"13.0.1200.242" { "Microsoft SQL Server 2016 Release Candidate 1 (RC1) / 2016-03-18" }
			"13.0.1100.288" { "Microsoft SQL Server 2016 Release Candidate 0 (RC0) / 2016-03-07" }
			"13.0.1000.281" { "Microsoft SQL Server 2016 Community Technology Preview 3.3 (CTP3.3) / 2016-02-03" }
			"13.0.900.73" { "Microsoft SQL Server 2016 Community Technology Preview 3.2 (CTP3.2) / 2015-12-16" }
			"13.0.800.11" { "Microsoft SQL Server 2016 Community Technology Preview 3.1 (CTP3.1) / 2015-11-30" }
			"13.0.700.139" { "Microsoft SQL Server 2016 Community Technology Preview 3.0 (CTP3.0) / 2015-10-28" }
			"13.0.600.65" { "Microsoft SQL Server 2016 Community Technology Preview 2.4 (CTP2.4) / 2015-09-30" }
			"13.0.500.53" { "Microsoft SQL Server 2016 Community Technology Preview 2.3 (CTP2.3) / 2015-08-28" }
			"13.0.407.1" { "Microsoft SQL Server 2016 Community Technology Preview 2.2 (CTP2.2) / 2015-07-23" }
			"13.0.400.91" { "Microsoft SQL Server 2016 Community Technology Preview 2.2 (CTP2.2) / 2015-07-22" }
			"13.0.300.44" { "Microsoft SQL Server 2016 Community Technology Preview 2.1 (CTP2.1) / 2015-06-24" }
			"13.0.200.172" { "Microsoft SQL Server 2016 Community Technology Preview 2 (CTP2) / 2015-05-27" }
			"12.0.6439.10" { "Security Update For SQL Server 2014 SP3 CU4: June 14, 2022 / 2022-06-14" }
			"12.0.6433.1" { "Security Update For SQL Server 2014 SP3 CU4: January 12, 2021 / 2021-01-12" }
			"12.0.6372.1" { "Security Update For SQL Server 2014 SP3 CU4: February 11, 2020 / 2020-02-11" }
			"12.0.6329.1" { "Cumulative Update Package 4 (CU4) For SQL Server 2014 Service Pack 3 / 2019-07-29" }
			"12.0.6293.0" { "Security Update For SQL Server 2014 SP3 CU3 GDR: July 9, 2019 / 2019-07-09" }
			"12.0.6259.0" { "Cumulative Update Package 3 (CU3) For SQL Server 2014 Service Pack 3 / 2019-04-16" }
			"12.0.6214.1" { "Cumulative Update Package 2 (CU2) For SQL Server 2014 Service Pack 3 / 2019-02-19" }
			"12.0.6205.1" { "Cumulative Update Package 1 (CU1) For SQL Server 2014 Service Pack 3 / 2018-12-12" }
			"12.0.6169.19" { "Security Update For SQL Server 2014 SP3 GDR: June 14, 2022 / 2022-06-14" }
			"12.0.6164.21" { "Security Update For SQL Server 2014 SP3 GDR: January 12, 2021 / 2021-01-12" }
			"12.0.6118.4" { "Security Update For SQL Server 2014 SP3 GDR: February 11, 2020 / 2020-02-11" }
			"12.0.6108.1" { "Security Update For SQL Server 2014 SP3 GDR: July 9, 2019 / 2019-07-09" }
			"12.0.6024.0" { "SQL Server 2014 Service Pack 3 (SP3) / 2018-10-30" }
			"12.0.5687.1" { "Cumulative Update Package 18 (CU18) For SQL Server 2014 Service Pack 2 / 2019-07-29" }
			"12.0.5659.1" { "Security Update For SQL Server 2014 SP2 CU17 GDR: July 9, 2019 / 2019-07-09" }
			"12.0.5632.1" { "Cumulative Update Package 17 (CU17) For SQL Server 2014 Service Pack 2 / 2019-04-16" }
			"12.0.5626.1" { "Cumulative Update Package 16 (CU16) For SQL Server 2014 Service Pack 2 / 2019-02-19" }
			"12.0.5605.1" { "Cumulative Update Package 15 (CU15) For SQL Server 2014 Service Pack 2 / 2018-12-12" }
			"12.0.5600.1" { "Cumulative Update Package 14 (CU14) For SQL Server 2014 Service Pack 2 / 2018-10-15" }
			"12.0.5590.1" { "Cumulative Update Package 13 (CU13) For SQL Server 2014 Service Pack 2 / 2018-08-27" }
			"12.0.5589.7" { "Cumulative Update Package 12 (CU12) For SQL Server 2014 Service Pack 2 / 2018-06-18" }
			"12.0.5579.0" { "Cumulative Update Package 11 (CU11) For SQL Server 2014 Service Pack 2 / 2018-03-19" }
			"12.0.5571.0" { "Cumulative Update Package 10 (CU10) For SQL Server 2014 Service Pack 2 - Security Advisory ADV180002 / 2018-01-16" }
			"12.0.5563.0" { "Cumulative Update Package 9 (CU9) For SQL Server 2014 Service Pack 2 / 2017-12-19" }
			"12.0.5557.0" { "Cumulative Update Package 8 (CU8) For SQL Server 2014 Service Pack 2 / 2017-10-17" }
			"12.0.5556.0" { "Cumulative Update Package 7 (CU7) For SQL Server 2014 Service Pack 2 / 2017-08-29" }
			"12.0.5553.0" { "Cumulative Update Package 6 (CU6) For SQL Server 2014 Service Pack 2 / 2017-08-08" }
			"12.0.5546.0" { "Cumulative Update Package 5 (CU5) For SQL Server 2014 Service Pack 2 / 2017-04-18" }
			"12.0.5540.0" { "Cumulative Update Package 4 (CU4) For SQL Server 2014 Service Pack 2 / 2017-02-21" }
			"12.0.5538.0" { "Cumulative Update Package 3 (CU3) For SQL Server 2014 Service Pack 2 - The Article Incorrectly Says It's Version 12.0.5537 / 2016-12-28" }
			"12.0.5532.0" { "MS16-136: Description Of The Security Update For SQL Server 2014 Service Pack 2 CU: November 8, 2016 / 2016-11-08" }
			"12.0.5522.0" { "Cumulative Update Package 2 (CU2) For SQL Server 2014 Service Pack 2 / 2016-10-18" }
			"12.0.5511.0" { "Cumulative Update Package 1 (CU1) For SQL Server 2014 Service Pack 2 / 2016-08-26" }
			"12.0.5223.6" { "Security Update For SQL Server 2014 SP2 GDR: July 9, 2019 / 2019-07-09" }
			"12.0.5214.6" { "Security Update For SQL Server 2014 Service Pack 2 GDR: January 16, 2018 - Security Advisory ADV180002 / 2018-01-16" }
			"12.0.5207.0" { "Security Update For SQL Server 2014 Service Pack 2 GDR: August 8, 2017 / 2017-08-08" }
			"12.0.5203.0" { "MS16-136: Description Of The Security Update For SQL Server 2014 Service Pack 2 GDR: November 8, 2016 / 2016-11-08" }
			"12.0.5000.0" { "SQL Server 2014 Service Pack 2 (SP2) / 2016-07-11" }
			"12.0.4522.0" { "Cumulative Update Package 13 (CU13) For SQL Server 2014 Service Pack 1 / 2017-08-08" }
			"12.0.4511.0" { "Cumulative Update Package 12 (CU12) For SQL Server 2014 Service Pack 1 / 2017-04-18" }
			"12.0.4502.0" { "Cumulative Update Package 11 (CU11) For SQL Server 2014 Service Pack 1 / 2017-02-21" }
			"12.0.4491.0" { "Cumulative Update Package 10 (CU10) For SQL Server 2014 Service Pack 1 / 2016-12-28" }
			"12.0.4487.0" { "MS16-136: Description Of The Security Update For SQL Server 2014 Service Pack 1 CU: November 8, 2016 / 2016-11-08" }
			"12.0.4474.0" { "Cumulative Update Package 9 (CU9) For SQL Server 2014 Service Pack 1 / 2016-10-18" }
			"12.0.4468.0" { "Cumulative Update Package 8 (CU8) For SQL Server 2014 Service Pack 1 / 2016-08-15" }
			"12.0.4463.0" { "A Memory Leak Occurs When You Use Azure Storage In SQL Server 2014 / 2016-08-04" }
			"12.0.4459.0" { "Cumulative Update Package 7 (CU7) For SQL Server 2014 Service Pack 1 / 2016-06-20" }
			"12.0.4457.1" { "REFRESHED Cumulative Update Package 6 (CU6) For SQL Server 2014 Service Pack 1 / 2016-05-31" }
			"12.0.4449.1" { "DEPRECATED Cumulative Update Package 6 (CU6) For SQL Server 2014 Service Pack 1 / 2016-04-19" }
			"12.0.4439.1" { "Cumulative Update Package 5 (CU5) For SQL Server 2014 Service Pack 1 / 2016-02-22" }
			"12.0.4437.0" { "On-Demand Hotfix Update Package For SQL Server 2014 Service Pack 1 Cumulative Update 4 / 2016-02-05" }
			"12.0.4436.0" { "Cumulative Update Package 4 (CU4) For SQL Server 2014 Service Pack 1 / 2015-12-22" }
			"12.0.4433.0" { "FIX: Error 3203 And A SQL Server 2014 Backup Job Can't Restart When A Network Failure Occurs / 2015-12-09" }
			"12.0.4432.0" { "FIX: Error When Your Stored Procedure Calls Another Stored Procedure On Linked Server In SQL Server 2014 / 2015-11-19" }
			"12.0.4237.0" { "Security Update For SQL Server 2014 Service Pack 1 GDR: August 8, 2017 / 2017-08-08" }
			"12.0.4232.0" { "MS16-136: Description Of The Security Update For SQL Server 2014 Service Pack 1 GDR: November 8, 2016 / 2016-11-08" }
			"12.0.4427.24" { "Cumulative Update Package 3 (CU3) For SQL Server 2014 Service Pack 1 / 2015-10-21" }
			"12.0.4422.0" { "Cumulative Update Package 2 (CU2) For SQL Server 2014 Service Pack 1 / 2015-08-17" }
			"12.0.4419.0" { "An On-Demand Hotfix Update Package Is Available For SQL Server 2014 SP1 / 2015-07-24" }
			"12.0.4416.0" { "Cumulative Update Package 1 (CU1) For SQL Server 2014 Service Pack 1 / 2015-06-22" }
			"12.0.4219.0" { "TLS 1.2 Support For SQL Server 2014 SP1 / 2016-01-27" }
			"12.0.4213.0" { "MS15-058: Description Of The Nonsecurity Update For SQL Server 2014 Service Pack 1 GDR: July 14, 2015 / 2015-07-14" }
			"12.0.4100.1" { "SQL Server 2014 Service Pack 1 (SP1) / 2015-05-14" }
			"12.0.4050.0" { "SQL Server 2014 Service Pack 1 (SP1) / 2015-04-15" }
			"12.0.2569.0" { "Cumulative Update Package 14 (CU14) For SQL Server 2014 / 2016-06-20" }
			"12.0.2568.0" { "Cumulative Update Package 13 (CU13) For SQL Server 2014 / 2016-04-18" }
			"12.0.2564.0" { "Cumulative Update Package 12 (CU12) For SQL Server 2014 / 2016-02-22" }
			"12.0.2560.0" { "Cumulative Update Package 11 (CU11) For SQL Server 2014 / 2015-12-22" }
			"12.0.2556.4" { "Cumulative Update Package 10 (CU10) For SQL Server 2014 / 2015-10-20" }
			"12.0.2553.0" { "Cumulative Update Package 9 (CU9) For SQL Server 2014 / 2015-08-17" }
			"12.0.2548.0" { "MS15-058: Description Of The Security Update For SQL Server 2014 QFE: July 14, 2015 / 2015-07-14" }
			"12.0.2546.0" { "Cumulative Update Package 8 (CU8) For SQL Server 2014 / 2015-06-22" }
			"12.0.2506.0" { "Update Enables Premium Storage Support For Data Files On Azure Storage And Resolves Backup Failures / 2015-05-19" }
			"12.0.2505.0" { "FIX: Error 1205 When You Execute Parallel Query That Contains Outer Join Operators In SQL Server 2014 / 2015-05-19" }
			"12.0.2504.0" { "FIX: Poor Performance When A Query Contains Table Joins In SQL Server 2014 / 2015-05-05" }
			"12.0.2504.0" { "FIX: Unpivot Transformation Task Changes Null To Zero Or Empty Strings In SSIS 2014 / 2015-05-05" }
			"12.0.2495.0" { "Cumulative Update Package 7 (CU7) For SQL Server 2014 / 2015-04-23" }
			"12.0.2488.0" { "FIX: Deadlock Cannot Be Resolved Automatically When You Run A SELECT Query That Can Result In A Parallel Batch-Mode Scan / 2015-04-01" }
			"12.0.2485.0" { "An On-Demand Hotfix Update Package Is Available For SQL Server 2014 / 2015-03-16" }
			"12.0.2480.0" { "Cumulative Update Package 6 (CU6) For SQL Server 2014 / 2015-02-16" }
			"12.0.2474.0" { "FIX: Alwayson Availability Groups Are Reported As NOT SYNCHRONIZING / 2015-05-15" }
			"12.0.2472.0" { "FIX: Cannot Show Requested Dialog After You Connect To The Latest SQL Database Update V12 (Preview) With SQL Server 2014 / 2015-01-28" }
			"12.0.2464.0" { "Large Query Compilation Waits On RESOURCE_SEMAPHORE_QUERY_COMPILE In SQL Server 2014 / 2015-01-05" }
			"12.0.2456.0" { "Cumulative Update Package 5 (CU5) For SQL Server 2014 / 2014-12-18" }
			"12.0.2436.0" { "FIX: 'Remote Hardening Failure' Exception Cannot Be Caught And A Potential Data Loss When You Use SQL Server 2014 / 2014-11-27" }
			"12.0.2430.0" { "Cumulative Update Package 4 (CU4) For SQL Server 2014 / 2014-10-21" }
			"12.0.2423.0" { "FIX: RTDATA_LIST Waits When You Run Natively Stored Procedures That Encounter Expected Failures In SQL Server 2014 / 2014-10-22" }
			"12.0.2405.0" { "FIX: Poor Performance When A Query Contains Table Joins In SQL Server 2014 / 2014-09-25" }
			"12.0.2402.0" { "Cumulative Update Package 3 (CU3) For SQL Server 2014 / 2014-08-18" }
			"12.0.2381.0" { "MS14-044: Description Of The Security Update For SQL Server 2014 (QFE) / 2014-08-12" }
			"12.0.2370.0" { "Cumulative Update Package 2 (CU2) For SQL Server 2014 / 2014-06-27" }
			"12.0.2342.0" { "Cumulative Update Package 1 (CU1) For SQL Server 2014 / 2014-04-21" }
			"12.0.2271.0" { "TLS 1.2 Support For SQL Server 2014 RTM / 2016-01-27" }
			"12.0.2269.0" { "MS15-058: Description Of The Security Update For SQL Server 2014 GDR: July 14, 2015 / 2015-07-14" }
			"12.0.2254.0" { "MS14-044: Description Of The Security Update For SQL Server 2014 (GDR) / 2014-08-12" }
			"12.0.2000.8" { "SQL Server 2014 RTM / 2014-04-01" }
			"12.0.1524.0" { "Microsoft SQL Server 2014 Community Technology Preview 2 (CTP2) / 2013-10-15" }
			"11.0.9120.0" { "Microsoft SQL Server 2014 Community Technology Preview 1 (CTP1) / 2013-06-25" }
			"11.0.7507.2" { "Security Update For SQL Server 2012 SP4 GDR: January 12, 2021 / 2021-01-12" }
			"11.0.7493.4" { "Security Update For SQL Server 2012 SP4 GDR: February 11, 2020 / 2020-02-11" }
			"11.0.7469.6" { "On-Demand Hotfix Update Package For SQL Server 2012 SP4 / 2018-03-28" }
			"11.0.7462.6" { "Description Of The Security Update For SQL Server 2012 SP4 GDR: January 12, 2018 - Security Advisory ADV180002 / 2018-01-12" }
			"11.0.7001.0" { "SQL Server 2012 Service Pack 4 (SP4) / 2017-10-05" }
			"11.0.6615.2" { "Description Of The Security Update For SQL Server 2012 SP3 CU: January 16, 2018 - Security Advisory ADV180002 / 2018-01-16" }
			"11.0.6607.3" { "Cumulative Update Package 10 (CU10) For SQL Server 2012 Service Pack 3 / 2017-08-08" }
			"11.0.6607.3" { "Security Update For SQL Server 2012 Service Pack 3 CU: August 8, 2017 / 2017-08-08" }
			"11.0.6598.0" { "Cumulative Update Package 9 (CU9) For SQL Server 2012 Service Pack 3 / 2017-05-15" }
			"11.0.6594.0" { "Cumulative Update Package 8 (CU8) For SQL Server 2012 Service Pack 3 / 2017-03-21" }
			"11.0.6579.0" { "Cumulative Update Package 7 (CU7) For SQL Server 2012 Service Pack 3 / 2017-01-17" }
			"11.0.6567.0" { "Cumulative Update Package 6 (CU6) For SQL Server 2012 Service Pack 3 / 2016-11-17" }
			"11.0.6567.0" { "MS16-136: Description Of The Security Update For SQL Server 2012 Service Pack 3 CU: November 8, 2016 / 2016-11-08" }
			"11.0.6544.0" { "Cumulative Update Package 5 (CU5) For SQL Server 2012 Service Pack 3 / 2016-09-21" }
			"11.0.6540.0" { "Cumulative Update Package 4 (CU4) For SQL Server 2012 Service Pack 3 / 2016-07-19" }
			"11.0.6537.0" { "Cumulative Update Package 3 (CU3) For SQL Server 2012 Service Pack 3 / 2016-05-17" }
			"11.0.6523.0" { "Cumulative Update Package 2 (CU2) For SQL Server 2012 Service Pack 3 / 2016-03-22" }
			"11.0.6518.0" { "Cumulative Update Package 1 (CU1) For SQL Server 2012 Service Pack 3 / 2016-01-19" }
			"11.0.6260.1" { "Description Of The Security Update For SQL Server 2012 SP3 GDR: January 16, 2018 - Security Advisory ADV180002 / 2018-01-16" }
			"11.0.6251.0" { "Description Of The Security Update For SQL Server 2012 Service Pack 3 GDR: August 8, 2017 / 2017-08-08" }
			"11.0.6248.0" { "MS16-136: Description Of The Security Update For SQL Server 2012 Service Pack 3 GDR: November 8, 2016 / 2016-11-08" }
			"11.0.6216.27" { "TLS 1.2 Support For SQL Server 2012 SP3 GDR / 2016-01-27" }
			"11.0.6020.0" { "SQL Server 2012 Service Pack 3 (SP3) / 2015-11-23" }
			"11.0.5678.0" { "Cumulative Update Package 16 (CU16) For SQL Server 2012 Service Pack 2 / 2017-01-18" }
			"11.0.5676.0" { "Cumulative Update Package 15 (CU15) For SQL Server 2012 Service Pack 2 / 2016-11-17" }
			"11.0.5676.0" { "MS16-136: Description Of The Security Update For SQL Server 2012 Service Pack 2 CU: November 8, 2016 / 2016-11-08" }
			"11.0.5657.0" { "Cumulative Update Package 14 (CU14) For SQL Server 2012 Service Pack 2 / 2016-09-20" }
			"11.0.5655.0" { "Cumulative Update Package 13 (CU13) For SQL Server 2012 Service Pack 2 / 2016-07-19" }
			"11.0.5649.0" { "Cumulative Update Package 12 (CU12) For SQL Server 2012 Service Pack 2 / 2016-05-16" }
			"11.0.5646.0" { "Cumulative Update Package 11 (CU11) For SQL Server 2012 Service Pack 2 / 2016-03-22" }
			"11.0.5644.0" { "Cumulative Update Package 10 (CU10) For SQL Server 2012 Service Pack 2 / 2016-01-20" }
			"11.0.5641.0" { "Cumulative Update Package 9 (CU9) For SQL Server 2012 Service Pack 2 / 2015-11-18" }
			"11.0.5636.3" { "FIX: Performance Decrease When Application With Connection Pooling Frequently Connects Or Disconnects In SQL Server / 2015-09-22" }
			"11.0.5634.0" { "Cumulative Update Package 8 (CU8) For SQL Server 2012 Service Pack 2 / 2015-09-21" }
			"11.0.5629.0" { "FIX: Access Violations When You Use The Filetable Feature In SQL Server 2012 / 2015-08-31" }
			"11.0.5623.0" { "Cumulative Update Package 7 (CU7) For SQL Server 2012 Service Pack 2 / 2015-07-20" }
			"11.0.5613.0" { "MS15-058: Description Of The Security Update For SQL Server 2012 Service Pack 2 QFE: July 14, 2015 / 2015-07-14" }
			"11.0.5592.0" { "Cumulative Update Package 6 (CU6) For SQL Server 2012 Service Pack 2 / 2015-05-19" }
			"11.0.5582.0" { "Cumulative Update Package 5 (CU5) For SQL Server 2012 Service Pack 2 / 2015-03-16" }
			"11.0.5571.0" { "FIX: Alwayson Availability Groups Are Reported As NOT SYNCHRONIZING / 2015-05-15" }
			"11.0.5569.0" { "Cumulative Update Package 4 (CU4) For SQL Server 2012 Service Pack 2 / 2015-01-20" }
			"11.0.5556.0" { "Cumulative Update Package 3 (CU3) For SQL Server 2012 Service Pack 2 / 2014-11-17" }
			"11.0.5548.0" { "Cumulative Update Package 2 (CU2) For SQL Server 2012 Service Pack 2 / 2014-09-15" }
			"11.0.5532.0" { "Cumulative Update Package 1 (CU1) For SQL Server 2012 Service Pack 2 / 2014-07-24" }
			"11.0.5522.0" { "FIX: Data Loss In Clustered Index Occurs When You Run Online Build Index In SQL Server 2012 (Hotfix For SQL2012 SP2) / 2014-06-20" }
			"11.0.5388.0" { "MS16-136: Description Of The Security Update For SQL Server 2012 Service Pack 2 GDR: November 8, 2016 / 2016-11-08" }
			"11.0.5352.0" { "TLS 1.2 Support For SQL Server 2012 SP2 GDR / 2016-01-27" }
			"11.0.5343.0" { "MS15-058: Description Of The Security Update For SQL Server 2012 Service Pack 2 GDR: July 14, 2015 / 2015-07-14" }
			"11.0.5058.0" { "SQL Server 2012 Service Pack 2 (SP2) / 2014-06-10" }
			"11.0.3513.0" { "MS15-058: Description Of The Security Update For SQL Server 2012 SP1 QFE: July 14, 2015 / 2015-07-14" }
			"11.0.3492.0" { "Cumulative Update Package 16 (CU16) For SQL Server 2012 Service Pack 1 / 2015-05-18" }
			"11.0.3487.0" { "Cumulative Update Package 15 (CU15) For SQL Server 2012 Service Pack 1 / 2015-03-16" }
			"11.0.3486.0" { "Cumulative Update Package 14 (CU14) For SQL Server 2012 Service Pack 1 / 2015-01-19" }
			"11.0.3460.0" { "MS14-044: Description Of The Security Update For SQL Server 2012 Service Pack 1 (QFE) / 2014-08-12" }
			"11.0.3482.0" { "Cumulative Update Package 13 (CU13) For SQL Server 2012 Service Pack 1 / 2014-11-17" }
			"11.0.3470.0" { "Cumulative Update Package 12 (CU12) For SQL Server 2012 Service Pack 1 / 2014-09-15" }
			"11.0.3449.0" { "Cumulative Update Package 11 (CU11) For SQL Server 2012 Service Pack 1 / 2014-07-21" }
			"11.0.3437.0" { "FIX: Data Loss In Clustered Index Occurs When You Run Online Build Index In SQL Server 2012 (Hotfix For SQL2012 SP1) / 2014-06-10" }
			"11.0.3431.0" { "Cumulative Update Package 10 (CU10) For SQL Server 2012 Service Pack 1 / 2014-05-19" }
			"11.0.3412.0" { "Cumulative Update Package 9 (CU9) For SQL Server 2012 Service Pack 1 / 2014-03-18" }
			"11.0.3401.0" { "Cumulative Update Package 8 (CU8) For SQL Server 2012 Service Pack 1 / 2014-01-20" }
			"11.0.3393.0" { "Cumulative Update Package 7 (CU7) For SQL Server 2012 Service Pack 1 / 2013-11-18" }
			"11.0.3381.0" { "Cumulative Update Package 6 (CU6) For SQL Server 2012 Service Pack 1 / 2013-09-16" }
			"11.0.3373.0" { "Cumulative Update Package 5 (CU5) For SQL Server 2012 Service Pack 1 / 2013-07-16" }
			"11.0.3368.0" { "Cumulative Update Package 4 (CU4) For SQL Server 2012 Service Pack 1 / 2013-05-31" }
			"11.0.3350.0" { "FIX: You Can'T Create Or Open SSIS Projects Or Maintenance Plans After You Apply Cumulative Update 3 For SQL Server 2012 SP1 / 2013-04-17" }
			"11.0.3349.0" { "Cumulative Update Package 3 (CU3) For SQL Server 2012 Service Pack 1 / 2013-03-18" }
			"11.0.3339.0" { "Cumulative Update Package 2 (CU2) For SQL Server 2012 Service Pack 1 / 2013-01-25" }
			"11.0.3335.0" { "FIX: Component Installation Process Fails After You Install SQL Server 2012 SP1 / 2013-01-14" }
			"11.0.3321.0" { "Cumulative Update Package 1 (CU1) For SQL Server 2012 Service Pack 1 / 2012-11-20" }
			"11.0.3156.0" { "MS15-058: Description Of The Security Update For SQL Server 2012 SP1 GDR: July 14, 2015 / 2015-07-14" }
			"11.0.3153.0" { "MS14-044: Description Of The Security Update For SQL Server 2012 Service Pack 1 (GDR) / 2014-08-12" }
			"11.0.3128.0" { "Windows Installer Starts Repeatedly After You Install SQL Server 2012 SP1 / 2013-01-03" }
			"11.0.3000.0" { "SQL Server 2012 Service Pack 1 (SP1) / 2012-11-06" }
			"11.0.2845.0" { "SQL Server 2012 Service Pack 1 Customer Technology Preview 4 (CTP4) / 2012-09-20" }
			"11.0.2809.24" { "SQL Server 2012 Service Pack 1 Customer Technology Preview 3 (CTP3) / 2012-07-05" }
			"11.0.2424.0" { "Cumulative Update Package 11 (CU11) For SQL Server 2012 / 2013-12-17" }
			"11.0.2420.0" { "Cumulative Update Package 10 (CU10) For SQL Server 2012 / 2013-10-21" }
			"11.0.2419.0" { "Cumulative Update Package 9 (CU9) For SQL Server 2012 / 2013-08-21" }
			"11.0.2410.0" { "Cumulative Update Package 8 (CU8) For SQL Server 2012 / 2013-06-18" }
			"11.0.2405.0" { "Cumulative Update Package 7 (CU7) For SQL Server 2012 / 2013-04-15" }
			"11.0.2401.0" { "Cumulative Update Package 6 (CU6) For SQL Server 2012 / 2013-02-18" }
			"11.0.2395.0" { "Cumulative Update Package 5 (CU5) For SQL Server 2012 / 2012-12-18" }
			"11.0.9000.5" { "Microsoft SQL Server 2012 With Power View For Multidimensional Models Customer Technology Preview (CTP3) / 2012-11-27" }
			"11.0.2383.0" { "Cumulative Update Package 4 (CU4) For SQL Server 2012 / 2012-10-18" }
			"11.0.2376.0" { "Microsoft Security Bulletin MS12-070 / 2012-10-09" }
			"11.0.2332.0" { "Cumulative Update Package 3 (CU3) For SQL Server 2012 / 2012-08-29" }
			"11.0.2325.0" { "Cumulative Update Package 2 (CU2) For SQL Server 2012 / 2012-06-18" }
			"11.0.2318.0" { "SQL Server 2012 Express Localdb RTM / 2012-04-19" }
			"11.0.2316.0" { "Cumulative Update Package 1 (CU1) For SQL Server 2012 / 2012-04-12" }
			"11.0.2218.0" { "Microsoft Security Bulletin MS12-070 / 2012-10-09" }
			"11.0.2214.0" { "FIX: SSAS Uses Only 20 Cores In SQL Server 2012 Business Intelligence / 2012-04-06" }
			"11.0.2100.60" { "SQL Server 2012 RTM / 2012-03-06" }
			"11.0.1913.37" { "Microsoft SQL Server 2012 Release Candidate 1 (RC1) / 2011-12-16" }
			"11.0.1750.32" { "Microsoft SQL Server 2012 Release Candidate 0 (RC0) / 2011-11-17" }
			"11.0.1440.19" { "Microsoft SQL Server 2012 (Codename Denali) Community Technology Preview 3 (CTP3) / 2011-07-11" }
			"11.0.1103.9" { "Microsoft SQL Server 2012 (Codename Denali) Community Technology Preview 1 (CTP1) / 2010-11-08" }
			"10.50.6560.0" { "Description Of The Security Update For SQL Server 2008 R2 SP3 GDR: January 6, 2018 - Security Advisory ADV180002 / 2018-01-06" }
			"10.50.6549.0" { "An Unknown But Existing Build / " }
			"10.50.6542.0" { "Intermittent Service Terminations Occur After You Install Any SQL Server 2008 Or SQL Server 2008 R2 Versions From KB3135244 / 2016-03-03" }
			"10.50.6537.0" { "TLS 1.2 Support For SQL Server 2008 R2 SP3 / 2016-01-27" }
			"10.50.6529.0" { "MS15-058: Description Of The Security Update For SQL Server 2008 R2 Service Pack 3 QFE: July 14, 2015 / 2015-07-14" }
			"10.50.6525.0" { "An On-Demand Hotfix Update Package Is Available For SQL Server 2008 R2 Service Pack 3 (SP3) / 2015-02-09" }
			"10.50.6220.0" { "MS15-058: Description Of The Security Update For SQL Server 2008 R2 Service Pack 3 GDR: July 14, 2015 / 2015-07-14" }
			"10.50.6000.34" { "SQL Server 2008 R2 Service Pack 3 (SP3) / 2014-09-26" }
			"10.50.4343.0" { "TLS 1.2 Support For SQL Server 2008 R2 SP2 (IA-64 Only) / 2016-01-27" }
			"10.50.4339.0" { "MS15-058: Description Of The Security Update For SQL Server 2008 R2 Service Pack 2 QFE: July 14, 2015 / 2015-07-14" }
			"10.50.4331.0" { "Restore Log With Standby Mode On An Advanced Format Disk May Cause A 9004 Error In SQL Server 2008 R2 Or SQL Server 2012 / 2014-08-27" }
			"10.50.4321.0" { "MS14-044: Description Of The Security Update For SQL Server 2008 R2 Service Pack 2 (QFE) / 2014-08-12" }
			"10.50.4319.0" { "Cumulative Update Package 13 (CU13) For SQL Server 2008 R2 Service Pack 2 / 2014-06-30" }
			"10.50.4305.0" { "Cumulative Update Package 12 (CU12) For SQL Server 2008 R2 Service Pack 2 / 2014-04-21" }
			"10.50.4302.0" { "Cumulative Update Package 11 (CU11) For SQL Server 2008 R2 Service Pack 2 / 2014-02-18" }
			"10.50.4297.0" { "Cumulative Update Package 10 (CU10) For SQL Server 2008 R2 Service Pack 2 / 2013-12-16" }
			"10.50.4295.0" { "Cumulative Update Package 9 (CU9) For SQL Server 2008 R2 Service Pack 2 / 2013-10-29" }
			"10.50.4290.0" { "Cumulative Update Package 8 (CU8) For SQL Server 2008 R2 Service Pack 2 / 2013-08-30" }
			"10.50.4286.0" { "Cumulative Update Package 7 (CU7) For SQL Server 2008 R2 Service Pack 2 / 2013-06-17" }
			"10.50.4285.0" { "Cumulative Update Package 6 (CU6) For SQL Server 2008 R2 Service Pack 2 (Updated) / 2013-06-13" }
			"10.50.4279.0" { "Cumulative Update Package 6 (CU6) For SQL Server 2008 R2 Service Pack 2 (Replaced) / 2013-04-15" }
			"10.50.4276.0" { "Cumulative Update Package 5 (CU5) For SQL Server 2008 R2 Service Pack 2 / 2013-02-18" }
			"10.50.4270.0" { "Cumulative Update Package 4 (CU4) For SQL Server 2008 R2 Service Pack 2 / 2012-12-17" }
			"10.50.4266.0" { "Cumulative Update Package 3 (CU3) For SQL Server 2008 R2 Service Pack 2 / 2012-10-15" }
			"10.50.4263.0" { "Cumulative Update Package 2 (CU2) For SQL Server 2008 R2 Service Pack 2 / 2012-08-29" }
			"10.50.4260.0" { "Cumulative Update Package 1 (CU1) For SQL Server 2008 R2 Service Pack 2 / 2012-08-01" }
			"10.50.4046.0" { "TLS 1.2 Support For SQL Server 2008 R2 SP2 GDR (IA-64 Only) / 2016-01-27" }
			"10.50.4042.0" { "MS15-058: Description Of The Security Update For SQL Server 2008 R2 Service Pack 2 GDR: July 14, 2015 / 2015-07-14" }
			"10.50.4033.0" { "MS14-044: Description Of The Security Update For SQL Server 2008 R2 Service Pack 2 (GDR) / 2014-08-12" }
			"10.50.4000.0" { "SQL Server 2008 R2 Service Pack 2 (SP2) / 2012-07-26" }
			"10.50.3720.0" { "SQL Server 2008 R2 Service Pack 2 Community Technology Preview (CTP) / 2012-05-13" }
			"10.50.2881.0" { "An On-Demand Hotfix Update Package For SQL Server 2008 R2 Service Pack 1 / 2013-08-12" }
			"10.50.2876.0" { "Cumulative Update Package 13 (CU13) For SQL Server 2008 R2 Service Pack 1 / 2013-06-17" }
			"10.50.2875.0" { "Cumulative Update Package 12 (CU12) For SQL Server 2008 R2 Service Pack 1 (Updated) / 2013-06-13" }
			"10.50.2874.0" { "Cumulative Update Package 12 (CU12) For SQL Server 2008 R2 Service Pack 1 (Replaced) / 2013-04-15" }
			"10.50.2861.0" { "Microsoft Security Bulletin MS12-070 / 2012-10-09" }
			"10.50.2869.0" { "Cumulative Update Package 11 (CU11) For SQL Server 2008 R2 Service Pack 1 / 2013-02-18" }
			"10.50.2868.0" { "Cumulative Update Package 10 (CU10) For SQL Server 2008 R2 Service Pack 1 / 2012-12-17" }
			"10.50.2866.0" { "Cumulative Update Package 9 (CU9) For SQL Server 2008 R2 Service Pack 1 / 2012-11-06" }
			"10.50.2861.0" { "MS12-070: Description Of The Security Update For SQL Server 2008 R2 Service Pack 1 QFE: October 9, 2012 / 2012-10-09" }
			"10.50.2822.0" { "Cumulative Update Package 8 (CU8) For SQL Server 2008 R2 Service Pack 1 / 2012-08-29" }
			"10.50.2817.0" { "Cumulative Update Package 7 (CU7) For SQL Server 2008 R2 Service Pack 1 / 2012-06-18" }
			"10.50.2811.0" { "Cumulative Update Package 6 (CU6) For SQL Server 2008 R2 Service Pack 1 / 2012-04-16" }
			"10.50.2807.0" { "FIX: Access Violation When You Run DML Statements Against A Table That Has Partitioned Indexes In SQL Server 2008 R2 / 2012-03-12" }
			"10.50.2806.0" { "Cumulative Update Package 5 (CU5) For SQL Server 2008 R2 Service Pack 1 / 2012-02-22" }
			"10.50.2799.0" { "FIX: 'Non-Yielding Scheduler' Error Might Occur When You Run A Query That Uses The CHARINDEX Function In SQL Server 2008 R2 / 2012-02-22" }
			"10.50.2796.0" { "Cumulative Update Package 4 (CU4) For SQL Server 2008 R2 Service Pack 1 / 2011-12-20" }
			"10.50.2789.0" { "Cumulative Update Package 3 (CU3) For SQL Server 2008 R2 Service Pack 1 / 2011-10-17" }
			"10.50.2776.0" { "FIX: Slow Performance When An AFTER Trigger Runs On A Partitioned Table In SQL Server 2008 R2 / 2011-10-18" }
			"10.50.2772.0" { "Cumulative Update Package 2 (CU2) For SQL Server 2008 R2 Service Pack 1 / 2011-08-15" }
			"10.50.2769.0" { "Cumulative Update Package 1 (CU1) For SQL Server 2008 R2 Service Pack 1 / 2011-07-18" }
			"10.50.2550.0" { "Microsoft Security Bulletin MS12-070 / 2012-10-09" }
			"10.50.2500.0" { "SQL Server 2008 R2 Service Pack 1 (SP1) / 2011-07-11" }
			"10.50.1817.0" { "Cumulative Update Package 14 (CU14) For SQL Server 2008 R2 / 2012-06-18" }
			"10.50.1815.0" { "Cumulative Update Package 13 (CU13) For SQL Server 2008 R2 / 2012-04-17" }
			"10.50.1810.0" { "Cumulative Update Package 12 (CU12) For SQL Server 2008 R2 / 2012-02-21" }
			"10.50.1809.0" { "Cumulative Update Package 11 (CU11) For SQL Server 2008 R2 / 2012-01-09" }
			"10.50.1807.0" { "Cumulative Update Package 10 (CU10) For SQL Server 2008 R2 / 2011-10-19" }
			"10.50.1804.0" { "Cumulative Update Package 9 (CU9) For SQL Server 2008 R2 / 2011-08-16" }
			"10.50.1800.0" { "FIX: Database Data Files Might Be Incorrectly Marked As Sparse In SQL Server 2008 R2 Or In SQL Server 2008 Even When The Physical Files Are Marked As Not Sparse In The File System / 2011-10-18" }
			"10.50.1797.0" { "Cumulative Update Package 8 (CU8) For SQL Server 2008 R2 / 2011-06-20" }
			"10.50.1790.0" { "MS11-049: Description Of The Security Update For SQL Server 2008 R2 QFE: June 14, 2011 / 2011-06-17" }
			"10.50.1777.0" { "Cumulative Update Package 7 (CU7) For SQL Server 2008 R2 / 2011-06-16" }
			"10.50.1769.0" { "FIX: Non-Yielding Scheduler Error When You Run A Query That Uses A TVP In SQL Server 2008 Or In SQL Server 2008 R2 If SQL Profiler Or SQL Server Extended Events Is Used / 2011-04-18" }
			"10.50.1765.0" { "Cumulative Update Package 6 (CU6) For SQL Server 2008 R2 / 2011-02-21" }
			"10.50.1753.0" { "Cumulative Update Package 5 (CU5) For SQL Server 2008 R2 / 2010-12-23" }
			"10.50.1746.0" { "Cumulative Update Package 4 (CU4) For SQL Server 2008 R2 / 2010-10-18" }
			"10.50.1734.0" { "Cumulative Update Package 3 (CU3) For SQL Server 2008 R2 / 2010-08-20" }
			"10.50.1720.0" { "Cumulative Update Package 2 (CU2) For SQL Server 2008 R2 / 2010-06-25" }
			"10.50.1702.0" { "Cumulative Update Package 1 (CU1) For SQL Server 2008 R2 / 2010-05-18" }
			"10.50.1617.0" { "MS11-049: Description Of The Security Update For SQL Server 2008 R2 GDR: June 14, 2011 / 2011-06-14" }
			"10.50.1600.1" { "SQL Server 2008 R2 RTM / 2010-04-21" }
			"10.50.1352.12" { "Microsoft SQL Server 2008 R2 November Community Technology Preview (CTP) / 2009-11-12" }
			"10.50.1092.20" { "Microsoft SQL Server 2008 R2 August Community Technology Preview (CTP) / 2009-06-30" }
			"10.0.6556.0" { "Description Of The Security Update For SQL Server 2008 SP4 GDR: January 6, 2018 - Security Advisory ADV180002 / 2018-01-06" }
			"10.0.6547.0" { "Intermittent Service Terminations Occur After You Install Any SQL Server 2008 Or SQL Server 2008 R2 Versions From KB3135244 / 2016-03-03" }
			"10.0.6543.0" { "TLS 1.2 Support For SQL Server 2008 SP4 / 2016-01-27" }
			"10.0.6535.0" { "MS15-058: Description Of The Security Update For SQL Server 2008 Service Pack 4 QFE: July 14, 2015 / 2015-07-14" }
			"10.0.6526.0" { "An On-Demand Hotfix Update Package Is Available For SQL Server 2008 Service Pack 4 (SP4) / 2015-02-09" }
			"10.0.6241.0" { "MS15-058: Description Of The Security Update For SQL Server 2008 Service Pack 4 GDR: July 14, 2015 / 2015-07-14" }
			"10.0.6000.29" { "SQL Server 2008 Service Pack 4 (SP4) / 2014-09-30" }
			"10.0.5894.0" { "TLS 1.2 Support For SQL Server 2008 SP3 (IA-64 Only) / 2016-01-27" }
			"10.0.5890.0" { "MS15-058: Description Of The Security Update For SQL Server 2008 Service Pack 3 QFE: July 14, 2015 / 2015-07-14" }
			"10.0.5869.0" { "MS14-044: Description Of The Security Update For SQL Server 2008 SP3 (QFE) / 2014-08-12" }
			"10.0.5867.0" { "FIX: Error 8985 When You Run The 'Dbcc Shrinkfile' Statement By Using The Logical Name Of A File In SQL Server 2008 R2 Or SQL Server 2008 / 2014-07-02" }
			"10.0.5861.0" { "Cumulative Update Package 17 (CU17) For SQL Server 2008 Service Pack 3 / 2014-05-19" }
			"10.0.5852.0" { "Cumulative Update Package 16 (CU16) For SQL Server 2008 Service Pack 3 / 2014-03-17" }
			"10.0.5850.0" { "Cumulative Update Package 15 (CU15) For SQL Server 2008 Service Pack 3 / 2014-01-20" }
			"10.0.5848.0" { "Cumulative Update Package 14 (CU14) For SQL Server 2008 Service Pack 3 / 2013-11-18" }
			"10.0.5846.0" { "Cumulative Update Package 13 (CU13) For SQL Server 2008 Service Pack 3 / 2013-09-16" }
			"10.0.5844.0" { "Cumulative Update Package 12 (CU12) For SQL Server 2008 Service Pack 3 / 2013-07-16" }
			"10.0.5841.0" { "Cumulative Update Package 11 (CU11) For SQL Server 2008 Service Pack 3 (Updated) / 2013-06-13" }
			"10.0.5840.0" { "Cumulative Update Package 11 (CU11) For SQL Server 2008 Service Pack 3 (Replaced) / 2013-05-20" }
			"10.0.5835.0" { "Cumulative Update Package 10 (CU10) For SQL Server 2008 Service Pack 3 / 2013-03-18" }
			"10.0.5829.0" { "Cumulative Update Package 9 (CU9) For SQL Server 2008 Service Pack 3 / 2013-01-23" }
			"10.0.5828.0" { "Cumulative Update Package 8 (CU8) For SQL Server 2008 Service Pack 3 / 2012-11-19" }
			"10.0.5826.0" { "Microsoft Security Bulletin MS12-070 / 2012-10-09" }
			"10.0.5794.0" { "Cumulative Update Package 7 (CU7) For SQL Server 2008 Service Pack 3 / 2012-09-21" }
			"10.0.5788.0" { "Cumulative Update Package 6 (CU6) For SQL Server 2008 Service Pack 3 / 2012-07-16" }
			"10.0.5785.0" { "Cumulative Update Package 5 (CU5) For SQL Server 2008 Service Pack 3 / 2012-05-19" }
			"10.0.5775.0" { "Cumulative Update Package 4 (CU4) For SQL Server 2008 Service Pack 3 / 2012-03-20" }
			"10.0.5770.0" { "Cumulative Update Package 3 (CU3) For SQL Server 2008 Service Pack 3 / 2012-01-16" }
			"10.0.5768.0" { "Cumulative Update Package 2 (CU2) For SQL Server 2008 Service Pack 3 / 2011-11-22" }
			"10.0.5766.0" { "Cumulative Update Package 1 (CU1) For SQL Server 2008 Service Pack 3 / 2011-10-18" }
			"10.0.5544.0" { "TLS 1.2 Support For SQL Server 2008 SP3 GDR (IA-64 Only) / 2016-01-27" }
			"10.0.5538.0" { "MS15-058: Description Of The Security Update For SQL Server 2008 Service Pack 3 GDR: July 14, 2015 / 2015-07-14" }
			"10.0.5520.0" { "MS14-044: Description Of The Security Update For SQL Server 2008 SP3 (GDR) / 2014-08-12" }
			"10.0.5512.0" { "Microsoft Security Bulletin MS12-070 / 2012-10-09" }
			"10.0.5500.0" { "SQL Server 2008 Service Pack 3 (SP3) / 2011-10-06" }
			"10.0.5416.0" { "SQL Server 2008 Service Pack 3 CTP / 2011-08-22" }
			"10.0.4371.0" { "Microsoft Security Bulletin MS12-070 / 2012-10-09" }
			"10.0.4333.0" { "Cumulative Update Package 11 (CU11) For SQL Server 2008 Service Pack 2 / 2012-07-16" }
			"10.0.4332.0" { "Cumulative Update Package 10 (CU10) For SQL Server 2008 Service Pack 2 / 2012-05-20" }
			"10.0.4330.0" { "Cumulative Update Package 9 (CU9) For SQL Server 2008 Service Pack 2 / 2012-03-19" }
			"10.0.4326.0" { "Cumulative Update Package 8 (CU8) For SQL Server 2008 Service Pack 2 / 2012-01-30" }
			"10.0.4323.0" { "Cumulative Update Package 7 (CU7) For SQL Server 2008 Service Pack 2 / 2011-11-21" }
			"10.0.4321.0" { "Cumulative Update Package 6 (CU6) For SQL Server 2008 Service Pack 2 / 2011-09-20" }
			"10.0.4316.0" { "Cumulative Update Package 5 (CU5) For SQL Server 2008 Service Pack 2 / 2011-07-18" }
			"10.0.4285.0" { "Cumulative Update Package 4 (CU4) For SQL Server 2008 Service Pack 2 / 2011-05-16" }
			"10.0.4279.0" { "Cumulative Update Package 3 (CU3) For SQL Server 2008 Service Pack 2 / 2011-03-11" }
			"10.0.4272.0" { "Cumulative Update Package 2 (CU2) For SQL Server 2008 Service Pack 2 / 2011-02-10" }
			"10.0.4266.0" { "Cumulative Update Package 1 (CU1) For SQL Server 2008 Service Pack 2 / 2010-11-15" }
			"10.0.4067.0" { "Microsoft Security Bulletin MS12-070 / 2012-10-09" }
			"10.0.4064.0" { "MS11-049: Description Of The Security Update For SQL Server 2008 Service Pack 2 GDR: June 14, 2011 / 2011-06-14" }
			"10.0.4000.0" { "SQL Server 2008 Service Pack 2 (SP2) / 2010-09-29" }
			"10.0.3798.0" { "SQL Server 2008 Service Pack 2 CTP / 2010-07-07" }
			"10.0.2850.0" { "Cumulative Update Package 16 (CU16) For SQL Server 2008 Service Pack 1 / 2011-09-19" }
			"10.0.2847.0" { "Cumulative Update Package 15 (CU15) For SQL Server 2008 Service Pack 1 / 2011-07-18" }
			"10.0.2841.0" { "MS11-049: Description Of The Security Update For SQL Server 2008 Service Pack 1 QFE: June 14, 2011 / 2011-06-14" }
			"10.0.2821.0" { "Cumulative Update Package 14 (CU14) For SQL Server 2008 Service Pack 1 / 2011-05-16" }
			"10.0.2816.0" { "Cumulative Update Package 13 (CU13) For SQL Server 2008 Service Pack 1 / 2011-03-22" }
			"10.0.2808.0" { "Cumulative Update Package 12 (CU12) For SQL Server 2008 Service Pack 1 / 2011-02-10" }
			"10.0.2804.0" { "Cumulative Update Package 11 (CU11) For SQL Server 2008 Service Pack 1 / 2010-11-15" }
			"10.0.2799.0" { "Cumulative Update Package 10 (CU10) For SQL Server 2008 Service Pack 1 / 2010-09-21" }
			"10.0.2789.0" { "Cumulative Update Package 9 (CU9) For SQL Server 2008 Service Pack 1 / 2010-07-21" }
			"10.0.2787.0" { "FIX: The Reporting Services Service Stops Unexpectedly After You Apply SQL Server 2008 SP1 CU 7 Or CU8 / 2010-07-30" }
			"10.0.2775.0" { "Cumulative Update Package 8 (CU8) For SQL Server 2008 Service Pack 1 / 2010-05-17" }
			"10.0.2766.0" { "Cumulative Update Package 7 (CU7) For SQL Server 2008 Service Pack 1 / 2010-03-26" }
			"10.0.2757.0" { "Cumulative Update Package 6 (CU6) For SQL Server 2008 Service Pack 1 / 2010-01-18" }
			"10.0.2746.0" { "Cumulative Update Package 5 (CU5) For SQL Server 2008 Service Pack 1 / 2009-11-16" }
			"10.0.2740.0" { "FIX: Error Message When You Perform A Rolling Upgrade In A SQL Server 2008 Cluster : '18401, Login Failed For User SQLTEST\Agentservice. Reason: Server Is In Script Upgrade Mode. Only Administrator Can Connect At This Time.[Sqlstate 42000]' / 2009-11-24" }
			"10.0.2734.0" { "Cumulative Update Package 4 (CU4) For SQL Server 2008 Service Pack 1 / 2009-09-22" }
			"10.0.2723.0" { "Cumulative Update Package 3 (CU3) For SQL Server 2008 Service Pack 1 / 2009-07-21" }
			"10.0.2714.0" { "Cumulative Update Package 2 (CU2) For SQL Server 2008 Service Pack 1 / 2009-05-18" }
			"10.0.2712.0" { "FIX: Error Message In SQL Server 2008 When You Run An INSERT SELECT Statement On A Table: 'Violation Of PRIMARY KEY Constraint '<Primarykey>'. Cannot Insert Duplicate Key In Object '<Tablename>'' / 2009-07-21" }
			"10.0.2710.0" { "Cumulative Update Package 1 (CU1) For SQL Server 2008 Service Pack 1 / 2009-04-16" }
			"10.0.2573.0" { "MS11-049: Description Of The Security Update For SQL Server 2008 Service Pack 1 GDR: June 14, 2011 / 2011-06-14" }
			"10.0.2531.0" { "SQL Server 2008 Service Pack 1 (SP1) / 2009-04-07" }
			"10.0.2520.0" { "SQL Server 2008 Service Pack 1 - CTP / 2009-02-23" }
			"10.0.1835.0" { "Cumulative Update Package 10 (CU10) For SQL Server 2008 / 2010-03-15" }
			"10.0.1828.0" { "Cumulative Update Package 9 (CU9) For SQL Server 2008 / 2010-01-18" }
			"10.0.1823.0" { "Cumulative Update Package 8 (CU8) For SQL Server 2008 / 2009-11-16" }
			"10.0.1818.0" { "Cumulative Update Package 7 (CU7) For SQL Server 2008 / 2009-09-21" }
			"10.0.1812.0" { "Cumulative Update Package 6 (CU6) For SQL Server 2008 / 2009-07-21" }
			"10.0.1806.0" { "Cumulative Update Package 5 (CU5) For SQL Server 2008 / 2009-05-18" }
			"10.0.1798.0" { "Cumulative Update Package 4 (CU4) For SQL Server 2008 / 2009-03-17" }
			"10.0.1787.0" { "Cumulative Update Package 3 (CU3) For SQL Server 2008 / 2009-01-19" }
			"10.0.1779.0" { "Cumulative Update Package 2 (CU2) For SQL Server 2008 / 2008-11-19" }
			"10.0.1771.0" { "FIX: You May Receive Incorrect Results When You Run A Query That References Three Or More Tables In The FROM Clause In SQL Server 2008 / 2008-10-29" }
			"10.0.1763.0" { "Cumulative Update Package 1 (CU1) For SQL Server 2008 / 2008-10-28" }
			"10.0.1750.0" { "FIX: A MERGE Statement May Not Enforce A Foreign Key Constraint When The Statement Updates A Unique Key Column That Is Not Part Of A Clustering Key That Has A Single Row As The Update Source In SQL Server 2008 / 2008-08-25" }
			"10.0.1600.22" { "SQL Server 2008 RTM / 2008-08-07" }
			"10.0.1442.32" { "Microsoft SQL Server 2008 RC0 / 2008-06-05" }
			"10.0.1300.13" { "Microsoft SQL Server 2008 CTP, February 2008 / 2008-02-19" }
			"10.0.1075.23" { "Microsoft SQL Server 2008 CTP, November 2007 / 2007-11-18" }
			"10.0.1049.14" { "SQL Server 2008 CTP, July 2007 / 2007-07-31" }
			"10.0.1019.17" { "SQL Server 2008 CTP, June 2007 / 2007-05-21" }
			"9.0.5324" { "MS12-070: Description Of The Security Update For SQL Server 2005 Service Pack 4 QFE / 2012-10-09" }
			"9.0.5296" { "FIX: 'Msg 7359' Error When A View Uses Another View In SQL Server 2005 If The Schema Version Of A Remote Table Is Updated / 2011-10-24" }
			"9.0.5295" { "FIX: SQL Server Agent Job Randomly Stops When You Schedule The Job To Run Past Midnight On Specific Days In SQL Server 2005, In SQL Server 2008 Or In SQL Server 2008 R2 / 2012-05-21" }
			"9.0.5294" { "FIX: Error 5180 When You Use The ONLINE Option To Rebuild An Index In SQL Server 2005 / 2011-08-10" }
			"9.0.5292" { "MS11-049: Description Of The Security Update For SQL Server 2005 Service Pack 4 QFE: June 14, 2011 / 2011-06-14" }
			"9.0.5266" { "Cumulative Update Package 3 (CU3) For SQL Server 2005 Service Pack 4 / 2011-03-22" }
			"9.0.5259" { "Cumulative Update Package 2 (CU2) For SQL Server 2005 Service Pack 4 / 2011-02-22" }
			"9.0.5254" { "Cumulative Update Package 1 (CU1) For SQL Server 2005 Service Pack 4 / 2010-12-24" }
			"9.0.5069" { "Microsoft Security Bulletin MS12-070 / 2012-10-09" }
			"9.0.5057" { "MS11-049: Description Of The Security Update For SQL Server 2005 Service Pack 4 GDR: June 14, 2011 / 2011-06-14" }
			"9.0.5000" { "SQL Server 2005 Service Pack 4 (SP4) / 2010-12-17" }
			"9.0.4912" { "SQL Server 2005 Service Pack 4 (SP4) - Customer Technology Preview (CTP) / 2010-11-03" }
			"9.0.4342" { "FIX: SQL Server Agent Job Randomly Stops When You Schedule The Job To Run Past Midnight On Specific Days In SQL Server 2005, In SQL Server 2008 Or In SQL Server 2008 R2 / 2012-05-21" }
			"9.0.4340" { "MS11-049: Description Of The Security Update For SQL Server 2005 Service Pack 3 QFE: June 14, 2011 / 2011-06-14" }
			"9.0.4325" { "Cumulative Update Package 15 (CU15) For SQL Server 2005 Service Pack 3 / 2011-03-22" }
			"9.0.4317" { "Cumulative Update Package 14 (CU14) For SQL Server 2005 Service Pack 3 / 2011-02-21" }
			"9.0.4315" { "Cumulative Update Package 13 (CU13) For SQL Server 2005 Service Pack 3 / 2010-12-23" }
			"9.0.4311" { "Cumulative Update Package 12 (CU12) For SQL Server 2005 Service Pack 3 / 2010-10-18" }
			"9.0.4309" { "Cumulative Update Package 11 (CU11) For SQL Server 2005 Service Pack 3 / 2010-08-16" }
			"9.0.4305" { "Cumulative Update Package 10 (CU10) For SQL Server 2005 Service Pack 3 / 2010-06-23" }
			"9.0.4294" { "Cumulative Update Package 9 (CU9) For SQL Server 2005 Service Pack 3 / 2010-04-19" }
			"9.0.4285" { "Cumulative Update Package 8 (CU8) For SQL Server 2005 Service Pack 3 / 2010-02-16" }
			"9.0.4273" { "Cumulative Update Package 7 (CU7) For SQL Server 2005 Service Pack 3 / 2009-12-21" }
			"9.0.4268" { "FIX: Error Message When You Add A Subscription To A Republisher That Is In A Merge Publication In SQL Server 2005: 'Cannot Create The Subscription Because The Subscription Already Exists In The Subscription Database' / 2009-12-21" }
			"9.0.4266" { "Cumulative Update Package 6 (CU6) For SQL Server 2005 Service Pack 3 / 2009-10-19" }
			"9.0.4262" { "MS09-062: Description Of The Security Update For SQL Server 2005 Service Pack 3 QFE: October 13, 2009 / 2009-10-13" }
			"9.0.4230" { "Cumulative Update Package 5 (CU5) For SQL Server 2005 Service Pack 3 / 2009-08-17" }
			"9.0.4226" { "Cumulative Update Package 4 (CU4) For SQL Server 2005 Service Pack 3 / 2009-06-16" }
			"9.0.4224" { "FIX: Error Message When You Run A Query That Contains Duplicate Join Conditions In SQL Server 2005: 'Internal Query Processor Error: The Query Processor Could Not Produce A Query Plan' / 2009-06-16" }
			"9.0.4220" { "Cumulative Update Package 3 (CU3) For SQL Server 2005 Service Pack 3 / 2009-04-20" }
			"9.0.4216" { "FIX: The Performance Of Database Mirroring Decreases When You Run A Database Maintenance Job That Generates A Large Number Of Transaction Log Activities In SQL Server 2005 / 2009-04-20" }
			"9.0.4211" { "Cumulative Update Package 2 (CU2) For SQL Server 2005 Service Pack 3 / 2009-02-17" }
			"9.0.4207" { "Cumulative Update Package 1 (CU1) For SQL Server 2005 Service Pack 3 / 2008-12-20" }
			"9.0.4060" { "MS11-049: Description Of The Security Update For SQL Server 2005 Service Pack 3 GDR: June 14, 2011 / 2011-06-14" }
			"9.0.4053" { "MS09-062: Description Of The Security Update For SQL Server 2005 Service Pack 3 GDR: October 13, 2009 / 2009-10-13" }
			"9.0.4035" { "SQL Server 2005 Service Pack 3 (SP3) / 2008-12-15" }
			"9.0.4028" { "SQL Server 2005 Service Pack 3 (SP3) - CTP / 2008-10-27" }
			"9.0.3356" { "Cumulative Update Package 17 (CU17) For SQL Server 2005 Service Pack 2 / 2009-12-21" }
			"9.0.3355" { "Cumulative Update Package 16 (CU16) For SQL Server 2005 Service Pack 2 / 2009-10-19" }
			"9.0.3353" { "MS09-062: Description Of The Security Update For SQL Server 2005 Service Pack 2 QFE: October 13, 2009 / 2009-10-13" }
			"9.0.3330" { "Cumulative Update Package 15 (CU15) For SQL Server 2005 Service Pack 2 / 2009-08-18" }
			"9.0.3328" { "Cumulative Update Package 14 (CU14) For SQL Server 2005 Service Pack 2 / 2009-06-16" }
			"9.0.3325" { "Cumulative Update Package 13 (CU13) For SQL Server 2005 Service Pack 2 / 2009-04-20" }
			"9.0.3320" { "FIX: Error Message When You Run The DBCC CHECKDB Statement On A Database In SQL Server 2005: 'Unable To Deallocate A Kept Page' / 2009-04-01" }
			"9.0.3318" { "FIX: The Wmiprvse.Exe Host Process Stops Responding When You Run A SQL Server 2005-Based Application That Sends A Windows Management Instrumentation (WMI) Query To The SQL Server WMI Provider / 2009-04-20" }
			"9.0.3315" { "Cumulative Update Package 12 (CU12) For SQL Server 2005 Service Pack 2 / 2009-02-17" }
			"9.0.3310" { "MS09-004: Description Of The Security Update For SQL Server 2005 QFE: February 10, 2009 / 2009-02-10" }
			"9.0.3301" { "Cumulative Update Package 11 (CU11) For SQL Server 2005 Service Pack 2 / 2008-12-16" }
			"9.0.3294" { "Cumulative Update Package 10 (CU10) For SQL Server 2005 Service Pack 2 / 2008-10-20" }
			"9.0.3282" { "Cumulative Update Package 9 (CU9) For SQL Server 2005 Service Pack 2 / 2008-06-16" }
			"9.0.3260" { "FIX: Error Message When You Run A Distributed Query In SQL Server 2005: 'OLE DB Provider 'SQLNCLI' For Linked Server '<Linked Server>' Returned Message 'No Transaction Is Active'' / 2008-07-14" }
			"9.0.3259" { "FIX: In SQL Server 2005, The Session That Runs The TRUNCATE TABLE Statement May Stop Responding, And You Cannot End The Session / 2008-08-14" }
			"9.0.3259" { "FIX: An Ongoing MS DTC Transaction Is Orphaned In SQL Server 2005 / 2008-07-14" }
			"9.0.3257" { "Cumulative Update Package 8 (CU8) For SQL Server 2005 Service Pack 2 / 2008-06-18" }
			"9.0.3246" { "FIX: All The MDX Queries That Are Running On An Instance Of SQL Server 2005 Analysis Services Are Canceled When You Start Or Stop A SQL Server Profiler Trace For The Instance / 2008-05-23" }
			"9.0.3244" { "FIX: The Replication Log Reader Agent May Fail Intermittently When A Transactional Replication Synchronizes Data In SQL Server 2005 / 2008-06-03" }
			"9.0.3240" { "FIX: An Access Violation Occurs When You Update A Table Through A View By Using A Cursor In SQL Server 2005 / 2008-05-21" }
			"9.0.3239" { "Cumulative Update Package 7 (CU7) For SQL Server 2005 Service Pack 2 / 2008-04-17" }
			"9.0.3232" { "FIX: Error Message When You Synchronize The Data Of A Merge Replication In SQL Server 2005: 'The Merge Process Is Retrying A Failed Operation Made To Article 'Articlename' - Reason: 'Invalid Input Parameter Values. Check The Status Values For Detail.'' / 2008-03-19" }
			"9.0.3231" { "FIX: Error Message When You Run A Query That Uses A Join Condition In SQL Server 2005: 'Non-Yielding Scheduler' / 2008-03-18" }
			"9.0.3231" { "FIX: Error Message When You Run A Transaction From A Remote Server By Using A Linked Server In SQL Server 2005: 'This Operation Conflicts With Another Pending Operation On This Transaction' / 2008-03-14" }
			"9.0.3230" { "FIX: Error Message When You Run Queries On A Database That Has The SNAPSHOT Isolation Level Enabled In SQL Server 2005: 'Unable To Deallocate A Kept Page' / 2008-03-07" }
			"9.0.3228" { "Cumulative Update Package 6 (CU6) For SQL Server 2005 Service Pack 2 / 2008-02-19" }
			"9.0.3224" { "FIX: A Stored Procedure Cannot Finish Its Execution In SQL Server 2005 / 2008-02-04" }
			"9.0.3221" { "FIX: The Change May Be Undone During The Later Synchronizations When You Change An Article On The Subscriber In SQL Server 2005 / 2008-01-31" }
			"9.0.3221" { "FIX: A Query Takes Longer To Finish In SQL Server 2005 Than In SQL Server 2000 When You Open A Fast Forward-Only Cursor For The Query / 2008-01-11" }
			"9.0.3221" { "FIX: Error Messages When You Delete Some Records Of A Table In A Transaction Or When You Update Some Records Of A Table In A Transaction In SQL Server 2005: 'Msg 9002,' 'Msg 3314,' And 'Msg 9001' / 2008-01-10" }
			"9.0.3221" { "FIX: You Cannot Cancel The Query Execution Immediately If You Open A Fast Forward-Only Cursor For The Query In SQL Server 2005 / 2008-01-09" }
			"9.0.3215" { "Cumulative Update Package 5 (CU5) For SQL Server 2005 Service Pack 2 / 2007-12-18" }
			"9.0.3208" { "FIX: A Federated Database Server Stops Responding When You Run Parallel Queries On A Multiprocessor Computer That Uses NUMA Architecture In SQL Server 2005 / 2007-11-21" }
			"9.0.3206" { "FIX: Conflicts Are Not Logged When You Use The Microsoft SQL Server Subscriber Always Wins Conflict Resolver For An Article In A Merge Replication In Microsoft SQL Server 2005 / 2007-12-11" }
			"9.0.3200" { "Cumulative Update Package 4 (CU4) For SQL Server 2005 Service Pack 2 / 2007-10-17" }
			"9.0.3194" { "FIX: Some Changes From Subscribers Who Use SQL Server 2005 Compact Edition Or Web Synchronization Are Not Uploaded To The Publisher When You Use The Republishing Model In A Merge Publication In Microsoft SQL Server 2005 / 2007-09-24" }
			"9.0.3186" { "FIX: The Performance Of A Query That Performs An Insert Operation Or An Update Operation Is Much Slower In SQL Server 2005 SP2 Than In Earlier Versions Of SQL Server 2005 / 2007-08-29" }
			"9.0.3186" { "FIX: A Cursor Uses The Incorrect Transaction Isolation Level After You Change The Transaction Isolation Level For The Cursor In SQL Server 2005 / 2007-08-24" }
			"9.0.3186" { "FIX: Error Message When You Try To Edit A SQL Server Agent Job Or A Maintenance Plan By Using SQL Server Management Studio In SQL Server 2005: 'String Or Binary Data Would Be Truncated' / 2007-08-23" }
			"9.0.3186" { "FIX: Performance Is Very Slow When The Same Stored Procedure Is Executed At The Same Time In Many Connections On A Multiple-Processor Computer That Is Running SQL Server 2005 / 2007-08-22" }
			"9.0.3186" { "FIX: Error Message When You Try To Update The Index Key Columns Of A Non-Unique Clustered Index In SQL Server 2005: 'Cannot Insert Duplicate Key Row In Object 'Objectname' With Unique Index 'Indexname'' / 2007-08-21" }
			"9.0.3186" { "FIX: Error Message When You Use The UNLOAD And REWIND Options To Back Up A Database To A Tape Device In SQL Server 2005: 'Operation On Device '<Tapedevice>' Exceeded Retry Count' / 2007-08-20" }
			"9.0.3186" { "FIX: Error Message When You Use The Copy Database Wizard To Move A Database From SQL Server 2000 To SQL Server 2005 / 2007-08-20" }
			"9.0.3186" { "FIX: Error Message When You Run A SQL Server 2005 Integration Services Package That Contains A Script Component Transformation:'Insufficient Memory To Continue The Execution Of The Program' / 2007-08-20" }
			"9.0.3186" { "FIX: Error 9003 Is Logged In The SQL Server Error Log File When You Use Log Shipping In SQL Server 2005 / 2007-08-20" }
			"9.0.3186" { "FIX: Data Is Not Replicated To A Subscriber In A Different Partition By Using Parameterized Row Filters In SQL Server 2005 / 2007-08-17" }
			"9.0.3186" { "FIX: Error Message When You Run A Query That Is Associated With A Parallel Execution Plan In SQL Server 2005: 'SQL Server Assertion: File: <Lckmgr.Cpp>, Line=10850 Failed Assertion = 'Getlocallockpartition () == Xactlockinfo->Getlocallockpartition ()'' / 2007-08-17" }
			"9.0.3186" { "FIX: Error Message When You Try To Create An Oracle Publication By Using The New Publication Wizard In SQL Server 2005 Service Pack 2: 'OLE DB Provider 'Oraoledb.ORACLE' For Linked Server <Linkedservername> Returned Message' / 2007-08-17" }
			"9.0.3186" { "FIX: Error Message When You Run A Stored Procedure That References Tables After You Upgrade A Database From SQL Server 2000 To SQL Server 2005: 'A Time-Out Occurred While Waiting For Buffer Latch' / 2007-08-17" }
			"9.0.3186" { "FIX: You Receive A System.Invalidcastexception Exception When You Run An Application That Calls The Server.Jobserver.Jobs.Contains Method On A Computer That Has SQL Server 2005 Service Pack 2 Installed / 2007-08-13" }
			"9.0.3186" { "FIX: An Access Violation May Occur, And You May Receive An Error Message, When You Query The Sys.Dm_Exe_Sessions Dynamic Management View In SQL Server 2005 / 2007-08-13" }
			"9.0.3186" { "FIX: The Performance Of Insert Operations Against A Table That Contains An Identity Column May Be Slow In SQL Server 2005 / 2007-08-10" }
			"9.0.3186" { "FIX: Error Message When You Try To Insert More Than 3 Megabytes Of Data Into A Distributed Partitioned View In SQL Server 2005: 'A System Assertion Check Has Failed' / 2007-08-08" }
			"9.0.3186" { "Cumulative Update Package 3 (CU3) For SQL Server 2005 Service Pack 2 / 2007-08-23" }
			"9.0.3182" { "FIX: You Receive Error 8623 When You Run A Complex Query In SQL Server 2005 / 2007-08-03" }
			"9.0.3179" { "FIX: Error Message When You Run A Full-Text Query Against A Catalog In SQL Server 2005: 'The Execution Of A Full-Text Query Failed. The Content Index Is Corrupt.' / 2007-07-30" }
			"9.0.3178" { "FIX: A SQL Server Agent Job Fails When You Run The SQL Server Agent Job In The Context Of A Proxy Account In SQL Server 2005 / 2007-08-22" }
			"9.0.3177" { "FIX: Error Message When You Run A Stored Procedure That Starts A Transaction That Contains A Transact-SQL Statement In SQL Server 2005: 'New Request Is Not Allowed To Start Because It Should Come With Valid Transaction Descriptor' / 2007-08-22" }
			"9.0.3177" { "FIX: Error Message When You Run A Query That Fires An INSTEAD OF Trigger In SQL Server 2005 Service Pack 2: 'Internal Query Processor Error The Query Processor Could Not Produce A Query Plan' / 2007-08-20" }
			"9.0.3177" { "FIX: Error Message When You Synchronize A Merge Replication In Microsoft SQL Server 2005: 'Msmerge_Del_<GUID>, Line 42 String Or Binary Data Would Be Truncated' / " }
			"9.0.3175" { "FIX: Error Message When The Distribution Agent Tries To Apply The Snapshot To The Subscriber In SQL Server 2005: 'Must Declare The Scalar Variable '@Variable'' / 2007-08-20" }
			"9.0.3175" { "FIX: The Distribution Agent May Skip Some Rows When You Configure A Transactional Replication That Uses The '-Skiperrors' Parameter In SQL Server 2005 / 2007-08-01" }
			"9.0.3175" { "The Service Pack Update Or Hotfix Installation Stops Unexpectedly When You Try To Install Either Microsoft SQL Server 2005 Service Pack 2 Or A Hotfix For SQL Server 2005 SP2 / 2007-07-10" }
			"9.0.3175" { "FIX: A Foreign Key Constraint That You Drop On A Table At The Publisher Is Not Dropped On The Table At The Subscriber In A SQL Server 2005 Merge Replication / 2007-06-29" }
			"9.0.3175" { "Cumulative Update Package 2 (CU2 Build 3175) For SQL Server 2005 Service Pack 2 Is Available / 2007-06-28" }
			"9.0.3171" { "FIX: You May Receive Error Messages When You Try To Log In To An Instance Of SQL Server 2005 And SQL Server Handles Many Concurrent Connections / 2007-07-16" }
			"9.0.3169" { "FIX: Error Message When You Run A Linked Server Query In SQL Server 2005: 'The Oledbprovider Unisys.Dmsii.1 For Linkserver '<Servername>' Reported An Error The Provider Ran Out Of Memory' / 2007-06-19" }
			"9.0.3169" { "FIX: Changes In The Publisher Database Are Not Replicated To The Subscribers In A Transactional Replication If The Publisher Database Runs Exposed In A Database Mirroring Session In SQL Server 2005 / 2007-05-25" }
			"9.0.3166" { "FIX: Blocking And Performance Problems May Occur When You Enable Trace Flag 1118 In SQL Server 2005 If The Temporary Table Creation Workload Is High / 2007-06-11" }
			"9.0.3166" { "FIX: A Database Is Marked As Suspect When You Update A Table That Contains A Nonclustered Index In SQL Server 2005 / 2007-07-16" }
			"9.0.3161" { "FIX: On A Computer That Is Running SQL Server 2005 And That Has Multiple Processors, You May Receive Incorrect Results When You Run A Query That Contains An Inner Join / 2007-09-24" }
			"9.0.3161" { "FIX: Error Message When You Perform A Piecemeal Restore Operation After You Enable Vardecimal Database Compression In SQL Server 2005 Service Pack 2: 'Piecemeal Restore Is Not Supported When An Upgrade Is Involved' / 2007-06-04" }
			"9.0.3161" { "FIX: The Query Performance Is Slow When You Run A Query That Uses A User-Defined Scalar Function Against An Instance Of SQL Server 2005 / 2007-05-09" }
			"9.0.3161" { "Cumulative Update Package (CU1 Build 3161) For SQL Server 2005 Service Pack 2 Is Available / 2007-04-16" }
			"9.0.3159" { "FIX: The Check Database Integrity Task And The Execute T-SQL Statement Task In A Maintenance Plan May Lose Database Context In Certain Circumstances In SQL Server 2005 Builds 3150 Through 3158 / 2007-04-03" }
			"9.0.3156" { "FIX: Error Message When You Try To Use Database Mail To Send An E-Mail Message In SQL Server 2005: 'Profile Name Is Not Valid (Microsoft SQL Server, Error 14607)' / 2007-04-25" }
			"9.0.3155" { "FIX: Error Message When You Run A Query That Contains Nested FOR XML Clauses In SQL Server 2005: 'The XML Data Type Is Damaged' / 2007-06-13" }
			"9.0.3155" { "FIX: Error Message When You Use Transactional Replication To Replicate The Execution Of Stored Procedures To Subscribers In SQL Server 2005: 'Insufficient Memory To Run Query' / 2007-06-12" }
			"9.0.3155" { "FIX: Failed Assertion Message In The Errorlog File When You Perform Various Operations In SQL Server 2005: 'Failed Assertion = 'Ffalse' Attempt To Access Expired Blob Handle (3)' / 2007-05-15" }
			"9.0.3155" { "FIX: You May Receive An Access Violation When You Perform A Bulk Copy Operation In SQL Server 2005 / 2007-04-25" }
			"9.0.3154" { "FIX: The Distribution Agent Does Not Deliver Commands To The Subscriber Even If The Distribution Agent Is Running In SQL Server 2005 / 2007-04-25" }
			"9.0.3154" { "FIX: The Distribution Agent Generates An Access Violation When You Configure A Transactional Replication Publication To Run An Additional Script After The Snapshot Is Applied At The Subscriber In SQL Server 2005 / 2007-04-25" }
			"9.0.3154" { "FIX: SQL Server 2005 Database Engine Generates Failed Assertion Errors When You Use The Replication Monitor To Monitor The Distribution Database / 2007-04-25" }
			"9.0.3153" { "FIX: A Gradual Increase In Memory Consumption For The USERSTORE_TOKENPERM Cache Store Occurs In SQL Server 2005 / 2007-04-16" }
			"9.0.3152" { "Cumulative Hotfix Package (Build 3152) For SQL Server 2005 Service Pack 2 Is Available / 2007-03-07" }
			"9.0.3080" { "MS09-062: Description Of The Security Update For GDI+ For SQL Server 2005 Service Pack 2 GDR: October 13, 2009 / 2009-10-13" }
			"9.0.3077" { "MS09-004: Description Of The Security Update For SQL Server 2005 GDR: February 10, 2009 / 2009-02-10" }
			"9.0.3073" { "MS08-052: Description Of The Security Update For GDI+ For SQL Server 2005 Service Pack 2 GDR: September 9, 2008 / 2008-09-09" }
			"9.0.3068" { "MS08-040: Vulnerabilities In Microsoft SQL Server Could Allow Elevation Of Privilege / 2008-08-05" }
			"9.0.3054" { "FIX: The Check Database Integrity Task And The Execute T-SQL Statement Task In A Maintenance Plan May Lose Database Context In Certain Circumstances In SQL Server 2005 Builds 3042 Through 3053 / 2008-01-02" }
			"9.0.3050" { "Microsoft SQL Server 2005 Service Pack 2 Issue: Cleanup Tasks Run At Different Intervals Than Intended / 2007-03-07" }
			"9.0.3042" { "SQL Server 2005 Service Pack 2 (SP2) / 2007-02-19" }
			"9.0.3033" { "SQL Server 2005 Service Pack 2 (SP2) - CTP December 2006 / 2006-12-19" }
			"9.0.3027" { "SQL Server 2005 Service Pack 2 (SP2) - CTP November 2006 / 2006-11-06" }
			"9.0.3026" { "FIX: A '17187' Error Message May Be Logged In The Errorlog File When An Instance Of SQL Server 2005 Is Under A Heavy Load / 2007-02-14" }
			"9.0.2239" { "FIX: Transactions That Are Being Committed On The Principal Server May Not Be Copied To The Mirror Server When A Database Mirroring Failover Occurs In SQL Server 2005 / 2007-09-24" }
			"9.0.2237" { "FIX: A Memory Leak Occurs When You Call The Initialize Method And The Terminate Method Of The Sqldistribution Object In A Loop In An Application That You Develop By Using Microsoft Activex Replication Controls In SQL Server 2005 / 2007-09-24" }
			"9.0.2236" { "FIX: Error Message When You Use Service Broker In SQL Server 2005: 'An Error Occurred While Receiving Data: '64(The Specified Network Name Is No Longer Available.)'' / 2007-07-29" }
			"9.0.2236" { "FIX: A Service Broker Endpoint Stops Passing Messages In A Database Mirroring Session Of SQL Server 2005 / 2007-07-26" }
			"9.0.2234" { "FIX: SQL Server 2005 Stops And Then Restarts Unexpectedly And Errors Occur In The Tempdb Database / 2007-06-20" }
			"9.0.2233" { "FIX: Error Message When You Use The BULK INSERT Statement To Import A Data File Into A Table In SQL Server 2005 With SP1: 'The OLE DB Provider 'BULK' For Linked Server '(Null)' Reported An Error' / 2007-06-18" }
			"9.0.2233" { "FIX: Error Message When You Use Transactional Replication To Replicate The Execution Of Stored Procedures To Subscribers In SQL Server 2005: 'Insufficient Memory To Run Query' / 2007-06-12" }
			"9.0.2233" { "FIX: You May Receive Error 3456 When You Try To Restore A Transaction Log For A SQL Server 2005 Database / 2007-06-05" }
			"9.0.2232" { "FIX: A Memory Leak Occurs When You Use The Sp_Oamethod Stored Procedure To Call A Method Of A COM Object In SQL Server 2005 / 2007-06-19" }
			"9.0.2231" { "FIX: You Cannot Bring The SQL Server Group Online In A Cluster Environment After You Rename The Virtual Server Name Of The Default Instance Of SQL Server 2005 / 2007-11-06" }
			"9.0.2230" { "FIX: Error Message When You Use SQL Native Client To Connect To An Instance Of A Principal Server In A Database Mirroring Session: 'The Connection Attempted To Fail Over To A Server That Does Not Have A Failover Partner' / 2007-09-20" }
			"9.0.2229" { "FIX: You Receive Error Messages When You Use The BULK INSERT Statement In SQL Server 2005 To Import Data In Bulk / 2007-06-11" }
			"9.0.2227" { "FIX: You May Receive Error 1203 When You Run An INSERT Statement Against A Table That Has An Identity Column In SQL Server 2005 / 2007-06-26" }
			"9.0.2226" { "FIX: Error Message When The Replication Merge Agent Runs To Synchronize A Merge Replication Subscription In SQL Server 2005: 'The Merge Process Failed To Execute A Query Because The Query Timed Out' / 2007-06-22" }
			"9.0.2226" { "FIX: You Receive Error 18815 When The Log Reader Agent Runs For A Transactional Publication In SQL Server 2005 / 2007-06-22" }
			"9.0.2223" { "FIX: You May Experience Poor Performance After You Install SQL Server 2005 Service Pack 1 / 2007-06-18" }
			"9.0.2221" { "FIX: A Script Task Or A Script Component May Not Run Correctly When You Run An SSIS Package In SQL Server 2005 Build 2153 And Later Builds / 2007-07-11" }
			"9.0.2219" { "FIX: The Ghost Row Clean-Up Thread Does Not Remove Ghost Rows On Some Data Files Of A Database In SQL Server 2005 / 2007-04-25" }
			"9.0.2218" { "FIX: SQL Server 2005 Does Not Reclaim The Disk Space That Is Allocated To The Temporary Table If The Stored Procedure Is Stopped / 2007-04-25" }
			"9.0.2216" { "FIX: High CPU Utilization By SQL Server 2005 May Occur When You Use NUMA Architecture On A Computer That Has An X64-Based Version Of SQL Server 2005 Installed / 2007-05-15" }
			"9.0.2214" { "FIX: Error Message When You Run DML Statements Against A Table That Is Published For Merge Replication In SQL Server 2005: 'Could Not Find Stored Procedure' / 2007-02-19" }
			"9.0.2214" { "FIX: I/O Requests That Are Generated By The Checkpoint Process May Cause I/O Bottlenecks If The I/O Subsystem Is Not Fast Enough To Sustain The IO Requests In SQL Server 2005 / 2007-02-13" }
			"9.0.2211" { "FIX: You Receive Error 1456 When You Try To Add A Witness To A DBM Session In SQL Server 2005 / 2007-02-20" }
			"9.0.2211" { "FIX: You Receive Error 1456 When You Add A Witness To A Database Mirroring Session And The Database Name Is The Same As An Existing Database Mirroring Session In SQL Server 2005 / 2007-02-14" }
			"9.0.2209" { "FIX: SQL Server 2005 May Not Perform Histogram Amendments When You Use Trace Flags 2389 And 2390 / 2007-02-07" }
			"9.0.2208" { "FIX: A Memory Leak May Occur Every Time That You Synchronize A SQL Server Mobile Subscriber In SQL Server 2005 / 2007-01-09" }
			"9.0.2207" { "FIX: The Changes Are Not Reflected In The Publication Database After You Reinitialize The Subscriptions In SQL Server 2005 / 2006-12-19" }
			"9.0.2207" { "FIX: Error Message When You Use A Synonym For A Stored Procedure In SQL Server 2005: 'A Severe Error Occurred On The Current Command' / 2006-12-19" }
			"9.0.2207" { "FIX: Error Message In The Database Mail Log When You Try To Use The Sp_Send_Dbmail Stored Procedure To Send An E-Mail In SQL Server 2005: 'Invalid XML Message Format Received On The Externalmailqueue' / 2007-01-02" }
			"9.0.2206" { "FIX: You May Receive An Error Message When You Run A CLR Stored Procedure Or CLR Function That Uses A Context Connection In SQL Server 2005 / " }
			"9.0.2206" { "FIX: The Full-Text Index Population For The Indexed View Is Very Slow In SQL Server 2005 / 2007-01-12" }
			"9.0.2206" { "FIX: Error Message When You Restore A Transaction-Log Backup That Is Generated In SQL Server 2000 SP4 To An Instance Of SQL Server 2005: Msg 3456, Level 16, State 1, Line 1. Could Not Redo Log Record' / 2007-01-02" }
			"9.0.2206" { "FIX: An Access Violation Is Logged In The SQL Server Errorlog File When You Run A Query That Uses A Plan Guide In SQL Server 2005 / 2006-12-13" }
			"9.0.2202" { "FIX: Some Search Results Are Missing When You Perform A Full-Text Search Operation On A Windows Sharepoint Services 2.0 Site After You Upgrade To SQL Server 2005 / 2007-02-16" }
			"9.0.2201" { "FIX: Updates To The SQL Server Mobile Subscriber May Not Be Reflected In The SQL Server 2005 Merge Publication / 2007-01-10" }
			"9.0.2198" { "FIX: You May Receive Incorrect Results When You Query A Table That Is Published In A Transactional Replication In SQL Server 2005 / 2007-02-21" }
			"9.0.2198" { "FIX: You Receive An Error Message When You Use The Print Preview Option On A Large Report In SQL Server 2005 Reporting Services / 2007-02-20" }
			"9.0.2198" { "FIX: The Restore Operation May Take A Long Time To Finish When You Restore A Database In SQL Server 2005 / 2007-02-02" }
			"9.0.2198" { "FIX: The Metadata Of The Description Object Of A Key Performance Indicator Appears In The Default Language After You Define A Translation For The Description Object In SQL Server 2005 Business Intelligence Development Studio / 2006-12-13" }
			"9.0.2198" { "FIX: SQL Server Agent Does Not Send An Alert Quickly Or Does Not Send An Alert When You Use An Alert Of The SQL Server Event Alert Type In SQL Server 2005 / 2007-01-04" }
			"9.0.2198" { "FIX: Error Message When You Run A Query That Uses A Fast Forward-Only Cursor In SQL Server 2005: 'Query Processor Could Not Produce A Query Plan Because Of The Hints Defined In This Query' / 2006-11-16" }
			"9.0.2198" { "FIX: SQL Server 2005 May Not Send A Message Notification That Is Based On The Specific String In The Forwarded Event When A Computer That Is Running SQL Server 2000 Forwards An Event To A Computer That Is Running SQL Server 2005 / 2006-11-28" }
			"9.0.2198" { "FIX: You Receive An Error Message, Or You Obtain An Incorrect Result When You Query Data In A Partitioned Table That Does Not Have A Clustered Index In SQL Server 2005 / 2006-12-13" }
			"9.0.2198" { "FIX: You May Experience Very Large Growth Increments Of A Principal Database After You Manually Fail Over A Database Mirroring Session In SQL Server 2005 / 2007-01-02" }
			"9.0.2196" { "Fix: Error Message When You Convert A Column From The Varbinary(Max) Data Type To The XML Data Type In SQL Server 2005: 'Msg 6322, Level 16, State 1, Line 2 Too Many Attributes Or Namespace Definitions' / 2006-11-10" }
			"9.0.2196" { "FIX: Error Message When You Trace The Audit Database Management Event And You Try To Bring A Database Online In SQL Server 2005: 'Msg 942, Level 14, State 4, Line 1' / 2006-12-05" }
			"9.0.2195" { "FIX: SQL Server 2005 May Stop Responding When You Use The Sqlbulkcopy Class To Import Data From Another Data Source / 2006-12-19" }
			"9.0.2194" { "FIX: Error Message When You Try To Use A SQL Server Authenticated Login To Log On To An Instance Of SQL Server 2005: 'Logon Error: 18456' / 2006-10-20" }
			"9.0.2192" { "FIX: Error Message When You Use A Table-Valued Function (TVF) Together With The CROSS APPLY Operator In A Query In SQL Server 2005: 'There Is Insufficient System Memory To Run This Query' / 2006-09-29" }
			"9.0.2192" { "FIX: Error Message When You Use A Label After A Transact-SQL Query In SQL Server 2005: 'Incorrect Syntax Near 'X'' / 2006-10-05" }
			"9.0.2191" { "FIX: An Empty String Is Replicated As A NULL Value When You Synchronize A Table To A SQL Server 2005 Compact Edition Subscriber / 2006-12-06" }
			"9.0.2190" { "FIX: Error Message When You Call The Sqltables Function Against An Instance Of SQL Server 2005: 'Invalid Cursor State (0)' / 2006-10-16" }
			"9.0.2189" { "FIX: You May Receive Different Date Values For Each Row When You Use The Getdate Function Within A Case Statement In SQL Server 2005 / 2006-09-22" }
			"9.0.2187" { "FIX: When You Run A Query That References A Partitioned Table In SQL Server 2005, Query Performance May Decrease / 2006-09-22" }
			"9.0.2181" { "FIX: A Deadlock Occurs And A Query Never Finishes When You Run The Query On A Computer That Is Running SQL Server 2005 And Has Multiple Processors / 2007-02-19" }
			"9.0.2181" { "FIX: Error Message When You Run An Application Against SQL Server 2005 That Uses Many Unique User Logins Or Performs Many User Login Impersonations: 'Insufficient System Memory To Run This Query' / 2006-10-04" }
			"9.0.2176" { "FIX: Error Message When You Use SQL Server 2005: 'High Priority System Task Thread Operating System Error Exception 0Xae Encountered' / 2007-02-12" }
			"9.0.2176" { "FIX: Log Reader Agent Fails, And An Assertion Error Message Is Logged When You Use Transactional Replication In SQL Server 2005 / 2006-09-06" }
			"9.0.2175" { "FIX: The Color And The Background Image May Not Appear When You Try To Display A Report In HTML Format In Report Manager In SQL Server 2005 Reporting Services / 2006-08-08" }
			"9.0.2175" { "FIX: SQL Server 2005 Performance May Be Slower Than SQL Server 2000 Performance When You Use An API Server Cursor / 2006-08-14" }
			"9.0.2175" { "FIX: In SQL Server 2005, The Sp_Altermessage Stored Procedure Does Not Suppress System Error Messages That Are Logged In The SQL Server Error Log And In The Application Log / 2006-08-30" }
			"9.0.2175" { "FIX: A Query May Take A Long Time To Compile When The Query Contains Several JOIN Clauses Against A SQL Server 2005 Database / 2006-12-14" }
			"9.0.2175" { "FIX: A Handled Access Violation May Occur In The Cvalswitch::Getdatax Function When You Run A Complex Query In SQL Server 2005 / 2006-12-18" }
			"9.0.2174" { "FIX: You May Notice A Large Increase In Compile Time When You Enable Trace Flags 2389 And 2390 In SQL Server 2005 Service Pack 1 / 2006-07-25" }
			"9.0.2167" { "FIX: SQL Server 2005 Treats An Identity Column In A View As An Ordinary Int Column When The Compatibility Level Of The Database Is Set To 80 / 2006-08-09" }
			"9.0.2164" { "FIX: Some Rows In The Text Data Column Are Always Displayed For A Trace That You Create By Using SQL Server Profiler In SQL Server 2005 / 2007-02-08" }
			"9.0.2164" { "FIX: SQL Server 2005 May Overestimate The Cardinality Of The JOIN Operator When A SQL Server 2005 Query Contains A Join Predicate That Is A Multicolumn Predicate / 2006-09-19" }
			"9.0.2164" { "FIX: The SQL Server 2005 Query Optimizer May Incorrectly Estimate The Cardinality For A Query That Has A Predicate That Contains An Index Union Alternative / 2006-09-19" }
			"9.0.2164" { "FIX: Error Message When The Replication Merge Agent Runs In SQL Server 2005: 'Source: MSSQL_REPL, Error Number: MSSQL_REPL-2147199402' / 2006-10-26" }
			"9.0.2164" { "FIX: You May Receive An Error Message When You Manually Define A Back Up Database Task In SQL Server 2005 To Back Up The Transaction Log / 2006-08-29" }
			"9.0.2164" { "FIX: System Performance May Be Slow When An Application Submits Many Queries Against A SQL Server 2005 Database That Uses Simple Parameterization / 2006-09-26" }
			"9.0.2164" { "FIX: A Query Plan Is Not Cached In SQL Server 2005 When The Text Of The Hint Is A Large Object / 2006-09-06" }
			"9.0.2164" { "FIX: Memory Usage Of The Compiled Query Plan May Unexpectedly Increase In SQL Server 2005 / 2006-07-26" }
			"9.0.2164" { "FIX: The BULK INSERT Statement May Not Return Any Errors When You Try To Import Data From A Text File To A Table By Using The BULK INSERT Statement In Microsoft SQL Server 2005 / 2006-08-09" }
			"9.0.2156" { "FIX: The Value Of The Automatic Growth Increment Of A Database File May Be Very Large In SQL Server 2005 With Service Pack 1 / 2006-07-26" }
			"9.0.2153" { "Cumulative Hotfix Package (Build 2153) For SQL Server 2005 Is Available / " }
			"9.0.2153" { "FIX: You May Receive An Error Message When You Install The Cumulative Hotfix Package (Build 2153) For SQL Server 2005 / 2006-05-23" }
			"9.0.2050" { "FIX: A Script Task Or A Script Component May Not Run Correctly When You Run An SSIS Package In SQL Server 2005 Build 2047 / 2007-07-11" }
			"9.0.2047" { "SQL Server 2005 Service Pack 1 (SP1) / 2006-04-18" }
			"9.0.2040" { "SQL Server 2005 Service Pack 1 (SP1) CTP March 2006 / 2006-03-12" }
			"9.0.2029" { "SQL Server 2005 Service Pack 1 (SP1) Beta / " }
			"9.0.1561" { "FIX: A Script Task Or A Script Component May Not Run Correctly When You Run An SSIS Package In SQL Server 2005 Build 1500 And Later Builds / 2007-07-11" }
			"9.0.1558" { "FIX: Error Message When You Restore A Transaction-Log Backup That Is Generated In SQL Server 2000 SP4 To An Instance Of SQL Server 2005: 'Msg 3456, Level 16, State 1, Line 1. Could Not Redo Log Record' / 2007-01-04" }
			"9.0.1554" { "FIX: When You Query Through A View That Uses The ORDER BY Clause In SQL Server 2005, The Result Is Still Returned In Random Order / 2007-06-26" }
			"9.0.1551" { "FIX: Error Message When You Schedule Some SQL Server 2005 Integration Services Packages To Run As Jobs: 'Package <Packagename> Has Been Cancelled' / 2007-01-22" }
			"9.0.1551" { "FIX: After You Detach A Microsoft SQL Server 2005 Database That Resides On Network-Attached Storage, You Cannot Reattach The SQL Server Database / 2006-11-22" }
			"9.0.1550" { "FIX: The Value Of The Automatic Growth Increment Of A Database File May Be Very Large In SQL Server 2005 / 2006-07-26" }
			"9.0.1550" { "FIX: You Receive An Error Message When You Try To Create A Differential Database Backup In SQL Server 2005 / 2006-11-22" }
			"9.0.1547" { "FIX: You Notice Additional Random Trailing Character In Values When You Retrieve The Values From A Fixed-Size Character Column Or A Fixed-Size Binary Column Of A Table In SQL Server 2005 / 2006-11-20" }
			"9.0.1545" { "FIX: SQL Server 2005 Performance May Be Slower Than SQL Server 2000 Performance When You Use An API Server Cursor / 2006-08-14" }
			"9.0.1541" { "FIX: Error Message When You Use A Server-Side Cursor To Run A Large Complex Query In SQL Server 2005: 'Error: 8623, Severity: 16, State: 1 The Query Processor Ran Out Of Internal Resources' / 2006-11-22" }
			"9.0.1541" { "FIX: You May Receive More Than 100,000 Page Faults When You Try To Back Up A SQL Server 2005 Database That Contains Hundreds Of Files And File Groups / 2006-11-22" }
			"9.0.1539" { "FIX: SQL Server 2005 System Performance May Be Slow When You Use A Keyset-Driven Cursor To Execute A FETCH Statement / 2006-08-11" }
			"9.0.1538" { "FIX: The SQL Server 2005 Sqlcommandbuilder.Deriveparameters Method Returns An Exception When The Input Parameter Is A XML Parameter That Has An Associated XSD From An SQL Schema / 2006-07-26" }
			"9.0.1536" { "FIX: The Monitor Server Does Not Monitor All Primary Servers And Secondary Servers When You Configure Log Shipping In SQL Server 2005 / 2006-07-26" }
			"9.0.1534" { "FIX: When You Run The 'Dbcc Dbreindex' Command Or The 'Alter Index' Command, Some Transactions Are Not Replicated To The Subscribers In A Transactional Replication In SQL Server 2005 / 2007-05-15" }
			"9.0.1533" { "FIX: Errors May Be Generated In The Tempdb Database When You Create And Then Drop Many Temporary Tables In SQL Server 2005 / 2006-07-26" }
			"9.0.1532" { "FIX: Indexes May Grow Very Large When You Insert A Row Into A Table And Then Update The Same Row In SQL Server 2005 / 2007-01-09" }
			"9.0.1531" { "FIX: The Internal Deadlock Monitor May Not Detect A Deadlock Between Two Or More Sessions In SQL Server 2005 / 2006-07-26" }
			"9.0.1528" { "FIX: When You Start A Merge Agent, Synchronization Between The Subscriber And The Publisher Takes A Long Time To Be Completed In SQL Server 2005 / 2007-01-15" }
			"9.0.1528" { "FIX: The CPU Usage Of The Server Reaches 100% When Many DML Activities Occur In SQL Server 2005 / 2007-01-04" }
			"9.0.1528" { "FIX: You Experience A Slow Uploading Process If Conflicts Occur When Many Merge Agents Upload Changes To The Publishers At The Same Time In SQL Server 2005 / 2007-01-11" }
			"9.0.1528" { "FIX: The Merge Agent Fails And A 'Permission Denied' Error Message Is Logged When You Synchronize A SQL Server 2005-Based Merge Publication / 2007-01-08" }
			"9.0.1528" { "FIX: Error Message When An ADO.NET-Connected Application Tries To Reuse A Connection From The Connection Pool In SQL Server 2005: 'The Request Failed To Run Because The Batch Is Aborted' / 2006-07-26" }
			"9.0.1519" { "FIX: The Merge Agent Does Not Use A Specified Custom User Update To Handle Conflicting UPDATE Statements In SQL Server 2005 / 2007-01-20" }
			"9.0.1518" { "FIX: A SQL Server Login May Have More Permissions When You Log On To An Instance Of SQL Server 2005 / 2006-09-22" }
			"9.0.1518" { "FIX: An Incorrect Result May Appear In The Subscribing Database When You Set Database Mirroring For A Database And Database Failover Occurs In SQL Server 2005 / 2006-07-26" }
			"9.0.1518" { "FIX: You May Receive Error Messages When You Use The Sp_Cursoropen Statement To Open A Cursor On A User-Defined Stored Procedure In SQL Server 2005 / 2006-07-26" }
			"9.0.1514" { "FIX: The Replication On The Server Does Not Work Any Longer When You Manually Fail Over Databases In SQL Server 2005 / 2006-07-26" }
			"9.0.1503" { "FIX: You May Receive An Access Violation Error Message When You Run A SELECT Query In SQL Server 2005 / 2006-07-26" }
			"9.0.1502" { "FIX: You Cannot Restore The Log Backups On The Mirror Server After You Remove Database Mirroring For The Mirror Database In SQL Server 2005 / 2006-07-26" }
			"9.0.1500" { "FIX: Error Message When You Run Certain Queries Or Certain Stored Procedures In SQL Server 2005: 'A Severe Error Occurred On The Current Command' / 2006-06-01" }
			"9.0.1406" { "FIX: A Script Task Or A Script Component May Not Run Correctly When You Run An SSIS Package In SQL Server 2005 Build 1399 / 2007-07-11" }
			"9.0.1399" { "SQL Server 2005 RTM / 2005-11-07" }
			"8.0.2305" { "MS12-060: Description Of The Security Update For SQL Server 2000 Service Pack 4 QFE: August 14, 2012 / 2012-08-14" }
			"8.0.2301" { "MS12-027: Description Of The Security Update For Microsoft SQL Server 2000 Service Pack 4 QFE: April 10, 2012 / 2012-04-10" }
			"8.0.2283" { "FIX: An Access Violation Occurs When You Run A DELETE Statement Or An UPDATE Statement In The Itanium-Based Versions Of SQL Server 2000 After You Install Security Update MS09-004 / 2009-06-15" }
			"8.0.2282" { "MS09-004: Description Of The Security Update For SQL Server 2000 QFE And For MSDE 2000: February 10, 2009 / 2009-02-10" }
			"8.0.2279" { "FIX: When You Run The Spsbackup.Exe Utility To Back Up A SQL Server 2000 Database That Is Configured As A Back-End Database For A Windows Sharepoint Services Server, The Backup Operation Fails / 2009-04-08" }
			"8.0.2273" { "MS08-040: Description Of The Security Update For SQL Server 2000 QFE And MSDE 2000 July 8, 2008 / 2008-08-05" }
			"8.0.2271" { "FIX: The SPACE Function Always Returns One Space In SQL Server 2000 If The SPACE Function Uses A Collation That Differs From The Collation Of The Current Database / 2008-03-12" }
			"8.0.2265" { "FIX: The Data On The Publisher Does Not Match The Data On The Subscriber When You Synchronize A SQL Server 2005 Mobile Edition Subscriber With A SQL Server 2000 'Merge Replication' Publisher / 2007-12-19" }
			"8.0.2253" { "FIX: The CPU Utilization May Suddenly Increase To 100 Percent When There Are Many Connections To An Instance Of SQL Server 2000 On A Computer That Has Multiple Processors / 2007-10-09" }
			"8.0.2249" { "FIX: An Access Violation May Occur When You Try To Log In To An Instance Of SQL Server 2000 / 2007-05-25" }
			"8.0.2248" { "FIX: The Foreign Key That You Created Between Two Tables Does Not Work After You Run The CREATE INDEX Statement In SQL Server 2000 / 2007-06-14" }
			"8.0.2246" { "An Updated Version Of Sqlvdi.Dll Is Now Available For SQL Server 2000 / 2007-06-18" }
			"8.0.2245" { "FIX: You May Receive An Assertion Or Database Corruption May Occur When You Use The Bcp Utility Or The 'Bulk Insert' Transact-SQL Command To Import Data In SQL Server 2000 / 2007-04-24" }
			"8.0.2244" { "FIX: A Hotfix For Microsoft SQL Server 2000 Service Pack 4 May Not Update All The Necessary Files On An X64-Based Computer / 2007-05-10" }
			"8.0.2242" { "FIX: In SQL Server 2000, The Synchronization Process Is Slow, And The CPU Usage Is High On The Computer That Is Configured As The Distributor / 2007-03-28" }
			"8.0.2238" { "FIX: The Merge Agent Fails Intermittently When You Use Merge Replication That Uses A Custom Resolver After You Install SQL Server 2000 Service Pack 4 / 2007-02-21" }
			"8.0.2236" { "FIX: CPU Utilization May Approach 100 Percent On A Computer That Is Running SQL Server 2000 After You Run The BACKUP DATABASE Statement Or The BACKUP LOG Statement / 2007-02-02" }
			"8.0.2234" { "FIX: Error Messages When You Try To Update Table Rows Or Insert Table Rows Into A Table In SQL Server 2000: '644' Or '2511' / 2007-02-22" }
			"8.0.2232" { "FIX: SQL Server 2000 Stops Responding When You Cancel A Query Or When A Query Time-Out Occurs, And Error Messages Are Logged In The SQL Server Error Log File / 2007-01-15" }
			"8.0.2231" { "FIX: The Sqldumper.Exe Utility Cannot Generate A Filtered SQL Server Dump File When You Use The Remote Desktop Connection Service Or Terminal Services To Connect To A Windows 2000 Server-Based Computer In SQL Server 2000 / 2007-06-19" }
			"8.0.2229" { "FIX: Error Message When You Create A Merge Replication For Tables That Have Computed Columns In SQL Server 2000 Service Pack 4: 'The Process Could Not Log Conflict Information' / 2007-07-24" }
			"8.0.2226" { "FIX: You May Experience One Or More Symptoms When You Run A 'CREATE INDEX' Statement On An Instance Of SQL Server 2000 / 2006-11-20" }
			"8.0.2226" { "FIX: You May Receive Inconsistent Comparison Results When You Compare Strings By Using A Width Sensitive Collation In SQL Server 2000 / 2006-11-13" }
			"8.0.2223" { "FIX: The Server Stops Responding, The Performance Is Slow, And A Time-Out Occurs In SQL Server 2000 / 2007-07-20" }
			"8.0.2223" { "FIX: Error Message When You Schedule A Replication Merge Agent Job To Run After You Install SQL Server 2000 Service Pack 4: 'The Process Could Not Enumerate Changes At The 'Subscriber'' / 2006-10-31" }
			"8.0.2218" { "FIX: The Result May Be Sorted In The Wrong Order When You Run A Query That Uses The ORDER BY Clause To Sort A Column In A Table In SQL Server 2000 / 2007-06-19" }
			"8.0.2217" { "FIX: You Cannot Stop The SQL Server Service, Or Many Minidump Files And Many Log Files Are Generated In SQL Server 2000 / 2007-10-25" }
			"8.0.2215" { "FIX: Data In A Subscriber Of A Merge Publication In SQL Server 2000 Differs From The Data In The Publisher / 2007-01-12" }
			"8.0.2215" { "FIX: The Query Performance May Be Slow When You Query Data From A View In SQL Server 2000 / 2006-10-05" }
			"8.0.2215" { "FIX: Error Message When You Configure An Immediate Updating Transactional Replication In SQL Server 2000: 'Implicit Conversion From Datatype 'Text' To 'Nvarchar' Is Not Allowed' / 2006-10-30" }
			"8.0.2215" { "FIX: You May Receive An Access Violation Error Message When You Import Data By Using The 'Bulk Insert' Command In SQL Server 2000 / 2006-12-28" }
			"8.0.2209" { "The Knowledge Base (KB) Article You Requested Is Currently Not Available / " }
			"8.0.2207" { "FIX: A SQL Server 2000 Session May Be Blocked For The Whole Time That A Snapshot Agent Job Runs / 2006-08-28" }
			"8.0.2201" { "FIX: Error Message When You Try To Run A Query On A Linked Server In SQL Server 2000 / 2006-08-21" }
			"8.0.2199" { "FIX: SQL Server 2000 May Take A Long Time To Complete The Synchronization Phase When You Create A Merge Publication / 2006-07-26" }
			"8.0.2197" { "FIX: Each Query Takes A Long Time To Compile When You Execute A Single Query Or When You Execute Multiple Concurrent Queries In SQL Server 2000 / 2006-08-02" }
			"8.0.2197" { "FIX: The Query May Return Incorrect Results, And The Execution Plan For The Query May Contain A 'Table Spool' Operator In SQL Server 2000 / 2006-08-08" }
			"8.0.2197" { "FIX: A Profiler Trace In SQL Server 2000 May Stop Logging Events Unexpectedly, And You May Receive The Following Error Message: 'Failed To Read Trace Data' / 2006-10-18" }
			"8.0.2196" { "FIX: A Memory Leak Occurs When You Run A Remote Query By Using A Linked Server In SQL Server 2000 / 2006-08-14" }
			"8.0.2194" { "FIX: Error 17883 Is Logged In The SQL Server Error Log, And The Instance Of SQL Server 2000 Temporarily Stops Responding / 2007-02-21" }
			"8.0.2194" { "FIX: You Receive An Access Violation Error Message When You Try To Perform A Read Of A Large Binary Large Object Column In SQL Server 2000 / 2006-09-22" }
			"8.0.2192" { "FIX: You May Notice A Decrease In Performance When You Run A Query That Uses The UNION ALL Operator In SQL Server 2000 Service Pack 4 / 2006-08-04" }
			"8.0.2191" { "FIX: Error Message When You Run SQL Server 2000: 'Failed Assertion = 'Lockfound == TRUE'' / 2006-07-26" }
			"8.0.2191" { "FIX: You May Experience Heap Corruption, And SQL Server 2000 May Shut Down With Fatal Access Violations When You Try To Browse Files In SQL Server 2000 Enterprise Manager On A Windows Server 2003 X64-Based Computer / 2006-10-03" }
			"8.0.2189" { "FIX: An Access Violation May Occur When You Run A Query On A Table That Has A Multicolumn Index In SQL Server 2000 / 2006-07-26" }
			"8.0.2189" { "FIX: The SQL Server Process May End Unexpectedly When You Turn On Trace Flag -T1204 And A Profiler Trace Is Capturing The Lock:Deadlock Chain Event In SQL Server 2000 SP4 / 2006-07-19" }
			"8.0.2187" { "FIX: A Deadlock Occurs When The Scheduled SQL Server Agent Job That You Add Or That You Update Is Running In SQL Server 2000 / 2007-06-18" }
			"8.0.2187" { "A Cumulative Hotfix Package Is Available For SQL Server 2000 Service Pack 4 Build 2187 / 2006-10-16" }
			"8.0.2187" { "FIX: The Database Status Changes To Suspect When You Perform A Bulk Copy In A Transaction And Then Roll Back The Transaction In SQL Server 2000 / 2006-07-26" }
			"8.0.2187" { "FIX: Error Message When You Try To Apply A Hotfix On A SQL Server 2000-Based Computer That Is Configured As A MSCS Node: 'An Error In Updating Your System Has Occurred' / 2006-12-11" }
			"8.0.2180" { "FIX: The Password That You Specify In A BACKUP Statement Appears In The SQL Server Errorlog File Or In The Application Event Log If The BACKUP Statement Does Not Run In SQL Server 2000 / 2007-02-19" }
			"8.0.2180" { "FIX: You May Receive Error Messages When You Use Linked Servers In SQL Server 2000 On A 64-Bit Itanium Processor / 2006-07-26" }
			"8.0.2175" { "FIX: No Rows May Be Returned, And You May Receive An Error Message When You Try To Import SQL Profiler Trace Files Into Tables By Using The Fn_Trace_Gettable Function In SQL Server 2000 / 2006-07-26" }
			"8.0.2172" { "FIX: When You Query A View That Was Created By Using The VIEW_METADATA Option, An Access Violation May Occur In SQL Server 2000 / 2006-07-26" }
			"8.0.2171" { "FIX: Automatic Checkpoints On Some SQL Server 2000 Databases Do Not Run As Expected / " }
			"8.0.2168" { "FIX: An Error Occurs When You Try To Access The Analysis Services Performance Monitor Counter Object After You Apply Windows Server 2003 SP1 / 2006-11-21" }
			"8.0.2166" { "FIX: An Error Message Is Logged, And New Diagnostics Do Not Capture The Thread Stack When The SQL Server User Mode Scheduler (UMS) Experiences A Nonyielding Thread In SQL Server 2000 Service Pack 4 / 2006-07-26" }
			"8.0.2162" { "A Cumulative Hotfix Package Is Available For SQL Server 2000 Service Pack 4 Build 2162 / 2006-09-15" }
			"8.0.2159" { "FIX: You May Experience Concurrency Issues When You Run The DBCC INDEXDEFRAG Statement In SQL Server 2000 / 2006-07-26" }
			"8.0.2156" { "FIX: You Receive An Error Message When You Try To Rebuild The Master Database After You Have Installed Hotfix Builds In SQL Server 2000 SP4 64-Bit / 2006-07-25" }
			"8.0.2151" { "FIX: You Receive An 'Error: 8526, Severity: 16, State: 2' Error Message In SQL Profiler When You Use SQL Query Analyzer To Start Or To Enlist Into A Distributed Transaction After You Have Installed SQL Server 2000 SP4 / 2006-07-25" }
			"8.0.2151" { "FIX: Incorrect Data Is Inserted Unexpectedly When You Perform A Bulk Copy Operation By Using The DB-Library API In SQL Server 2000 Service Pack 4 / 2007-06-13" }
			"8.0.2148" { "FIX: An Access Violation May Occur When You Run A SELECT Query And The NO_BROWSETABLE Option Is Set To ON In Microsoft SQL Server 2000 / 2006-07-25" }
			"8.0.2148" { "FIX: An Access Violation Occurs In The Mssdi98.Dll File, And SQL Server Crashes When You Use SQL Query Analyzer To Debug A Stored Procedure In SQL Server 2000 Service Pack 4 / 2006-07-25" }
			"8.0.2148" { "FIX: The Mssdmn.Exe Process May Use Lots Of CPU Capacity When You Perform A SQL Server 2000 Full Text Search Of Office Word Documents / 2006-06-01" }
			"8.0.2148" { "FIX: The Results Of The Query May Be Returned Much Slower Than You Expect When You Run A Query That Includes A GROUP BY Statement In SQL Server 2000 / 2006-06-01" }
			"8.0.2148" { "FIX: You Receive An Error Message If You Use The Sp_Addalias Or Sp_Dropalias Procedures When The IMPLICIT_TRANSACTIONS Option Is Set To ON In SQL Server 2000 SP4 / 2006-07-25" }
			"8.0.2148" { "FIX: Some 32-Bit Applications That Use SQL-DMO And SQL-VDI Apis May Stop Working After You Install SQL Server 2000 Service Pack 4 On An Itanium-Based Computer / 2006-06-01" }
			"8.0.2148" { "FIX: You Receive A 'Getting Registry Information' Message When You Run The Sqldiag.Exe Utility After You Install SQL Server 2000 SP4 / 2006-07-25" }
			"8.0.2147" { "FIX: You May Experience Slow Server Performance When You Start A Trace In An Instance Of SQL Server 2000 That Runs On A Computer That Has More Than Four Processors / 2006-06-01" }
			"8.0.2145" { "FIX: A Query That Uses A View That Contains A Correlated Subquery And An Aggregate Runs Slowly / 2005-10-25" }
			"8.0.2145" { "FIX: You Receive Query Results That Were Not Expected When You Use Both ANSI Joins And Non-ANSI Joins / 2006-06-07" }
			"8.0.2066" { "Microsoft Security Bulletin MS12-060 / 2012-08-14" }
			"8.0.2065" { "MS12-027: Description Of The Security Update For Microsoft SQL Server 2000 Service Pack 4 GDR: April 10, 2012 / 2012-04-10" }
			"8.0.2055" { "MS09-004: Vulnerabilities In Microsoft SQL Server Could Allow Remote Code Execution / 2009-02-10" }
			"8.0.2050" { "MS08-040: Description Of The Security Update For SQL Server 2000 GDR And MSDE 2000: July 8, 2008 / 2008-07-08" }
			"8.0.2040" { "FIX: Not All Memory Is Available When AWE Is Enabled On A Computer That Is Running A 32-Bit Version Of SQL Server 2000 SP4 / 2006-08-15" }
			"8.0.2039" { "SQL Server 2000 Service Pack 4 (SP4) / 2005-05-06" }
			"8.0.2026" { "SQL Server 2000 Service Pack 4 (SP4) Beta / " }
			"8.0.1547" { "FIX: You May Experience Slow Server Performance When You Start A Trace In An Instance Of SQL Server 2000 That Runs On A Computer That Has More Than Four Processors / 2006-06-01" }
			"8.0.1077" { "983814 MS12-070: Description Of The Security Update For SQL Server 2000 Reporting Services Service Pack 2 / 2012-10-09" }
			"8.0.1037" { "FIX: CPU Utilization May Approach 100 Percent On A Computer That Is Running SQL Server 2000 After You Run The BACKUP DATABASE Statement Or The BACKUP LOG Statement / 2007-02-02" }
			"8.0.1036" { "FIX: Error Message When You Run A Full-Text Query In SQL Server 2000: 'Error: 17883, Severity: 1, State: 0' / 2007-01-11" }
			"8.0.1035" { "FIX: The 'Audit Logout' Event Does Not Appear In The Trace Results File When You Run A Profiler Trace Against A Linked Server Instance In SQL Server 2000 / 2006-09-22" }
			"8.0.1034" { "FIX: You May Intermittently Experience An Access Violation Error When A Query Is Executed In A Parallel Plan And The Execution Plan Contains Either A HASH JOIN Operation Or A Sort Operation In SQL Server 2000 / 2006-08-09" }
			"8.0.1029" { "FIX: Error Message When You Run An UPDATE Statement That Uses Two JOIN Hints To Update A Table In SQL Server 2000: 'Internal SQL Server Error' / 2006-06-01" }
			"8.0.1027" { "FIX: A 17883 Error May Occur You Run A Query That Uses A Hash Join In SQL Server 2000 / 2006-07-25" }
			"8.0.1025" { "FIX: You Receive Incorrect Results When You Run A Query That Uses A Cross Join Operator In SQL Server 2000 SP3 / 2006-06-01" }
			"8.0.1025" { "FIX: An Access Violation May Occur When You Run A SELECT Query And The NO_BROWSETABLE Option Is Set To ON In Microsoft SQL Server 2000 / 2006-07-25" }
			"8.0.1024" { "FIX: Error Message When You Use SQL Server 2000: 'Time Out Occurred While Waiting For Buffer Latch Type 3' / 2006-07-25" }
			"8.0.1021" { "FIX: Server Network Utility May Display Incorrect Protocol Properties In SQL Server 2000 / 2006-07-25" }
			"8.0.1020" { "FIX: The Subscriber May Not Be Able To Upload Changes To The Publisher When You Incrementally Add An Article To A Publication In SQL Server 2000 SP3 / 2006-07-25" }
			"8.0.1019" { "FIX: You May Receive A Memory-Related Error Message When You Repeatedly Create And Destroy An Out-Of-Process COM Object Within The Same Batch Or Stored Procedure In SQL Server 2000 / 2006-06-01" }
			"8.0.1017" { "FIX: The BULK INSERT Statement Silently Skips Insert Attempts When The Data Value Is NULL And The Column Is Defined As NOT NULL For INT, SMALLINT, And BIGINT Data Types In SQL Server 2000 / 2006-06-01" }
			"8.0.1014" { "FIX: You May Receive Error Message 701, Error Message 802, And Error Message 17803 When Many Hashed Buffers Are Available In SQL Server 2000 / 2006-06-01" }
			"8.0.1014" { "FIX: You Receive An Error Message When You Try To Delete Records By Running A Delete Transact-SQL Statement In SQL Server 2000 / 2006-07-25" }
			"8.0.1013" { "FIX: The Query Runs Slower Than You Expected When You Try To Parse A Query In SQL Server 2000 / 2006-06-01" }
			"8.0.1009" { "FIX: You Receive An 'Incorrect Syntax Near ')'' Error Message When You Run A Script That Was Generated By SQL-DMO For An Operator Object In SQL Server 2000 / 2006-06-01" }
			"8.0.1007" { "FIX: You May Receive A 'SQL Server Could Not Spawn Process_Loginread Thread' Error Message, And A Memory Leak May Occur When You Cancel A Remote Query In SQL Server 2000 / 2006-06-01" }
			"8.0.1003" { "FIX: Differential Database Backups May Not Contain Database Changes In The Page Free Space (PFS) Pages In SQL Server 2000 / 2006-06-01" }
			"8.0.1001" { "FIX: You May Receive A 17883 Error Message When SQL Server 2000 Performs A Very Large Hash Operation / 2006-06-01" }
			"8.0.1000" { "FIX: Database Recovery Does Not Occur, Or A User Database Is Marked As Suspect In SQL Server 2000 / 2006-06-01" }
			"8.0.997" { "FIX: You Cannot Create New TCP/IP Socket Based Connections After Error Messages 17882 And 10055 Are Written To The Microsoft SQL Server 2000 Error Log / 2006-07-18" }
			"8.0.996" { "FIX: SQL Server 2000 May Stop Responding To Other Requests When You Perform A Large Deallocation Operation / 2006-06-01" }
			"8.0.996" { "FIX: You Receive A 17883 Error Message And SQL Server 2000 May Stop Responding To Other Requests When You Perform Large In-Memory Sort Operations / 2006-06-01" }
			"8.0.994" { "FIX: Some Complex Queries Are Slower After You Install SQL Server 2000 Service Pack 2 Or SQL Server 2000 Service Pack 3 / 2006-06-01" }
			"8.0.994" { "FIX: You Experience Non-Convergence In A Replication Topology When You Unpublish Or Drop Columns From A Dynamically Filtered Publication In SQL Server 2000 / 2006-06-01" }
			"8.0.994" { "FIX: You Receive A 'Server: Msg 107, Level 16, State 3, Procedure TEMP_VIEW_Merge, Line 1' Error Message When The Sum Of The Length Of The Published Column Names In A Merge Publication Exceeds 4,000 Characters In SQL Server 2000 / 2006-06-01" }
			"8.0.993" { "FIX: The @@ERROR System Function May Return An Incorrect Value When You Execute A Transact-SQL Statement That Uses A Parallel Execution Plan In SQL Server 2000 32-Bit Or In SQL Server 2000 64-Bit / 2006-06-01" }
			"8.0.993" { "FIX: You Receive A 17883 Error In SQL Server 2000 Service Pack 3 Or In SQL Server 2000 Service Pack 3A When A Worker Thread Becomes Stuck In A Registry Call / 2006-06-01" }
			"8.0.993" { "FIX: Error Message When You Use A Loopback Linked Server To Run A Distributed Query In SQL Server 2000: 'Could Not Perform The Requested Operation Because The Minimum Query Memory Is Not Available' / 2006-05-15" }
			"8.0.991" { "FIX: Non-Convergence May Occur In A Merge Replication Topology If The Primary Connection To The Publisher Is Disconnected / 2006-06-01" }
			"8.0.990" { "FIX: SQL Server 2000 Stops Listening For New TCP/IP Socket Connections Unexpectedly After Error Message 17882 Is Written To The SQL Server 2000 Error Log / " }
			"8.0.988" { "FIX: You Receive A 'Msg 3628' Error Message When You Run An Inner Join Query In SQL Server 2000 / 2006-06-01" }
			"8.0.985" { "FIX: Start Times In The SQL Profiler Are Different For The Audit:Login And Audit:Logout Events In SQL Server 2000 / 2006-06-01" }
			"8.0.980" { "FIX: A Fetch On A Dynamic Cursor Can Cause Unexpected Results In SQL Server 2000 Service Pack 3 / 2006-06-01" }
			"8.0.977" { "You Receive A 'The Product Does Not Have A Prerequisite Update Installed' Error Message When You Try To Install A SQL Server 2000 Post-Service Pack 3 Hotfix / 2005-08-31" }
			"8.0.973" { "FIX: A SPID Stops Responding With A NETWORKIO (0X800) Waittype In SQL Server Enterprise Manager When SQL Server Tries To Process A Fragmented TDS Network Packet / 2006-06-01" }
			"8.0.972" { "FIX: An Assertion Error Occurs When You Insert Data In The Same Row In A Table By Using Multiple Connections To An Instance Of SQL Server / 2006-06-01" }
			"8.0.970" { "FIX: A CHECKDB Statement Reports A 2537 Corruption Error After SQL Server Transfers Data To A Sql_Variant Column In SQL Server 2000 / 2006-06-01" }
			"8.0.967" { "FIX: You May Receive An Error Message When You Run A SET IDENTITY_INSERT ON Statement On A Table And Then Try To Insert A Row Into The Table In SQL Server 2000 / 2006-06-01" }
			"8.0.962" { "FIX: A User-Defined Function Returns Results That Are Not Correct For A Query / 2006-06-01" }
			"8.0.961" { "FIX: An Access Violation Exception May Occur When Multiple Users Try To Perform Data Modification Operations At The Same Time That Fire Triggers That Reference A Deleted Or An Inserted Table In SQL Server 2000 On A Computer That Is Running SMP / 2006-06-01" }
			"8.0.959" { "FIX: An Audit Object Permission Event Is Not Produced When You Run A TRUNCATE TABLE Statement / 2006-06-01" }
			"8.0.957" { "FIX: An Access Violation Exception May Occur When You Run A Query That Uses Index Names In The WITH INDEX Option To Specify An Index Hint / 2006-06-01" }
			"8.0.955" { "FIX: The @Date_Received Parameter Of The Xp_Readmail Extended Stored Procedure Incorrectly Returns The Date And The Time That An E-Mail Message Is Submitted By The Sender In SQL Server 2000 / 2007-01-08" }
			"8.0.954" { "FIX: The Osql.Exe Utility Does Not Run A Transact-SQL Script Completely If You Start The Program From A Remote Session By Using A Background Service And Then Log Off The Console Session / 2007-01-05" }
			"8.0.952" { "FIX: The Log Reader Agent May Cause 17883 Error Messages / 2006-06-01" }
			"8.0.952" { "FIX: Merge Replication Non-Convergence Occurs With SQL Server CE Subscribers / 2006-06-01" }
			"8.0.952" { "FIX: Merge Agent May Fail With An 'Invalid Character Value For Cast Specification' Error Message / 2006-06-01" }
			"8.0.949" { "FIX: Shared Page Locks Can Be Held Until End Of The Transaction And Can Cause Blocking Or Performance Problems In SQL Server 2000 Service Pack 3 (SP3) / 2006-06-02" }
			"8.0.948" { "FIX: You May Receive An 8623 Error Message When You Try To Run A Complex Query On An Instance Of SQL Server / 2006-06-01" }
			"8.0.944" { "FIX: SQL Debugging Does Not Work In Visual Studio .NET After You Install Windows XP Service Pack 2 / 2006-06-05" }
			"8.0.937" { "FIX: Additional Diagnostics Have Been Added To SQL Server 2000 To Detect Unreported Read Operation Failures / 2006-06-01" }
			"8.0.936" { "FIX: SQL Server 2000 May Underestimate The Cardinality Of A Query Expression Under Certain Circumstances / 2006-06-01" }
			"8.0.935" { "FIX: You May Notice Incorrect Values For The 'Active Transactions' Counter When You Perform Multiple Transactions On An Instance Of SQL Server 2000 That Is Running On An SMP Computer / 2006-06-01" }
			"8.0.934" { "FIX: You May Receive A 'The Query Processor Could Not Produce A Query Plan' Error Message In SQL Server When You Run A Query That Includes Multiple Subqueries That Use Self-Joins / 2006-06-01" }
			"8.0.933" { "FIX: The Mssqlserver Service Exits Unexpectedly In SQL Server 2000 Service Pack 3 / 2006-06-02" }
			"8.0.929" { "FIX: 8621 Error Conditions May Cause SQL Server 2000 64-Bit To Close Unexpectedly / 2006-06-01" }
			"8.0.928" { "FIX: The Thread Priority Is Raised For Some Threads In A Parallel Query / 2006-06-01" }
			"8.0.927" { "FIX: Profiler RPC Events Truncate Parameters That Have A Text Data Type To 16 Characters / 2006-06-01" }
			"8.0.926" { "FIX: An Access Violation Exception May Occur When You Update A Text Column By Using A Stored Procedure In SQL Server 2000 / 2006-06-01" }
			"8.0.923" { "FIX: The Xp_Logininfo Procedure May Fail With Error 8198 After You Install Q825042 Or Any Hotfix With SQL Server 8.0.0840 Or Later / 2006-06-01" }
			"8.0.922" { "FIX: You May Receive An 'Invalid Object Name...' Error Message When You Run The DBCC CHECKCONSTRAINTS Transact-SQL Statement On A Table In SQL Server 2000 / 2005-10-25" }
			"8.0.919" { "FIX: When You Use Transact-SQL Cursor Variables To Perform Operations That Have Large Iterations, Memory Leaks May Occur In SQL Server 2000 / 2005-10-25" }
			"8.0.916" { "FIX: Sqlakw32.Dll May Corrupt SQL Statements / 2005-09-27" }
			"8.0.915" { "FIX: Rows Are Not Successfully Inserted Into A Table When You Use The BULK INSERT Command To Insert Rows / 2005-10-25" }
			"8.0.913" { "FIX: You Receive Query Results That Were Not Expected When You Use Both ANSI Joins And Non-ANSI Joins / 2006-06-07" }
			"8.0.911" { "FIX: When You Use Transact-SQL Cursor Variables To Perform Operations That Have Large Iterations, Memory Leaks May Occur In SQL Server 2000 / 2005-10-25" }
			"8.0.910" { "FIX: SQL Server 2000 May Not Start If Many Users Try To Log In To SQL Server When SQL Server Is Trying To Start / 2005-10-25" }
			"8.0.908" { "FIX: You Receive A 644 Error Message When You Run An UPDATE Statement And The Isolation Level Is Set To READ UNCOMMITTED / 2005-10-25" }
			"8.0.904" { "FIX: The Snapshot Agent May Fail After You Make Schema Changes To The Underlying Tables Of A Publication / 2005-04-22" }
			"8.0.892" { "FIX: You Receive An Error Message When You Try To Restore A Database Backup That Spans Multiple Devices / 2005-10-25" }
			"8.0.891" { "FIX: An Access Violation Exception May Occur When SQL Server Runs Many Parallel Query Processing Operations On A Multiprocessor Computer / 2005-04-01" }
			"8.0.879" { "FIX: The DBCC PSS Command May Cause Access Violations And 17805 Errors In SQL Server 2000 / 2005-10-25" }
			"8.0.878" { "FIX: You Receive Error Message 3456 When You Try To Apply A Transaction Log To A Server / 2005-10-25" }
			"8.0.876" { "FIX: Key Names Read From An .Ini File For A Dynamic Properties Task May Be Truncated / 2005-10-25" }
			"8.0.876" { "FIX: An Invalid Cursor State Occurs After You Apply Hotfix 8.00.0859 Or Later In SQL Server 2000 / 2005-10-25" }
			"8.0.876" { "FIX: An AWE System Uses More Memory For Sorting Or For Hashing Than A Non-AWE System In SQL Server 2000 / 2005-10-25" }
			"8.0.873" { "FIX: Some Queries That Have A Left Outer Join And An IS NULL Filter Run Slower After You Install SQL Server 2000 Post-SP3 Hotfix / 2005-10-25" }
			"8.0.871" { "FIX: SQL Query Analyzer May Stop Responding When You Close A Query Window Or Open A File / 2005-10-25" }
			"8.0.871" { "FIX: The Performance Of A Computer That Is Running SQL Server 2000 Degrades When Query Execution Plans Against Temporary Tables Remain In The Procedure Cache / " }
			"8.0.870" { "FIX: Unconditional Update May Not Hold Key Locks On New Key Values / " }
			"8.0.869" { "FIX: Access Violation When You Trace Keyset-Driven Cursors By Using SQL Profiler / 2005-10-25" }
			"8.0.866" { "FIX: An Access Violation Occurs In SQL Server 2000 When A High Volume Of Local Shared Memory Connections Occur After You Install Security Update MS03-031 / " }
			"8.0.865" { "FIX: An Access Violation Occurs During Compilation If The Table Contains Statistics For A Computed Column / 2005-10-25" }
			"8.0.865" { "FIX: You Cannot Insert Explicit Values In An IDENTITY Column Of A SQL Server Table By Using The Sqlbulkoperations Function Or The Sqlsetpos ODBC Function In SQL Server 2000 / 2005-10-25" }
			"8.0.863" { "FIX: Query Performance May Be Slow And May Be Inconsistent When You Run A Query While Another Query That Contains An IN Operator With Many Values Is Compiled / 2005-10-25" }
			"8.0.863" { "FIX: A Floating Point Exception Occurs During The Optimization Of A Query / 2005-10-25" }
			"8.0.859" { "FIX: Issues That Are Resolved In SQL Server 2000 Build 8.00.0859 / 2005-03-31" }
			"8.0.858" { "FIX: Users Can Control The Compensating Change Process In Merge Replication / " }
			"8.0.857" { "The Knowledge Base (KB) Article You Requested Is Currently Not Available / " }
			"8.0.857" { "FIX: A Query May Fail With Retail Assertion When You Use The NOLOCK Hint Or The READ UNCOMMITTED Isolation Level / 2005-11-23" }
			"8.0.857" { "FIX: An Internet Explorer Script Error Occurs When You Access Metadata Information By Using DTS In SQL Server Enterprise Manager / 2005-10-25" }
			"8.0.856" { "FIX: Key Locks Are Held Until The End Of The Statement For Rows That Do Not Pass Filter Criteria / 2005-10-25" }
			"8.0.854" { "FIX: An Access Violation Occurs When You Run DBCC UPDATEUSAGE On A Database That Has Many Objects / 2005-10-25" }
			"8.0.852" { "FIX: You May Receive An 'Internal SQL Server Error' Error Message When You Run A Transact-SQL SELECT Statement On A View That Has Many Subqueries In SQL Server 2000 / 2005-04-01" }
			"8.0.852" { "FIX: Slow Execution Times May Occur When You Run DML Statements Against Tables That Have Cascading Referential Integrity / " }
			"8.0.851" { "FIX: A Deadlock Occurs If You Run An Explicit UPDATE STATISTICS Command / 2005-10-25" }
			"8.0.850" { "FIX: Linked Server Query May Return NULL If It Is Performed Through A Keyset Cursor / 2005-10-25" }
			"8.0.850" { "FIX: You Receive An 8623 Error Message In SQL Server When You Try To Run A Query That Has Multiple Correlated Subqueries / " }
			"8.0.850" { "FIX: A Query That Uses A View That Contains A Correlated Subquery And An Aggregate Runs Slowly / 2005-10-25" }
			"8.0.848" { "FIX: A Member Of The Db_Accessadmin Fixed Database Role Can Create An Alias For The Dbo Special User / " }
			"8.0.847" { "PRB: Additional SQL Server Diagnostics Added To Detect Unreported I/O Problems / 2005-10-25" }
			"8.0.845" { "FIX: A Query With A LIKE Comparison Results In A Non-Optimal Query Plan When You Use A Hungarian SQL Server Collation / " }
			"8.0.845" { "FIX: No Exclusive Locks May Be Taken If The Disallowspagelocks Value Is Set To True / 2005-10-25" }
			"8.0.844" { "FIX: SQL Server 2000 Protocol Encryption Applies To JDBC Clients / 2006-10-17" }
			"8.0.842" { "FIX: Rows Are Unexpectedly Deleted When You Run A Distributed Query To Delete Or To Update A Linked Server Table / 2005-10-25" }
			"8.0.841" { "FIX: You Receive An Error Message When You Run A Parallel Query That Uses An Aggregation Function Or The GROUP BY Clause / 2005-10-25" }
			"8.0.840" { "FIX: Extremely Large Number Of User Tables On AWE System May Cause Bpool::Map Errors / 2005-09-27" }
			"8.0.840" { "FIX: Extremely Large Number Of User Tables On AWE System May Cause Bpool::Map Errors / 2005-09-27" }
			"8.0.839" { "FIX: An Access Violation May Occur When You Run A Query That Contains 32,000 Or More OR Clauses / 2005-10-25" }
			"8.0.839" { "FIX: A Cursor With A Large Object Parameter May Cause An Access Violation On Cstmtcond::Xretexecute / 2005-10-25" }
			"8.0.837" { "FIX: Delayed Domain Authentication May Cause SQL Server To Stop Responding / 2005-10-25" }
			"8.0.837" { "FIX: Lock Monitor Exception In Deadlockmonitor::Resolvedeadlock / 2005-10-25" }
			"8.0.837" { "FIX: A Parallel Query May Generate An Access Violation After You Install SQL Server 2000 SP3 / 2005-10-25" }
			"8.0.837" { "FIX: MS DTC Transaction Commit Operation Blocks Itself / 2005-10-25" }
			"8.0.837" { "FIX: Build 8.0.0837: A Query That Contains A Correlated Subquery Runs Slowly / 2005-10-25" }
			"8.0.819" { "FIX: You Are Prompted For Password Confirmation After You Change A Standard SQL Server Login / 2005-10-25" }
			"8.0.818" { "MS03-031: Security Patch For SQL Server 2000 Service Pack 3 / 2006-01-09" }
			"8.0.818" { "FIX: Localized Versions Of SQL Mail And The Web Assistant Wizard May Not Work As Expected In SQL Server 2000 64 Bit / 2005-03-16" }
			"8.0.818" { "FIX: A Transact-SQL Statement That Is Embedded In The Database Name Runs With System Administrator Permissions / 2005-02-10" }
			"8.0.818" { "FIX: You Are Prompted For Password Confirmation After You Change A Standard SQL Server Login / 2005-10-25" }
			"8.0.818" { "MS03-031: Security Patch For SQL Server 2000 64-Bit / 2006-03-14" }
			"8.0.816" { "FIX: Intense SQL Server Activity Results In Spinloop Wait / 2005-10-25" }
			"8.0.814" { "FIX: Distribution Cleanup Agent Incorrectly Cleans Up Entries For Anonymous Subscribers / 2005-10-25" }
			"8.0.811" { "FIX: An Access Violation Exception May Occur When You Insert A Row In A Table That Is Referenced By Indexed Views In SQL Server 2000 / 2006-04-03" }
			"8.0.811" { "FIX: Distribution Cleanup Agent Incorrectly Cleans Up Entries For Anonymous Subscribers / 2005-10-25" }
			"8.0.811" { "FIX: Invalid TDS Sent To SQL Server Results In Access Violation / 2005-10-25" }
			"8.0.807" { "FIX: Error Message 3628 May Occur When You Run A Complex Query / 2005-10-25" }
			"8.0.804" { "FIX: Internal Query Processor Error 8623 When Microsoft SQL Server Tries To Compile A Plan For A Complex Query / 2005-10-25" }
			"8.0.801" { "FIX: SQL Server Enterprise Manager Unexpectedly Quits When You Modify A DTS Package / 2006-01-26" }
			"8.0.800" { "FIX: The Sqldumper.Exe File Does Not Generate A Userdump File When It Runs Against A Windows Service / 2005-09-27" }
			"8.0.800" { "FIX: An Access Violation May Occur When You Run DBCC DBREINDEX On A Table That Has Hypothetical Indexes / 2005-09-27" }
			"8.0.800" { "FIX: Query On The Sysmembers Virtual Table May Fail With A Stack Overflow / 2005-09-27" }
			"8.0.798" { "FIX: Using Sp_Executesql In Merge Agent Operations / 2005-09-27" }
			"8.0.794" { "FIX: Using Sp_Executesql In Merge Agent Operations / 2005-09-27" }
			"8.0.794" { "FIX: OLE DB Conversion Errors May Occur After You Select A Literal String That Represents Datetime Data As A Column / 2005-09-27" }
			"8.0.794" { "FIX: Error 8623 Is Raised When SQL Server Compiles A Complex Query / 2005-09-27" }
			"8.0.794" { "FIX: SQL Server 2000 Might Produce An Incorrect Cardinality Estimate For Outer Joins / 2005-02-11" }
			"8.0.791" { "FIX: Performance Of A Query That Is Run From A Client Program On A SQL Server SP3 Database Is Slow After You Restart The Instance Of SQL Server / 2005-09-27" }
			"8.0.790" { "FIX: You Receive An Error Message When You Use The SQL-DMO Bulkcopy Object To Import Data Into A SQL Server Table / 2005-09-27" }
			"8.0.789" { "FIX: Error 17883 May Display Message Text That Is Not Correct / 2005-09-27" }
			"8.0.788" { "FIX: You Cannot Install SQL Server 2000 SP3 On The Korean Version Of SQL Server 2000 / 2005-09-27" }
			"8.0.781" { "FIX: SQL Server 2000 Uninstall Option Does Not Remove All Files / 2005-09-27" }
			"8.0.780" { "FIX: Code Point Comparison Semantics For SQL_Latin1_General_Cp850_BIN Collation / 2005-09-27" }
			"8.0.780" { "FIX: Sysindexes.Statblob Column May Be Corrupted After You Run A DBCC DBREINDEX Statement / 2005-09-27" }
			"8.0.780" { "SQL Server 2000 Hotfix Update For SQL Server 2000 Service Pack 3 And 3A / 2006-10-10" }
			"8.0.779" { "FIX: A Full-Text Population Fails After You Apply SQL Server 2000 Service Pack 3 / 2005-09-27" }
			"8.0.776" { "Unidentified / " }
			"8.0.775" { "FIX: A DTS Package That Uses Global Variables Ignores An Error Message Raised By RAISERROR / 2005-09-27" }
			"8.0.769" { "FIX: A DELETE Statement With A JOIN Might Fail And You Receive A 625 Error / 2005-09-27" }
			"8.0.769" { "FIX: Error Message: 'Insufficient Key Column Information For Updating' Occurs In SQL Server 2000 SP3 / 2005-09-27" }
			"8.0.765" { "FIX: An Access Violation Occurs If An Sp_Cursoropen Call References A Parameter That Is Not Defined / 2005-09-27" }
			"8.0.765" { "FIX: Merge Agent Can Resend Changes For Filtered Publications / 2005-09-27" }
			"8.0.765" { "FIX: Reinitialized SQL Server CE 2.0 Subscribers May Experience Data Loss And Non-Convergence / 2005-09-27" }
			"8.0.765" { "FIX: You May Experience Slow Performance When You Debug A SQL Server Service / 2005-09-27" }
			"8.0.763" { "FIX: DTS Designer May Generate An Access Violation After You Install SQL Server 2000 Service Pack 3 / 2005-09-27" }
			"8.0.762" { "FIX: Merge Publications Cannot Synchronize On SQL Server 2000 Service Pack 3 / 2005-09-27" }
			"8.0.760" { "SQL Server 2000 Service Pack 3 (SP3 / Sp3a) / 2003-08-27" }
			"8.0.743" { "FIX: A Transact-SQL Query That Uses Views May Fail Unexpectedly In SQL Server 2000 SP2 / 2005-10-18" }
			"8.0.743" { "FIX: Intense SQL Server Activity Results In Spinloop Wait In SQL Server 2000 Service Pack 2 / 2005-10-25" }
			"8.0.741" { "FIX: Many Extent Lock Time-Outs May Occur During Extent Allocation / 2005-02-10" }
			"8.0.736" { "FIX: A Memory Leak May Occur When You Use The Sp_Oamethod Stored Procedure To Call A Method Of A COM Object / 2005-09-27" }
			"8.0.735" { "FIX: A DELETE Statement With A JOIN Might Fail And You Receive A 625 Error / 2005-09-27" }
			"8.0.733" { "FIX: A Large Number Of NULL Values In Join Columns Result In Slow Query Performance / 2005-09-27" }
			"8.0.730" { "FIX: You May Experience Slow Performance When You Debug A SQL Server Service / 2005-09-27" }
			"8.0.728" { "FIX: Merge Replication With Alternate Synchronization Partners May Not Succeed After You Change The Retention Period / 2005-09-27" }
			"8.0.725" { "FIX: A Query With An Aggregate Function May Fail With A 3628 Error / 2005-09-27" }
			"8.0.725" { "FIX: Distribution Agent Fails With 'Violation Of Primary Key Constraint' Error Message / 2005-09-27" }
			"8.0.723" { "FIX: A UNION ALL View May Not Use Index If Partitions Are Removed At Compile Time / 2005-09-27" }
			"8.0.721" { "FIX: Indexed View May Cause A Handled Access Violation In Cindex::Setlevel1names / 2005-09-27" }
			"8.0.721" { "FIX: Update Or Delete Statement Fails With Error 1203 During Row Lock Escalation / 2005-09-27" }
			"8.0.718" { "FIX: Unexpected Results From Partial Aggregations Based On Conversions / 2005-09-27" }
			"8.0.715" { "FIX: Merge Agent Can Resend Changes For Filtered Publications / 2005-09-27" }
			"8.0.715" { "FIX: Reinitialized SQL Server CE 2.0 Subscribers May Experience Data Loss And Non-Convergence / 2005-09-27" }
			"8.0.714" { "FIX: Restoring A SQL Server 7.0 Database Backup In SQL Server 2000 Service Pack 2 (SP2) May Cause An Assertion Error In The Xdes.Cpp File / 2005-10-18" }
			"8.0.713" { "FIX: An Error Message Occurs When You Perform A Database Or A File SHRINK Operation / 2005-09-27" }
			"8.0.710" { "FIX: Latch Time-Out Message 845 Occurs When You Perform A Database Or File SHRINK Operation / 2005-09-27" }
			"8.0.705" { "FIX: The JOIN Queries In The Triggers That Involve The Inserted Table Or The Deleted Table May Return Results That Are Not Consistent / 2005-09-27" }
			"8.0.703" { "FIX: Cursors That Have A Long Lifetime May Cause Memory Fragmentation / 2005-09-27" }
			"8.0.702" { "FIX: Concurrency Enhancements For The Tempdb Database / 2006-07-19" }
			"8.0.701" { "FIX: A DELETE Statement With A Self-Join May Fail And You Receive A 625 Error / 2005-09-27" }
			"8.0.701" { "FIX: An Access Violation Occurs If An Sp_Cursoropen Call References A Parameter That Is Not Defined / 2005-09-27" }
			"8.0.700" { "FIX: Merge Replication Reconciler Stack Overflow / 2005-09-27" }
			"8.0.696" { "FIX: A Memory Leak Occurs When Cursors Are Opened During A Connection / 2005-09-27" }
			"8.0.696" { "FIX: The Fn_Get_Sql System Table Function May Cause Various Handled Access Violations / 2005-09-27" }
			"8.0.695" { "FIX: Update/Delete Statement Fails With Error 1203 During Page Lock Escalation / 2005-09-27" }
			"8.0.695" { "FIX: The Xp_Readmail Extended Stored Procedure Overwrites Attachment That Already Exists / 2005-02-10" }
			"8.0.695" { "FIX: The Xp_Readmail And Xp_Findnextmsg Extended Stored Procedures Do Not Read Mail In Time Received Order / 2005-02-10" }
			"8.0.693" { "FIX: Parallel Logical Operation Returns Results That Are Not Consistent / 2005-09-27" }
			"8.0.690" { "FIX: The SELECT Statement With Parallelism Enabled May Cause An Assertion / 2005-10-12" }
			"8.0.689" { "FIX: Replication Removed From Database After Restore WITH RECOVERY / 2005-10-11" }
			"8.0.688" { "FIX: Transaction Log Restore Fails With Message 3456 / 2005-10-11" }
			"8.0.686" { "SQL Server 2000 Security Update For Service Pack 2 / 2006-11-24" }
			"8.0.682" { "FIX: Assertion And Error Message 3314 Occurs If You Try To Roll Back A Text Operation With READ UNCOMMITTED / 2005-10-18" }
			"8.0.679" { "SQL Server 2000 Security Update For Service Pack 2 / 2006-11-24" }
			"8.0.678" { "FIX: A RESTORE DATABASE WITH RECOVERY Statement Can Fail With Error 9003 Or Error 9004 / 2005-09-27" }
			"8.0.667" { "2000 SP2+8/14 Fix / " }
			"8.0.665" { "2000 SP2+8/8 Fix / " }
			"8.0.661" { "FIX: Lock Escalation On A Scan While An Update Query Is Running Causes A 1203 Error Message To Occur / 2005-09-27" }
			"8.0.655" { "2000 SP2+7/24 Fix / " }
			"8.0.652" { "FIX: The Fn_Get_Sql System Table Function May Cause Various Handled Access Violations / 2005-09-27" }
			"8.0.650" { "FIX: SQL Server Grants Unnecessary Permissions Or An Encryption Function Contains Unchecked Buffers / 2003-11-05" }
			"8.0.644" { "FIX: Slow Compile Time And Execution Time With Query That Contains Aggregates And Subqueries / 2005-09-27" }
			"8.0.636" { "Microsoft Security Bulletin MS02-039 / 2002-06-24" }
			"8.0.608" { "FIX: SQL Extended Procedure Functions Contain Unchecked Buffers / 2004-06-21" }
			"8.0.604" { "2000 SP2+3/29 Fix / " }
			"8.0.599" { "FIX: Improved SQL Manager Robustness For Odd Length Buffer / 2005-09-27" }
			"8.0.594" { "FIX: Extremely Large Number Of User Tables On AWE System May Cause Bpool::Map Errors / 2005-09-27" }
			"8.0.584" { "FIX: Reorder Outer Joins With Filter Criteria Before Non-Selective Joins And Outer Joins / 2008-02-04" }
			"8.0.578" { "FIX: Unchecked Buffer May Occur When You Connect To Remote Data Source / 2005-09-27" }
			"8.0.578" { "FIX: SELECT With Timestamp Column That Uses FOR XML AUTO May Fail With Stack Overflow Or AV / 2005-09-27" }
			"8.0.568" { "317748 FIX: Handle Leak Occurs In SQL Server When Service Or Application Repeatedly Connects And Disconnects With Shared Memory Network Library / 2002-10-30" }
			"8.0.561" { "2000 SP2+1/29 Fix / " }
			"8.0.558" { "FIX: Query That Uses DESC Index May Result In Access Violation / 2005-09-26" }
			"8.0.558" { "FIX: COM May Not Be Uninitialized For Worker Thread When You Use Sp_OA / 2005-09-27" }
			"8.0.552" { "The Knowledge Base (KB) Article You Requested Is Currently Not Available / " }
			"8.0.552" { "FIX: SELECT From Computed Column That References UDF Causes SQL Server To Terminate / 2005-09-26" }
			"8.0.534" { "2000 SP2.01 / " }
			"8.0.532" { "SQL Server 2000 Service Pack 2 (SP2) / 2003-02-04" }
			"8.0.475" { "2000 SP1+1/29 Fix / " }
			"8.0.474" { "FIX: COM May Not Be Uninitialized For Worker Thread When You Use Sp_OA / 2005-09-27" }
			"8.0.473" { "FIX: Query That Uses DESC Index May Result In Access Violation / 2005-09-26" }
			"8.0.471" { "FIX: Shared Table Lock Is Not Released After Lock Escalation / 2005-09-26" }
			"8.0.469" { "FIX: SELECT From Computed Column That References UDF Causes SQL Server To Terminate / 2005-09-26" }
			"8.0.452" { "FIX: SELECT DISTINCT From Table With LEFT JOIN Of View Causes Error Messages Or Client Application May Stop Responding / 2005-09-26" }
			"8.0.444" { "FIX: Sqlputdata May Result In Leak Of Buffer Pool Memory / 2005-09-26" }
			"8.0.444" { "FIX: Querying Syslockinfo With Large Numbers Of Locks May Cause Server To Stop Responding / 2005-10-07" }
			"8.0.443" { "FIX: Sqltrace Start And Stop Is Now Reported In Windows NT Event Log For SQL Server 2000 / 2005-09-26" }
			"8.0.428" { "FIX: SQL Server Text Formatting Functions Contain Unchecked Buffers / 2004-08-05" }
			"8.0.384" { "SQL Server 2000 Service Pack 1 (SP1) / 2001-06-11" }
			"8.0.296" { "FIX: Query Method Used To Access Data May Allow Rights That The Login Might Not Normally Have / 2004-08-09" }
			"8.0.287" { "FIX: Deletes, Updates And Rank Based Selects May Cause Deadlock Of MSSEARCH / 2005-10-07" }
			"8.0.251" { "FIX: Error 644 Using Two Indexes On A Column With Uppercase Preference Sort Order / 2003-10-17" }
			"8.0.250" { "The Knowledge Base (KB) Article You Requested Is Currently Not Available / " }
			"8.0.249" { "FIX: Lock Monitor Uses Excessive CPU / 2003-09-12" }
			"8.0.239" { "FIX: Complex ANSI Join Query With Distributed Queries May Cause Handled Access Violation / 2003-10-09" }
			"8.0.233" { "FIX: Opening The Database Folder In SQL Server Enterprise Manager 2000 Takes A Long Time / 2003-10-09" }
			"8.0.231" { "FIX: Execution Of Sp_Oacreate On COM Object Without Type Information Causes Server Shut Down / 2003-10-09" }
			"8.0.226" { "FIX: Extreme Memory Usage When Adding Many Security Roles / 2006-11-21" }
			"8.0.225" { "Access Denied Error Message When You Try To Use A Network Drive To Modify Windows 2000 Permissions / 2006-10-30" }
			"8.0.223" { "FIX: Buffer Overflow Exploit Possible With Extended Stored Procedures / 2004-06-29" }
			"8.0.222" { "FIX: Exception Access Violation Encountered During Query Normalization / 2005-10-07" }
			"8.0.218" { "FIX: Scripting Object With Several Extended Properties May Cause Exception / 2003-10-09" }
			"8.0.217" { "FIX: CASE Using LIKE With Empty String Can Result In Access Violation Or Abnormal Server Shutdown / 2003-10-09" }
			"8.0.211" { "FIX: Complex Distinct Or Group By Query Can Return Unexpected Results With Parallel Execution Plan / 2003-11-05" }
			"8.0.210" { "FIX: Linked Server Query With Hyphen In LIKE Clause May Run Slowly / 2003-10-09" }
			"8.0.205" { "FIX: Sending Open Files As Attachment In SQL Mail Fails With Error 18025 / 2005-10-07" }
			"8.0.204" { "FIX: Optimizer Slow To Generate Query Plan For Complex Queries That Have Many Joins And Semi-Joins / 2003-10-09" }
			"8.0.194" { "SQL Server 2000 RTM (No SP) / 2000-11-30" }
			"8.0.190" { "SQL Server 2000 Gold / " }
			"8.0.100" { "SQL Server 2000 Beta 2 / " }
			"8.0.078" { "SQL Server 2000 EAP5 / " }
			"8.0.047" { "SQL Server 2000 EAP4 / " }
			"7.0.1152" { "MS08-040: Description Of The Security Update For SQL Server 7.0: July 8, 2008 / 2012-05-09" }
			"7.0.1149" { "FIX: An Access Violation Exception May Occur When You Run A SELECT Statement That Contains Complex JOIN Operations In SQL Server 7.0 / 2006-06-01" }
			"7.0.1143" { "New Connection Events Are Not Recorded In SQL Server Traces / 2005-10-25" }
			"7.0.1143" { "FIX: An Attention Signal That Is Sent From A SQL Server Client Application Because Of A Query Time-Out May Cause The SQL Server Service To Quit Unexpectedly / 2005-10-25" }
			"7.0.1097" { "A Complex UPDATE Statement That Uses An Index Spool Operation May Cause An Assertion / 2005-10-25" }
			"7.0.1094" { "MS03-031: Security Patch For SQL Server 7.0 Service Pack 4 / 2006-05-11" }
			"7.0.1094" { "MS03-031: Cumulative Security Patch For SQL Server / 2006-05-10" }
			"7.0.1092" { "FIX: Delayed Domain Authentication May Cause SQL Server To Stop Responding / 2005-10-25" }
			"7.0.1087" { "FIX: SQL Server 7.0 Scheduler May Periodically Stop Responding During Large Sort Operation / 2005-09-27" }
			"7.0.1079" { "FIX: Replication Removed From Database After Restore WITH RECOVERY / 2005-10-11" }
			"7.0.1078" { "INF: SQL Server 7.0 Security Update For Service Pack 4 / 2005-09-27" }
			"7.0.1077" { "SQL Server 2000 Security Update For Service Pack 2 / 2006-11-24" }
			"7.0.1063" { "SQL Server 7.0 Service Pack 4 (SP4) / 2002-04-26" }
			"7.0.1033" { "FIX: Error Message 9004 May Occur When You Restore A Log That Does Not Contain Any Transactions / 2005-10-12" }
			"7.0.1026" { "FIX: Assertion And Error Message 3314 Occurs If You Try To Roll Back A Text Operation With READ UNCOMMITTED / 2005-10-18" }
			"7.0.1004" { "FIX: SQL Server Text Formatting Functions Contain Unchecked Buffers / 2004-08-05" }
			"7.0.996" { "FIX: Query Method Used To Access Data May Allow Rights That The Login Might Not Normally Have / 2004-08-09" }
			"7.0.978" { "FIX: Update With Self Join May Update Incorrect Number Of Rows / 2003-10-28" }
			"7.0.977" { "FIX: SQL Server Profiler And SQL Server Agent Alerts May Fail To Work After Installing SQL Server 7.0 SP3 / 2002-04-25" }
			"7.0.970" { "FIX: SQL Server May Generate Nested Query For Linked Server When Option Is Disabled / 2002-10-15" }
			"7.0.970" { "FIX: Incorrect Results With Join Of Column Converted To Binary / 2003-10-29" }
			"7.0.961" { "SQL Server 7.0 Service Pack 3 (SP3) / 2000-12-15" }
			"7.0.921" { "FIX: SQL Server May Generate Nested Query For Linked Server When Option Is Disabled / 2002-10-15" }
			"7.0.919" { "FIX: Incorrect Results With Join Of Column Converted To Binary / 2003-10-29" }
			"7.0.918" { "FIX: Buffer Overflow Exploit Possible With Extended Stored Procedures / 2004-06-29" }
			"7.0.917" { "FIX: Bcp.Exe With Long Query String Can Result In Assertion Failure / 2005-09-26" }
			"7.0.910" { "FIX: SQL RPC That Raises Error Will Mask @@ERROR With Msg 7221 / 2003-10-31" }
			"7.0.905" { "FIX: Data Modification Query With A Distinct Subquery On A View May Cause Error 3624 / 2004-07-15" }
			"7.0.889" { "FIX: Replication Initialize Method Causes Handle Leak On Failure / 2005-10-05" }
			"7.0.879" { "FIX: Linked Index Server Query Through OLE DB Provider With OR Clause Reports Error 7349 / 2006-03-14" }
			"7.0.857" { "FIX: Transactional Publications With A Filter On Numeric Columns Fail To Replicate Data / 2006-03-14" }
			"7.0.843" { "FIX: Temporary Stored Procedures In SA Owned Databases May Bypass Permission Checks When You Run Stored Procedures / 2006-03-14" }
			"7.0.842" { "SQL Server 7.0 Service Pack 2 (SP2) / 2000-03-20" }
			"7.0.839" { "SQL Server 7.0 Service Pack 2 (SP2) Unidentified / " }
			"7.0.835" { "SQL Server 7.0 Service Pack 2 (SP2) Beta / " }
			"7.0.776" { "FIX: Non-Admin User That Executes Batch While Server Shuts Down May Encounter Retail Assertion / 2006-03-14" }
			"7.0.770" { "FIX: Slow Compile Time On Complex Joins With Unfiltered Table / 2006-03-14" }
			"7.0.745" { "FIX: SQL Server Components That Access The Registry In A Cluster Environment May Cause A Memory Leak / 2005-10-07" }
			"7.0.722" { "FIX: Replication: Problems Mapping Characters To DB2 OLEDB Subscribers / 2005-10-05" }
			"7.0.699" { "SQL Server 7.0 Service Pack 1 (SP1) / 1999-07-01" }
			"7.0.689" { "SQL Server 7.0 Service Pack 1 (SP1) Beta / " }
			"7.0.677" { "SQL Server 7.0 MSDE From Office 2000 Disc / " }
			"7.0.662" { "FIX: Query With Complex View Hierarchy May Be Slow To Compile / 2005-10-05" }
			"7.0.658" { "FIX: Access Violation Under High Cursor Stress / 2006-03-14" }
			"7.0.657" { "FIX: Unable To Perform Automated Installation Of SQL 7.0 Using File Images / 2005-10-05" }
			"7.0.643" { "FIX: SQL Cluster Install Fails When SVS Name Contains Special Characters / 2005-10-05" }
			"7.0.623" { "SQL Server 7.0 RTM (Gold, No SP) / 1998-11-27" }
			"7.0.583" { "SQL Server 7.0 RC1 / " }
			"7.0.517" { "SQL Server 7.0 Beta 3 / " }
			"6.50.480" { "FIX: Integrated Security Sprocs Have Race Condition Between Threads That Can Result In An Access Violation / 2005-10-07" }
			"6.50.479" { "Microsoft SQL Server 6.5 Post Service Pack 5A Update / 2000-09-12" }
			"6.50.469" { "FIX: SQL Performance Counters May Cause Handle Leak In Winlogon Process / " }
			"6.50.465" { "FIX: Memory Leak With Xp_Sendmail Using Attachments / " }
			"6.50.464" { "FIX: Insert Error (Msg 213) With NO_BROWSETABLE And INSERT EXEC / 1999-11-08" }
			"6.50.462" { "FIX: Terminating Clients With TSQL KILL May Cause ODS AV / " }
			"6.50.451" { "FIX: ODS Errors During Attention Signal May Cause SQL Server To Stop Responding / " }
			"6.50.444" { "FIX: Multiple Attachments Not Sent Correctly Using Xp_Sendmail / " }
			"6.50.441" { "FIX: SNMP Extended Stored Procedures May Leak Memory / " }
			"6.50.422" { "FIX: Large Query Text From Socket Client May Cause Open Data Services Access Violation / " }
			"6.50.416" { "Microsoft SQL Server 6.5 Service Pack 5A (Sp5a) / 1998-12-24" }
			"6.50.415" { "Microsoft SQL Server 6.5 Service Pack 5 (SP5) / " }
			"6.50.339" { "Y2K Hotfix / " }
			"6.50.297" { "Site Server 3.0 Commerce Edition Hotfix / " }
			"6.50.281" { "Microsoft SQL Server 6.5 Service Pack 4 (SP4) / " }
			"6.50.259" { "6.5 As Included With 'Small Business Server' Only / " }
			"6.50.258" { "Microsoft SQL Server 6.5 Service Pack 3A (Sp3a) / " }
			"6.50.252" { "Microsoft SQL Server 6.5 Service Pack 3 (SP3) / " }
			"6.50.240" { "Microsoft SQL Server 6.5 Service Pack 2 (SP2) / " }
			"6.50.213" { "Microsoft SQL Server 6.5 Service Pack 1 (SP1) / " }
			"6.50.201" { "Microsoft SQL Server 6.5 RTM / 1996-06-30" }
			"6.0.151" { "Microsoft SQL Server 6.0 Service Pack 3 (SP3) / " }
			"6.0.139" { "Microsoft SQL Server 6.0 Service Pack 2 (SP2) / " }
			"6.0.124" { "Microsoft SQL Server 6.0 Service Pack 1 (SP1) / " }
			"6.0.121" { "Microsoft SQL Server 6.0 RTM / 1995-06-13" }
			default { "Unknown Version" }
		}
	}
	elseif ($Product -eq 'SSRS')
	{
		$Output = switch ($BuildVersion)
		{
	# SSRS List: https://sqlserverbuilds.blogspot.com/2020/09/sql-server-reporting-services-ssrs.html
    <# 
       SQL Server Reporting Services (SSRS) 2019 Versions
    #>
			'15.0.1102.962' { "SQL Server Reporting Services 2019 - April 2022 Release / 2022 April 4" }
			'15.0.8115.18148' { "SQL Server Reporting Services 2019 - April 2022 Release / 2022 April 4" } #File Version
			
			'15.0.1102.932' { "SQL Server Reporting Services 2019 - October 2021 Release / 2021 October 20" }
			'15.0.7961.31630' { "SQL Server Reporting Services 2019 - October 2021 Release / 2021 October 20" } #File Version
			'15.0.1102.911' { "SQL Server Reporting Services 2019 - June 2021 Release / 2021 June 24" }
			'15.0.7842.32355' { "SQL Server Reporting Services 2019 - June 2021 Release / 2021 June 24" } #File Version
			'15.0.1102.896' { "SQL Server Reporting Services 2019 - April 2021 Release / 2021 April 07" }
			'15.0.7765.17516' { "SQL Server Reporting Services 2019 - April 2021 Release / 2021 April 07" } #File Version
			'15.0.1102.861' { "SQL Server Reporting Services 2019 - August 2020 Release / 2020 August 31" }
			'15.0.7545.4810' { "SQL Server Reporting Services 2019 - August 2020 Release / 2020 August 31" } #File Version
			'15.0.1102.675' { "SQL Server Reporting Services 2019 - October 2021 Release / 2021 October 20" }
			'15.0.7243.37714' { "SQL Server Reporting Services 2019 - Initial Release / 2019 November 1" } #File Version
    <# 
       SQL Server Reporting Services (SSRS) 2017 Versions
    #>
			'14.0.600.1860' { "SQL Server Reporting Services 2017 - April 2022 Release / 2022 April 26" }
			'14.0.8091.35795' { "SQL Server Reporting Services 2017 - April 2022 Release / 2022 April 26" } #File Version
			
			'14.0.600.1763' { "SQL Server Reporting Services 2017 - June 2021 Release / 2021 June 28" }
			'14.0.7844.42503' { "SQL Server Reporting Services 2017 - June 2021 Release / 2021 June 28" } #File Version
			
			'14.0.600.1669' { "SQL Server Reporting Services 2017 - August 2020 Release / 2020 August 31" }
			'14.0.7544.5078' { "SQL Server Reporting Services 2017 - August 2020 Release / 2020 August 31" } #File Version
			'14.0.600.1572' { "SQL Server Reporting Services 2017 - April 2020 Release / 2020 April 6" }
			'14.0.600.1453' { "SQL Server Reporting Services 2017 - November 2019 Release 2 / 2019 November 14" }
			'14.0.600.1451' { "SQL Server Reporting Services 2017 - November 2019 Release / 2019 November 13" }
			'14.0.600.1274' { "SQL Server Reporting Services 2017 - July 2019 Release / 2019 July 1" }
			'14.0.600.1109' { "SQL Server Reporting Services 2017 - February 2019 Release / 2019 February 12" }
			'14.0.600.906' { "SQL Server Reporting Services 2017 - September 2018 Release / 2018 September 12" }
			'14.0.600.892' { "SQL Server Reporting Services 2017 - August 2018 Release / 2018 August 31" }
			'14.0.600.744' { "SQL Server Reporting Services 2017 - April 2018 Release / 2018 April 25" }
			'14.0.600.689' { "SQL Server Reporting Services 2017 - February 2018 Release / 2018 February 28" }
			'14.0.600.594' { "SQL Server Reporting Services 2017 - January 2018 Release / 2018 January 9" }
			'14.0.600.490' { "SQL Server Reporting Services 2017 - November 2017 Release / 2017 November 1" }
			'14.0.600.451' { "SQL Server Reporting Services 2017 - Initial Release / 2017 September 30" }
			
    <# 
       SQL Server Reporting Services (SSRS) 2016 and below Versions (these were integrated into SQL Install Directly)
    #>
			"13.0.6404.1" { "On-Demand Hotfix Update Package For SQL Server 2016 Service Pack 3 (SP3) / 2021 October 27" }
			"13.0.6300.2" { "Microsoft SQL Server 2016 Service Pack 3 (SP3) / 2021 September 15" }
			"13.0.5888.11" { "Cumulative Update 17 (CU17) For SQL Server 2016 Service Pack 2 / 2021 March 29" }
			"13.0.5882.1" { "Cumulative Update 16 (CU16) For SQL Server 2016 Service Pack 2 / 2021 February 11" }
			"13.0.5865.1" { "Security Update For SQL Server 2016 SP2 CU15: January 12, 2021 / 2021 January 12" }
			"13.0.5850.14" { "Cumulative Update 15 (CU15) For SQL Server 2016 Service Pack 2 / 2020 September 28" }
			"13.0.5830.85" { "Cumulative Update 14 (CU14) For SQL Server 2016 Service Pack 2 / 2020 August 06" }
			"13.0.5820.21" { "Cumulative Update 13 (CU13) For SQL Server 2016 Service Pack 2 / 2020 May 28" }
			"13.0.5698.0" { "Cumulative Update 12 (CU12) For SQL Server 2016 Service Pack 2 / 2020 February 25" }
			"13.0.5622.0" { "Security Update For SQL Server 2016 SP2 CU11: February 11, 2020 / 2020 February 11" }
			"13.0.5598.27" { "Cumulative Update 11 (CU11) For SQL Server 2016 Service Pack 2 / 2019 December 09" }
			"13.0.5492.2" { "Cumulative Update 10 (CU10) For SQL Server 2016 Service Pack 2 / 2019 October 08" }
			"13.0.5479.0" { "4515435 Cumulative Update 9 (CU9) For SQL Server 2016 Service Pack 2 / 2019 September 30" }
			"13.0.5426.0" { "Cumulative Update 8 (CU8) For SQL Server 2016 Service Pack 2 / 2019 July 31" }
			"13.0.5382.0" { "On-Demand Hotfix Update Package 2 For SQL Server 2016 Service Pack 2 (SP2) Cumulative Update 7 (CU7) / 2019 July 09" }
			"13.0.5366.0" { "Security Update For SQL Server 2016 SP2 CU7 GDR: July 9, 2019 / 2019 July 09" }
			"13.0.5343.1" { "On-Demand Hotfix Update Package For SQL Server 2016 Service Pack 2 (SP2) Cumulative Update 7 (CU7) / 2019 June 24" }
			"13.0.5337.0" { "Cumulative Update 7 (CU7) For SQL Server 2016 Service Pack 2 / 2019 May 22" }
			"13.0.5292.0" { "Cumulative Update 6 (CU6) For SQL Server 2016 Service Pack 2 / 2019 March 19" }
			"13.0.5270.0" { "On-Demand Hotfix Update Package For SQL Server 2016 SP2 CU5 / 2019 February 14" }
			"13.0.5264.1" { "Cumulative Update 5 (CU5) For SQL Server 2016 Service Pack 2 / 2019 January 23" }
			"13.0.5239.0" { "On-Demand Hotfix Update Package 2 For SQL Server 2016 SP2 CU4 / 2018 December 21" }
			"13.0.5233.0" { "Cumulative Update 4 (CU4) For SQL Server 2016 Service Pack 2 / 2018 November 13" }
			"13.0.5221.0" { "FIX: Assertion Error Occurs When You Restart The SQL Server 2016 Database / 2018 October 09" }
			"13.0.5221.0" { "FIX: '3414' And '9003' Errors And A .Pmm Log File Grows Large In SQL Server 2016 / 2018 October 09" }
			"13.0.5216.0" { "Cumulative Update 3 (CU3) For SQL Server 2016 Service Pack 2 / 2018 September 21" }
			"13.0.5201.2" { "Security Update For The Remote Code Execution Vulnerability In SQL Server 2016 SP2 CU: August 19, 2018 / 2018 August 19" }
			"13.0.5161.0" { "Security Update For The Remote Code Execution Vulnerability In SQL Server 2016 SP2 CU: August 14, 2018 / 2018 August 14" }
			"13.0.5153.0" { "Cumulative Update 2 (CU2) For SQL Server 2016 Service Pack 2 / 2018 July 17" }
			"13.0.5149.0" { "Cumulative Update 1 (CU1) For SQL Server 2016 Service Pack 2 / 2018 May 30" }
			"13.0.5103.6" { "Security Update For SQL Server 2016 SP2 GDR: January 12, 2021 / 2021 January 12" }
			"13.0.5102.14" { "Security Update For SQL Server 2016 SP2 GDR: February 11, 2020 / 2020 February 11" }
			"13.0.5101.9" { "Security Update For SQL Server 2016 SP2 GDR: July 9, 2019 / 2019 July 09" }
			"13.0.5081.1" { "Security Update For The Remote Code Execution Vulnerability In SQL Server 2016 SP2 GDR: August 14, 2018 / 2018 August 14" }
			"13.0.5026.0" { "Microsoft SQL Server 2016 Service Pack 2 (SP2) / 2018 April 24" }
			"13.0.4604.0" { "Security Update For SQL Server 2016 SP1 CU15 GDR: July 9, 2019 / 2019 July 09" }
			"13.0.4577.0" { "On-Demand Hotfix Update Package For SQL Server 2016 Service Pack 1 (SP1) Cumulative Update 15 (CU15) / 2019 June 20" }
			"13.0.4574.0" { "Cumulative Update 15 (CU15) For SQL Server 2016 Service Pack 1 / 2019 May 16" }
			"13.0.4560.0" { "Cumulative Update 14 (CU14) For SQL Server 2016 Service Pack 1 / 2019 March 19" }
			"13.0.4550.1" { "Cumulative Update 13 (CU13) For SQL Server 2016 Service Pack 1 / 2019 January 23" }
			"13.0.4541.0" { "Cumulative Update 12 (CU12) For SQL Server 2016 Service Pack 1 / 2018 November 13" }
			"13.0.4531.0" { "FIX: The 'Modification_Counter' In DMV Sys.Dm_Db_Stats_Properties Shows Incorrect Value When Partitions Are Merged Through ALTER PARTITION In SQL Server 2016 / 2018 September 27" }
			"13.0.4528.0" { "Cumulative Update 11 (CU11) For SQL Server 2016 Service Pack 1 / 2018 September 18" }
			"13.0.4522.0" { "Security Update For The Remote Code Execution Vulnerability In SQL Server 2016 SP1 CU: August 14, 2018 / 2018 August 14" }
			"13.0.4514.0" { "Cumulative Update 10 (CU10) For SQL Server 2016 Service Pack 1 / 2018 July 16" }
			"13.0.4502.0" { "Cumulative Update 9 (CU9) For SQL Server 2016 Service Pack 1 / 2018 May 30" }
			"13.0.4477.0" { "On-Demand Hotfix Update Package For SQL Server 2016 SP1 / 2018 June 02" }
			"13.0.4474.0" { "Cumulative Update 8 (CU8) For SQL Server 2016 Service Pack 1 / 2018 March 19" }
			"13.0.4466.4" { "Cumulative Update 7 (CU7) For SQL Server 2016 Service Pack 1 - Security Advisory ADV180002 / 2018 January 04" }
			"13.0.4457.0" { "Cumulative Update 6 (CU6) For SQL Server 2016 Service Pack 1 / 2017 November 21" }
			"13.0.4451.0" { "Cumulative Update 5 (CU5) For SQL Server 2016 Service Pack 1 / 2017 September 18" }
			"13.0.4446.0" { "Cumulative Update 4 (CU4) For SQL Server 2016 Service Pack 1 / 2017 August 08" }
			"13.0.4435.0" { "Cumulative Update 3 (CU3) For SQL Server 2016 Service Pack 1 / 2017 May 15" }
			"13.0.4422.0" { "Cumulative Update 2 (CU2) For SQL Server 2016 Service Pack 1 / 2017 March 22" }
			"13.0.4411.0" { "Cumulative Update 1 (CU1) For SQL Server 2016 Service Pack 1 / 2017 January 18" }
			"13.0.4259.0" { "Security Update For SQL Server 2016 SP1 GDR: July 9, 2019 / 2019 July 09" }
			"13.0.4224.16" { "Security Update For The Remote Code Execution Vulnerability In SQL Server 2016 SP1 GDR: August 22, 2018 / 2018 August 22" }
			"13.0.4223.10" { "Security Update For The Remote Code Execution Vulnerability In SQL Server 2016 SP1 GDR: August 14, 2018 / 2018 August 14" }
			"13.0.4210.6" { "Description Of The Security Update For SQL Server 2016 SP1 GDR: January 3, 2018 - Security Advisory ADV180002 / 2018 January 03" }
			"13.0.4206.0" { "Security Update For SQL Server 2016 Service Pack 1 GDR: August 8, 2017 / 2017 August 08" }
			"13.0.4202.2" { "GDR Update Package For SQL Server 2016 SP1 / 2016 December 16" }
			"13.0.4199.0" { "Important Update For SQL Server 2016 SP1 Reporting Services / 2016 November 23" }
			"13.0.4001.0" { "Microsoft SQL Server 2016 Service Pack 1 (SP1) / 2016 November 16" }
			"13.0.2218.0" { "Description Of The Security Update For SQL Server 2016 CU: January 6, 2018 - Security Advisory ADV180002 / 2018 January 06" }
			"13.0.2216.0" { "Cumulative Update 9 (CU9) For SQL Server 2016 / 2017 November 21" }
			"13.0.2213.0" { "Cumulative Update 8 (CU8) For SQL Server 2016 / 2017 September 18" }
			"13.0.2210.0" { "Cumulative Update 7 (CU7) For SQL Server 2016 / 2017 August 08" }
			"13.0.2204.0" { "Cumulative Update 6 (CU6) For SQL Server 2016 / 2017 May 15" }
			"13.0.2197.0" { "Cumulative Update 5 (CU5) For SQL Server 2016 / 2017 March 21" }
			"13.0.2193.0" { "Cumulative Update 4 (CU4) For SQL Server 2016 / 2017 January 18" }
			"13.0.2190.2" { "On-Demand Hotfix Update Package For SQL Server 2016 CU3 / 2016 December 16" }
			"13.0.2186.6" { "Cumulative Update 3 (CU3) For SQL Server 2016 / 2016 November 08" }
			"13.0.2186.6" { "MS16-136: Description Of The Security Update For SQL Server 2016 CU: November 8, 2016 / 2016 November 08" }
			"13.0.2170.0" { "On-Demand Hotfix Update Package For SQL Server 2016 CU2 / 2016 November 01" }
			"13.0.2169.0" { "On-Demand Hotfix Update Package For SQL Server 2016 CU2 / 2016 October 26" }
			"13.0.2164.0" { "Cumulative Update 2 (CU2) For SQL Server 2016 / 2016 September 22" }
			"13.0.2149.0" { "Cumulative Update 1 (CU1) For SQL Server 2016 / 2016 July 26" }
			"13.0.1745.2" { "Description Of The Security Update For SQL Server 2016 GDR: January 6, 2018 - Security Advisory ADV180002 / 2018 January 06" }
			"13.0.1742.0" { "Security Update For SQL Server 2016 RTM GDR: August 8, 2017 / 2017 August 08" }
			"13.0.1728.2" { "GDR Update Package For SQL Server 2016 RTM / 2016 December 16" }
			"13.0.1722.0" { "MS16-136: Description Of The Security Update For SQL Server 2016 GDR: November 8, 2016 / 2016 November 08" }
			"13.0.1711.0" { "Processing A Partition Causes Data Loss On Other Partitions After The Database Is Restored In SQL Server 2016 (1200) / 2016 August 17" }
			"13.0.1708.0" { "Critical Update For SQL Server 2016 MSVCRT Prerequisites / 2016 June 03" }
			"13.0.1601.5" { "Microsoft SQL Server 2016 RTM / 2016 June 01" }
			"13.0.1400.361" { "Microsoft SQL Server 2016 Release Candidate 3 (RC3) / 2016 April 15" }
			"13.0.1300.275" { "Microsoft SQL Server 2016 Release Candidate 2 (RC2) / 2016 April 01" }
			"13.0.1200.242" { "Microsoft SQL Server 2016 Release Candidate 1 (RC1) / 2016 March 18" }
			"13.0.1100.288" { "Microsoft SQL Server 2016 Release Candidate 0 (RC0) / 2016 March 07" }
			"13.0.1000.281" { "Microsoft SQL Server 2016 Community Technology Preview 3.3 (CTP3.3) / 2016 February 03" }
			"13.0.900.73" { "Microsoft SQL Server 2016 Community Technology Preview 3.2 (CTP3.2) / 2015 December 16" }
			"13.0.800.11" { "Microsoft SQL Server 2016 Community Technology Preview 3.1 (CTP3.1) / 2015 November 30" }
			"13.0.700.139" { "Microsoft SQL Server 2016 Community Technology Preview 3.0 (CTP3.0) / 2015 October 28" }
			"13.0.600.65" { "Microsoft SQL Server 2016 Community Technology Preview 2.4 (CTP2.4) / 2015 September 30" }
			"13.0.500.53" { "Microsoft SQL Server 2016 Community Technology Preview 2.3 (CTP2.3) / 2015 August 28" }
			"13.0.407.1" { "Microsoft SQL Server 2016 Community Technology Preview 2.2 (CTP2.2) / 2015 July 23" }
			"13.0.400.91" { "Microsoft SQL Server 2016 Community Technology Preview 2.2 (CTP2.2) / 2015 July 22" }
			"13.0.300.44" { "Microsoft SQL Server 2016 Community Technology Preview 2.1 (CTP2.1) / 2015 June 24" }
			"13.0.200.172" { "Microsoft SQL Server 2016 Community Technology Preview 2 (CTP2) / 2015 May 27" }
			"12.0.6433.1" { "Security Update For SQL Server 2014 SP3 CU4: January 12, 2021 / 2021 January 12" }
			"12.0.6372.1" { "Security Update For SQL Server 2014 SP3 CU4: February 11, 2020 / 2020 February 11" }
			"12.0.6329.1" { "Cumulative Update Package 4 (CU4) For SQL Server 2014 Service Pack 3 / 2019 July 29" }
			"12.0.6293.0" { "Security Update For SQL Server 2014 SP3 CU3 GDR: July 9, 2019 / 2019 July 09" }
			"12.0.6259.0" { "Cumulative Update Package 3 (CU3) For SQL Server 2014 Service Pack 3 / 2019 April 16" }
			"12.0.6214.1" { "Cumulative Update Package 2 (CU2) For SQL Server 2014 Service Pack 3 / 2019 February 19" }
			"12.0.6205.1" { "Cumulative Update Package 1 (CU1) For SQL Server 2014 Service Pack 3 / 2018 December 12" }
			"12.0.6164.21" { "Security Update For SQL Server 2014 SP3 GDR: January 12, 2021 / 2021 January 12" }
			"12.0.6118.4" { "Security Update For SQL Server 2014 SP3 GDR: February 11, 2020 / 2020 February 11" }
			"12.0.6108.1" { "Security Update For SQL Server 2014 SP3 GDR: July 9, 2019 / 2019 July 09" }
			"12.0.6024.0" { "SQL Server 2014 Service Pack 3 (SP3) / 2018 October 30" }
			"12.0.5687.1" { "Cumulative Update Package 18 (CU18) For SQL Server 2014 Service Pack 2 / 2019 July 29" }
			"12.0.5659.1" { "Security Update For SQL Server 2014 SP2 CU17 GDR: July 9, 2019 / 2019 July 09" }
			"12.0.5632.1" { "Cumulative Update Package 17 (CU17) For SQL Server 2014 Service Pack 2 / 2019 April 16" }
			"12.0.5626.1" { "Cumulative Update Package 16 (CU16) For SQL Server 2014 Service Pack 2 / 2019 February 19" }
			"12.0.5605.1" { "Cumulative Update Package 15 (CU15) For SQL Server 2014 Service Pack 2 / 2018 December 12" }
			"12.0.5600.1" { "Cumulative Update Package 14 (CU14) For SQL Server 2014 Service Pack 2 / 2018 October 15" }
			"12.0.5590.1" { "Cumulative Update Package 13 (CU13) For SQL Server 2014 Service Pack 2 / 2018 August 27" }
			"12.0.5589.7" { "Cumulative Update Package 12 (CU12) For SQL Server 2014 Service Pack 2 / 2018 June 18" }
			"12.0.5579.0" { "Cumulative Update Package 11 (CU11) For SQL Server 2014 Service Pack 2 / 2018 March 19" }
			"12.0.5571.0" { "Cumulative Update Package 10 (CU10) For SQL Server 2014 Service Pack 2 - Security Advisory ADV180002 / 2018 January 16" }
			"12.0.5563.0" { "Cumulative Update Package 9 (CU9) For SQL Server 2014 Service Pack 2 / 2017 December 19" }
			"12.0.5557.0" { "Cumulative Update Package 8 (CU8) For SQL Server 2014 Service Pack 2 / 2017 October 17" }
			"12.0.5556.0" { "Cumulative Update Package 7 (CU7) For SQL Server 2014 Service Pack 2 / 2017 August 29" }
			"12.0.5553.0" { "Cumulative Update Package 6 (CU6) For SQL Server 2014 Service Pack 2 / 2017 August 08" }
			"12.0.5546.0" { "Cumulative Update Package 5 (CU5) For SQL Server 2014 Service Pack 2 / 2017 April 18" }
			"12.0.5540.0" { "Cumulative Update Package 4 (CU4) For SQL Server 2014 Service Pack 2 / 2017 February 21" }
			"12.0.5538.0" { "Cumulative Update Package 3 (CU3) For SQL Server 2014 Service Pack 2 - The Article Incorrectly Says It's Version 12.0.5537 / 2016 December 28" }
			"12.0.5532.0" { "MS16-136: Description Of The Security Update For SQL Server 2014 Service Pack 2 CU: November 8, 2016 / 2016 November 08" }
			"12.0.5522.0" { "Cumulative Update Package 2 (CU2) For SQL Server 2014 Service Pack 2 / 2016 October 18" }
			"12.0.5511.0" { "Cumulative Update Package 1 (CU1) For SQL Server 2014 Service Pack 2 / 2016 August 26" }
			"12.0.5223.6" { "Security Update For SQL Server 2014 SP2 GDR: July 9, 2019 / 2019 July 09" }
			"12.0.5214.6" { "Security Update For SQL Server 2014 Service Pack 2 GDR: January 16, 2018 - Security Advisory ADV180002 / 2018 January 16" }
			"12.0.5207.0" { "Security Update For SQL Server 2014 Service Pack 2 GDR: August 8, 2017 / 2017 August 08" }
			"12.0.5203.0" { "MS16-136: Description Of The Security Update For SQL Server 2014 Service Pack 2 GDR: November 8, 2016 / 2016 November 08" }
			"12.0.5000.0" { "SQL Server 2014 Service Pack 2 (SP2) / 2016 July 11" }
			"12.0.4522.0" { "Cumulative Update Package 13 (CU13) For SQL Server 2014 Service Pack 1 / 2017 August 08" }
			"12.0.4511.0" { "Cumulative Update Package 12 (CU12) For SQL Server 2014 Service Pack 1 / 2017 April 18" }
			"12.0.4502.0" { "Cumulative Update Package 11 (CU11) For SQL Server 2014 Service Pack 1 / 2017 February 21" }
			"12.0.4491.0" { "Cumulative Update Package 10 (CU10) For SQL Server 2014 Service Pack 1 / 2016 December 28" }
			"12.0.4487.0" { "MS16-136: Description Of The Security Update For SQL Server 2014 Service Pack 1 CU: November 8, 2016 / 2016 November 08" }
			"12.0.4474.0" { "Cumulative Update Package 9 (CU9) For SQL Server 2014 Service Pack 1 / 2016 October 18" }
			"12.0.4468.0" { "Cumulative Update Package 8 (CU8) For SQL Server 2014 Service Pack 1 / 2016 August 15" }
			"12.0.4463.0" { "A Memory Leak Occurs When You Use Azure Storage In SQL Server 2014 / 2016 August 04" }
			"12.0.4459.0" { "Cumulative Update Package 7 (CU7) For SQL Server 2014 Service Pack 1 / 2016 June 20" }
			"12.0.4457.1" { "REFRESHED Cumulative Update Package 6 (CU6) For SQL Server 2014 Service Pack 1 / 2016 May 31" }
			"12.0.4449.1" { "DEPRECATED Cumulative Update Package 6 (CU6) For SQL Server 2014 Service Pack 1 / 2016 April 19" }
			"12.0.4439.1" { "Cumulative Update Package 5 (CU5) For SQL Server 2014 Service Pack 1 / 2016 February 22" }
			"12.0.4437.0" { "On-Demand Hotfix Update Package For SQL Server 2014 Service Pack 1 Cumulative Update 4 / 2016 February 05" }
			"12.0.4436.0" { "Cumulative Update Package 4 (CU4) For SQL Server 2014 Service Pack 1 / 2015 December 22" }
			"12.0.4433.0" { "FIX: Error 3203 And A SQL Server 2014 Backup Job Can't Restart When A Network Failure Occurs / 2015 December 09" }
			"12.0.4432.0" { "FIX: Error When Your Stored Procedure Calls Another Stored Procedure On Linked Server In SQL Server 2014 / 2015 November 19" }
			"12.0.4237.0" { "Security Update For SQL Server 2014 Service Pack 1 GDR: August 8, 2017 / 2017 August 08" }
			"12.0.4232.0" { "MS16-136: Description Of The Security Update For SQL Server 2014 Service Pack 1 GDR: November 8, 2016 / 2016 November 08" }
			"12.0.4427.24" { "Cumulative Update Package 3 (CU3) For SQL Server 2014 Service Pack 1 / 2015 October 21" }
			"12.0.4422.0" { "Cumulative Update Package 2 (CU2) For SQL Server 2014 Service Pack 1 / 2015 August 17" }
			"12.0.4419.0" { "An On-Demand Hotfix Update Package Is Available For SQL Server 2014 SP1 / 2015 July 24" }
			"12.0.4416.0" { "Cumulative Update Package 1 (CU1) For SQL Server 2014 Service Pack 1 / 2015 June 22" }
			"12.0.4219.0" { "TLS 1.2 Support For SQL Server 2014 SP1 / 2016 January 27" }
			"12.0.4213.0" { "MS15-058: Description Of The Nonsecurity Update For SQL Server 2014 Service Pack 1 GDR: July 14, 2015 / 2015 July 14" }
			"12.0.4100.1" { "SQL Server 2014 Service Pack 1 (SP1) / 2015 May 14" }
			"12.0.4050.0" { "SQL Server 2014 Service Pack 1 (SP1) / 2015 April 15" }
			"12.0.2569.0" { "Cumulative Update Package 14 (CU14) For SQL Server 2014 / 2016 June 20" }
			"12.0.2568.0" { "Cumulative Update Package 13 (CU13) For SQL Server 2014 / 2016 April 18" }
			"12.0.2564.0" { "Cumulative Update Package 12 (CU12) For SQL Server 2014 / 2016 February 22" }
			"12.0.2560.0" { "Cumulative Update Package 11 (CU11) For SQL Server 2014 / 2015 December 22" }
			"12.0.2556.4" { "Cumulative Update Package 10 (CU10) For SQL Server 2014 / 2015 October 20" }
			"12.0.2553.0" { "Cumulative Update Package 9 (CU9) For SQL Server 2014 / 2015 August 17" }
			"12.0.2548.0" { "MS15-058: Description Of The Security Update For SQL Server 2014 QFE: July 14, 2015 / 2015 July 14" }
			"12.0.2546.0" { "Cumulative Update Package 8 (CU8) For SQL Server 2014 / 2015 June 22" }
			"12.0.2506.0" { "Update Enables Premium Storage Support For Data Files On Azure Storage And Resolves Backup Failures / 2015 May 19" }
			"12.0.2505.0" { "FIX: Error 1205 When You Execute Parallel Query That Contains Outer Join Operators In SQL Server 2014 / 2015 May 19" }
			"12.0.2504.0" { "FIX: Poor Performance When A Query Contains Table Joins In SQL Server 2014 / 2015 May 05" }
			"12.0.2504.0" { "FIX: Unpivot Transformation Task Changes Null To Zero Or Empty Strings In SSIS 2014 / 2015 May 05" }
			"12.0.2495.0" { "Cumulative Update Package 7 (CU7) For SQL Server 2014 / 2015 April 23" }
			"12.0.2488.0" { "FIX: Deadlock Cannot Be Resolved Automatically When You Run A SELECT Query That Can Result In A Parallel Batch-Mode Scan / 2015 April 01" }
			"12.0.2485.0" { "An On-Demand Hotfix Update Package Is Available For SQL Server 2014 / 2015 March 16" }
			"12.0.2480.0" { "Cumulative Update Package 6 (CU6) For SQL Server 2014 / 2015 February 16" }
			"12.0.2474.0" { "FIX: Alwayson Availability Groups Are Reported As NOT SYNCHRONIZING / 2015 May 15" }
			"12.0.2472.0" { "FIX: Cannot Show Requested Dialog After You Connect To The Latest SQL Database Update V12 (Preview) With SQL Server 2014 / 2015 January 28" }
			"12.0.2464.0" { "Large Query Compilation Waits On RESOURCE_SEMAPHORE_QUERY_COMPILE In SQL Server 2014 / 2015 January 05" }
			"12.0.2456.0" { "Cumulative Update Package 5 (CU5) For SQL Server 2014 / 2014 December 18" }
			"12.0.2436.0" { "FIX: 'Remote Hardening Failure' Exception Cannot Be Caught And A Potential Data Loss When You Use SQL Server 2014 / 2014 November 27" }
			"12.0.2430.0" { "Cumulative Update Package 4 (CU4) For SQL Server 2014 / 2014 October 21" }
			"12.0.2423.0" { "FIX: RTDATA_LIST Waits When You Run Natively Stored Procedures That Encounter Expected Failures In SQL Server 2014 / 2014 October 22" }
			"12.0.2405.0" { "FIX: Poor Performance When A Query Contains Table Joins In SQL Server 2014 / 2014 September 25" }
			"12.0.2402.0" { "Cumulative Update Package 3 (CU3) For SQL Server 2014 / 2014 August 18" }
			"12.0.2381.0" { "MS14-044: Description Of The Security Update For SQL Server 2014 (QFE) / 2014 August 12" }
			"12.0.2370.0" { "Cumulative Update Package 2 (CU2) For SQL Server 2014 / 2014 June 27" }
			"12.0.2342.0" { "Cumulative Update Package 1 (CU1) For SQL Server 2014 / 2014 April 21" }
			"12.0.2271.0" { "TLS 1.2 Support For SQL Server 2014 RTM / 2016 January 27" }
			"12.0.2269.0" { "MS15-058: Description Of The Security Update For SQL Server 2014 GDR: July 14, 2015 / 2015 July 14" }
			"12.0.2254.0" { "MS14-044: Description Of The Security Update For SQL Server 2014 (GDR) / 2014 August 12" }
			"12.0.2000.8" { "SQL Server 2014 RTM / 2014 April 01" }
			"12.0.1524.0" { "Microsoft SQL Server 2014 Community Technology Preview 2 (CTP2) / 2013 October 15" }
			"11.0.9120.0" { "Microsoft SQL Server 2014 Community Technology Preview 1 (CTP1) / 2013 June 25" }
			"11.0.7507.2" { "Security Update For SQL Server 2012 SP4 GDR: January 12, 2021 / 2021 January 12" }
			"11.0.7493.4" { "Security Update For SQL Server 2012 SP4 GDR: February 11, 2020 / 2020 February 11" }
			"11.0.7469.6" { "On-Demand Hotfix Update Package For SQL Server 2012 SP4 / 2018 March 28" }
			"11.0.7462.6" { "Description Of The Security Update For SQL Server 2012 SP4 GDR: January 12, 2018 - Security Advisory ADV180002 / 2018 January 12" }
			"11.0.7001.0" { "SQL Server 2012 Service Pack 4 (SP4) / 2017 October 05" }
			"11.0.6615.2" { "Description Of The Security Update For SQL Server 2012 SP3 CU: January 16, 2018 - Security Advisory ADV180002 / 2018 January 16" }
			"11.0.6607.3" { "Cumulative Update Package 10 (CU10) For SQL Server 2012 Service Pack 3 / 2017 August 08" }
			"11.0.6607.3" { "Security Update For SQL Server 2012 Service Pack 3 CU: August 8, 2017 / 2017 August 08" }
			"11.0.6598.0" { "Cumulative Update Package 9 (CU9) For SQL Server 2012 Service Pack 3 / 2017 May 15" }
			"11.0.6594.0" { "Cumulative Update Package 8 (CU8) For SQL Server 2012 Service Pack 3 / 2017 March 21" }
			"11.0.6579.0" { "Cumulative Update Package 7 (CU7) For SQL Server 2012 Service Pack 3 / 2017 January 17" }
			"11.0.6567.0" { "Cumulative Update Package 6 (CU6) For SQL Server 2012 Service Pack 3 / 2016 November 17" }
			"11.0.6567.0" { "MS16-136: Description Of The Security Update For SQL Server 2012 Service Pack 3 CU: November 8, 2016 / 2016 November 08" }
			"11.0.6544.0" { "Cumulative Update Package 5 (CU5) For SQL Server 2012 Service Pack 3 / 2016 September 21" }
			"11.0.6540.0" { "Cumulative Update Package 4 (CU4) For SQL Server 2012 Service Pack 3 / 2016 July 19" }
			"11.0.6537.0" { "Cumulative Update Package 3 (CU3) For SQL Server 2012 Service Pack 3 / 2016 May 17" }
			"11.0.6523.0" { "Cumulative Update Package 2 (CU2) For SQL Server 2012 Service Pack 3 / 2016 March 22" }
			"11.0.6518.0" { "Cumulative Update Package 1 (CU1) For SQL Server 2012 Service Pack 3 / 2016 January 19" }
			"11.0.6260.1" { "Description Of The Security Update For SQL Server 2012 SP3 GDR: January 16, 2018 - Security Advisory ADV180002 / 2018 January 16" }
			"11.0.6251.0" { "Description Of The Security Update For SQL Server 2012 Service Pack 3 GDR: August 8, 2017 / 2017 August 08" }
			"11.0.6248.0" { "MS16-136: Description Of The Security Update For SQL Server 2012 Service Pack 3 GDR: November 8, 2016 / 2016 November 08" }
			"11.0.6216.27" { "TLS 1.2 Support For SQL Server 2012 SP3 GDR / 2016 January 27" }
			"11.0.6020.0" { "SQL Server 2012 Service Pack 3 (SP3) / 2015 November 23" }
			"11.0.5678.0" { "Cumulative Update Package 16 (CU16) For SQL Server 2012 Service Pack 2 / 2017 January 18" }
			"11.0.5676.0" { "Cumulative Update Package 15 (CU15) For SQL Server 2012 Service Pack 2 / 2016 November 17" }
			"11.0.5676.0" { "MS16-136: Description Of The Security Update For SQL Server 2012 Service Pack 2 CU: November 8, 2016 / 2016 November 08" }
			"11.0.5657.0" { "Cumulative Update Package 14 (CU14) For SQL Server 2012 Service Pack 2 / 2016 September 20" }
			"11.0.5655.0" { "Cumulative Update Package 13 (CU13) For SQL Server 2012 Service Pack 2 / 2016 July 19" }
			"11.0.5649.0" { "Cumulative Update Package 12 (CU12) For SQL Server 2012 Service Pack 2 / 2016 May 16" }
			"11.0.5646.0" { "Cumulative Update Package 11 (CU11) For SQL Server 2012 Service Pack 2 / 2016 March 22" }
			"11.0.5644.0" { "Cumulative Update Package 10 (CU10) For SQL Server 2012 Service Pack 2 / 2016 January 20" }
			"11.0.5641.0" { "Cumulative Update Package 9 (CU9) For SQL Server 2012 Service Pack 2 / 2015 November 18" }
			"11.0.5636.3" { "FIX: Performance Decrease When Application With Connection Pooling Frequently Connects Or Disconnects In SQL Server / 2015 September 22" }
			"11.0.5634.0" { "Cumulative Update Package 8 (CU8) For SQL Server 2012 Service Pack 2 / 2015 September 21" }
			"11.0.5629.0" { "FIX: Access Violations When You Use The Filetable Feature In SQL Server 2012 / 2015 August 31" }
			"11.0.5623.0" { "Cumulative Update Package 7 (CU7) For SQL Server 2012 Service Pack 2 / 2015 July 20" }
			"11.0.5613.0" { "MS15-058: Description Of The Security Update For SQL Server 2012 Service Pack 2 QFE: July 14, 2015 / 2015 July 14" }
			"11.0.5592.0" { "Cumulative Update Package 6 (CU6) For SQL Server 2012 Service Pack 2 / 2015 May 19" }
			"11.0.5582.0" { "Cumulative Update Package 5 (CU5) For SQL Server 2012 Service Pack 2 / 2015 March 16" }
			"11.0.5571.0" { "FIX: Alwayson Availability Groups Are Reported As NOT SYNCHRONIZING / 2015 May 15" }
			"11.0.5569.0" { "Cumulative Update Package 4 (CU4) For SQL Server 2012 Service Pack 2 / 2015 January 20" }
			"11.0.5556.0" { "Cumulative Update Package 3 (CU3) For SQL Server 2012 Service Pack 2 / 2014 November 17" }
			"11.0.5548.0" { "Cumulative Update Package 2 (CU2) For SQL Server 2012 Service Pack 2 / 2014 September 15" }
			"11.0.5532.0" { "Cumulative Update Package 1 (CU1) For SQL Server 2012 Service Pack 2 / 2014 July 24" }
			"11.0.5522.0" { "FIX: Data Loss In Clustered Index Occurs When You Run Online Build Index In SQL Server 2012 (Hotfix For SQL2012 SP2) / 2014 June 20" }
			"11.0.5388.0" { "MS16-136: Description Of The Security Update For SQL Server 2012 Service Pack 2 GDR: November 8, 2016 / 2016 November 08" }
			"11.0.5352.0" { "TLS 1.2 Support For SQL Server 2012 SP2 GDR / 2016 January 27" }
			"11.0.5343.0" { "MS15-058: Description Of The Security Update For SQL Server 2012 Service Pack 2 GDR: July 14, 2015 / 2015 July 14" }
			"11.0.5058.0" { "SQL Server 2012 Service Pack 2 (SP2) / 2014 June 10" }
			"11.0.3513.0" { "MS15-058: Description Of The Security Update For SQL Server 2012 SP1 QFE: July 14, 2015 / 2015 July 14" }
			"11.0.3492.0" { "Cumulative Update Package 16 (CU16) For SQL Server 2012 Service Pack 1 / 2015 May 18" }
			"11.0.3487.0" { "Cumulative Update Package 15 (CU15) For SQL Server 2012 Service Pack 1 / 2015 March 16" }
			"11.0.3486.0" { "Cumulative Update Package 14 (CU14) For SQL Server 2012 Service Pack 1 / 2015 January 19" }
			"11.0.3460.0" { "MS14-044: Description Of The Security Update For SQL Server 2012 Service Pack 1 (QFE) / 2014 August 12" }
			"11.0.3482.0" { "Cumulative Update Package 13 (CU13) For SQL Server 2012 Service Pack 1 / 2014 November 17" }
			"11.0.3470.0" { "Cumulative Update Package 12 (CU12) For SQL Server 2012 Service Pack 1 / 2014 September 15" }
			"11.0.3449.0" { "Cumulative Update Package 11 (CU11) For SQL Server 2012 Service Pack 1 / 2014 July 21" }
			"11.0.3437.0" { "FIX: Data Loss In Clustered Index Occurs When You Run Online Build Index In SQL Server 2012 (Hotfix For SQL2012 SP1) / 2014 June 10" }
			"11.0.3431.0" { "Cumulative Update Package 10 (CU10) For SQL Server 2012 Service Pack 1 / 2014 May 19" }
			"11.0.3412.0" { "Cumulative Update Package 9 (CU9) For SQL Server 2012 Service Pack 1 / 2014 March 18" }
			"11.0.3401.0" { "Cumulative Update Package 8 (CU8) For SQL Server 2012 Service Pack 1 / 2014 January 20" }
			"11.0.3393.0" { "Cumulative Update Package 7 (CU7) For SQL Server 2012 Service Pack 1 / 2013 November 18" }
			"11.0.3381.0" { "Cumulative Update Package 6 (CU6) For SQL Server 2012 Service Pack 1 / 2013 September 16" }
			"11.0.3373.0" { "Cumulative Update Package 5 (CU5) For SQL Server 2012 Service Pack 1 / 2013 July 16" }
			"11.0.3368.0" { "Cumulative Update Package 4 (CU4) For SQL Server 2012 Service Pack 1 / 2013 May 31" }
			"11.0.3350.0" { "FIX: You Can'T Create Or Open SSIS Projects Or Maintenance Plans After You Apply Cumulative Update 3 For SQL Server 2012 SP1 / 2013 April 17" }
			"11.0.3349.0" { "Cumulative Update Package 3 (CU3) For SQL Server 2012 Service Pack 1 / 2013 March 18" }
			"11.0.3339.0" { "Cumulative Update Package 2 (CU2) For SQL Server 2012 Service Pack 1 / 2013 January 25" }
			"11.0.3335.0" { "FIX: Component Installation Process Fails After You Install SQL Server 2012 SP1 / 2013 January 14" }
			"11.0.3321.0" { "Cumulative Update Package 1 (CU1) For SQL Server 2012 Service Pack 1 / 2012 November 20" }
			"11.0.3156.0" { "MS15-058: Description Of The Security Update For SQL Server 2012 SP1 GDR: July 14, 2015 / 2015 July 14" }
			"11.0.3153.0" { "MS14-044: Description Of The Security Update For SQL Server 2012 Service Pack 1 (GDR) / 2014 August 12" }
			"11.0.3128.0" { "Windows Installer Starts Repeatedly After You Install SQL Server 2012 SP1 / 2013 January 03" }
			"11.0.3000.0" { "SQL Server 2012 Service Pack 1 (SP1) / 2012 November 06" }
			"11.0.2845.0" { "SQL Server 2012 Service Pack 1 Customer Technology Preview 4 (CTP4) / 2012 September 20" }
			"11.0.2809.24" { "SQL Server 2012 Service Pack 1 Customer Technology Preview 3 (CTP3) / 2012 July 05" }
			"11.0.2424.0" { "Cumulative Update Package 11 (CU11) For SQL Server 2012 / 2013 December 17" }
			"11.0.2420.0" { "Cumulative Update Package 10 (CU10) For SQL Server 2012 / 2013 October 21" }
			"11.0.2419.0" { "Cumulative Update Package 9 (CU9) For SQL Server 2012 / 2013 August 21" }
			"11.0.2410.0" { "Cumulative Update Package 8 (CU8) For SQL Server 2012 / 2013 June 18" }
			"11.0.2405.0" { "Cumulative Update Package 7 (CU7) For SQL Server 2012 / 2013 April 15" }
			"11.0.2401.0" { "Cumulative Update Package 6 (CU6) For SQL Server 2012 / 2013 February 18" }
			"11.0.2395.0" { "Cumulative Update Package 5 (CU5) For SQL Server 2012 / 2012 December 18" }
			"11.0.9000.5" { "Microsoft SQL Server 2012 With Power View For Multidimensional Models Customer Technology Preview (CTP3) / 2012 November 27" }
			"11.0.2383.0" { "Cumulative Update Package 4 (CU4) For SQL Server 2012 / 2012 October 18" }
			"11.0.2376.0" { "Microsoft Security Bulletin MS12-070 / 2012 October 09" }
			"11.0.2332.0" { "Cumulative Update Package 3 (CU3) For SQL Server 2012 / 2012 August 29" }
			"11.0.2325.0" { "Cumulative Update Package 2 (CU2) For SQL Server 2012 / 2012 June 18" }
			"11.0.2318.0" { "SQL Server 2012 Express Localdb RTM / 2012 April 19" }
			"11.0.2316.0" { "Cumulative Update Package 1 (CU1) For SQL Server 2012 / 2012 April 12" }
			"11.0.2218.0" { "Microsoft Security Bulletin MS12-070 / 2012 October 09" }
			"11.0.2214.0" { "FIX: SSAS Uses Only 20 Cores In SQL Server 2012 Business Intelligence / 2012 April 06" }
			"11.0.2100.60" { "SQL Server 2012 RTM / 2012 March 06" }
			# If nothing else found then default to version number
			default { "Unknown Version" }
		}
		return $Output
	}
	return $Output
}

	Write-Progress -Activity "Collection Running" -Status "Progress-> 67%" -PercentComplete 67
	foreach ($server in $Servers)
	{
		function Inner-GeneralInfoFunction
		{
			param
			(
				[cmdletbinding()]
				[switch]$LocalManagementServer
			)
			# Uncomment the below to turn on Verbose Output.
			#$VerbosePreference = 'Continue'
			trap
			{
				#potential error code
				#use continue or break keywords
				$e = $_.Exception
				$line = $_.InvocationInfo.ScriptLineNumber
				$msg = $e.Message
				
				Write-Verbose "Caught Exception: $e at line: $line"
				"$(Time-Stamp)Caught Exception: $e at line: $line" | Out-File $OutputPath\Error.log -Append
			}
			Function Time-Stamp
			{
				$TimeStamp = Get-Date -Format "MM/dd/yyyy hh:mm:ss tt"
				return "$TimeStamp - "
			}
			Write-Verbose "================================================================"
			Write-Verbose "$(Time-Stamp)Started gathering on this machine: $env:COMPUTERNAME"
			Write-Verbose "$(Time-Stamp)Loading Product Version Function"
			#region AllServersGeneralInfo
			$ProductVersionScript = "function Get-ProductVersion { ${function:Get-ProductVersion} }"
			. ([ScriptBlock]::Create($ProductVersionScript))
			Write-Verbose "$(Time-Stamp)Grabbing System Uptime"
			$Uptime = (($(Get-Date) - $(Get-CimInstance -ClassName Win32_OperatingSystem | Select LastBootUpTime -ExpandProperty LastBootUpTime)) | Select Hours, Minutes, Seconds) | % { Write-Output "$($_.Hours) hour(s), $($_.Minutes) minute(s), $($_.Seconds) second(s)" }
			try
			{
				$winrmConfig = winrm get winrm/config
			}
			catch
			{
				$winrmConfig = $false
			}
			#=======================================================================
			# Start General Information Gather
			#=======================================================================
			# Get PowerShell Version section
			#=======================================================================
			$PSVer = $PSVersionTable.PSVersion
			[string]$PSMajor = $PSVer.Major
			[string]$PSMinor = $PSVer.Minor
			$PSVersion = $PSMajor + "." + $PSMinor
			#=======================================================================
			# Get PowerShell CLR Version section
			#=======================================================================
			$CLRVer = $PSVersionTable.CLRVersion
			[string]$CLRMajor = $CLRVer.Major
			[string]$CLRMinor = $CLRVer.Minor
			$CLRVersion = $CLRMajor + "." + $CLRMinor
			#=======================================================================
			$OSVersion = (Get-CimInstance win32_operatingsystem).Caption
			$Freespace = Get-PSDrive -PSProvider FileSystem | Select-Object @{ Name = 'Drive'; Expression = { $_.Root } }, @{ Name = "Used (GB)"; Expression = { "{0:###0.00}" -f ($_.Used / 1GB) } }, @{ Name = "Free (GB)"; Expression = { "{0:###0.00}" -f ($_.Free / 1GB) } }, @{ Name = "Total (GB)"; Expression = { "{0:###0.00}" -f (($_.Free / 1GB) + ($_.Used / 1GB)) } }
			$localServicesList = (Get-CimInstance Win32_service).where{ $_.name -eq 'omsdk' -or $_.name -eq 'cshost' -or $_.name -eq 'HealthService' -or $_.name -eq 'System Center Management APM' -or $_.name -eq 'AdtAgent' -or $_.name -match "MSSQL" -or $_.name -like "SQLAgent*" -or $_.name -eq 'SQLBrowser' -or $_.name -eq 'SQLServerReportingServices' }
			
			$localServices = $localServicesList | Format-List @{ Label = "Service Display Name"; Expression = 'DisplayName' }, @{ Label = "Service Name"; Expression = 'Name' }, @{ Label = "Account Name"; Expression = 'StartName' }, @{ Label = "Start Mode"; Expression = 'StartMode' }, @{ Label = "Current State"; Expression = 'State' } | Out-String -Width 4096
			$WinHTTPProxy = netsh winhttp show proxy
			#=======================================================================
			# Build IP List from Windows Computer Property
			#=======================================================================
			#We want to remove Link local IP
			$ip = ([System.Net.Dns]::GetHostAddresses($Env:COMPUTERNAME)).IPAddressToString;
			[string]$IPList = ""
			$IPSplit = $IP.Split(", ")
			FOREACH ($IPAddr in $IPSplit)
			{
				[string]$IPAddr = $IPAddr.Trim()
				IF (!($IPAddr.StartsWith("fe80") -or $IPAddr.StartsWith("169.254")))
				{
					$IPList = $IPList + $IPAddr + ", "
				}
			}
			$IPList = $IPList.TrimEnd(", ")
			#=======================================================================
			# Get TLS12Enforced Section
			#=======================================================================
			#Set the value to good by default then look for any bad or missing settings
			$TLS12Enforced = $True
			
			IF (Test-Path "HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\SSL 2.0\Client")
			{
				$Enabled = (Get-ItemProperty "HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\SSL 2.0\Client").Enabled
				$DisabledByDefault = (Get-ItemProperty "HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\SSL 2.0\Client").DisabledByDefault
				IF ($Enabled -ne 0 -or $DisabledByDefault -ne 1)
				{
					$TLS12Enforced = $False
				}
			}
			ELSE
			{
				$TLS12Enforced = $False
			}
			
			IF (Test-Path "HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\SSL 2.0\Server")
			{
				$Enabled = (Get-ItemProperty "HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\SSL 2.0\Server").Enabled
				$DisabledByDefault = (Get-ItemProperty "HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\SSL 2.0\Server").DisabledByDefault
				IF ($Enabled -ne 0 -or $DisabledByDefault -ne 1)
				{
					$TLS12Enforced = $False
				}
			}
			ELSE
			{
				$TLS12Enforced = $False
			}
			
			IF (Test-Path "HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\SSL 3.0\Client")
			{
				$Enabled = (Get-ItemProperty "HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\SSL 3.0\Client").Enabled
				$DisabledByDefault = (Get-ItemProperty "HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\SSL 3.0\Client").DisabledByDefault
				IF ($Enabled -ne 0 -or $DisabledByDefault -ne 1)
				{
					$TLS12Enforced = $False
				}
			}
			ELSE
			{
				$TLS12Enforced = $False
			}
			
			IF (Test-Path "HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\SSL 3.0\Server")
			{
				$Enabled = (Get-ItemProperty "HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\SSL 3.0\Server").Enabled
				$DisabledByDefault = (Get-ItemProperty "HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\SSL 3.0\Server").DisabledByDefault
				IF ($Enabled -ne 0 -or $DisabledByDefault -ne 1)
				{
					$TLS12Enforced = $False
				}
			}
			ELSE
			{
				$TLS12Enforced = $False
			}
			
			IF (Test-Path "HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\TLS 1.0\Client")
			{
				$Enabled = (Get-ItemProperty "HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\TLS 1.0\Client").Enabled
				$DisabledByDefault = (Get-ItemProperty "HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\TLS 1.0\Client").DisabledByDefault
				IF ($Enabled -ne 0 -or $DisabledByDefault -ne 1)
				{
					$TLS12Enforced = $False
				}
			}
			ELSE
			{
				$TLS12Enforced = $False
			}
			
			IF (Test-Path "HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\TLS 1.0\Server")
			{
				$Enabled = (Get-ItemProperty "HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\TLS 1.0\Server").Enabled
				$DisabledByDefault = (Get-ItemProperty "HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\TLS 1.0\Server").DisabledByDefault
				IF ($Enabled -ne 0 -or $DisabledByDefault -ne 1)
				{
					$TLS12Enforced = $False
				}
			}
			ELSE
			{
				$TLS12Enforced = $False
			}
			
			IF (Test-Path "HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\TLS 1.1\Client")
			{
				$Enabled = (Get-ItemProperty "HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\TLS 1.1\Client").Enabled
				$DisabledByDefault = (Get-ItemProperty "HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\TLS 1.1\Client").DisabledByDefault
				IF ($Enabled -ne 0 -or $DisabledByDefault -ne 1)
				{
					$TLS12Enforced = $False
				}
			}
			ELSE
			{
				$TLS12Enforced = $False
			}
			
			IF (Test-Path "HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\TLS 1.1\Server")
			{
				$Enabled = (Get-ItemProperty "HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\TLS 1.1\Server").Enabled
				$DisabledByDefault = (Get-ItemProperty "HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\TLS 1.1\Server").DisabledByDefault
				IF ($Enabled -ne 0 -or $DisabledByDefault -ne 1)
				{
					$TLS12Enforced = $False
				}
			}
			ELSE
			{
				$TLS12Enforced = $False
			}
			
			IF (Test-Path "HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\TLS 1.2\Client")
			{
				$Enabled = (Get-ItemProperty "HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\TLS 1.2\Client").Enabled
				$DisabledByDefault = (Get-ItemProperty "HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\TLS 1.2\Client").DisabledByDefault
				IF ($Enabled -ne 1 -or $DisabledByDefault -ne 0)
				{
					$TLS12Enforced = $False
				}
			}
			ELSE
			{
				$TLS12Enforced = $False
			}
			
			IF (Test-Path "HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\TLS 1.2\Server")
			{
				$Enabled = (Get-ItemProperty "HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\TLS 1.2\Server").Enabled
				$DisabledByDefault = (Get-ItemProperty "HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\TLS 1.2\Server").DisabledByDefault
				IF ($Enabled -ne 1 -or $DisabledByDefault -ne 0)
				{
					$TLS12Enforced = $False
				}
			}
			ELSE
			{
				$TLS12Enforced = $False
			}
			
			IF (Test-Path "HKLM:\SOFTWARE\Microsoft\.NETFramework\v4.0.30319")
			{
				$SchUseStrongCrypto = (Get-ItemProperty "HKLM:\SOFTWARE\Microsoft\.NETFramework\v4.0.30319").SchUseStrongCrypto
				IF ($SchUseStrongCrypto -ne 1)
				{
					$TLS12Enforced = $False
				}
			}
			ELSE
			{
				$TLS12Enforced = $False
			}
			
			IF (Test-Path "HKLM:\SOFTWARE\WOW6432Node\Microsoft\.NETFramework\v4.0.30319")
			{
				$SchUseStrongCrypto = (Get-ItemProperty "HKLM:\SOFTWARE\WOW6432Node\Microsoft\.NETFramework\v4.0.30319").SchUseStrongCrypto
				IF ($SchUseStrongCrypto -ne 1)
				{
					$TLS12Enforced = $False
				}
			}
			ELSE
			{
				$TLS12Enforced = $False
			}
			Write-Verbose "$(Time-Stamp)Gathering File System Allocation Information"
			$driveData = @()
			try
			{
				$Freespace | Foreach-Object {
					$driveLetter = ($_.Drive -replace "\\", '')
					$driveData += (Get-CimInstance Win32_Volume) | Where { $driveLetter -eq $_.DriveLetter } | Select-Object -Property @{ Name = 'DriveLetter'; Expression = { $_.DriveLetter } }, @{ Name = 'BytesPerCluster'; Expression = { "$($_.BlockSize) ($($_.BlockSize / 1kb) KB)" } }
				}
			}
			catch
			{
				Write-Verbose "$(Time-Stamp) - Unable to gather the File System Allocation Information!"
			}
			Write-Verbose "$(Time-Stamp)Gathering w32tm Information"
			$w32tmQueryStatus = & 'w32tm' '/query', '/status'
			try
			{
				$PowershellGPOs = (Get-ChildItem 'HKLM:\SOFTWARE\WOW6432Node\Policies\Microsoft\Windows\PowerShell\' -ErrorAction Stop | Out-String).Replace("Hive: HKEY_LOCAL_MACHINE", "Path: HKLM:")
			}
			catch
			{
				$PowershellGPOs = 'Unable to locate any Group Policies'
			}
			
			###################################################
			# Test .NET Framework version on ALL servers
			# Get version from registry
			Write-Verbose "$(Time-Stamp)Checking .NET Version"
			$RegPath = "HKLM:SOFTWARE\Microsoft\NET Framework Setup\NDP\v4\Full\"
			[int]$ReleaseRegValue = (Get-ItemProperty $RegPath -ErrorAction SilentlyContinue).Release
			# Interpret .NET version
			[string]$dotNetVersionString = switch ($ReleaseRegValue)
			{
				"378389" { ".NET Framework 4.5" }
				"378675" { ".NET Framework 4.5.1" }
				"378758" { ".NET Framework 4.5.1" }
				"379893" { ".NET Framework 4.5.2" }
				"393295" { ".NET Framework 4.6" }
				"393297" { ".NET Framework 4.6" }
				"394254" { ".NET Framework 4.6.1" }
				"394271" { ".NET Framework 4.6.1" }
				"394802" { ".NET Framework 4.6.2" }
				"394806" { ".NET Framework 4.6.2" }
				"460798" { ".NET Framework 4.7" }
				"460805" { ".NET Framework 4.7" }
				"461308" { ".NET Framework 4.7.1" }
				"461310" { ".NET Framework 4.7.1" }
				"461814" { ".NET Framework 4.7.2" }
				"461808" { ".NET Framework 4.7.2" }
				"461814" { ".NET Framework 4.7.2" }
				"528040" { ".NET Framework 4.8" }
				"528372" { ".NET Framework 4.8" }
				"528049" { ".NET Framework 4.8" }
				"528449" { ".NET Framework 4.8" }
				default { "Unknown .NET version: $ReleaseRegValue" }
			}
			Write-Verbose "$(Time-Stamp) - .NET Version detected: $dotNetVersionString"
			Write-Host '-' -NoNewline -ForegroundColor Green
			#endregion AllServersGeneralInfo
			Write-Verbose "$(Time-Stamp)End all servers general info"
			Add-Type -TypeDefinition @"
public class OpsMgrSetupRegKey{
    public string CurrentVersion;
    public string DatabaseName;
    public string DatabaseServerName;
    public string DatabaseVersion;
    public string DataWarehouseDBName;
    public string DataWarehouseDBServerName;
    public string InstallDirectory;
    public string InstalledOn;
    public string ManagementServerPort;
    public string Product;
    public string ServerVersion;
    public string UIVersion;
}
"@
			# this is the path we want to retrieve the values from
			$opsMgrSetupRegKeyPath = 'HKLM:\SOFTWARE\Microsoft\Microsoft Operations Manager\3.0\Setup'
			Write-Verbose "$(Time-Stamp)Start gathering registry information regarding Operations Manager in this path: $opsMgrSetupRegKeyPath"
			# get the values
			try
			{
				$opsMgrSetupRegKey = Get-ItemProperty -Path $opsMgrSetupRegKeyPath -ErrorAction Stop
				
				# construct a new object
				$setuplocation = New-Object OpsMgrSetupRegKey
				
				#set the object values from the registry key
				$setuplocation.CurrentVersion = $opsMgrSetupRegKey.CurrentVersion
				$setuplocation.DatabaseName = $opsMgrSetupRegKey.DatabaseName
				$setuplocation.DatabaseServerName = $opsMgrSetupRegKey.DatabaseServerName
				$setuplocation.DatabaseVersion = $opsMgrSetupRegKey.DatabaseVersion
				$setuplocation.DataWarehouseDBName = $opsMgrSetupRegKey.DataWarehouseDBName
				$setuplocation.DataWarehouseDBServerName = $opsMgrSetupRegKey.DataWarehouseDBServerName
				$setuplocation.InstallDirectory = $opsMgrSetupRegKey.InstallDirectory
				$setuplocation.InstalledOn = $opsMgrSetupRegKey.InstalledOn
				$setuplocation.ManagementServerPort = $opsMgrSetupRegKey.ManagementServerPort
				$setuplocation.Product = $opsMgrSetupRegKey.Product
				$setuplocation.ServerVersion = $opsMgrSetupRegKey.ServerVersion
				$setuplocation.UIVersion = $opsMgrSetupRegKey.UIVersion
				
				$Agent = $false
				$ManagementServer = $false
				$Gateway = $false
			}
			catch
			{
				$setuplocation = $null
				Write-Verbose "$(Time-Stamp)Unable to return the data from registry: $opsMgrSetupRegKeyPath"
			}
			if ($setuplocation)
			{
				if ($setuplocation.Product -eq "Microsoft Monitoring Agent")
				{
					Write-Verbose "$(Time-Stamp)Found Microsoft Monitoring Agent"
					$Agent = $true
					$installdir = (Resolve-Path "$($setuplocation.InstallDirectory)`..\")
				}
				elseif ($setuplocation.Product -like "System Center Operations Manager*Server")
				{
					Write-Verbose "$(Time-Stamp)Found System Center Operations Manager Server"
					$ManagementServer = $true
					$installdir = (Resolve-Path "$($setuplocation.InstallDirectory)`..\")
					$SCOMPath = $installdir.Path.TrimEnd("\")
					if ($LocalManagementServer)
					{
						$global:localLocation = $installdir
					}
					if ($setuplocation.InstallDirectory -like "*Gateway*")
					{
						Write-Verbose "$(Time-Stamp)Found System Center Operations Manager Gateway Server"
						$Gateway = $true
					}
				}
				Write-Verbose "$(Time-Stamp)Grabbing Health Service State Folder Properties"
				$healthServiceState = Get-ItemProperty "$($setuplocation.InstallDirectory)\Health Service State"
				
				function Get-FolderSize
				{
					
					Begin
					{
						
						$fso = New-Object -comobject Scripting.FileSystemObject
					}
					
					Process
					{
						
						$Path = $input.Fullname
						$Folder = $Fso.GetFolder($Path)
						$DateModified = $Folder.DateLastModified
						$DateCreated = $Folder.DateCreated
						$Size = $Folder.Size
						[PSCustomObject]@{ Location = $Path; Size = (Format-FileSize $Size); Modified = $DateModified; Created = $DateCreated }
					}
				}
				
				Function Format-FileSize($size)
				{
					# Param ([int]$size)
					If ($size -gt 1TB) { [string]::Format("{0:0.00} TB", $size / 1TB) }
					ElseIf ($size -gt 1GB) { [string]::Format("{0:0.00} GB", $size / 1GB) }
					ElseIf ($size -gt 1MB) { [string]::Format("{0:0.00} MB", $size / 1MB) }
					ElseIf ($size -gt 1KB) { [string]::Format("{0:0.00} kB", $size / 1KB) }
					ElseIf ($size -gt 0) { [string]::Format("{0:0.00} B", $size) }
					Else { "" }
				}
				$HSStateFolder = $healthServiceState | Get-FolderSize
				
				try
				{
					$configUpdated = @()
					Write-Verbose "$(Time-Stamp)Grabbing Connector Configuration Cache on $env:COMPUTERNAME"
					$mgsFound = Get-ChildItem -Path "$($HSStateFolder.Location)\Connector Configuration Cache" -ErrorAction Stop
					Write-Verbose "$(Time-Stamp)Management Groups Found: $mgsFound"
					foreach ($ManagementGroup in $mgsFound)
					{
						Write-Verbose "$(Time-Stamp)Current Management Group: $ManagementGroup"
						$HSConfigInformation = $null
						$HSConfigInformation = [pscustomobject] @{ }
						$HSConfigInformation | Add-Member -MemberType NoteProperty -Name 'Management Group Name' -Value $ManagementGroup.Name
						try
						{
							Write-Verbose "$(Time-Stamp)Get-ItemProperty `"$($ManagementGroup.PSPath)\OpsMgrConnector.Config.xml`""
							$LastUpdated = ((Get-ItemProperty "$($ManagementGroup.PSPath)\OpsMgrConnector.Config.xml" -ErrorAction Stop).LastWriteTime | Get-Date -Format "MMMM dd, yyyy h:mm tt")
							$HSConfigInformation | Add-Member -MemberType NoteProperty -Name 'Last Time Configuration Updated' -Value $($LastUpdated)
						}
						catch
						{
							Write-Verbose "$(Time-Stamp)Could not detect file: OpsMgrConnector.Config.xml"
							$HSConfigInformation | Add-Member -MemberType NoteProperty -Name 'Last Time Configuration Updated' -Value 'Could not detect file: OpsMgrConnector.Config.xml'
						}
						Write-Verbose "$(Time-Stamp)Adding: $HSConfigInformation"
						$configUpdated += $HSConfigInformation
					}
					Write-Verbose "$(Time-Stamp)Completed: $configUpdated"
				}
				catch
				{
					Write-Verbose "$(Time-Stamp)$($error[0])"
					$configUpdated = $false
				}
			}
			
			#Start SCOM Management Server, Agent, and Gateway Related Gathering.
			if ($ManagementServer)
			{
				#=======================================================================
				# Get Certificate Section
				#=======================================================================
				$CertRegKey = "HKLM:\SOFTWARE\Microsoft\Microsoft Operations Manager\3.0\Machine Settings"
				IF (Test-Path $CertRegKey)
				{
					[array]$CertValue = (Get-ItemProperty $CertRegKey).ChannelCertificateSerialNumber
					IF ($Certvalue)
					{
						$CertLoaded = $True
						[string]$ThumbPrint = (Get-ItemProperty $CertRegKey).ChannelCertificateHash
						$Cert = Get-ChildItem -path cert:\LocalMachine\My | Where-Object { $_.Thumbprint -eq $ThumbPrint }
						IF ($Cert)
						{
							[datetime]$CertExpiresDateTime = $Cert.NotAfter
							[string]$CertExpires = $CertExpiresDateTime.ToShortDateString()
							$CertIssuerArr = $Cert.Issuer
							$CertIssuerSplit = $CertIssuerArr.Split(",")
							[string]$CertIssuer = $CertIssuerSplit[0].TrimStart("CN=")
						}
						ELSE
						{
							$CertIssuer = "NotFound"
							$CertExpires = "NotFound"
						}
						
					}
					ELSE
					{
						$CertLoaded = $False
					}
				}
				ELSE
				{
					$CertLoaded = $False
				}
				try
				{
					$LinuxAuthType = Get-ItemProperty -Path 'HKLM:\SOFTWARE\Microsoft\Microsoft Operations Manager\3.0\Setup\Linux Auth' -ErrorAction SilentlyContinue | Select-Object Authentication -ExpandProperty Authentication
				}
				catch
				{
					$LinuxAuthType = $null
				}
				$ServerVersionSwitch = (Get-ProductVersion -Product SCOM -BuildVersion $setuplocation.ServerVersion)
				$LocalServerVersionSwitchOut = $ServerVersionSwitch + " (" + $setuplocation.ServerVersion + ")"
				Write-Verbose "$(Time-Stamp)Gathering Server Version - Registry - via Product Version Function: $LocalServerVersionSwitchOut"
				
				$serverdll = Get-Item "$($setuplocation.InstallDirectory)`MOMAgentManagement.dll" | foreach-object { "{0}" -f [System.Diagnostics.FileVersionInfo]::GetVersionInfo($_).FileVersion }
				$ServerVersionDLLSwitch = (Get-ProductVersion -Product SCOM -BuildVersion $serverdll)
				$ServerVersionDLL = $ServerVersionDLLSwitch + " (" + $serverdll + ")"
				Write-Verbose "$(Time-Stamp)Gathering Server Version - DLL - via Product Version Function: $ServerVersionDLL"
				
				$OctoberPatchserverDLL = Get-Item "$($setuplocation.InstallDirectory)`MOMModules2.dll" | foreach-object { "{0}" -f [System.Diagnostics.FileVersionInfo]::GetVersionInfo($_).FileVersion }
				$OctoberPatchserverDLLSwitch = (Get-ProductVersion -Product SCOM -BuildVersion $OctoberPatchserverDLL)
				$OctoberPatchserver = $OctoberPatchserverDLLSwitch + " (" + $OctoberPatchserverDLL + ")"
				Write-Verbose "$(Time-Stamp)Gathering Server Version (SCOM 2019 October 2021 Patch) - DLL - via Product Version Function: $ServerVersionDLL"
				
				try
				{
					$ServerAgentOMVersionDLL = Get-Item "$($setuplocation.InstallDirectory)`\AgentManagement\amd64\OMVersion.dll" -ErrorAction Stop | foreach-object { "{0}" -f [System.Diagnostics.FileVersionInfo]::GetVersionInfo($_).FileVersion }
					if ($ServerAgentOMVersionDLL)
					{
						$ServerAgentVersionDLLSwitch = (Get-ProductVersion -Product SCOM -BuildVersion $ServerAgentOMVersionDLL)
						$ServerAgentVersionDLL = $ServerAgentVersionDLLSwitch + " (" + $ServerAgentOMVersionDLL + ")"
						Write-Verbose "$(Time-Stamp)Server Agent Management DLL Version - $ServerAgentVersionDLL"
						$ServerAgentVersion_info = $true
					}
					$ServerAgentUnixVersionDLL = Get-ItemProperty "$($setuplocation.InstallDirectory)`\AgentManagement\UnixAgents\DownloadedKits\*" -ErrorAction Stop | Format-Table Name -AutoSize | Out-String -Width 4096
				}
				catch
				{
					$ServerAgentVersion_info = $false
				}
				try
				{
					$UIExe = Get-Item "$($setuplocation.InstallDirectory)`..\Console\Microsoft.EnterpriseManagement.Monitoring.Console.exe" -ErrorAction Stop | foreach-object { "{0}" -f [System.Diagnostics.FileVersionInfo]::GetVersionInfo($_).FileVersion }
					if (($setuplocation.UIVersion) -and ($UIExe))
					{
						$UIVersionSwitch = (Get-ProductVersion -Product SCOM -BuildVersion $setuplocation.UIVersion)
						$UIVersionFinal = $UIVersionSwitch + " (" + $setuplocation.UIVersion + ")"
						
						$UIVersionExeSwitch = (Get-ProductVersion -Product SCOM -BuildVersion $UIExe)
						$UIVersionExe = $UIVersionExeSwitch + " (" + $UIExe + ")"
						$UI_info = $true
					}
					
				}
				catch
				{
					$UI_info = $false
				}
				try
				{
					$WebConsoleDLL = Get-Item "$($setuplocation.InstallDirectory)`..\WebConsole\MonitoringView\OMVersion.dll" -ErrorAction Stop | foreach-object { "{0}" -f [System.Diagnostics.FileVersionInfo]::GetVersionInfo($_).FileVersion }
					$WebConsoleDLLSwitch = (Get-ProductVersion -Product SCOM -BuildVersion $WebConsoleDLL)
					$WebConsoleVersionDLL = $WebConsoleDLLSwitch + " (" + $WebConsoleDLL + ")"
					
					$WebConsole_info = $true
					try
					{
						if (Test-Path -Path "$($setuplocation.InstallDirectory)`..\WebConsole\AppDiagnostics\AppAdvisor\Web\Bin\ARViewer.dll")
						{
							$WebConsolePatchPath = "..\WebConsole\AppDiagnostics\AppAdvisor\Web\Bin\ARViewer.dll"
							$WebConsolePatchDLL = Get-Item "$($setuplocation.InstallDirectory)`..\WebConsole\AppDiagnostics\AppAdvisor\Web\Bin\ARViewer.dll" -ErrorAction Stop | foreach-object { "{0}" -f [System.Diagnostics.FileVersionInfo]::GetVersionInfo($_).FileVersion }
						}
						else
						{
							$WebConsolePatchPath = "..\WebConsole\AppDiagnostics\Web\bin\SEMWebViewer.dll"
							$WebConsolePatchDLL = Get-Item "$($setuplocation.InstallDirectory)`..\WebConsole\AppDiagnostics\Web\bin\SEMWebViewer.dll" -ErrorAction Stop | foreach-object { "{0}" -f [System.Diagnostics.FileVersionInfo]::GetVersionInfo($_).FileVersion }
						}
						$WebConsolePatchSwitch = (Get-ProductVersion -Product SCOM -BuildVersion $WebConsolePatchDLL)
						$WebConsolePatchVersionDLL = $WebConsolePatchSwitch + " (" + $WebConsolePatchDLL + ")"
					}
					catch
					{
						return
					}
				}
				catch { $WebConsole_info = $false }
				$CurrentVersionSwitch = (Get-ProductVersion -Product SCOM -BuildVersion $setuplocation.CurrentVersion)
				if ($LocalManagementServer)
				{
					try
					{
						$SQLPatchVersionOpsDB = (Import-Csv "$OutputPath`\MG_SQLPatchVersion_OpsDB.csv" -ErrorAction Stop) | Where { $_.State -eq 'COMPLETED' } | Sort-Object @{ Expression = { [version]$_.Value } } -Descending | Select-Object -First 1
						if ($SQLPatchVersionOpsDB)
						{
							$SQLPatchVersionOpsDBSwitch = (Get-ProductVersion -Product SCOM -BuildVersion $SQLPatchVersionOpsDB.Value)
							$SQLPatchVersionOpsDBInfo = $SQLPatchVersionOpsDBSwitch + " (" + $SQLPatchVersionOpsDB.Value + ")"
						}
					}
					catch
					{
						#potential error code
						#use continue or break keywords
						#$e = $_.Exception
						$line = $_.InvocationInfo.ScriptLineNumber
						$msg = $e.Message
						
						Write-Verbose "$(Time-Stamp)Caught Exception: $($error[0]) at line: $line"
						"$(Time-Stamp)Caught Exception: $($error[0]) at line: $line" | Out-File $OutputPath\Error.log -Append
					}
					try
					{
						$SQLPatchVersionDW = (Import-Csv "$OutputPath`\MG_SQLPatchVersion_DW.csv" -ErrorAction SilentlyContinue) | Where{ $_.State -eq 'COMPLETED' } | Sort-Object @{ Expression = { [version]$_.Value } } -Descending | Select-Object -First 1
						if ($SQLPatchVersionDW)
						{
							$SQLPatchVersionDWSwitch = (Get-ProductVersion -Product SCOM -BuildVersion $SQLPatchVersionDW.Value)
							$SQLPatchVersionDWInfo = $SQLPatchVersionDWSwitch + " (" + $SQLPatchVersionDW.Value + ")"
						}
					}
					catch
					{
						#potential error code
						#use continue or break keywords
						#$e = $_.Exception
						$line = $_.InvocationInfo.ScriptLineNumber
						$msg = $e.Message
						
						Write-Verbose "$(Time-Stamp)Caught Exception: $($error[0]) at line: $line"
						"$(Time-Stamp)Caught Exception: $($error[0]) at line: $line" | Out-File $OutputPath\Error.log -Append
					}
				}
				
				$CurrentVersionFinal = $CurrentVersionSwitch + " (" + $setuplocation.CurrentVersion + ")"
				
				
				$ReportingRegistryKey = get-itemproperty -path "HKLM:\SOFTWARE\Microsoft\System Center Operations Manager\12\Setup\Reporting" -ErrorAction SilentlyContinue | Select-Object * -exclude PSPath, PSParentPath, PSChildName, PSProvider, PSDrive
				
				try
				{
					Write-Verbose "$(Time-Stamp)Running - Get-SCOMRMSEmulator"
					$rmsEmulator = Get-SCOMRMSEmulator -ErrorAction Stop | Select-Object -Property DisplayName -ExpandProperty DisplayName
				}
				catch
				{
					$rmsEmulator = "Unable to run Get-SCOMRMSEmulator."
				}
				
				Write-Host "-" -NoNewline -ForegroundColor Green
				try
				{
					Write-Verbose "$(Time-Stamp)Running - Get-SCOMManagementGroup"
					$ManagementGroup = Get-SCOMManagementGroup -ErrorAction Stop | Select-Object -Property Name -ExpandProperty Name
				}
				catch
				{
					$ManagementGroup = "Unable to run Get-SCOMManagementGroup."
				}
				$LastUpdatedConfiguration = (Get-WinEvent -LogName 'Operations Manager' -ErrorAction SilentlyContinue | Where{ $_.Id -eq 1210 } | Select-Object -First 1).TimeCreated
				if (!$LastUpdatedConfiguration) { $LastUpdatedConfiguration = "No Event ID 1210 Found in Operations Manager Event Log" }
				else { $LastUpdatedConfiguration = $LastUpdatedConfiguration | Get-Date -Format "MMMM dd, yyyy h:mm tt" }
				
				[double]$WorkflowCount = $null
				[double]$WorkflowCount = (((Get-Counter -Counter '\Health Service\Workflow Count' -ErrorAction SilentlyContinue -SampleInterval 5 -MaxSamples 5).CounterSamples).CookedValue | Measure-Object -Average).Average
				Write-Verbose "$(Time-Stamp)Workflow count - $WorkflowCount"
				#=======================================================================
				
				$ACSReg = "HKLM:\SYSTEM\CurrentControlSet\Services\AdtServer"
				IF (Test-Path $ACSReg)
				{
					#This is an ACS Collector server
					$ACS = $true
					
				}
				ELSE
				{
					#This is NOT an ACS Collector server
					$ACS = $false
					
				}
				
			}
			elseif ($Agent)
			{
				Write-Verbose "$(Time-Stamp)Agent Detected"
				#$ManagementGroups = Get-Item "HKLM:\SOFTWARE\Microsoft\Microsoft Operations Manager\3.0\Agent Management Groups\*" | Select-Object PSChildName -ExpandProperty PSChildName
				$ADIntegration = (Get-ItemProperty HKLM:\SYSTEM\CurrentControlSet\Services\HealthService\Parameters\ConnectorManager).EnableADIntegration
				
				$ADIntegrationSwitch = switch ($ADIntegration)
				{
					'0' { "Disabled" }
					'1' { "Enabled" }
				}
				
				$LastUpdatedConfiguration = (Get-WinEvent -LogName 'Operations Manager' | Where{ $_.Id -eq 1210 } | Select-Object -First 1).TimeCreated
				if (!$LastUpdatedConfiguration) { $LastUpdatedConfiguration = "No Event ID 1210 Found in Operations Manager Event Log" }
				else { $LastUpdatedConfiguration = $LastUpdatedConfiguration | Get-Date -Format "MMMM dd, yyyy h:mm tt" }
				
				[string]$SCOMAgentURVersion = (Get-ProductVersion -Product SCOM -BuildVersion $setuplocation.CurrentVersion)
				Write-Verbose "$(Time-Stamp)Load Agent Scripting Module"
				# Load Agent Scripting Module
				#=======================================================================
				$AgentCfg = New-Object -ComObject "AgentConfigManager.MgmtSvcCfg"
				#=======================================================================
				
				# Get Agent Management groups section
				#=======================================================================
				#Get management groups
				Write-Verbose "$(Time-Stamp)Gathering Management Groups"
				$MGs = $AgentCfg.GetManagementGroups()
				$MGDetails = @()
				foreach ($MG in $MGs)
				{
					Write-Verbose "$(Time-Stamp)Found Management Group - $MG"
					$MGDetails += $MG | Select *
					<#
				    $managementGroup.ManagementGroupName
				    $managementGroup.ManagementServer
				    $managementGroup.ManagementServerPort
				    $managementGroup.IsManagementGroupFromActiveDirectory
				    $managementGroup.ActionAccount
				    #>
				}
				# Get Agent OMS Workspaces section
				#=======================================================================
				# This section depends on AgentConfigManager.MgmtSvcCfg object in previous section
				[string]$OMSList = ''
				# Agent might not support OMS
				$AgentSupportsOMS = $AgentCfg | Get-Member -Name 'GetCloudWorkspaces'
				IF (!$AgentSupportsOMS)
				{
					Write-Verbose "$(Time-Stamp)This agent version does not support Cloud Workspaces"
					#This agent version does not support Cloud Workspaces.
				}
				ELSE
				{
					$OMSWorkSpaces = $AgentCfg.GetCloudWorkspaces()
					FOREACH ($OMSWorkSpace in $OMSWorkSpaces)
					{
						$OMSList = $OMSList + $OMSWorkspace.workspaceId + ", "
					}
					IF ($OMSList)
					{
						$OMSList = $OMSList.TrimEnd(", ")
					}
					Write-Verbose "$(Time-Stamp)OMS List - $OMSList"
					#Get ProxyURL
					[string]$ProxyURL = $AgentCfg.proxyUrl
				}
				
				#=======================================================================
				# Get Certificate Section
				#=======================================================================
				$CertRegKey = "HKLM:\SOFTWARE\Microsoft\Microsoft Operations Manager\3.0\Machine Settings"
				IF (Test-Path $CertRegKey)
				{
					[array]$CertValue = (Get-ItemProperty $CertRegKey).ChannelCertificateSerialNumber
					IF ($Certvalue)
					{
						Write-Verbose "$(Time-Stamp)Found Certificate Registry Key"
						$CertLoaded = $True
						[string]$ThumbPrint = (Get-ItemProperty $CertRegKey).ChannelCertificateHash
						$Cert = Get-ChildItem -path cert:\LocalMachine\My | Where-Object { $_.Thumbprint -eq $ThumbPrint }
						IF ($Cert)
						{
							[datetime]$CertExpiresDateTime = $Cert.NotAfter
							[string]$CertExpires = $CertExpiresDateTime.ToShortDateString()
							$CertIssuerArr = $Cert.Issuer
							$CertIssuerSplit = $CertIssuerArr.Split(",")
							[string]$CertIssuer = $CertIssuerSplit[0].TrimStart("CN=")
						}
						ELSE
						{
							$CertIssuer = "NotFound"
							$CertExpires = "NotFound"
						}
						
					}
					ELSE
					{
						Write-Verbose "$(Time-Stamp)MOMCertImport needs to be run"
						$CertLoaded = $False
					}
				}
				ELSE
				{
					Write-Verbose "$(Time-Stamp)Certificate key not present"
					$CertLoaded = $False
				}
				# Build IP List from Windows Computer Property
				#=======================================================================
				#We want to remove Link local IP
				$ip = ([System.Net.Dns]::GetHostAddresses($Env:COMPUTERNAME)).IPAddressToString;
				[string]$IPList = ""
				$IPSplit = $IP.Split(",")
				FOREACH ($IPAddr in $IPSplit)
				{
					[string]$IPAddr = $IPAddr.Trim()
					IF (!($IPAddr.StartsWith("fe80") -or $IPAddr.StartsWith("169.254")))
					{
						$IPList = $IPList + $IPAddr + ","
					}
				}
				$IPList = $IPList.TrimEnd(",")
				$SCOMAgentVersion = $SCOMAgentURVersion + " (" + $setuplocation.CurrentVersion + ")"
				
				$AgentURDLL = Get-Item "$($setuplocation.InstallDirectory)`..\Agent\Tools\TMF\OMAgentTraceTMFVer.Dll" -ErrorAction SilentlyContinue | foreach-object { "{0}" -f [System.Diagnostics.FileVersionInfo]::GetVersionInfo($_).FileVersion }
				[string]$SCOMAgentURVersionDLL = (Get-ProductVersion -Product SCOM -BuildVersion $AgentURDLL)
				$SCOMAgentVersionDLL = $SCOMAgentURVersionDLL + " (" + $AgentURDLL + ")"
			}
			elseif ($Gateway)
			{
				$GatewayDLL = Get-Item "$($setuplocation.InstallDirectory)`..\Gateway\MOMAgentManagement.dll" | foreach-object { "{0}" -f [System.Diagnostics.FileVersionInfo]::GetVersionInfo($_).FileVersion }
			}
			
			#Author: Blake Drumm (blakedrumm@microsoft.com)
			#Date Created: August 10th, 2022
			
			# This returns information almost identical to the Task Manager
			
			function Resource-Info
			{
				$CPUInfo = (Get-CIMInstance -ErrorAction Stop -Class 'CIM_Processor')
				$ComputerSystem = (Get-CIMInstance -ErrorAction Stop 'CIM_ComputerSystem')
				"Computer Manufacturer: $($ComputerSystem.Manufacturer)"
				"  Computer Model     : $($ComputerSystem.Model)"
				"  System Type        : $($ComputerSystem.SystemType)"
				
				" "
				
				"CPU Name: $($CPUInfo.Name)"
				"  CPU Load                    : $(($CPUInfo | Measure-Object -Property LoadPercentage -Average).Average)%"
				"  CPU Sockets                 : $(($CPUInfo.SocketDesignation).Count)"
				"  Number of Cores             : $($CPUInfo.NumberOfCores)"
				"  Number of Logical Processors: $($CPUInfo.NumberOfLogicalProcessors)"
				"  Virtualization              : $(
					$HypervisorPresent = switch (($ComputerSystem).HypervisorPresent)
					{
						True{ 'Enabled' }; False{ 'Disabled' }
					}
					if ($HypervisorPresent -eq 'Disabled')
					{
						if ($CPUInfo.VirtualizationFirmwareEnabled)
						{
							switch ($CPUInfo.VirtualizationFirmwareEnabled)
							{
								True{ 'Enabled' }; False{ 'Disabled' }
							}
						}
						else
						{
							$HypervisorPresent
						}
					}
					else
					{
						$HypervisorPresent
					}
				)"
				
				" "
				
				$MemoryInfo = (Get-CIMInstance -ErrorAction Stop -Class 'CIM_PhysicalMemory')
				"Total Memory: $(($MemoryInfo | Measure-Object -Property capacity -Sum).sum / 1gb) GB"
				$MemorySlotInfo = (Get-CIMInstance -ErrorAction Stop -Class 'Win32_PhysicalMemoryArray')
				"  Memory Slots      : $($MemoryInfo.Count) of $($MemorySlotInfo.MemoryDevices) used"
				$OSInfo = Get-CIMInstance -ErrorAction Stop -Class CIM_OperatingSystem
				"  Memory Utilization: $([math]::Round(($OSInfo.TotalVisibleMemorySize - $OSInfo.FreePhysicalMemory) / 1mb, 1)) GB / $([math]::Round($OSInfo.TotalVisibleMemorySize / 1mb, 1)) GB ($([math]::Round(((($OSInfo.TotalVisibleMemorySize - $OSInfo.FreePhysicalMemory) * 100)/ $OSInfo.TotalVisibleMemorySize), 0))%)"
				" "
				"  Memory Sockets:"
				$i = 0
				foreach ($memory in $MemoryInfo)
				{
					$i++
					$i = $i
					"      $i)     Name: $($memory.Name)"
					"             Type: $(
						switch ($memory.MemoryType)
						{
							0{ 'Unknown' }
							1{ 'Other' }
							2{ 'DRAM' }
							3{ 'Synchronous DRAM' }
							4{ 'Cache DRAM' }
							5{ 'EDO' }
							6{ 'EDRAM' }
							7{ 'VRAM' }
							8{ 'SRAM' }
							9{ 'RAM' }
							10{ 'ROM' }
							11{ 'Flash' }
							12{ 'EEPROM' }
							13{ 'FEPROM' }
							14{ 'EPROM' }
							15{ 'CDRAM' }
							16{ '3DRAM' }
							17{ 'SDRAM' }
							18{ 'SGRAM' }
							19{ 'RDRAM' }
							20{ 'DDR' }
							21{ 'DDR2' }
							22{ 'DDR2 FB-DIMM' }
							24{ 'DDR3' }
							25{ 'FBD2' }
							26{ 'DDR4' }
							default { 'Unknown' }
						})"
					"      Memory Size: $($memory.Capacity / 1gb) GB"
					"      Form Factor: $(
						switch ($memory.FormFactor)
						{
							0{ 'Unknown' }
							1{ 'Other' }
							2{ 'SIP' }
							3{ 'DIP' }
							4{ 'ZIP' }
							5{ 'SOJ' }
							6{ 'Proprietary' }
							7{ 'SIMM' }
							8{ 'DIMM' }
							9{ 'TSOP' }
							10{ 'PGA' }
							11{ 'RIMM' }
							12{ 'SODIMM' }
							13{ 'SRIMM' }
							14{ 'SMD' }
							15{ 'SSMP' }
							16{ 'QFP' }
							17{ 'TQFP' }
							18{ 'SOIC' }
							19{ 'LCC' }
							20{ 'PLCC' }
							21{ 'BGA' }
							22{ 'FPBGA' }
							23{ 'LGA' }
							24{ 'FB-DIMM' }
							default { 'Unknown' }
						})"
					"     Memory Speed: $($memory.ConfiguredClockSpeed) MHz"
					" "
					return
				}
			}
			$ResourceAllocation = try { Resource-Info | Out-String -Width 4096 }catch{ 'Unable to gather OS Resource Information.' }
			
			$setupOutput = [pscustomobject]@{ }
			$setupOutput | Add-Member -MemberType NoteProperty -Name 'Computer Name' -Value $env:COMPUTERNAME
			if ($Uptime)
			{
				$setupOutput | Add-Member -MemberType NoteProperty -Name 'System Uptime' -Value $Uptime
			}
			if ($WorkflowCount)
			{
				$setupOutput | Add-Member -MemberType NoteProperty -Name 'Workflow Count' -Value $WorkflowCount
			}
			
			$setupOutput | Add-Member -MemberType NoteProperty -Name 'IP Address' -Value $IPList
			$setupOutput | Add-Member -MemberType NoteProperty -Name 'OS Version' -Value $OSVersion
			$setupOutput | Add-Member -MemberType NoteProperty -Name 'WinHTTP Proxy' -Value $WinHTTPProxy
			$setupOutput | Add-Member -MemberType NoteProperty -Name 'Resource Information' -Value $ResourceAllocation
			if ($setuplocation)
			{
				if ($setuplocation.ManagementServerPort)
				{
					$setupOutput | Add-Member -MemberType NoteProperty -Name 'Management Server Port' -Value $setuplocation.ManagementServerPort
				}
				$setupOutput | Add-Member -MemberType NoteProperty -Name 'Product' -Value $setuplocation.Product
				$setupOutput | Add-Member -MemberType NoteProperty -Name 'Installed On' -Value $setuplocation.InstalledOn
			}
			if ($ACS)
			{
				$setupOutput | Add-Member -MemberType NoteProperty -Name 'ACS Collector' -Value 'True'
			}
			else
			{
				$setupOutput | Add-Member -MemberType NoteProperty -Name 'ACS Collector' -Value 'False'
			}
			if ($SCOMAgentVersion)
			{
				$setupOutput | Add-Member -MemberType NoteProperty -Name 'Current Agent Version (Registry: HKLM:\SOFTWARE\Microsoft\Microsoft Operations Manager\3.0\Setup)' -Value $SCOMAgentVersion
				$setupOutput | Add-Member -MemberType NoteProperty -Name 'Current Agent Version (DLL: ..\Agent\Tools\TMF\OMAgentTraceTMFVer.Dll)' -Value $SCOMAgentVersionDLL
			}
			if ($CurrentVersionFinal)
			{
				$setupOutput | Add-Member -MemberType NoteProperty -Name 'Current Version (Registry: HKLM:\SOFTWARE\Microsoft\Microsoft Operations Manager\3.0\Setup)' -Value $CurrentVersionFinal
			}
			if ($LocalServerVersionSwitchOut)
			{
				$setupOutput | Add-Member -MemberType NoteProperty -Name 'Server Version (Registry: HKLM:\SOFTWARE\Microsoft\Microsoft Operations Manager\3.0\Setup)' -Value $LocalServerVersionSwitchOut
				$setupOutput | Add-Member -MemberType NoteProperty -Name '               (DLL: ..\Server\MOMAgentManagement.dll)' -Value $ServerVersionDLL
			}
			if ('10.19.10552.0' -eq $OctoberPatchserverDLL)
			{
				$setupOutput | Add-Member -MemberType NoteProperty -Name 'Server Version [Patch] (DLL: ..\Server\MOMModules2.dll)' -Value $OctoberPatchserver
			}
			if ($ServerAgentVersion_info)
			{
				$setupOutput | Add-Member -MemberType NoteProperty -Name 'Agent Management Windows Version (DLL: ..\Server\AgentManagement\amd64\OMVersion.dll)' -Value $ServerAgentVersionDLL
				$setupOutput | Add-Member -MemberType NoteProperty -Name 'Agent Management Unix/Linux Versions (Files: ..\Server\AgentManagement\UnixAgents\DownloadedKits\*)' -Value $ServerAgentUnixVersionDLL
			}
			
			if ($UI_info)
			{
				$setupOutput | Add-Member -MemberType NoteProperty -Name 'UI Version (Registry: HKLM:\SOFTWARE\Microsoft\Microsoft Operations Manager\3.0\Setup)' -Value $UIVersionFinal
				$setupOutput | Add-Member -MemberType NoteProperty -Name '           (EXE: ..\Console\Microsoft.EnterpriseManagement.Monitoring.Console.exe)' -Value $UIVersionExe
			}
			if ($WebConsole_info)
			{
				$setupOutput | Add-Member -MemberType NoteProperty -Name "Web Console Version (DLL: $WebConsolePatchPath)" -Value $WebConsoleVersionDLL
				if ('10.19.10550.0' -eq $WebConsolePatchDLL)
				{
					$setupOutput | Add-Member -MemberType NoteProperty -Name "Web Console Version [Patch] (DLL: $WebConsolePatchPath)" -Value $WebConsolePatchVersionDLL
				}
			}
			if ($LocalManagementServer)
			{
				$setupOutput | Add-Member -MemberType NoteProperty -Name 'Operations Manager DB Version (Query)' -Value $SQLPatchVersionOpsDBInfo
				$setupOutput | Add-Member -MemberType NoteProperty -Name 'Data Warehouse DB Version (Query)' -Value $SQLPatchVersionDWInfo
			}
			if ($ManagementServer)
			{
				if ($LinuxAuthType)
				{
					$setupOutput | Add-Member -MemberType NoteProperty -Name 'Linux Authentication Type (Registry: HKLM:\SOFTWARE\Microsoft\Microsoft Operations Manager\3.0\Setup\Linux Auth)' -Value $LinuxAuthType
				}
				else
				{
					$setupOutput | Add-Member -MemberType NoteProperty -Name 'Linux Authentication Type (Registry: HKLM:\SOFTWARE\Microsoft\Microsoft Operations Manager\3.0\Setup\Linux Auth)' -Value 'Missing Registry Key, assuming: Basic'
				}
			}
			if ($ADIntegrationSwitch)
			{
				$setupOutput | Add-Member -MemberType NoteProperty -Name 'AD Integration' -Value $ADIntegrationSwitch
			}
			
			if ($setuplocation)
			{
				$setupOutput | Add-Member -MemberType NoteProperty -Name 'Installation Directory' -Value $setuplocation.InstallDirectory
			}
			if ($MGDetails)
			{
				$setupOutput | Add-Member -MemberType NoteProperty -Name '(Agent) Management Group Details' -Value ($MGDetails | Format-List * | Out-String -Width 4096)
			}
			elseif ($MGlist)
			{
				$setupOutput | Add-Member -MemberType NoteProperty -Name '(Agent) Management Group Name' -Value $MGlist
			}
			elseif ($ManagementGroup)
			{
				$setupOutput | Add-Member -MemberType NoteProperty -Name '(Management Server) Management Group Name' -Value $ManagementGroup
			}
			if ($ManagementServers)
			{
				$setupOutput | Add-Member -MemberType NoteProperty -Name 'Management Servers in Management Group' -Value (($ManagementServers | Sort-Object) -join ", ")
			}
			if ($OMSList)
			{
				$setupOutput | Add-Member -MemberType NoteProperty -Name 'Agent OMS Workspaces' -Value $OMSList
			}
			if ($ProxyURL)
			{
				$setupOutput | Add-Member -MemberType NoteProperty -Name 'Proxy URL' -Value $ProxyURL
			}
			
			if ($rmsEmulator)
			{
				$setupOutput | Add-Member -MemberType NoteProperty -Name 'Remote Management Server Emulator (Primary Server)' -Value "$rmsEmulator"
			}
			if ($Freespace)
			{
				$setupOutput | Add-Member -MemberType NoteProperty -Name 'Free Space' -Value $($Freespace | Format-Table * -AutoSize | Out-String)
			}
			
			if ($driveData)
			{
				$setupOutput | Add-Member -MemberType NoteProperty -Name 'Disk Allocation Unit Size' -Value $($driveData | Format-Table * -AutoSize | Out-String -Width 4096)
			}
			if ($CertLoaded)
			{
				$setupOutput | Add-Member -MemberType NoteProperty -Name 'Certificate Loaded' -Value $CertLoaded
			}
			else
			{
				$setupOutput | Add-Member -MemberType NoteProperty -Name 'Certificate Loaded' -Value 'Unable to detect any certificate in registry.'
			}
			if ($winrmConfig)
			{
				$setupOutput | Add-Member -MemberType NoteProperty -Name 'WinRM Configuration' -Value "$($winrmConfig | Out-String -Width 4096)"
			}
			else
			{
				$setupOutput | Add-Member -MemberType NoteProperty -Name 'WinRM Configuration' -Value "Unable to gather Configuration."
			}
			$setupOutput | Add-Member -MemberType NoteProperty -Name 'TLS 1.2 Enforced' -Value $TLS12Enforced
			$setupOutput | Add-Member -MemberType NoteProperty -Name 'Powershell Version' -Value $PSVersion
			$setupOutput | Add-Member -MemberType NoteProperty -Name 'CLR Version' -Value $CLRVersion
			if ($dotNetVersionString)
			{
				$setupOutput | Add-Member -MemberType NoteProperty -Name '.NET Version' -Value $dotNetVersionString
			}
			if ($PowershellGPOs)
			{
				$setupOutput | Add-Member -MemberType NoteProperty -Name 'Powershell Group Policy' -Value $PowershellGPOs
			}
			if ($setuplocation)
			{
				$setupOutput | Add-Member -MemberType NoteProperty -Name 'Health Service State Directory' -Value $($HSStateFolder | Format-Table * -AutoSize | Out-String -Width 4096)
			}
			if ($configUpdated)
			{
				$setupOutput | Add-Member -MemberType NoteProperty -Name 'Last Time Configuration Updated (File: ..\OpsMgrConnector.Config.xml)' -Value $($configUpdated | Format-Table -AutoSize | Out-String -Width 4096)
			}
			if ($LastUpdatedConfiguration)
			{
				$setupOutput | Add-Member -MemberType NoteProperty -Name 'Last Time Configuration Updated (1210 EventID)' -Value $LastUpdatedConfiguration
			}
			else
			{
				$setupOutput | Add-Member -MemberType NoteProperty -Name 'Last Time Configuration Updated (1210 EventID)' -Value 'Unable to locate 1210 EventID.'
			}
			$setupOutput | Add-Member -MemberType NoteProperty -Name 'Current System Time' -Value (Get-Date -Format "MMMM dd, yyyy h:mm tt")
			
			if ('7.2.11719.0' -ge $setuplocation.ServerVersion) # SCOM 2016 RTM
			{
				try { $UseMIAPI = (Get-Item 'HKLM:\SOFTWARE\Microsoft\Microsoft Operations Manager\3.0\Setup\UseMIAPI' -ErrorAction Stop | Select-Object Name, Property).Property | Out-String } # https://docs.microsoft.com/en-us/system-center/scom/whats-new-in-om?view=sc-om-2019#scalability-improvement-with-unix-or-linux-agent-monitoring
				catch [System.Management.Automation.RuntimeException]{ $UseMIAPI = 'Not Set (or Unknown)' }
				$setupOutput | Add-Member -MemberType NoteProperty -Name 'UseMIAPI Registry' -Value $UseMIAPI
			}
			try
			{
				$ReportingRegistryKey = get-itemproperty -path "HKLM:\SOFTWARE\Microsoft\System Center Operations Manager\12\Setup\Reporting" -ErrorAction SilentlyContinue | Select-Object * -exclude PSPath, PSParentPath, PSChildName, PSProvider, PSDrive
				if ($ReportingRegistryKey)
				{
					Write-Verbose "$(Time-Stamp)  Found SSRS Registry Key: $ReportingRegistryKey"
						<#
$setupOutputRemote += @"

================================ `
=---- Reporting Server ----= `
================================
"@
#>
					$ReportingInstallPath = $ReportingRegistryKey.InstallDirectory
					$ReportingDLL = Get-Item "$ReportingInstallPath`\Tools\TMF\OMTraceTMFVer.Dll" -ErrorAction Stop | foreach-object { "{0}" -f [System.Diagnostics.FileVersionInfo]::GetVersionInfo($_).FileVersion }
					$ReportingProductVersionSwitch = (Get-ProductVersion -Product SCOM -BuildVersion $ReportingDLL)
					$ReportingInfo = $ReportingProductVersionSwitch + " (" + $ReportingDLL + ")"
					$setupOutput | Add-Member -MemberType NoteProperty -Name 'Reporting Services Version (DLL: ..\Reporting\Tools\TMF\OMTraceTMFVer.dll)' -Value $ReportingInfo
					try
					{
						
						$RS = "root\Microsoft\SqlServer\ReportServer\" + (Get-CimInstance -Namespace root\Microsoft\SqlServer\ReportServer -Class __Namespace -Recurse -ErrorAction Stop | Select -First 1).Name
						$RSV = $RS + "\" + (Get-CimInstance -Namespace $RS -Class __Namespace -Recurse -ErrorAction Stop | Select -First 1).Name + "\Admin"
						$RSInfo = Get-CimInstance -Namespace $RSV -Class MSReportServer_ConfigurationSetting -ErrorAction Stop
						
						try
						{
							$RSInfoSwitch = (Get-ProductVersion -Product SSRS -BuildVersion $RSInfo.Version)
							$RSInfoSwitchInfo = $RSInfoSwitch + " (" + $RSInfo.Version + ")"
						}
						catch
						{
							$RSInfoSwitchInfo = "Unable to detect / return Product version for SSRS"
							Write-Verbose "$(Time-Stamp)Unable to detect / return Product version for SSRS: $($error[0])"
						}
						
						$SSRS_Info = [pscustomobject]@{ }
						$SSRS_Info | Add-Member -MemberType NoteProperty -Name 'ConnectionPoolSize' -Value $RSInfo.ConnectionPoolSize -ErrorAction SilentlyContinue
						$SSRS_Info | Add-Member -MemberType NoteProperty -Name 'DatabaseLogonAccount' -Value $RSInfo.DatabaseLogonAccount -ErrorAction SilentlyContinue
						$SSRS_Info | Add-Member -MemberType NoteProperty -Name 'DatabaseLogonTimeout' -Value $RSInfo.DatabaseLogonTimeout -ErrorAction SilentlyContinue
						$SSRS_Info | Add-Member -MemberType NoteProperty -Name 'DatabaseLogonType' -Value $RSInfo.DatabaseLogonType -ErrorAction SilentlyContinue
						$SSRS_Info | Add-Member -MemberType NoteProperty -Name 'DatabaseName' -Value $RSInfo.DatabaseName -ErrorAction SilentlyContinue
						$SSRS_Info | Add-Member -MemberType NoteProperty -Name 'DatabaseQueryTimeout' -Value $RSInfo.DatabaseQueryTimeout -ErrorAction SilentlyContinue
						$SSRS_Info | Add-Member -MemberType NoteProperty -Name 'ExtendedProtectionLevel' -Value $RSInfo.ExtendedProtectionLevel -ErrorAction SilentlyContinue
						$SSRS_Info | Add-Member -MemberType NoteProperty -Name 'ExtendedProtectionScenario' -Value $RSInfo.ExtendedProtectionScenario -ErrorAction SilentlyContinue
						$SSRS_Info | Add-Member -MemberType NoteProperty -Name 'FileShareAccount' -Value $RSInfo.FileShareAccount -ErrorAction SilentlyContinue
						$SSRS_Info | Add-Member -MemberType NoteProperty -Name 'InstanceName' -Value $RSInfo.InstanceName -ErrorAction SilentlyContinue
						$SSRS_Info | Add-Member -MemberType NoteProperty -Name 'IsInitialized' -Value $RSInfo.IsInitialized -ErrorAction SilentlyContinue
						$SSRS_Info | Add-Member -MemberType NoteProperty -Name 'IsPowerBIFeatureEnabled' -Value $RSInfo.IsPowerBIFeatureEnabled -ErrorAction SilentlyContinue
						$SSRS_Info | Add-Member -MemberType NoteProperty -Name 'IsReportManagerEnabled' -Value $RSInfo.IsReportManagerEnabled -ErrorAction SilentlyContinue
						$SSRS_Info | Add-Member -MemberType NoteProperty -Name 'IsSharePointIntegrated' -Value $RSInfo.IsSharePointIntegrated -ErrorAction SilentlyContinue
						$SSRS_Info | Add-Member -MemberType NoteProperty -Name 'IsWebServiceEnabled' -Value $RSInfo.IsWebServiceEnabled -ErrorAction SilentlyContinue
						$SSRS_Info | Add-Member -MemberType NoteProperty -Name 'IsWindowsServiceEnabled' -Value $RSInfo.IsWindowsServiceEnabled -ErrorAction SilentlyContinue
						$SSRS_Info | Add-Member -MemberType NoteProperty -Name 'MachineAccountIdentity' -Value $RSInfo.MachineAccountIdentity -ErrorAction SilentlyContinue
						$SSRS_Info | Add-Member -MemberType NoteProperty -Name 'PathName' -Value $RSInfo.PathName -ErrorAction SilentlyContinue
						$SSRS_Info | Add-Member -MemberType NoteProperty -Name 'SecureConnectionLevel' -Value $RSInfo.SecureConnectionLevel -ErrorAction SilentlyContinue
						$SSRS_Info | Add-Member -MemberType NoteProperty -Name 'ServiceName' -Value $RSInfo.ServiceName -ErrorAction SilentlyContinue
						$SSRS_Info | Add-Member -MemberType NoteProperty -Name 'UnattendedExecutionAccount' -Value $RSInfo.UnattendedExecutionAccount -ErrorAction SilentlyContinue
						$SSRS_Info | Add-Member -MemberType NoteProperty -Name 'Version' -Value $RSInfoSwitchInfo -ErrorAction SilentlyContinue
						$SSRS_Info | Add-Member -MemberType NoteProperty -Name 'VirtualDirectoryReportManager' -Value $RSInfo.VirtualDirectoryReportManager -ErrorAction SilentlyContinue
						$SSRS_Info | Add-Member -MemberType NoteProperty -Name 'VirtualDirectoryReportServer' -Value $RSInfo.VirtualDirectoryReportServer -ErrorAction SilentlyContinue
						$SSRS_Info | Add-Member -MemberType NoteProperty -Name 'WindowsServiceIdentityActual' -Value $RSInfo.WindowsServiceIdentityActual -ErrorAction SilentlyContinue
						$SSRS_Info | Add-Member -MemberType NoteProperty -Name 'WindowsServiceIdentityConfigured' -Value $RSInfo.WindowsServiceIdentityConfigured -ErrorAction SilentlyContinue
						$SSRS_Info | Add-Member -MemberType NoteProperty -Name ' ' -Value ' ' -ErrorAction SilentlyContinue
						$setupOutput | Add-Member -MemberType NoteProperty -Name 'Reporting Services Information' -Value ($SSRS_Info | Format-List * | Out-String -Width 4096)
					}
					catch
					{
						#potential error code
						#use continue or break keywords
						$e = $_.Exception
						$line = $_.InvocationInfo.ScriptLineNumber
						$msg = $e.Message
						
						Write-Verbose "$(Time-Stamp)Caught Exception during Reporting Services gathering: $e :: Message: $msg :: at line: $line"
						"$(Time-Stamp)Caught Exception during Reporting Services gathering: $e :: Message: $msg :: at line: $line" | Out-File $OutputPath\Error.log -Append
					}
				}
			}
			catch
			{
				#potential error code
				#use continue or break keywords
				$e = $_.Exception
				$line = $_.InvocationInfo.ScriptLineNumber
				$msg = $e.Message
				
				Write-Verbose "$(Time-Stamp)Caught Exception during Reporting Services gathering: $e :: Message: $msg :: at line: $line"
				"$(Time-Stamp)Caught Exception during Reporting Services gathering: $e :: Message: $msg :: at line: $line" | Out-File $OutputPath\Error.log -Append
			}
			if ($w32tmQueryStatus)
			{
				$setupOutput | Add-Member -MemberType NoteProperty -Name 'w32tm Query Status' -Value ($w32tmQueryStatus | Out-String -Width 4096)
			}
			$setupOutput | Add-Member -MemberType NoteProperty -Name 'Services' -Value $localServices
			Write-Verbose "Completed Inner-GeneralInformation Function : `n$setupOutput"
			return $setupOutput
		}
		#End Inner General Info
		trap
		{
			#potential error code
			#use continue or break keywords
			$e = $_.Exception
			$line = $_.InvocationInfo.ScriptLineNumber
			$msg = $e.Message
			Write-Host "Caught Exception: $e at line: $line" -ForegroundColor Red
			"$(Time-Stamp)Caught Exception: $e at line: $line" | Out-File $OutputPath\Error.log -Append
		}
		if ($server -match "^$env:COMPUTERNAME") # If server equals Local Computer
		{
			$localServicesList = (Get-CimInstance Win32_service).where{ $_.name -eq 'omsdk' -or $_.name -eq 'cshost' -or $_.name -eq 'HealthService' -or $_.name -eq 'System Center Management APM' -or $_.name -eq 'AdtAgent' -or $_.name -match "^SQL" -or $_.name -match "MSSQL" -or $_.name -like "SQLAgent*" -or $_.name -eq 'SQLBrowser' -or $_.name -eq 'SQLServerReportingServices' }
			$localServicesList | % {
				[PSCustomObject]@{
					ComputerName	   = $server
					ServiceDisplayName = $_.DisplayName
					ServiceName	       = $_.Name
					AccountName	       = $_.StartName
					StartMode		   = $_.StartMode
					CurrentState	   = $_.State
				}
			} | Sort-Object ServiceName | Export-Csv "$OutputPath`\OS_Services.csv" -NoTypeInformation -Append
			$GeneralInfoGather = Inner-GeneralInfoFunction -LocalManagementServer
			@"
======================================
=---- Local General Information  ----=
======================================
"@ | Out-File -FilePath "$OutputPath\General Information.txt" -Append -Width 4096
			$GeneralInfoGather | Out-File -FilePath "$OutputPath\General Information.txt" -Append -Width 4096
		}
		else
		{
			$InnerGeneralInfoFunctionScript = "function Inner-GeneralInfoFunction { ${function:Inner-GeneralInfoFunction} }"
			$ProductVersionScript = "function Get-ProductVersion { ${function:Get-ProductVersion} }"
			$GeneralInfoGather = Invoke-Command -ComputerName $server -ArgumentList $InnerGeneralInfoFunctionScript, $ProductVersionScript, $VerbosePreference -ScriptBlock {
				Param ($script,
					$versionscript,
					$VerbosePreference)
				. ([ScriptBlock]::Create($script))
				. ([ScriptBlock]::Create($versionscript))
				if ($VerbosePreference -eq 'continue')
				{
					Inner-GeneralInfoFunction -Verbose
				}
				else
				{
					Inner-GeneralInfoFunction
				}
				
			}
			$ServicesList = (Get-CimInstance Win32_service -ComputerName $server).where{ $_.name -eq 'omsdk' -or $_.name -eq 'cshost' -or $_.name -eq 'HealthService' -or $_.name -eq 'System Center Management APM' -or $_.name -eq 'AdtAgent' -or $_.name -match "MSSQL" -or $_.name -like "SQLAgent*" -or $_.name -eq 'SQLBrowser' -or $_.name -eq 'SQLServerReportingServices' }
			$ServicesList | % {
				[PSCustomObject]@{
					ComputerName	   = $server
					ServiceDisplayName = $_.DisplayName
					ServiceName	       = $_.Name
					AccountName	       = $_.StartName
					StartMode		   = $_.StartMode
					CurrentState	   = $_.State
				}
			} | Sort-Object ServiceName | Export-Csv "$OutputPath`\OS_Services.csv" -NoTypeInformation -Append
			@"
========================================
=----- Remote General Information -----=
========================================
"@ | Out-File -FilePath "$OutputPath\General Information.txt" -Append -Width 4096
			$GeneralInfoGather | select * -ExcludeProperty PSComputerName, RunspaceId | Out-String -Width 4096 | Out-File -FilePath "$OutputPath\General Information.txt" -Append
		}
	}
	Write-Progress -Activity "Collection Running" -Status "Progress-> 76%" -PercentComplete 76
	@"
================================
=---- Database Information ----=
================================
"@ | Out-File -FilePath "$OutputPath\General Information.txt" -Append -Width 4096
	try
	{
		$OMSQLPropertiesImport = Import-Csv "$OutputPath`\SQL_Properties_OpsDB.csv"
		try { $OMSQLOwnerImport = Import-Csv "$OutputPath`\SQL_DBOwner_OpsDB.csv" }
		catch { "$(Time-Stamp)Caught Exception: $e at line: $line" | Out-File $OutputPath\Error.log -Append }
		##########################################
		#########################################
		#####################################
		################################
		$OMSQLVersionSwitch = (Get-ProductVersion -Product SQL -BuildVersion $OMSQLPropertiesImport.ProductVersion)
		$OMSQLProperties = $OMSQLVersionSwitch + "`n(" + ($OMSQLPropertiesImport).ProductVersion + ") -" + " (" + ($OMSQLPropertiesImport).ProductLevel + ")" + " - " + ($OMSQLPropertiesImport).Edition + " - " + ($OMSQLPropertiesImport).Version
		if ($OMSQLOwnerImport)
		{
			$OMSQLProperties = $OMSQLProperties + "`n" + "[DB Owner: $($OMSQLOwnerImport.Owner)]"
		}
		if ('True' -eq $OMSQLPropertiesImport.IsClustered)
		{
			$OMSQLProperties = $OMSQLProperties + "`n" + "[Clustered]"
		}
		else
		{
			$OMSQLProperties = $OMSQLProperties + "`n" + "[Not Clustered]"
		}
		try
		{
			if ('True' -eq $OMSQLPropertiesImport.Is_Broker_Enabled)
			{
				$OMSQLProperties = $OMSQLProperties + "`n" + "[Broker Enabled]"
			}
			else
			{
				$OMSQLProperties = $OMSQLProperties + "`n" + "[Broker Not Enabled]"
			}
		}
		catch
		{
			$OMSQLProperties = $OMSQLProperties + "`n" + "[Broker Not Found or Disabled]"
		}
		try
		{
			if ('True' -eq $OMSQLPropertiesImport.Is_CLR_Enabled)
			{
				$OMSQLProperties = $OMSQLProperties + "`n" + "[CLR Enabled]"
			}
			else
			{
				$OMSQLProperties = $OMSQLProperties + "`n" + "[CLR Not Enabled]"
			}
		}
		catch
		{
			$OMSQLProperties = $OMSQLProperties + "`n" + "[CLR Not Found or Disabled]"
		}
		if ('True' -eq $OMSQLPropertiesImport.IsFullTextInstalled)
		{
			$OMSQLProperties = $OMSQLProperties + "`n" + "[FullText Installed]"
		}
		else
		{
			$OMSQLProperties = $OMSQLProperties + "`n" + "[FullText Not Installed]"
		}
		try
		{
			if ('True' -eq $OMSQLPropertiesImport.Is_AlwaysOn_Enabled)
			{
				$OMSQLProperties = $OMSQLProperties + "`n" + "[Always On Enabled]"
			}
			else
			{
				$OMSQLProperties = $OMSQLProperties + "`n" + "[Always On Disabled]"
			}
		}
		catch
		{
			$OMSQLProperties = $OMSQLProperties + "`n" + "[Always On Not Found or Disabled]"
		}
		if ($OMSQLPropertiesImport.Collation -notmatch "SQL_Latin1_General_CP1_CI_AS|Latin1_General_CI_AS|Latin1_General_100_CI_AS|French_CI_AS|French_100_CI_AS|Cyrillic_General_CI_AS|Chinese_PRC_CI_AS|Chinese_Simplified_Pinyin_100_CI_AS|Chinese_Traditional_Stroke_Count_100_CI_AS|Japanese_CI_ASJapanese_XJIS_100_CI_AS|Traditional_Spanish_CI_AS|Modern_Spanish_100_CI_AS|Latin1_General_CI_AS|Cyrillic_General_100_CI_AS|Korean_100_CI_AS|Czech_100_CI_AS|Hungarian_100_CI_AS|Polish_100_CI_AS|Finnish_Swedish_100_CI_AS")
		{
			$OMSQLProperties = $OMSQLProperties + "`n" + "(ISSUE: " + $OMSQLPropertiesImport.Collation + ") <------------ Correct the Collation to a supported one: https://docs.microsoft.com/system-center/scom/plan-sqlserver-design#sql-server-collation-setting"
		}
		$OMSQLProperties = $OMSQLProperties + "`n"
	}
	catch
	{
		
		#potential error code
		#use continue or break keywords
		#$e = $_.Exception
		$line = $_.InvocationInfo.ScriptLineNumber
		$msg = $e.Message
		
		Write-Verbose "Caught Exception: $($error[0]) at line: $line"
		"$(Time-Stamp)Caught Exception: $($error[0]) at line: $line" | Out-File $OutputPath\Error.log -Append
	}
	Write-Host "-" -NoNewline -ForegroundColor Green
	try
	{
		$DWSQLPropertiesImport = Import-Csv "$OutputPath`\SQL_Properties_DW.csv"
		try { $DWSQLOwnerImport = Import-Csv "$OutputPath`\SQL_DBOwner_DW.csv" }
		catch { "$(Time-Stamp)Caught Exception: $e at line: $line" | Out-File $OutputPath\Error.log -Append }
		##########################################
		#########################################
		#####################################
		################################
		$DWSQLVersionSwitch = (Get-ProductVersion -Product SQL -BuildVersion $DWSQLPropertiesImport.ProductVersion)
		$DWSQLProperties = $DWSQLVersionSwitch + "`n(" + ($DWSQLPropertiesImport).ProductVersion + ") - (" + ($DWSQLPropertiesImport).ProductLevel + ") - " + ($DWSQLPropertiesImport).Edition + " - " + ($DWSQLPropertiesImport).Version
		if ($DWSQLOwnerImport)
		{
			$DWSQLProperties = $DWSQLProperties + "`n" + "[DB Owner: $($DWSQLOwnerImport.Owner)]"
		}
		if ('True' -eq $DWSQLPropertiesImport.IsClustered)
		{
			$DWSQLProperties = $DWSQLProperties + "`n" + "[Clustered]"
		}
		else
		{
			$DWSQLProperties = $DWSQLProperties + "`n" + "[Not Clustered]"
		}
		try
		{
			if ('True' -eq $DWSQLPropertiesImport.Is_Broker_Enabled)
			{
				$DWSQLProperties = $DWSQLProperties + "`n" + "[Broker Enabled]"
			}
			else
			{
				$DWSQLProperties = $DWSQLProperties + "`n" + "[Broker Not Enabled]"
			}
		}
		catch
		{
			$DWSQLProperties = $DWSQLProperties + "`n" + "[Broker Not Found or Disabled]"
		}
		if ('True' -eq $DWSQLPropertiesImport.IsFullTextInstalled)
		{
			$DWSQLProperties = $DWSQLProperties + "`n" + "[FullText Installed]"
		}
		else
		{
			$DWSQLProperties = $DWSQLProperties + "`n" + "[FullText Not Installed]"
		}
		try
		{
			if ('True' -eq $DWSQLPropertiesImport.Is_AlwaysOn_Enabled)
			{
				$DWSQLProperties = $DWSQLProperties + "`n" + "[Always On Enabled]"
			}
			else
			{
				$DWSQLProperties = $DWSQLProperties + "`n" + "[Always On Disabled]"
			}
		}
		catch
		{
			$DWSQLProperties = $DWSQLProperties + "`n" + "[Always On Not Found or Disabled]"
		}
		if ($DWSQLPropertiesImport.Collation -notmatch "SQL_Latin1_General_CP1_CI_AS|Latin1_General_CI_AS|Latin1_General_100_CI_AS|French_CI_AS|French_100_CI_AS|Cyrillic_General_CI_AS|Chinese_PRC_CI_AS|Chinese_Simplified_Pinyin_100_CI_AS|Chinese_Traditional_Stroke_Count_100_CI_AS|Japanese_CI_ASJapanese_XJIS_100_CI_AS|Traditional_Spanish_CI_AS|Modern_Spanish_100_CI_AS|Latin1_General_CI_AS|Cyrillic_General_100_CI_AS|Korean_100_CI_AS|Czech_100_CI_AS|Hungarian_100_CI_AS|Polish_100_CI_AS|Finnish_Swedish_100_CI_AS")
		{
			$DWSQLProperties = $DWSQLProperties + "`n" + "(ISSUE: " + $DWSQLPropertiesImport.Collation + ") <------------ Update the Collation to a supported one: https://docs.microsoft.com/system-center/scom/plan-sqlserver-design#sql-server-collation-setting"
		}
	}
	catch
	{
		#potential error code
		#use continue or break keywords
		#$e = $_.Exception
		$line = $_.InvocationInfo.ScriptLineNumber
		$msg = $e.Message
		
		Write-Verbose "Caught Exception: $($error[0]) at line: $line"
		"$(Time-Stamp)Caught Exception: $($error[0]) at line: $line" | Out-File $OutputPath\Error.log -Append
	}
	try
	{
		Add-Type -TypeDefinition @"
public class OpsMgrSetupRegKey{
    public string CurrentVersion;
    public string DatabaseName;
    public string DatabaseServerName;
    public string DatabaseVersion;
    public string DataWarehouseDBName;
    public string DataWarehouseDBServerName;
    public string InstallDirectory;
    public string InstalledOn;
    public string ManagementServerPort;
    public string Product;
    public string ServerVersion;
    public string UIVersion;
}
"@
		
		# this is the path we want to retrieve the values from
		$opsMgrSetupRegKeyPath = 'HKLM:\SOFTWARE\Microsoft\Microsoft Operations Manager\3.0\Setup'
		
		# get the values
		try
		{
			$opsMgrSetupRegKey = Get-ItemProperty -Path $opsMgrSetupRegKeyPath -ErrorAction Stop
			
			# construct a new object
			$setuplocation = New-Object OpsMgrSetupRegKey
			
			#set the object values from the registry key
			$setuplocation.CurrentVersion = $opsMgrSetupRegKey.CurrentVersion
			$setuplocation.DatabaseName = $opsMgrSetupRegKey.DatabaseName
			$setuplocation.DatabaseServerName = $opsMgrSetupRegKey.DatabaseServerName
			$setuplocation.DatabaseVersion = $opsMgrSetupRegKey.DatabaseVersion
			$setuplocation.DataWarehouseDBName = $opsMgrSetupRegKey.DataWarehouseDBName
			$setuplocation.DataWarehouseDBServerName = $opsMgrSetupRegKey.DataWarehouseDBServerName
			$setuplocation.InstallDirectory = $opsMgrSetupRegKey.InstallDirectory
			$setuplocation.InstalledOn = $opsMgrSetupRegKey.InstalledOn
			$setuplocation.ManagementServerPort = $opsMgrSetupRegKey.ManagementServerPort
			$setuplocation.Product = $opsMgrSetupRegKey.Product
			$setuplocation.ServerVersion = $opsMgrSetupRegKey.ServerVersion
			$setuplocation.UIVersion = $opsMgrSetupRegKey.UIVersion
		}
		catch
		{
			$setuplocation = $null
		}
		$dbOutput = [pscustomobject]@{ }
		$dbOutput | Add-Member -MemberType NoteProperty -Name 'Operations Manager DB Server Name' -Value $setuplocation.DatabaseServerName -ErrorAction SilentlyContinue
		$dbOutput | Add-Member -MemberType NoteProperty -Name 'Operations Manager DB Name' -Value $setuplocation.DatabaseName -ErrorAction SilentlyContinue
		try
		{
			$dbOutput | Add-Member -MemberType NoteProperty -Name 'Operations Manager SQL Properties' -Value $OMSQLProperties -ErrorAction SilentlyContinue
		}
		catch
		{
			$dbOutput | Add-Member -MemberType NoteProperty -Name 'Operations Manager SQL Properties' -Value 'Unable to locate the file needed for this data. Typically this is due to permissions.' -ErrorAction SilentlyContinue
		}
		$dbOutput | Add-Member -MemberType NoteProperty -Name 'Data Warehouse DB Server Name' -Value $setuplocation.DataWarehouseDBServerName -ErrorAction SilentlyContinue
		$dbOutput | Add-Member -MemberType NoteProperty -Name 'Data Warehouse DB Name' -Value $setuplocation.DataWarehouseDBName -ErrorAction SilentlyContinue
		try
		{
			$dbOutput | Add-Member -MemberType NoteProperty -Name 'Data Warehouse SQL Properties' -Value $DWSQLProperties -ErrorAction SilentlyContinue
		}
		catch
		{
			$dbOutput | Add-Member -MemberType NoteProperty -Name 'Data Warehouse SQL Properties' -Value 'Unable to locate the file needed for this data. Typically this is due to permissions.' -ErrorAction SilentlyContinue
		}
		$foundsomething = $false
		try
		{
			$UserRolesImport = Import-Csv "$OutputPath`\UserRoles.csv"
			$UserRoles = "User Role Name" + " - " + "Is System?" + "`n----------------------------`n"
			$UserRolesImport | % {
				if ($_.IsSystem -eq $false)
				{
					$foundsomething = $true
					$UserRoles += $_.UserRoleName + " - " + $_.IsSystem + "`n"
				}
			}
			if ($foundsomething)
			{
				$dbOutput | Add-Member -MemberType NoteProperty -Name 'User Roles (Non-Default)' -Value $UserRoles
			}
		}
		catch
		{
			#potential error code
			#use continue or break keywords
			#$e = $_.Exception
			$line = $_.InvocationInfo.ScriptLineNumber
			$msg = $e.Message
			
			Write-Verbose "Caught Exception: $($error[0]) at line: $line"
			"$(Time-Stamp)Caught Exception: $($error[0]) at line: $line" | Out-File $OutputPath\Error.log -Append
		}
	}
	catch
	{
		Write-Warning $error[0]
	}
	if ($dbOutput)
	{
		$dbOutput | Out-File -FilePath "$OutputPath\General Information.txt" -Append -Width 4096
	}
	else
	{
		"Unable to locate any Data in one of the following files / registry paths:`n..\CSV\SQL_Properties_OpsDB.csv`n..\CSV\SQL_Properties_DW.csv`nHKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Microsoft Operations Manager\3.0\Setup" | Out-File -FilePath "$OutputPath\General Information.txt" -Append -Width 4096
	}
	
	Write-Progress -Activity "Collection Running" -Status "Progress-> 80%" -PercentComplete 80
	$UpdatesOutput = foreach ($Server in $Servers) { Write-Host "-" -NoNewline -ForegroundColor Green; Invoke-Command -ComputerName $Server -ScriptBlock { Get-HotFix } -ErrorAction SilentlyContinue }
	Write-Progress -Activity "Collection Running" -Status "Progress-> 82%" -PercentComplete 82
	if ($UpdatesOutput.HotfixId)
	{
		@"
================================
=----- Installed Updates  -----=
================================
"@ | Out-File -FilePath "$OutputPath\General Information.txt" -Append -Width 4096
		$UpdatesOutput | Sort InstalledOn, PSComputerName -Descending | Add-Member -MemberType AliasProperty -Name 'Computer Name' -Value PSComputerName -PassThru | Select-Object -Property 'Computer Name', Description, HotFixID, InstalledBy, InstalledOn, Caption | Format-Table * -AutoSize | Out-File -FilePath "$OutputPath\General Information.txt" -Append -Width 4096
	}
	else
	{
		@"
=================================================
=----- Unable to Detect Installed Updates  -----=
=================================================
"@ | Out-File -FilePath "$OutputPath\General Information.txt" -Append -Width 4096
	}
	
	Write-Progress -Activity "Collection Running" -Status "Progress-> 84%" -PercentComplete 84
	
	@"
======================================= 
=-- ConfigService.config File Check --= 
=======================================
"@ | Out-File -FilePath "$OutputPath\General Information.txt" -Append -Width 4096
	$localpath = (get-itemproperty -path "HKLM:\SOFTWARE\Microsoft\Microsoft Operations Manager\3.0\Setup" -ErrorAction Stop).InstallDirectory
	Write-Progress -Activity "Collection Running" -Status "Progress-> 80%" -PercentComplete 85
	foreach ($server in $ManagementServers)
	{
		Write-Host "-" -NoNewline -ForegroundColor Green
		if ($server -notmatch $env:COMPUTERNAME)
		{
			try
			{
				$remoteConfig = $null
				$remoteConfig = Invoke-Command -ComputerName $server -ScriptBlock {
					trap
					{
						#potential error code
						#use continue or break keywords
						$e = $_.Exception
						$line = $_.InvocationInfo.ScriptLineNumber
						$msg = $e.Message
						Write-Host "Caught Exception: $e at line: $line" -ForegroundColor Red
					}
					$scompath = (get-itemproperty -path "HKLM:\SOFTWARE\Microsoft\Microsoft Operations Manager\3.0\Setup" -ErrorAction Stop).InstallDirectory
					return (Get-Content -Path "$scompath`\ConfigService.config" -ErrorAction Stop)
				} -ErrorAction Stop
				$compare = Compare-Object -ReferenceObject (Get-Content -Path "$localpath`\ConfigService.config" -ErrorAction Stop) -DifferenceObject $remoteConfig -ErrorAction Stop
				
				if ($compare)
				{
					Write-Output "There are differences between : $server <-> $env:ComputerName" | Out-File -FilePath "$OutputPath\General Information.txt" -Append
				}
				else
				{
					Write-Output "Configuration Matches between : $server <-> $env:ComputerName" | Out-File -FilePath "$OutputPath\General Information.txt" -Append
				}
			}
			catch
			{
				"$(Time-Stamp)$server (Remote) - Unreachable" | Out-File $OutputPath\Error.log -Append
				Write-Output "$server (Remote) - Unreachable" | Out-File -FilePath "$OutputPath\General Information.txt" -Append
			}
		}
		else
		{
			Write-Output "$server (Source)" | Out-File -FilePath "$OutputPath\General Information.txt" -Append
		}
	}
	Write-Progress -Activity "Collection Running" -Status "Progress-> 87%" -PercentComplete 87
	
	" " | Out-File -FilePath "$OutputPath\General Information.txt" -Append
	@"
================================
=------ Clock Sync Check ------=
================================
"@ | Out-File -FilePath "$OutputPath\General Information.txt" -Append -Width 4096
	foreach ($server in $Servers)
	{
		try
		{
			Write-Progress -Activity "Collection Running" -Status "Progress-> 88%" -PercentComplete 88
			Write-Host "-" -NoNewline -ForegroundColor Green
			if ($server -ne $Comp)
			{
				try
				{
					$remoteTime = Invoke-Command -ComputerName $Server { return [System.DateTime]::UtcNow } -ErrorAction Stop
				}
				catch
				{
					Write-Output "Unable to run any commands against the Remote Server : $server" | Out-File -FilePath "$OutputPath\General Information.txt" -Append
					continue
				}
				
				$localTime = [System.DateTime]::UtcNow
				if ($remoteTime.Hour -match $localtime.Hour)
				{
					if ($remoteTime.Minute -match $localtime.Minute)
					{
						Write-Output "Time synchronized between : $server <-> $Comp" | Out-File -FilePath "$OutputPath\General Information.txt" -Append
					}
				}
				elseif (!$remoteTime)
				{
					Write-Output "Unable to check the Time of Remote Server : $server" | Out-File -FilePath "$OutputPath\General Information.txt" -Append
				}
				else
				{
					Write-Output "Time NOT synchronized between : $server <-> $Comp : Remote Time: $remoteTime - Local Time: $localTime" | Out-File -FilePath "$OutputPath\General Information.txt" -Append
				}
			}
		}
		catch { Write-Warning $_ }
	}
	Write-Progress -Activity "Collection Running" -Status "Progress-> 90%" -PercentComplete 90
	########### Gateway Stuff 
	try
	{
		$Gateways = Get-SCOMManagementServer -ErrorAction Stop | where { $_.IsGateway -eq $true }
	}
	catch
	{
		$Gateways = $false
	}
	if ($Gateways)
	{
		" " | Out-File -FilePath "$OutputPath\General Information.txt" -Append
		@"
======================================
=------- Gateway Information --------=
======================================
"@ | Out-File -FilePath "$OutputPath\General Information.txt" -Append -Width 4096
		
		$gwinfo = @()
		# Show the gateway server assignments for primary and failover 
		foreach ($Gateway in $Gateways)
		{
			try
			{
				$gwOSVersion = $null
				$gwOSVersion = (Get-SCOMClass -Name Microsoft.Windows.OperatingSystem -ErrorAction Stop | Get-SCOMClassInstance -ErrorAction Stop | select path, displayname | Where { $_.Path -match "$($Gateway.DisplayName)" }).DisplayName
			}
			catch
			{
				$gwOSVersion = 'Unable to find OS Version in SCOM.'
			}
			try
			{
				$gwAgentCount = ($Gateway | Get-SCOMAgent -ErrorAction Stop).Count
			}
			catch
			{
				$gwAgentCount = "Unable to return the Count of Agents Managed by $Gateway."
			}
			
			$gwinfo += [pscustomobject]@{
				'Gateway Name' = $Gateway.DisplayName
				'Agent Count'  = $gwAgentCount
				'Gateway Domain' = $Gateway.Domain
				'OS Version'   = $gwOSVersion
				'Action Account' = $Gateway.ActionAccountIdentity
				'IP Address'   = $Gateway.IPAddress
				'Communication Port' = $Gateway.CommunicationPort
				'AemEnabled'   = $Gateway.AemEnabled
				'Last Modified' = $Gateway.LastModified.ToString().Trim()
				'Installed On' = $Gateway.InstallTime.ToString().Trim()
				'Primary Management Server' = $Gateway.GetPrimaryManagementServer().DisplayName
				'Failover Management Servers' = $Gateway.GetFailoverManagementServers().DisplayName
				'Auto Approve Manually Installed Agents' = $Gateway.AutoApproveManuallyInstalledAgents.Value
				'Reject Manually Installed Agents' = $Gateway.RejectManuallyInstalledAgents.Value
			}
		}
		$gwinfo | Out-File -FilePath "$OutputPath\General Information.txt" -Append -Width 4096
	}
	###########
	Write-Progress -Activity "Collection Running" -Status "Progress-> 92%" -PercentComplete 92
	" " | Out-File -FilePath "$OutputPath\General Information.txt" -Append
	@"
================================
=------- Latency Check --------=
================================
"@ | Out-File -FilePath "$OutputPath\General Information.txt" -Append -Width 4096
	$OpsDBServer = $global:OpsDB_SQLServer
	$DWDBServer = $global:DW_SQLServer
	foreach ($ms in $ManagementServers) #Go Through each Management Server
	{
		$pingoutput = @()
		if ($ms -notmatch $Comp) #If not equal local
		{
			if ($OpsDBServer -notmatch $DWDBServer) #If OpsDB and DW are not the same run the below
			{
				try
				{
					Invoke-Command -ErrorAction Stop -ComputerName $ms -ScriptBlock {
						$dataoutput = @()
						try
						{
							$test = @()
							$test = (Test-Connection -ComputerName $using:OpsDBServer -Count 4 -ErrorAction Stop | measure-Object -Property ResponseTime -Average).average
							$response = @()
							$response = ($test -as [int])
							$innerdata = @()
							[string]$innerdata = "$using:ms -> $using:OpsDBServer : $response ms"
							$dataoutput += $innerdata
						}
						catch
						{
							Write-Verbose $_
						}
						try
						{
							$test = @()
							$test = (Test-Connection -ComputerName $using:DWDBServer -Count 4 -ErrorAction Stop | measure-Object -Property ResponseTime -Average).average
							$response = @()
							$response = ($test -as [int])
							$innerdata = @()
							[string]$innerdata = "$using:ms -> $using:DWDBServer : $response ms"
							$dataoutput += $innerdata
						}
						catch
						{
							Write-Verbose $_
						}
						# Run Checks Against Management Servers
						try
						{
							foreach ($mgmtserver in $using:ManagementServers)
							{
								$test = @()
								$test = (Test-Connection -ComputerName $mgmtserver -Count 4 -ErrorAction Stop | measure-Object -Property ResponseTime -Average).average
								$response = @()
								$response = ($test -as [int])
								$innerdata = @()
								[string]$innerdata = "$using:ms -> $mgmtserver : $response ms"
								$dataoutput += $innerdata
							}
						}
						catch
						{
							Write-Verbose $_
						}
						return $dataoutput
					} | Out-File -FilePath "$OutputPath\General Information.txt" -Append #end invoke
				}
				catch
				{
					"$ms is Offline or Error occurred." | Out-File -FilePath "$OutputPath\General Information.txt" -Append
				}
				
			} #end if
			else #Else run the below
			{
				try
				{
					Invoke-Command -ComputerName $ms -ErrorAction Stop -ScriptBlock {
						$pingoutput = @()
						try
						{
							$test = @()
							$test = (Test-Connection -ComputerName $using:OpsDBServer -Count 4 -ErrorAction Stop | measure-Object -Property ResponseTime -Average).average
							$response = @()
							$response = ($test -as [int])
							$innerdata = @()
							[string]$innerdata = "$using:ms -> $using:OpsDBServer : $response ms"
							$dataoutput += $innerdata
						}
						catch
						{
							Write-Verbose $_
						}
						return $dataoutput
					} | Out-File -FilePath "$OutputPath\General Information.txt" -Append -Width 4096 #end invoke
				}
				catch
				{
					"$ms is Offline or Error occurred." | Out-File -FilePath "$OutputPath\General Information.txt" -Append
				}
			} #end else
		} #end If not equal local
		else #Local Execution
		{
			if ($OpsDBServer -ne $DWDBServer)
			{
				try
				{
					$test = @()
					$test = (Test-Connection -ComputerName $OpsDBServer -Count 4 -ErrorAction Stop | measure-Object -Property ResponseTime -Average).average
					$response = @()
					$response = ($test -as [int])
					$innerdata = @()
					[string]$innerdata = "$ms -> $OpsDBServer : $response ms"
					$innerdata | Out-File -FilePath "$OutputPath\General Information.txt" -Append
				}
				catch
				{
					Write-Verbose $_
					
				}
				try
				{
					$test = @()
					$test = (Test-Connection -ComputerName $DWDBServer -Count 4 -ErrorAction Stop | measure-Object -Property ResponseTime -Average).average
					$response = @()
					$response = ($test -as [int])
					$innerdata = @()
					[string]$innerdata = "$ms -> $DWDBServer : $response ms"
					$innerdata | Out-File -FilePath "$OutputPath\General Information.txt" -Append
				}
				catch
				{
					Write-Verbose $_
				}
			}
			else
			{
				try
				{
					$test = @()
					$test = (Test-Connection -ComputerName $OpsDBServer -Count 4 -ErrorAction Stop | measure-Object -Property ResponseTime -Average).average
					$response = @()
					$response = ($test -as [int])
					$innerdata = @()
					[string]$innerdata = "$ms -> $OpsDBServer : $response ms"
					$innerdata | Out-File -FilePath "$OutputPath\General Information.txt" -Append
				}
				catch
				{
					Write-Verbose $_
				}
			}
		}
	}
	Write-Progress -Activity "Collection Running" -Status "Progress-> 94%" -PercentComplete 94
	if ($pingall)
	{
		foreach ($server in $TestedTLSservers)
		{
			Invoke-Command -ComputerName $server -ErrorAction SilentlyContinue -ScriptBlock {
				#Start Checking for Connectivity to Management Servers in MG
				$pingoutput = @()
				foreach ($ms in $using:ManagementServers)
				{
					if ($ms -eq $env:COMPUTERNAME) { continue }
					try
					{
						$test = @()
						$test = (Test-Connection -ComputerName $ms -Count 4 | measure-Object -Property ResponseTime -Average).average
						$response = @()
						$response = ($test -as [int])
						$innerdata = @()
						[string]$innerdata = "$using:server -> $ms : $response ms"
					}
					catch
					{
						Write-Warning $_
						continue
					}
				}
				return $innerdata
			} | Out-File -FilePath "$OutputPath\General Information.txt" -Append
		}
	}
	$pingoutput | Out-File -FilePath "$OutputPath\General Information.txt" -Append
	
	$mginfra = @(
		'Operations Manager Management Group',
		'Operations Manager Management Servers',
		'Data Warehouse Database',
		'Operations Database',
		'Operations Manager Agents'
	)
	$atable = New-Object System.Data.DataTable
	$atable.Columns.Add("Management Group Infrastructure", "System.String") | Out-Null
	$atable.Columns.Add("DisplayName", "System.String") | Out-Null
	$atable.Columns.Add("HealthState", "System.String") | Out-Null
	$atable.Columns.Add("IsAvailable", "System.String") | Out-Null
	$atable.Columns.Add("LastModified", "System.String") | Out-Null
	ForEach ($monitor in $mginfra)
	{
		$data = $null
		$data = Get-SCOMClass -DisplayName $monitor | Get-SCOMClassInstance
		$aRow = $atable.NewRow()
		$aRow.DisplayName = $data.DisplayName
		$aRow.HealthState = ($data.HealthState).ToString().Replace("Success", "Healthy")
		$aRow.IsAvailable = $data.IsAvailable
		$aRow.LastModified = $data.LastModified
		$atable.Rows.Add($aRow)
	}
	$mgfunctions = @(
		'All Management Servers Resource Pool',
		'Data Access Service Group',
		'Management Configuration Service Group',
		'Web User Interfaces'
	)
	$btable = New-Object System.Data.DataTable
	$btable.Columns.Add("Management Group Functions", "System.String") | Out-Null
	$btable.Columns.Add("DisplayName", "System.String") | Out-Null
	$btable.Columns.Add("HealthState", "System.String") | Out-Null
	$btable.Columns.Add("IsAvailable", "System.String") | Out-Null
	$btable.Columns.Add("LastModified", "System.String") | Out-Null
	ForEach ($monitor in $mgfunctions)
	{
		$data = $null
		$data = (Get-SCOMClass -DisplayName $monitor | Get-SCOMClassInstance) | Where { $_.FullName -ne 'Microsoft.SystemCenter.ManagementServicePoolWatchersGroup' }
		$bRow = $btable.NewRow()
		$bRow.DisplayName = $data.DisplayName
		$bRow.HealthState = ($data.HealthState).ToString().Replace("Success", "Healthy")
		$bRow.IsAvailable = $data.IsAvailable
		$bRow.LastModified = $data.LastModified
		$btable.Rows.Add($bRow)
	}
	#(Get-SCOMClass -Name 'Microsoft.SystemCenter.ManagementServicePoolWatchersGroup' | Get-SCOMClassInstance | Select -Property DisplayName, HealthState)
	$msstate = @(
		'Microsoft.SystemCenter.CollectionManagementServerWatcherGroup'
	)
	$ctable = New-Object System.Data.DataTable
	$ctable.Columns.Add("Management Server State from Health Service Watcher", "System.String") | Out-Null
	$ctable.Columns.Add("DisplayName", "System.String") | Out-Null
	$ctable.Columns.Add("HealthState", "System.String") | Out-Null
	$ctable.Columns.Add("IsAvailable", "System.String") | Out-Null
	$ctable.Columns.Add("LastModified", "System.String") | Out-Null
	ForEach ($monitor in $msstate)
	{
		$data = $null
		$data = (Get-SCOMClassInstance -Name $monitor)
		$cRow = $ctable.NewRow()
		$cRow.DisplayName = $data.DisplayName
		$cRow.HealthState = ($data.HealthState).ToString().Replace("Success", "Healthy")
		$cRow.IsAvailable = $data.IsAvailable
		$cRow.LastModified = $data.LastModified
		$ctable.Rows.Add($cRow)
	}
	$msservers = Get-SCOMClass -DisplayName 'Management Server' | Get-SCOMClassInstance
	$dtable = New-Object System.Data.DataTable
	$dtable.Columns.Add("Management Server State", "System.String") | Out-Null
	$dtable.Columns.Add("DisplayName", "System.String") | Out-Null
	$dtable.Columns.Add("HealthState", "System.String") | Out-Null
	$dtable.Columns.Add("IsAvailable", "System.String") | Out-Null
	$dtable.Columns.Add("LastModified", "System.String") | Out-Null
	ForEach ($server in $msservers)
	{
		$dRow = $dtable.NewRow()
		$dRow.DisplayName = $server.DisplayName
		$dRow.HealthState = ($server.HealthState).ToString().Replace("Success", "Healthy")
		$dRow.IsAvailable = $server.IsAvailable
		$dRow.LastModified = $server.LastModified
		$dtable.Rows.Add($dRow)
	}
	
	" " | Out-File -FilePath "$OutputPath\General Information.txt" -Append
	@"
=====================================
=------- MG Health Overview --------=
=====================================
"@ | Out-File -FilePath "$OutputPath\General Information.txt" -Append
	$atable | Export-CSV "$OutputPath`\MG_HealthOverview.csv" -Force -NoTypeInformation
	$btable | Export-CSV "$OutputPath`\MG_HealthOverview.csv" -Append -Force -NoTypeInformation
	$ctable | Export-CSV "$OutputPath`\MG_HealthOverview.csv" -Append -Force -NoTypeInformation
	$dtable | Export-CSV "$OutputPath`\MG_HealthOverview.csv" -Append -Force -NoTypeInformation
	$atable | Format-Table -AutoSize | Out-String -Width 4096 | Out-File -FilePath "$OutputPath\General Information.txt" -Append
	$btable | Format-Table -AutoSize | Out-String -Width 4096 | Out-File -FilePath "$OutputPath\General Information.txt" -Append
	$ctable | Format-Table -AutoSize | Out-String -Width 4096 | Out-File -FilePath "$OutputPath\General Information.txt" -Append
	$dtable | Format-Table -AutoSize | Out-String -Width 4096 | Out-File -FilePath "$OutputPath\General Information.txt" -Append
	
	# ==================================================================================
	try
	{
		$mgOverviewImport = Import-Csv "$OutputPath`\MG_Overview.csv"
		Write-Progress -Activity "Collection Running" -Status "Progress-> 95%" -PercentComplete 95
		$mgOverviewImport | % {
			$MGName = $_.MG_Name
			$MSCount = $_.MS_Count
			$GWCount = $_.GW_Count
			$AgentCount = $_.Agent_Count
			$AgentPending = $_.Agent_Pending
			$UnixCount = $_.Unix_Count
			$NetworkDeviceCount = $_.NetworkDevice_Count
			$NoteUpdate = [pscustomobject]@{ }
			$NoteUpdate | Add-Member -MemberType NoteProperty -Name "Management Group Name" -Value $MGName -ErrorAction SilentlyContinue
			$NoteUpdate | Add-Member -MemberType NoteProperty -Name "Gateway Count" -Value $GWCount -ErrorAction SilentlyContinue
			$NoteUpdate | Add-Member -MemberType NoteProperty -Name "Agent Count" -Value $AgentCount -ErrorAction SilentlyContinue
			$NoteUpdate | Add-Member -MemberType NoteProperty -Name "Agent Pending" -Value $AgentPending -ErrorAction SilentlyContinue
			$NoteUpdate | Add-Member -MemberType NoteProperty -Name "Unix Count" -Value $UnixCount -ErrorAction SilentlyContinue
			$NoteUpdate | Add-Member -MemberType NoteProperty -Name "Network Device Count" -Value $NetworkDeviceCount -ErrorAction SilentlyContinue
			$NoteUpdate | Add-Member -MemberType NoteProperty -Name "Environment Type" -Value '(Prod / Non-Prod / Dev)' -ErrorAction SilentlyContinue
			$NoteUpdate | Format-List * | Out-File -FilePath "$OutputPath\note.txt" -Width 4096
		}
	}
	catch
	{
		#potential error code
		#use continue or break keywords
		#$e = $_.Exception
		$line = $_.InvocationInfo.ScriptLineNumber
		$msg = $e.Message
		
		Write-Verbose "Caught Exception: $($error[0]) at line: $line"
		"$(Time-Stamp)Caught Exception: $($error[0]) at line: $line" | Out-File $OutputPath\Error.log -Append
	}
	
	"Environment:" | Out-File -FilePath "$OutputPath\note.txt" -Append
	$NoteUpdate = [pscustomobject]@{ }
	$NoteUpdate | Add-Member -MemberType NoteProperty -Name "SCOM Version" -Value '<Type in Manually>' -ErrorAction SilentlyContinue
	$NoteUpdate | Add-Member -MemberType NoteProperty -Name "MS Server OS Version" -Value $((Get-CimInstance win32_operatingsystem).Caption) -ErrorAction SilentlyContinue
	$NoteUpdate | Add-Member -MemberType NoteProperty -Name "Number of MS" -Value $MSCount -ErrorAction SilentlyContinue
	$NoteUpdate | Add-Member -MemberType NoteProperty -Name "SQL Info" -Value ($dbOutput | fl * | Out-String -Width 4096) -ErrorAction SilentlyContinue
	$NoteUpdate | Format-List * | Out-File -FilePath "$OutputPath\note.txt" -Append -Width 4096
	
	Write-Progress -Activity "Collection Running" -Status "Progress-> 96%" -PercentComplete 96
}

		Write-Progress -Activity "Collection Running" -Status "Progress-> 66%" -PercentComplete 66
		Write-Verbose "$(Time-Stamp)Executing General Info Function"
		Get-SCOMGeneralInfo -Servers $TestedTLSservers
		Write-Host "> Completed!`n" -NoNewline -ForegroundColor Green
		Write-Progress -Activity "Collection Running" -Status "Progress-> 97%" -PercentComplete 97
	}
	# Best Practices
	Write-Verbose "$(Time-Stamp)Executing Best Practice Function"
	Function Get-BestPractices
{
	[cmdletbinding()]
	param ([String[]]$Servers)
	begin
	{
		# Updated on 10/26/2022
		Function Time-Stamp
		{
			$TimeStamp = Get-Date -Format "MM/dd/yyyy hh:mm:ss tt"
			return "$TimeStamp - "
		}
		trap
		{
			#potential error code
			#use continue or break keywords
			$e = $_.Exception
			$line = $_.InvocationInfo.ScriptLineNumber
			$msg = $e.Message
			
			Write-Warning "Caught Exception: $e :: Message: $msg :: at line: $line"
			"$(Time-Stamp)Caught Exception: $e :: Message: $msg :: at line: $line" | Out-File $OutputPath\Error.log -Append
		}
		if (!$Servers)
		{
			$Servers = $env:COMPUTERNAME
		}
		
		$header = @"
Detected Issues / Best Practices for SCOM
=========================================
"@
	}
	PROCESS
	{
		function Inner-GetBestPractices
		{
			[CmdletBinding()]
			param ()
			
			Function Time-Stamp
			{
				$TimeStamp = Get-Date -Format "MM/dd/yyyy hh:mm:ss tt"
				return "$TimeStamp - "
			}
			Write-Verbose "========================================"
			Write-Verbose "$(Time-Stamp)  Working on: $env:COMPUTERNAME"
			$script:bestpractice = @()
			if ($OutputPath)
			{
				$OutputResolvedPath = Resolve-Path $OutputPath -ErrorAction SilentlyContinue
			}
			else
			{
				$OutputResolvedPath = $false
			}
			
			Write-Verbose "$(Time-Stamp)Checking the Operations Manager Event log for 33333 event ids and messages like: *Violation of PRIMARY KEY constraint 'PK_StateChangeEvent'. Cannot insert duplicate key in object 'dbo.StateChangeEvent'. The duplicate key value is*"
			$events = (Get-EventLog -LogName 'Operations Manager' -Source 'DataAccessLayer' -ErrorAction SilentlyContinue | Where-Object { $_.EventID -eq 33333 })
			Write-Host '-' -NoNewline -ForegroundColor Green
			# If Event 33333 found in the OperationsManager Event Log, do the below
			if (($events.Message -like "*Violation of PRIMARY KEY constraint 'PK_StateChangeEvent'. Cannot insert duplicate key in object 'dbo.StateChangeEvent'. The duplicate key value is*") -and ($events.Message -like "*f1baeb56-8cce-f8c7-79ae-d69796c9d926*"))
			{
				$message = $events | %{ ($_ | Select-Object -Property Message -ExpandProperty Message) }
				$matches = $message -split "," | select-string "MonitorId=(.*)"
				$match = $matches.matches.groups[1].value.TrimEnd(")")
				$script:bestpractice += "$env:COMPUTERNAME : Found $($message.count) issues with the Event ID 33333 (Monitor Id: $match), see the following article:`n   https://kevinholman.com/2017/05/29/stop-healthservice-restarts-in-scom-2016/"
				Write-Verbose "$(Time-Stamp)$env:COMPUTERNAME : Found $($message.count) issues with the Event ID 33333 (Monitor Id: $match), see the following article:`n   https://kevinholman.com/2017/05/29/stop-healthservice-restarts-in-scom-2016/"
				
				Write-Host "-" -NoNewline -ForegroundColor Green
			}
			# Check if Async Notification Channel Issue is Present
			Write-Verbose "$(Time-Stamp)Check if Async Notification Channel Issue is Present"
			$AsyncEvents = (Get-EventLog -LogName 'Operations Manager' -Source 'Health Service Modules' -ErrorAction SilentlyContinue | Where-Object { $_.EventID -eq 21410 })
			if ($AsyncEvents.Message -like "*The process could not be created because the maximum number of asynchronous responses*")
			{
				$AsyncMessage = $AsyncEvents | %{ ($_ | Select-Object -Property Message -ExpandProperty Message) }
				$AsyncMatches = $AsyncMessage -split "," | select-string "(.*)"
				$AsyncMatch = $AsyncMatches.matches.groups[1].value.TrimEnd(")")
				$script:bestpractice += "$env:COMPUTERNAME : Found Event ID 21410, regarding issue with asynchronous responses for Command Notification Channel. Consider increasing the registry key (HKLM:\SOFTWARE\Microsoft\Microsoft Operations Manager\3.0\Modules\Global\Command Executer\AsyncProcessLimit or HKLM:\SOFTWARE\Microsoft\Microsoft Operations Manager\3.0\Modules\Global\AsyncProcessLimit) between 5 (default) and 100 (max).`n    Current Async responses possible: '$AsyncMatch'`n      https://kevinholman.com/2021/08/25/what-account-will-command-channel-notifications-run-as-in-scom/"
				Write-Verbose "$(Time-Stamp)$env:COMPUTERNAME : Found Event ID 21410, regarding issue with asynchronous responses for Command Notification Channel. Consider increasing the registry key (HKLM:\SOFTWARE\Microsoft\Microsoft Operations Manager\3.0\Modules\Global\Command Executer\AsyncProcessLimit or HKLM:\SOFTWARE\Microsoft\Microsoft Operations Manager\3.0\Modules\Global\AsyncProcessLimit) between 5 (default) and 100 (max).`n    Current Async responses possible: '$AsyncMatch'`n      https://kevinholman.com/2021/08/25/what-account-will-command-channel-notifications-run-as-in-scom/"
				Write-Host '-' -NoNewline -ForegroundColor Green
			}
			
			# Check if Management Server has MMA Configured to report to an Management Group
			Write-Verbose "$(Time-Stamp)Check if Management Server has MMA Configured to report to an Management Group"
			$ServerMG = Get-ItemProperty -Path 'HKLM:\SOFTWARE\Microsoft\Microsoft Operations Manager\3.0\Server Management Groups\*' -Name IsServer | Select-Object IsServer -ExpandProperty IsServer
			if ($ServerMG)
			{
				$AgentMG = Get-Item -Path 'HKLM:\SOFTWARE\Microsoft\Microsoft Operations Manager\3.0\Agent Management Groups\*' -ErrorAction SilentlyContinue
				if ($AgentMG)
				{
					Write-Verbose "$(Time-Stamp)$env:COMPUTERNAME : Found Microsoft Monitoring Agent has Management Groups Configured on a Management Server:`n   Remove all Management Groups under Microsoft Monitoring Agent in Control Panel."
					$script:bestpractice += "$env:COMPUTERNAME : Found Microsoft Monitoring Agent has Management Groups Configured on a Management Server:`n   Remove all Management Groups under Microsoft Monitoring Agent in Control Panel."
					Write-Host "-" -NoNewline -ForegroundColor Green
				}
			}
			Write-Host '-' -NoNewline -ForegroundColor Green
			# Check DW Writer Login from Database against RunAs Profile 'Data Warehouse Account'
			if ($OutputResolvedPath)
			{
				try
				{
					Write-Verbose "$(Time-Stamp)Check DW Writer Login from Database against RunAs Profile 'Data Warehouse Account'"
					$writerLoginName = (Import-Csv -ErrorAction SilentlyContinue -Path $OutputPath\DW_WriterLoginName.csv).WriterLoginName
					$DWAction = (Import-Csv -Path $OutputPath\RunAsProfiles.csv -ErrorAction SilentlyContinue | Where { $_.ProfileName -eq 'Microsoft.SystemCenter.DataWarehouse.ActionAccount' }) | Select-Object Domain, UserName, AccountName, TypeName -Unique
					$DWWriterAccount = @()
					if ($DWAction)
					{
						if (($DWAction | Select-Object -ExpandProperty UserName -Unique).Count -ne 1 -or ($DWAction.Count -ne 4))
						{
							foreach ($actionAccount in $DWAction)
							{
								if (($($actionAccount.TypeName) -eq 'Microsoft.SystemCenter.CollectionManagementServer') -or ($($actionAccount.TypeName) -eq 'Microsoft.SystemCenter.DataWarehouse.DataSet') -or ($($actionAccount.TypeName) -eq 'Microsoft.SystemCenter.Apm.DataTransferService') -or ($($actionAccount.TypeName) -eq 'Microsoft.SystemCenter.DataWarehouseSynchronizationService'))
								{
									Write-Verbose "$(Time-Stamp)$($actionAccount.Domain)\$($actionAccount.UserName) : `"$($actionAccount.AccountName)`" - KEEP"
									$DWWriterAccount += "$($actionAccount.Domain)\$($actionAccount.UserName) : `"$($actionAccount.AccountName)`" - KEEP"
								}
								else
								{
									Write-Verbose "$(Time-Stamp)$($actionAccount.Domain)\$($actionAccount.UserName) : `"$($actionAccount.AccountName)`" - REMOVE"
									$DWWriterAccount += "$($actionAccount.Domain)\$($actionAccount.UserName) : `"$($actionAccount.AccountName)`" - REMOVE"
								}
								if ($actionAccount.TypeName -eq 'Microsoft.SystemCenter.CollectionManagementServer')
								{
									$j++
									$j = $j
								}
								elseif ($dwwrite.TypeName -eq 'Microsoft.SystemCenter.DataWarehouse.DataSet')
								{
									$j++
									$j = $j
								}
								elseif ($dwwrite.TypeName -eq 'Microsoft.SystemCenter.Apm.DataTransferService')
								{
									$j++
									$j = $j
								}
								elseif ($dwwrite.TypeName -eq 'Microsoft.SystemCenter.DataWarehouseSynchronizationService')
								{
									$j++
									$j = $j
								}
								
							}
							if ($j -lt '3' -or $j -gt '4')
							{
								Write-Verbose "$(Time-Stamp)$env:COMPUTERNAME : Missing one of the core class types that are required for the Data Warehouse Action Account profile, you should verify the RunAs Profile 'Data Warehouse Account' is set to the intended accounts:`n`n    Check this blog post: https://blakedrumm.com/blog/data-reader-account-provided-is-not-same-as-that-in-the-management-group/"
								$script:bestpractice += "$env:COMPUTERNAME : Missing one of the core class types that are required for the Data Warehouse Action Account profile, you should verify the RunAs Profile 'Data Warehouse Account' is set to the intended accounts:`n`n    Check this blog post: https://blakedrumm.com/blog/data-reader-account-provided-is-not-same-as-that-in-the-management-group/"
							}
							$DWWriterAccount = $DWWriterAccount | Select-Object -Unique
							$script:bestpractice += "$env:COMPUTERNAME : Found an issue with the Data Warehouse Action Account RunAs Profile, you should verify the RunAs Profile 'Data Warehouse Account' is set to the intended accounts:`n`n    SQL Query DW_WriterLoginName:          $writerLoginName`n    Current Data Warehouse Action Account: $($DWWriterAccount -join "`n                                           ")"
							Write-Verbose "$(Time-Stamp)$env:COMPUTERNAME : Found an issue with the Data Warehouse Action Account RunAs Profile, you should verify the RunAs Profile 'Data Warehouse Account' is set to the intended accounts:`n`n    SQL Query DW_WriterLoginName:          $writerLoginName`n    Current Data Warehouse Action Account: $($DWWriterAccount -join "`n                                           ")"
							Write-Host "-" -NoNewline -ForegroundColor Green
						}
						else
						{
							$DWWriter = "$($DWAction.Domain | Select-Object -First 1)\$($DWAction.UserName | Select-Object -First 1)"
							if ($DWWriter -ne $writerLoginName)
							{
								$MGID = (Import-Csv -Path $OutputPath\MG_Info.csv).ManagementGroupId
								$script:bestpractice += "$env:COMPUTERNAME : Found mismatch with the Data Warehouse Action Account, you should verify the RunAs Profile 'Data Warehouse Account' is set to the intended accounts:`n    SQL Query DW_WriterLoginName:          $writerLoginName`n    Data Warehouse Action Account:   $DWWriter`n`n    Query to update the Data Warehouse DB: UPDATE dbo.ManagementGroup SET WriterLoginName='$DWWriter' WHERE ManagementGroupGuid='$MGID'"
								Write-Verbose "$(Time-Stamp)Found mismatch with the Data Warehouse Action Account"
								Write-Host "-" -NoNewline -ForegroundColor Green
							}
							
							$j = 0
							foreach ($dwaccount in $DWAction)
							{
								if ($dwaccount.TypeName -eq 'Microsoft.SystemCenter.CollectionManagementServer')
								{
									$j++
									$j = $j
								}
								elseif ($dwaccount.TypeName -eq 'Microsoft.SystemCenter.DataWarehouse.DataSet')
								{
									$j++
									$j = $j
								}
								elseif ($dwaccount.TypeName -eq 'Microsoft.SystemCenter.Apm.DataTransferService')
								{
									$j++
									$j = $j
								}
								elseif ($dwaccount.TypeName -eq 'Microsoft.SystemCenter.DataWarehouseSynchronizationService')
								{
									$j++
									$j = $j
								}
								else
								{
									$j = $j - 4
								}
							}
							if ($j -lt '3' -or $j -gt '4')
							{
								Write-Verbose "$(Time-Stamp)$env:COMPUTERNAME : Found an issue with the Data Warehouse Action Account, you should verify the RunAs Profile 'Data Warehouse Account' is set to the intended accounts:`n`n    Check this blog post: https://blakedrumm.com/blog/data-reader-account-provided-is-not-same-as-that-in-the-management-group/"
								$script:bestpractice += "$env:COMPUTERNAME : Found an issue with the Data Warehouse Action Account, you should verify the RunAs Profile 'Data Warehouse Account' is set to the intended accounts:`n`n    Check this blog post: https://blakedrumm.com/blog/data-reader-account-provided-is-not-same-as-that-in-the-management-group/"
							}
						}
					}
				}
				catch
				{
					#potential error code
					#use continue or break keywords
					#$e = $_.Exception
					$line = $_.InvocationInfo.ScriptLineNumber
					$msg = $e.Message
					
					Write-Verbose "Caught Exception: $($error[0]) at line: $line"
					"$(Time-Stamp)Caught Exception: $($error[0]) at line: $line" | Out-File $OutputPath\Error.log -Append
				}
				Write-Host '-' -NoNewline -ForegroundColor Green
				Write-Verbose "$(Time-Stamp)Local output path resolved, this is a local machine."
				# Check RunAs Profile 'Data Warehouse Report Deployment Account'
				try
				{
					Write-Verbose "$(Time-Stamp)Check RunAs Profile 'Data Warehouse Report Deployment Account'"
					$rptDeploymentAccount = @()
					$DWReportDeployment = (Import-Csv -Path $OutputPath\RunAsProfiles.csv | Where { $_.ProfileName -eq 'Microsoft.SystemCenter.DataWarehouse.ReportDeploymentActionAccount' }) | Select-Object Domain, UserName, AccountName, TypeName -Unique
					if ($DWReportDeployment)
					{
						if (($DWReportDeployment | Select-Object -ExpandProperty UserName -Unique).Count -ne 1 -or ($DWReportDeployment.Count -ne 2))
						{
							foreach ($reportDeploymentAccount in $DWReportDeployment)
							{
								if (($($reportDeploymentAccount.TypeName) -eq 'Microsoft.SystemCenter.CollectionManagementServer') -or ($($reportDeploymentAccount.TypeName) -eq 'Microsoft.SystemCenter.DataWarehouseSynchronizationService'))
								{
									$rptDeploymentAccount += "$($reportDeploymentAccount.Domain)\$($reportDeploymentAccount.UserName) : `"$($reportDeploymentAccount.AccountName)`" - KEEP"
								}
								else
								{
									$rptDeploymentAccount += "$($reportDeploymentAccount.Domain)\$($reportDeploymentAccount.UserName) : `"$($reportDeploymentAccount.AccountName)`" - REMOVE"
								}
								
							}
							$rptDeploymentAccount = $rptDeploymentAccount | Select-Object -Unique
							$script:bestpractice += "$env:COMPUTERNAME : Found an issue with the Data Warehouse Report Deployment Action Account RunAs Profile, you should verify the RunAs Profile 'Data Warehouse Report Deployment Account' is set to the intended accounts:`n`n    Check this blog post: https://blakedrumm.com/blog/data-reader-account-provided-is-not-same-as-that-in-the-management-group/"
							Write-Verbose "$(Time-Stamp)Found an issue with the Data Warehouse Report Deployment Action Account RunAs Profile"
							Write-Host "-" -NoNewline -ForegroundColor Green
						}
						else
						{
							$z = 0
							foreach ($dwReportDeploy in $DWReportDeployment)
							{
								if ($dwReportDeploy.TypeName -eq 'Microsoft.SystemCenter.CollectionManagementServer')
								{
									$z++
									$z = $z
								}
								elseif ($dwReportDeploy.TypeName -eq 'Microsoft.SystemCenter.DataWarehouseSynchronizationService')
								{
									$z++
									$z = $z
								}
								else
								{
									$z = $z - 1
								}
							}
							if ($z -ne 2)
							{
								Write-Verbose "$(Time-Stamp)$env:COMPUTERNAME : Found an issue with the Data Warehouse Report Deployment Action Account RunAs Profile, you should verify the RunAs Profile 'Data Warehouse Report Deployment Account' is set to the intended accounts:`n`n    Check this blog post: https://blakedrumm.com/blog/data-reader-account-provided-is-not-same-as-that-in-the-management-group/"
								$script:bestpractice += "$env:COMPUTERNAME : Found an issue with the Data Warehouse Report Deployment Action Account RunAs Profile, you should verify the RunAs Profile 'Data Warehouse Report Deployment Account' is set to the intended accounts:`n`n    Check this blog post: https://blakedrumm.com/blog/data-reader-account-provided-is-not-same-as-that-in-the-management-group/"
							}
							
						}
					}
				}
				catch
				{
					#potential error code
					#use continue or break keywords
					#$e = $_.Exception
					$line = $_.InvocationInfo.ScriptLineNumber
					$msg = $e.Message
					
					Write-Verbose "Caught Exception: $($error[0]) at line: $line"
					"$(Time-Stamp)Caught Exception: $($error[0]) at line: $line" | Out-File $OutputPath\Error.log -Append
				}
				#=============================================================
				# Check SQL Configuration for Best Practices
				#=============================================================
				try
				{
					#=============================================================
					# Operations Manager DB
					#=============================================================
					Write-Verbose "$(Time-Stamp)Checking SCOM SQL Configuration for Best Practices"
					Write-Verbose "$(Time-Stamp)Importing CSV: $(Resolve-Path -Path "$OutputPath\SQL_Properties_OpsDB.csv")"
					
					$SQLPropertiesOpsDB = Import-Csv "$OutputPath\SQL_Properties_OpsDB.csv" -ErrorAction SilentlyContinue
					if ($SQLPropertiesOpsDB)
					{
						Write-Verbose "$(Time-Stamp)Is the correct edition of SQL Server being used for the OpsDB: $($SQLPropertiesOpsDB.Edition)"
						if (($SQLPropertiesOpsDB).Edition -notmatch "Enterprise|Standard")
						{
							Write-Verbose "$(Time-Stamp)Found an issue with the edition of SQL Server for the Operations Manager Database SQL Instance, Operations Manager only allows Enterprise and Standard edition of SQL Server:`n    You are currently running: $(($OMSQLPropertiesImport).Edition)`n    https://learn.microsoft.com/system-center/scom/plan-sqlserver-design#sql-server-requirements"
							$script:bestpractice += "Found an issue with the edition of SQL Server for the Operations Manager Database SQL Instance, Operations Manager only allows Enterprise and Standard edition of SQL Server:`n    You are currently running: $(($OMSQLPropertiesImport).Edition)`n    https://learn.microsoft.com/system-center/scom/plan-sqlserver-design#sql-server-requirements"
						}
						Write-Verbose "$(Time-Stamp)Is Broker enabled for the OpsDB: $($SQLPropertiesOpsDB.Is_Broker_Enabled)"
						if ($SQLPropertiesOpsDB.Is_Broker_Enabled -eq 'FALSE')
						{
							Write-Verbose "$(Time-Stamp)SQL Broker is not enabled on the Operations Manager Database. You need to enable it: https://learn.microsoft.com/troubleshoot/system-center/scom/troubleshoot-sql-server-service-broker-issues"
							$script:bestpractice += "SQL Broker is not enabled on the Operations Manager Database. You need to enable it: https://learn.microsoft.com/troubleshoot/system-center/scom/troubleshoot-sql-server-service-broker-issues"
						}
						Write-Verbose "$(Time-Stamp)Is CLR enabled for the OpsDB: $($SQLPropertiesOpsDB.Is_CLR_Enabled)"
						if ($SQLPropertiesOpsDB.Is_CLR_Enabled -eq 'FALSE')
						{
							Write-Verbose "$(Time-Stamp)SQL CLR is not enabled on the Operations Manager Database. You need to enable it: https://learn.microsoft.com/sql/relational-databases/clr-integration/clr-integration-enabling"
							$script:bestpractice += "SQL CLR is not enabled on the Operations Manager Database. You need to enable it: https://learn.microsoft.com/sql/relational-databases/clr-integration/clr-integration-enabling"
						}
						Write-Verbose "$(Time-Stamp)Is Full Text Installed for the OpsDB: $($SQLPropertiesOpsDB.IsFullTextInstalled)"
						if ($SQLPropertiesOpsDB.IsFullTextInstalled -eq 'FALSE')
						{
							Write-Verbose "$(Time-Stamp)SQL Full Text is not installed on the Operations Manager Database. To fix this you will need to reinstall the SQL Instance and check FullText during setup of SQL Instance."
							$script:bestpractice += "SQL Full Text is not installed on the Operations Manager Database. To fix this you will need to reinstall the SQL Instance and check FullText during setup of SQL Instance."
						}
						Write-Verbose "$(Time-Stamp)Checking if SQL Collation set correctly for OpsDB SQL Instance: $($SQLPropertiesOpsDB.Collation)"
						if ($SQLPropertiesOpsDB.Collation -notmatch "SQL_Latin1_General_CP1_CI_AS|Latin1_General_CI_AS|Latin1_General_100_CI_AS|French_CI_AS|French_100_CI_AS|Cyrillic_General_CI_AS|Chinese_PRC_CI_AS|Chinese_Simplified_Pinyin_100_CI_AS|Chinese_Traditional_Stroke_Count_100_CI_AS|Japanese_CI_ASJapanese_XJIS_100_CI_AS|Traditional_Spanish_CI_AS|Modern_Spanish_100_CI_AS|Latin1_General_CI_AS|Cyrillic_General_100_CI_AS|Korean_100_CI_AS|Czech_100_CI_AS|Hungarian_100_CI_AS|Polish_100_CI_AS|Finnish_Swedish_100_CI_AS")
						{
							Write-Verbose "$(Time-Stamp)SQL Server Collation is not set correctly for the Operations Manager SQL Instance: $($SQLPropertiesOpsDB.Collation)"
							$script:bestpractice += "SQL Server Collation is not set correctly for the Operations Manager SQL Instance: $($SQLPropertiesOpsDB.Collation)"
						}
					}
					#=============================================================
					# Data Warehouse DB
					#=============================================================
					
					$SQLPropertiesDW = Import-Csv "$OutputPath\SQL_Properties_DW.csv" -ErrorAction SilentlyContinue
					if ($SQLPropertiesDW)
					{
						Write-Verbose "$(Time-Stamp)Is the correct edition of SQL Server being used for the Data Warehouse: $($SQLPropertiesDW.Edition)"
						if (($SQLPropertiesDW).Edition -notmatch "Enterprise|Standard")
						{
							$script:bestpractice += "Found an issue with the edition of SQL Server for the Operations Manager Data Warehouse Database SQL Instance, Operations Manager only allows Enterprise and Standard edition of SQL Server:`n    You are currently running: $(($SQLPropertiesDW).Edition)`n    https://learn.microsoft.com/system-center/scom/plan-sqlserver-design#sql-server-requirements"
						}
						Write-Verbose "$(Time-Stamp)Is Full Text Installed for the Data Warehouse: $($SQLPropertiesDW.IsFullTextInstalled)"
						if ($SQLPropertiesDW.IsFullTextInstalled -eq 'FALSE')
						{
							$script:bestpractice += "SQL Full Text is not installed on the Data Warehouse Database. To fix this you will need to reinstall the SQL Instance and check FullText during setup of SQL Instance."
						}
						Write-Verbose "$(Time-Stamp)Checking if SQL Collation set correctly for Data Warehouse SQL Instance: $($SQLPropertiesDW.Collation)"
						if ($SQLPropertiesDW.Collation -notmatch "SQL_Latin1_General_CP1_CI_AS|Latin1_General_CI_AS|Latin1_General_100_CI_AS|French_CI_AS|French_100_CI_AS|Cyrillic_General_CI_AS|Chinese_PRC_CI_AS|Chinese_Simplified_Pinyin_100_CI_AS|Chinese_Traditional_Stroke_Count_100_CI_AS|Japanese_CI_ASJapanese_XJIS_100_CI_AS|Traditional_Spanish_CI_AS|Modern_Spanish_100_CI_AS|Latin1_General_CI_AS|Cyrillic_General_100_CI_AS|Korean_100_CI_AS|Czech_100_CI_AS|Hungarian_100_CI_AS|Polish_100_CI_AS|Finnish_Swedish_100_CI_AS")
						{
							$script:bestpractice += "SQL Server Collation is not set correctly for the Data Warehouse SQL Instance: $($SQLPropertiesDW.Collation)"
						}
					}
					#=============================================================
					#=============================================================
					
					#=============================================================
					# DB Sizes
					#=============================================================
					
					#=============================================================
					# Operations Manager DB
					#=============================================================
					Write-Verbose "$(Time-Stamp)Running check for the SCOM DB Sizes"
					$SQLDBSizesOpsDB = Import-Csv "$OutputPath\SQL_DBSize_OpsDB.csv" -ErrorAction SilentlyContinue
					if ($SQLDBSizesOpsDB)
					{
						$OpsDB_MOMData = $SQLDBSizesOpsDB | Where-Object { $_.Name -eq 'MOM_DATA' }
						if ([int]$(($OpsDB_MOMData.'FreeSpace(%)').Split("%").Trim()[0]) -lt 6)
						{
							Write-Verbose "$(Time-Stamp)Operations Manager Database is nearing full, less than 6% free: $($OpsDB_MOMData.'FreeSpace(%)') free space"
							$script:bestpractice += "Operations Manager Database is nearing full, less than 6% free: $($OpsDB_MOMData.'FreeSpace(%)') free space"
						}
						$OpsDB_DataDiskDrive = ($OpsDB_MOMData.Location).Split(":")[0]
					}
					else
					{
						$OpsDB_DataDiskDrive = $null
					}
					
					#=============================================================
					# Data Warehouse DB
					#=============================================================
					
					$SQLDBSizesDWDB = Import-Csv "$OutputPath\SQL_DBSize_DW.csv" -ErrorAction SilentlyContinue
					if ($SQLDBSizesDWDB)
					{
						$DWDB_MOMData = $SQLDBSizesDWDB | Where-Object { $_.Name -eq 'MOM_DATA' }
						if ([int]$(($DWDB_MOMData.'FreeSpace(%)').Split(" %")[0]) -lt 6)
						{
							Write-Verbose "$(Time-Stamp)Operations Manager Data Warehouse Database is nearing full, less than 6% free: $($DWDB_MOMData.'FreeSpace(%)') free space"
							$script:bestpractice += "Operations Manager Data Warehouse Database is nearing full, less than 6% free: $($DWDB_MOMData.'FreeSpace(%)') free space"
						}
						$DWDB_DataDiskDrive = ($DWDB_MOMData.Location).Split(":")[0]
					}
					else
					{
						$DWDB_DataDiskDrive = $null
					}
					
					#=============================================================
					# tempdb DB
					#=============================================================
					[int]$freespace_percent = $null
					$SQLOpsDB_tempdb = Import-Csv "$OutputPath\SQL_DBSize_OpsDB_TempDB.csv" -ErrorAction SilentlyContinue
					if ($SQLOpsDB_tempdb)
					{
						$OpsDB_tempData = $SQLOpsDB_tempdb | Where-Object { $_.Name -notmatch "templog" -and $_.Status -eq 2 }
						if ($OpsDB_tempData)
						{
							foreach ($OpsDBTempData in $(($OpsDB_tempData.'FreeSpace(%)').Replace(" ", '').Split("%")))
							{
								$freespace_percent += [int]$OpsDBTempData;
								$resultNumber = [int]$freespace_percent + [int]$OpsDBTempData
							}
							
							if ($resultNumber -lt 10)
							{
								Write-Verbose "$(Time-Stamp)Operations Manager tempdb Database is nearing full, less than 10% free overall: $resultNumber`% free space"
								$script:bestpractice += "Operations Manager tempdb Database is nearing full, less than 10% free overall: $resultNumber`% free space"
							}
						}
						$driveLetters = @()
						foreach ($OpsDBtempdbDrive in $SQLOpsDB_tempdb.Location)
						{
							$OpsDB_tempdb_driveLetters += "$($OpsDBtempdbDrive.Split(":") | Select-Object -First 1)`:\ "
						}
						$OpsDB_tempdb_driveLetters = $OpsDB_tempdb_driveLetters.Split(" ") | Select-Object -Unique
					}
					$SQLDW_tempdb = Import-Csv "$OutputPath\SQL_DBSize_DW_TempDB.csv" -ErrorAction SilentlyContinue
					if ($SQLDW_tempdb)
					{
						[int]$freespace_percent = $null
						$DW_tempData = $SQLDW_tempdb | Where-Object { $_.Name -notmatch "templog" -and $_.Status -eq 2 }
						if ($DW_tempData)
						{
							foreach ($DWtempdata in $(($DW_tempData.'FreeSpace(%)').Replace(" ", '').Split("%")))
							{
								$freespace_percent += [int]$DWtempdata;
								$resultNumber = [int]$freespace_percent + [int]$DWtempdata
							}
							
							if ($resultNumber -lt 10)
							{
								Write-Verbose "$(Time-Stamp)Operations Manager Data Warehouse tempdb Database is nearing full, less than 10% free overall: $($DW_tempData.'FreeSpace(%)') free space"
								$script:bestpractice += "Operations Manager Data Warehouse tempdb Database is nearing full, less than 10% free overall: $($DW_tempData.'FreeSpace(%)') free space"
							}
						}
						$driveLetters = @()
						foreach ($DWDBtempdbDrive in $SQLOpsDB_tempdb.Location)
						{
							$DW_tempdb_driveLetters += "$($DWDBtempdbDrive.Split(":") | Select-Object -First 1)`:\ "
						}
						$DW_tempdb_driveLetters = $DW_tempdb_driveLetters.Split(" ") | Select-Object -Unique
						if ($OpsDB_DataDiskDrive -eq $DWDB_DataDiskDrive -or
							$OpsDB_DataDiskDrive -match $OpsDB_tempdb_driveLetters -or
							$DWDB_DataDiskDrive -match $DW_tempdb_driveLetters)
						{
							Write-Verbose "$(Time-Stamp)Operations Manager Database file (MOM_DATA) is sharing the same drive as the Data Warehouse ($OpsDB_DataDiskDrive`:\) or tempdb. It is recommended to seperate these to their own respective drives due to I/O constraints and other issues that arise.`n    Operations Manager Database File Location: $($OpsDB_MOMData.Location)`n    Data Warehouse Database File Location: $($DWDB_MOMData.Location)`n    Operations Manager tempdb Database File Location: $OpsDB_tempdb_driveLetters `n    Data Warehouse tempdb Database File Location: $DW_tempdb_driveLetters"
							$script:bestpractice += "Operations Manager Database file (MOM_DATA) is sharing the same drive as the Data Warehouse ($OpsDB_DataDiskDrive`:\) or tempdb. It is recommended to seperate these to their own respective drives due to I/O constraints and other issues that arise.`n    Operations Manager Database File Location: $($OpsDB_MOMData.Location)`n    Data Warehouse Database File Location: $($DWDB_MOMData.Location)`n    Operations Manager tempdb Database File Location: $OpsDB_tempdb_driveLetters `n    Data Warehouse tempdb Database File Location: $DW_tempdb_driveLetters"
						}
					}
					
					
					
					#=============================================================
					#=============================================================
					
				}
				catch
				{
					"$(Time-Stamp)Unable to run Best Practice Analyzer for SCOM SQL Configuration due to Error: $($error[0])`n`n    Line: $line`n    Message:$msg" | Out-File $OutputPath\Error.log -Append
					#potential error code
					#use continue or break keywords
					#$e = $_.Exception
					$line = $_.InvocationInfo.ScriptLineNumber
					$msg = $e.Message
					
					Write-Verbose "$(Time-Stamp)Unable to run Best Practice Analyzer for SCOM SQL Configuration due to Error: $($error[0])`n`n    Line: $line`n    Message:$msg"
				}
				
				
				#=============================================================
				# Check SPN gathered Data for discrepancies
				#$outputpath = '.\'
				#=============================================================
				#=============================================================
				#=============================================================
				try
				{
					function Get-SPNBestPractice
					{
						Write-Verbose "Starting SPN Checker"
						Write-Verbose "Importing CSV: $(Resolve-Path -Path "$OutputPath\SPN-Output.csv" -ErrorAction Stop)"
						$SPNdata = Import-Csv "$OutputPath\SPN-Output.csv" -ErrorAction Stop
						try
						{
							$ManagementServers = Import-Csv "$OutputPath\ManagementServers.csv" -ErrorAction Stop
						}
						catch
						{
							if (!$ManagementServers)
							{
								$ManagementServers = Get-SCOMManagementServer
							}
						}
						[array]$MSlist = $ManagementServers | Select-Object -Property DisplayName -ExpandProperty DisplayName -Unique
						
						ForEach ($ManagementServer in $MSlist)
						{
							Write-Verbose "SPN Best Practices for: $ManagementServer"
							$MS = (($ManagementServer | Out-String).Split("."))[0]
							#$SPNdata | Where { ($_.ServiceClass -eq 'MSOMHSvc') -and ($_.ComputerName -eq "$MS") }
							$MSOMSDKSvc = $SPNdata | Where { ($_.ServiceClass -eq 'MSOMSdkSvc') -and ($_.SPN -eq "MSOMSdkSvc/$MS") -or ($_.SPN -eq "MSOMSdkSvc/$ManagementServer") }
							
							$OSServicesData = (Get-CimInstance Win32_service -ComputerName $ManagementServer).where{ $_.name -eq 'omsdk' -or $_.name -eq 'cshost' -or $_.name -eq 'HealthService' }
							$OSServices = @()
							$OSServicesData | % {
								$OSServices += [PSCustomObject]@{
									ComputerName	   = $MS
									ServiceDisplayName = $_.DisplayName
									ServiceName	       = $_.Name
									AccountName	       = $_.StartName
									StartMode		   = $_.StartMode
									CurrentState	   = $_.State
								}
							} | Sort-Object ServiceName
							Write-Verbose "SPN: $ManagementServer - MSOMSDKSvc : $($MSOMSDKSvc.SPN)"
							if ($MSOMSDKSvc)
							{
								Write-Verbose "SPN: $ManagementServer - Found MSOMSDKSvc"
								$needsChecking = $null
								if ($OSServices)
								{
									Write-Verbose "  - $ManagementServer - Found SCOM Services"
									foreach ($Service in $OSServices)
									{
										if ($Service.ServiceName -eq 'OMSDK')
										{
											Write-Verbose "  - Found Service `'OMSDK`' running as $($Service.AccountName)"
											if ($MSOMSDKSvc.SAMAccountName -notmatch $(($Service.AccountName).Split("\") | Select-Object -Last 1))
											{
												Write-Verbose "  - SPN does not match: $($MSOMSDKSvc.SAMAccountName -notmatch $(($Service.AccountName).Split("\") | Select-Object -Last 1))"
												foreach ($SDKSvcName in $MSOMSDKSvc)
												{
													Write-Verbose "  - Account Name: $($SDKSvcName.SAMAccountName) and SPN: $($SDKSvcName.SPN)"
													if ($Service.AccountName -eq 'LocalSystem')
													{
														Write-Verbose "  - Service running as Computer Account"
														$fullAccountName = "$((($Service.ComputerName).Split("."))[0])$"
														if ($SDKSvcName.SAMAccountName -ne "$fullAccountName")
														{
															Write-Verbose "   - SPN does not match to $fullAccountName"
															$script:bestpractice += "$ManagementServer : SPNs are set incorrectly for MSOMSdkSvc (Service Running as Computer Account), the following commands will resolve your SPN issues:`n    setspn -D $($SDKSvcName.SPN) $($SDKSvcName.SAMAccountName)`n    setspn -S $($SDKSvcName.SPN) $fullAccountName`n"
														}
														else
														{
															Write-Verbose "   - SPN is set correctly"
															Write-Verbose "       - Account Name: $fullAccountName"
															Write-Verbose "       - SPN: $($SDKSvcName.SPN)"
														}
													}
													else
													{
														Write-Verbose "  - Service running as User Account ($($Service.AccountName))"
														$fullAccountName = $(($Service.AccountName).Split("\") | Select-Object -Last 1)
														Write-Verbose "  - $($SDKSvcName.SAMAccountName) -notmatch $($fullAccountName)"
														if ($SDKSvcName.SAMAccountName -ne $fullAccountName)
														{
															Write-Verbose "   - SPN does not match to $fullAccountName"
															$script:bestpractice += "$ManagementServer : SPNs are set incorrectly for MSOMSdkSvc (Service Running as User Account), the following commands will resolve your SPN issues:`n    setspn -D $($SDKSvcName.SPN) $($SDKSvcName.SAMAccountName)`n    setspn -S $($SDKSvcName.SPN) $($Service.AccountName)`n"
														}
														else
														{
															Write-Verbose "   - SPN is set correctly"
															Write-Verbose "       - Account Name: $fullAccountName"
															Write-Verbose "       - SPN: $($SDKSvcName.SPN)"
														}
													}
												}
												
											}
											else
											{
												Write-Verbose "   - SPN is set correctly"
											}
										}
									}
								}
								else
								{
									Write-Verbose "$(Time-Stamp)  Unable to gather OSServices data for checking the account SCOM is running as."
								<#
								$SDKDomain = '<your domain>'
								$SDKAccount = '<scom sdk domain account>'
								#>
								}
							}
						}
					}
					#=============================================================
					#=============================================================
					#=============================================================
					
					
					
					<#
					try
					{
						$ManagementServers = Import-Csv "$OutputPath\ManagementServers.csv" -ErrorAction Stop
					}
					catch
					{
						if (!$ManagementServers)
						{
							$ManagementServers = Get-SCOMManagementServer | Select-Object -ExpandProperty DisplayName
						}
					}
					#>
					
					Write-Verbose "$(Time-Stamp)Running SPN best practice analyzer"
					Get-SPNBestPractice
					
					#=============================================================
					#=============================================================
					#=============================================================
					#=============================================================
					#=============================================================
					#=============================================================
					#=============================================================
					#=============================================================
					#=============================================================
				}
				catch
				{
					"$(Time-Stamp)Unable to run Best Practice Analyzer for SPN data due to Error: $($error[0])" | Out-File $OutputPath\Error.log -Append
					Write-Verbose $_
				}
				# #=============================================================
				# SCOM Group Checker
				# #=============================================================
				try
				{
					$Groups = Get-SCOMGroup -ErrorAction Stop
					
					$groupOut = @()
					$i = 0
					foreach ($Group in $Groups)
					{
						$i++
						$i = $i
						Write-Verbose "($i/$(($Groups.DisplayName).Count)) Group: $($Group.DisplayName)"
						if ($Group.GetMonitoringDiscoveries())
						{
							$obj = New-Object System.Object
							$obj | Add-Member -MemberType NoteProperty -Name DynamicGroupName -Value $Group.DisplayName
							$obj | Add-Member -MemberType NoteProperty -Name DiscoveryName -Value ($Group.GetMonitoringDiscoveries() | % { $_ | Select -ExpandProperty DisplayName })
							$obj | Add-Member -MemberType NoteProperty -Name DiscoveryID -Value ($Group.GetMonitoringDiscoveries() | Select -ExpandProperty ID)
							$obj | Add-Member -MemberType NoteProperty -Name OuterXML -Value ($Group.GetMonitoringDiscoveries().CreateNavigator() | Select -ExpandProperty OuterXml)
							$obj | Add-Member -MemberType NoteProperty -Name Typedvalue -Value ($Group.GetMonitoringDiscoveries().CreateNavigator() | Select -ExpandProperty TypedValue)
							$obj | Add-Member -MemberType NoteProperty -Name DynamicExpressionCount -Value (($obj.OuterXML | %{ $_ | Select-Xml -XPath "//Expression" }).Count)
							$obj | Add-Member -MemberType NoteProperty -Name MemberCount -Value $($Group | Get-SCOMClassInstance).Count
							Write-Debug "         - Object: `n$($obj | Select *)"
							$groupOut += $obj | Where { $_.OuterXML -match "<Expression>" }
							Write-Verbose "              - Dynamic Expression Count: $($obj.DynamicExpressionCount)"
						}
					}
					
					if ($groupOut.DynamicExpressionCount -gt 15)
					{
						Write-Verbose "           - Tagged Group, too many Dynamic expressions!`n------------------------------------------------------------------"
						$script:bestpractice += @"
A high number of dynamic groups detected, this may cause some issues with group calculation (https://kevinholman.com/2017/03/08/recommended-registry-tweaks-for-scom-2016-management-servers/). Try updating the following registry key:
     Path: HKLM:\SOFTWARE\Microsoft\System Center\2010\Common\
     REG_DWORD Decimal Value:       GroupCalcPollingIntervalMilliseconds = 1800000

     SCOM existing registry value:  (not present)
     SCOM default code value:  30000 (30 seconds)

     Description:  This setting will slow down how often group calculation runs to find changes in group memberships. Group calculation can be very expensive, especially with a large number of groups, large agent count, or complex group membership expressions.
                   Groups with complex expressions in large environments can actually take several minutes to calculate. Multiply that times a large number of groups and you have problems. Slowing this down will help keep groupcalc from consuming all the healthservice and database I/O.
                  1800000 milliseconds is every 30 minutes. This means once a group initializes (31410 event) on a management server in the pool, that specific group will wait 30 minutes before evaluating if any members need to be added/removed based on dynamic inclusion criteria in the expression.


     Overall Dynamic Membership Group Count: $($groupOut.Count)

     $($groupOut | Select DynamicGroupName, DiscoveryName, DynamicExpressionCount, MemberCount | Sort-Object DynamicExpressionCount, MemberCount -Descending | Out-String -Width 4096)
"@
					}
				}
				catch
				{
					"$(Time-Stamp)Unable to run Best Practice Analyzer for SCOM Group Checker due to Error: $($error[0])" | Out-File $OutputPath\Error.log -Append
					Write-Verbose $_
				}
			}
			# Check information in General Info Text File for discrepancies
			$GeneralInfo = Get-Content "$OutputPath\General Information.txt" -ErrorAction SilentlyContinue
			if ($GeneralInfo)
			{
				foreach ($line in $GeneralInfo)
				{
					# Check Latency between Management Server(s) and SQL Database(s)
					$objectSplit = ($line | Where { ($_ -match "-> $global:OpsDB_SQLServer :|-> $global:DW_SQLServer :") }) -split " "
					if ($objectSplit)
					{
						$serverName = $objectSplit | Select-Object -Index 0
						$dbServerName = $objectSplit | Select-Object -Index 2
						$responseTime = $objectSplit | Select-Object -Last 2
						if ([int]$($responseTime.Split(" ") | Select-Object -First 1) -gt 10)
						{
							$script:bestpractice += "Management Server: $serverName has high (greater than 10ms) response time to Database: $dbServerName - ($responseTime)"
						}
					}
					# Check that time is synchronized
					$timeSync = ($line | Where { $_ -match "Time NOT synchronized between :" })
					if ($timeSync)
					{
						$script:bestpractice += $timeSync
					}
					# Verify the ConfigService.config file is the same across all the Management Servers
					$configCheck = ($line | Where { $_ -match "There are differences between :" }) -split " "
					if ($configCheck)
					{
						$originManagementServer = $configCheck | Select-Object -Index 5
						$destinationManagementServer = $configCheck | Select-Object -Index 7
						$script:bestpractice += "Configuration differences between $originManagementServer and $destinationManagementServer. (ConfigService.config)"
					}
				}
			}
			
			return $script:bestpractice
		}
		$gatheredData = @()
		# Go through each server passed to the main function: Get-BestPractices
		foreach ($server in $Servers)
		{
			Write-Host "    $server" -NoNewline -ForegroundColor Cyan
			if ($server -match $env:COMPUTERNAME)
			{
				# If Local
				Write-Host '-' -NoNewline -ForegroundColor Green
				$gatheredData += Inner-GetBestPractices
				Write-Host "> Completed!`n" -NoNewline -ForegroundColor Green
			}
			else
			{
				# If Remote
				Write-Host '-' -NoNewline -ForegroundColor Green
				$InnerGetBestPracticesFunctionScript = "function Inner-GetBestPractices { ${function:Inner-GetBestPractices} }"
				$gatheredData += Invoke-Command -ComputerName $server -ArgumentList $InnerGetBestPracticesFunctionScript, $VerbosePreference -ScriptBlock {
					Param ($script,
						$VerbosePreference)
					. ([ScriptBlock]::Create($script))
					<#
					if ($VerbosePreference.value__ -ne 0)
					{
						return Inner-GetBestPractices -Verbose
					}
					else
					{
						return Inner-GetBestPractices
					}
					#>
					return Inner-GetBestPractices
				}
				Write-Host "> Completed!`n" -NoNewline -ForegroundColor Green
			}
		}
	}
	END
	{
		$i = 0
		# Organize the output so it looks clean and seperated, each item will have its own number. (1, 2, 3, 4, etc.)
		foreach ($item in $gatheredData)
		{
			$i++
			$i = $i
			$processedData += @"
$i`. $item`n`r
"@
		}
		if ($processedData)
		{
			$finalOut = @"
$header
$processedData
"@
		}
		else
		{
			$finalOut = @"
$header
No issues detected.
"@
		}
		Write-Verbose "Writing Best Practices text file: $OutputPath\Best Practices.txt"
		$finalOut | Out-File -FilePath "$OutputPath\Best Practices.txt"
	}
}

	Write-Progress -Activity "Collection Running" -Status "Progress-> 98%" -PercentComplete 98
	Write-Output " "
	try
	{
		Write-Output "================================`nStarting System Center Operations Manager Best Practice Analyzer"
		Get-BestPractices -Servers $ManagementServers
	}
	catch
	{
		"$(Time-Stamp)Unable to gather Best Practices due to Error: $($error[0])" | Out-File $OutputPath\Error.log -Append
		Write-Warning $error[0]
	}
	
	# end Best Practices
	try
	{
		if ($GenerateHTML)
		{
			Write-Output "`n================================`nGenerating System Center Operations Manager Report Webpage"
			Function Report-Webpage
{
	# The Name and Location of are we going to save this Report
	$ReportName = "DataCollector.html"
	$ReportPath = "$OutputPath\HTML Report\$ReportName"
	
	$ReportNameDW = "DataCollectorDW.html"
	$ReportPathDW = "$OutputPath\HTML Report\$ReportNameDW"
	
	
	# Create header for OpsMgr HTML Report
	$Head = "<style>"
	$Head += "BODY{background-color:#CCCCCC;font-family:Calibri,sans-serif; font-size: small;}"
	$Head += "TABLE{border-width: 1px;border-style: solid;border-color: black;border-collapse: collapse; width: 98%;}"
	$Head += "TH{border-width: 1px;padding: 0px;border-style: solid;border-color: black;background-color:#293956;color:white;padding: 5px; font-weight: bold;text-align:left;}"
	$Head += "H3{border-width: 1px;padding: 0px;border-style: solid;border-color: black;background-color:#293956;color:white;padding: 5px; font-weight: bold;text-align:left;}"
	$Head += "TD{border-width: 1px;padding: 0px;border-style: solid;border-color: black;background-color:#F0F0F0; color:black; padding: 2px;}"
	$Head += ".tab {overflow: hidden; border: 1px solid #ccc; background-color: #f1f1f1;}"
	$Head += ".tab button {background-color: inherit; float: left; border: none; outline: none; cursor: pointer; padding: 14px 16px; transition: 0.3s; }"
	$Head += ".tab button:hover { background-color: #ddd; }"
	$Head += ".tab button.active { background-color: #ccc; }"
	$Head += ".tabcontent { display: none; padding: 6px 12px; border: 1px solid #ccc; border-top: none; }"
	$Head += "</style>"
	
	$Head += "<script type='text/javascript'>"
	$Head += "function openCategory(evt, cityName) {
  var i, tabcontent, tablinks;
  tabcontent = document.getElementsByClassName('tabcontent');
  for (i = 0; i < tabcontent.length; i++) {
    tabcontent[i].style.display = 'none';
  }
  tablinks = document.getElementsByClassName('tablinks');
  for (i = 0; i < tablinks.length; i++) {
    tablinks[i].className = tablinks[i].className.replace(' active', '');
  }

  document.getElementById(cityName).style.display = 'block';
  evt.currentTarget.className += ' active';
}"
	$Head += "</script>"
	
	# Create header for OpsMgr DW HTML Report
	$HeadDW = "<style>"
	$HeadDW += "BODY{background-color:#CCCCCC; color:grey;font-family:Calibri,sans-serif; font-size: small;}"
	$HeadDW += "TABLE{border-width: 1px;border-style: solid;border-color: black;border-collapse: collapse; width: 98%;}"
	$HeadDW += "TH{border-width: 1px;padding: 0px;border-style: solid;border-color: black;background-color:#293956;color:white;padding: 5px; font-weight: bold;text-align:left;}"
	$HeadDW += "H3{border-width: 1px;padding: 0px;border-style: solid;border-color: black;background-color:#293956;color:white;padding: 5px; font-weight: bold;text-align:left;}"
	$HeadDW += "TD{border-width: 1px;padding: 0px;border-style: solid;border-color: black;background-color:#F0F0F0; color:black; padding: 2px;}"
	$HeadDW += ".tab {overflow: hidden; border: 1px solid #ccc; background-color: #f1f1f1;}"
	$HeadDW += ".tab button {background-color: inherit; float: left; border: none; outline: none; cursor: pointer; padding: 14px 16px; transition: 0.3s; }"
	$HeadDW += ".tab button:hover { background-color: #ddd; }"
	$HeadDW += ".tab button.active { background-color: #ccc; }"
	$HeadDW += ".tabcontent { display: none; padding: 6px 12px; border: 1px solid #ccc; border-top: none; }"
	$HeadDW += "</style>"
	
	$HeadDW += "<script type='text/javascript'>"
	$HeadDW += "function openCategoryDW(evt, cityName) {
  var i, tabcontent, tablinks;
  tabcontent = document.getElementsByClassName('tabcontent');
  for (i = 0; i < tabcontent.length; i++) {
    tabcontent[i].style.display = 'none';
  }
  tablinks = document.getElementsByClassName('tablinks');
  for (i = 0; i < tablinks.length; i++) {
    tablinks[i].className = tablinks[i].className.replace(' active', '');
  }

  document.getElementById(cityName).style.display = 'block';
  evt.currentTarget.className += ' active';
}"
	$HeadDW += "</script>"
	#$ReportOutput += "<p>Operational Database Server      :  $OpsDB_SQLServer</p>"
	#$ReportOutput += "<p>Data Warehouse Database Server   :  $DW_SQLServer</p>"  
	
	$CSVFileLocation = "$CSVFile\output"
	
	# Tabs for Operations Manager Report
	
	$ReportOutput += "<div class='tab'>"
	$ReportOutput += "<button class='tablinks' onclick=`"openCategory(event, 'general')`">General Information</button>"
	$ReportOutput += "<button class='tablinks' onclick=`"openCategory(event, 'alertView')`">Alert</button>"
	$ReportOutput += "<button class='tablinks' onclick=`"openCategory(event, 'configLogs')`">Config Logs</button>"
	$ReportOutput += "<button class='tablinks' onclick=`"openCategory(event, 'configChurn')`">Config Churn</button>"
	$ReportOutput += "<button class='tablinks' onclick=`"openCategory(event, 'eventView')`">Event</button>"
	$ReportOutput += "<button class='tablinks' onclick=`"openCategory(event, 'healthService')`">Health Service</button>"
	$ReportOutput += "<button class='tablinks' onclick=`"openCategory(event, 'instances')`">Instances</button>"
	$ReportOutput += "<button class='tablinks' onclick=`"openCategory(event, 'managementPack')`">Management Pack</button>"
	$ReportOutput += "<button class='tablinks' onclick=`"openCategory(event, 'managementServers')`">Management Servers</button>"
	$ReportOutput += "<button class='tablinks' onclick=`"openCategory(event, 'managementGroup')`">Management Groups</button>"
	$ReportOutput += "<button class='tablinks' onclick=`"openCategory(event, 'networkDevice')`">Network Device</button>"
	$ReportOutput += "<button class='tablinks' onclick=`"openCategory(event, 'operationsDBSQL')`">Ops DB/SQL</button>"
	$ReportOutput += "<button class='tablinks' onclick=`"openCategory(event, 'perfData')`">Performance</button>"
	$ReportOutput += "<button class='tablinks' onclick=`"openCategory(event, 'stateData')`">State Events</button>"
	$ReportOutput += "<button class='tablinks' onclick=`"openCategory(event, 'syncData')`">Sync Data</button>"
	$ReportOutput += "</div>"
	
	# Tabs for Operations Manager DW Report
	
	$ReportOutputDW += "<div class='tab'>"
	$ReportOutputDW += "<button class='tablinks' onclick=`"openCategoryDW(event, 'general')`">General Information</button>"
	$ReportOutputDW += "<button class='tablinks' onclick=`"openCategoryDW(event, 'configChurn')`">Config Churn</button>"
	$ReportOutputDW += "<button class='tablinks' onclick=`"openCategoryDW(event, 'aggregation')`">Aggregation</button>"
	$ReportOutputDW += "<button class='tablinks' onclick=`"openCategoryDW(event, 'databaseSize')`">Database & Table Size/Properties</button>"
	$ReportOutputDW += "<button class='tablinks' onclick=`"openCategoryDW(event, 'largeTables')`">Large Tables</button>"
	$ReportOutputDW += "<button class='tablinks' onclick=`"openCategoryDW(event, 'sqlProperties')`">SQL Properties</button>"
	$ReportOutputDW += "<button class='tablinks' onclick=`"openCategoryDW(event, 'stagingBackups')`">Staging & Backups</button>"
	$ReportOutputDW += "<button class='tablinks' onclick=`"openCategoryDW(event, 'greyed')`">Greyed Out</button>"
	$ReportOutputDW += "<button class='tablinks' onclick=`"openCategoryDW(event, 'indexMaint')`">Index Maint</button>"
	$ReportOutputDW += "</div>"
	
	# General Information - OpsMgr
	$reportDetail = $setupLocation.Product, $setupLocation.InstalledOn, $setupLocation.CurrentVersion, $setupLocation.ServerVersion, $setupLocation.UIVersion, $setupLocation.ManagementServerPort, "$ManagementServers", $setupLocation.DatabaseServerName, $setupLocation.DatabaseName, $setupLocation.InstallDirectory, "$OMSQLProperties"
	$reportDetail = "<tr>" + ($reportDetail | % { "<td>$_</td>" }) + "</tr>"
	$ReportOutput += @("<div id='general' class='tabcontent'>
<h3>General Information</h3>
<table style='width: 300px; '><th>Product</th><th>Installed On</th><th>Current Version</th><th>Server Version</th><th>UI Version</th><th>Management Server Port</th><th>Management Servers in Mgmt Group</th><th>Operations Manager DB Server</th><th>Operations Manager DB</th><th>Install Directory</th><th>Operations Manager SQL Properties</th>
", $reportDetail, "</table>
</div>")
	
	# General Information - OpsMgr DW
	
	$ReportOutputDW += @("<div id='general' class='tabcontent'>
<h3>General Information</h3>
<table style='width: 300px; '><th>Product</th><th>Installed On</th><th>Current Version</th><th>Server Version</th><th>UI Version</th><th>Data Warehouse DB Server</th><th>Operations Manager DW</th>
<tr><td>" + $setupLocation.Product + "</td><td>" + $setupLocation.InstalledOn + "</td><td>" + $setupLocation.CurrentVersion + "</td><td>" + $setupLocation.ServerVersion + "</td><td>" + $setupLocation.UIVersion + "</td><td>" + $setupLocation.DataWarehouseDBServerName + "</td><td>" + $setupLocation.DataWarehouseDBName + "</td></tr>
</table>
</div>")
	
	#
	#
	# !!! ALERT VIEW - OPSMGR !!!
	#
	#
	
	
	$AlertsByDayImport = Import-Csv "$CSVFileLocation`\Alerts_ByDay.csv"
	
	$ReportOutput += "<div id='alertView' class='tabcontent'>"
	$ReportOutput += "<h3>Alerts By Day</h3>"
	$ReportOutput += "<table style='width: 300px;'><th>Day Added</th><th># of Alerts Per Day</th>"
	foreach ($line in $AlertsByDayImport)
	{
		$ReportOutput += "<tr><td>" + $line[0].DayAdded + "</td><td>" + $line[0].NumAlertsPerDay + "</td></tr>"
	}
	$ReportOutput += "</table>"
	
	$AlertsByCountImport = Import-Csv "$CSVFileLocation`\Alerts_ByCount.csv"
	$ReportOutput += "<h3>Alerts By Count</h3>"
	$ReportOutput += "<table style='width: 300px;'><th>Alert Count</th><th>Alert String Name</th><th>Alert String Description</th><th>Monitoring Rule ID</th><th>Name</th>"
	foreach ($line in $AlertsByCountImport)
	{
		$ReportOutput += "<tr><td>" + $line[0].AlertCount + "</td><td>" + $line[0].AlertStringName + "</td><td>" + $line[0].AlertStringDescription + "</td><td>" + $line[0].MonitoringRuleId + "</td><td>" + $line[0].Name + "</td></tr>"
	}
	$ReportOutput += "</table>"
	
	$AlertsByRepeatImport = Import-Csv "$CSVFileLocation`\Alerts_ByRepeat.csv"
	$ReportOutput += "<h3>Alerts By Repeat</h3>"
	$ReportOutput += "<table style='width: 300px;'><th>Repeat Count</th><th>Alert String Name</th><th>Alert String Description</th><th>Monitoring Rule ID</th><th>Name</th>"
	foreach ($line in $AlertsByRepeatImport)
	{
		$ReportOutput += "<tr><td>" + $line[0].RepeatCount + "</td><td>" + $line[0].AlertStringName + "</td><td>" + $line[0].AlertStringDescription + "</td><td>" + $line[0].MonitoringRuleId + "</td><td>" + $line[0].Name + "</td></tr>"
	}
	$ReportOutput += "</table>"
	$ReportOutput += "</div>"
	
	#
	#
	# !!! END ALERT VIEW -OPSMGR !!!
	#
	#
	
	#
	#
	# !!! EVENT VIEW - OPSMGR !!!
	#
	#
	
	$EventsByComputerImport = Import-CSV "$CSVFileLocation`\Events_ByComputer.csv"
	$ReportOutput += "<div id='eventView' class='tabcontent'>"
	$ReportOutput += "<h3>Events By Computer</h3>"
	$ReportOutput += "<table style='width: 300px;'><th>Computer Name</th><th>Total Events</th><th>Event ID</th>"
	foreach ($line in $EventsByComputerImport)
	{
		$ReportOutput += "<tr><td>" + $line[0].ComputerName + "</td><td>" + $line[0].TotalEvents + "</td><td>" + $line[0].EventID + "</td></tr>"
	}
	$ReportOutput += "</table>"
	
	#EventsByNumber
	
	$EventsByNumberImport = Import-CSV "$CSVFileLocation`\Events_ByNumber.csv"
	$ReportOutput += "<h3>Events By Number</h3>"
	$ReportOutput += "<table style='width: 300px;'><th>Event ID</th><th>Total Events</th><th>Event Source</th>"
	foreach ($line in $EventsByNumberImport)
	{
		$ReportOutput += "<tr><td>" + $line[0].EventID + "</td><td>" + $line[0].TotalEvents + "</td><td>" + $line[0].EventSource + "</td></tr>"
	}
	$ReportOutput += "</table>"
	$ReportOutput += "</div>"
	
	#
	#
	# !!! END EVENT VIEW - OPSMGR !!!
	#
	#
	
	#
	#
	# !!! CONFIG LOGS - OPSMGR !!!
	#
	
	
	$ConfigLogsImport = Import-CSV "$CSVFileLocation`\Config_Logs.csv"
	$ReportOutput += "<div id='configLogs' class='tabcontent'>"
	$ReportOutput += "<h3>Config Logs</h3>"
	$ReportOutput += "<table style='width: 300px;'><th>Work Item Row ID</th><th>Work Item Name</th><th>Work Item State ID</th><th>Server Name</th><th>Instance Name</th><th>Started Date Time - UTC</th><th>Last Activity Date Time - UTC</th><th>Completed Date Time - UTC</th><th>Duration in Seconds</th>"
	foreach ($line in $ConfigLogsImport)
	{
		$ReportOutput += "<tr><td>" + $line[0].WorkItemRowId + "</td><td>" + $line[0].WorkItemName + "</td><td>" + $line[0].WorkItemStateId + "</td><td>" + $line[0].ServerName + "</td><td>" + $line[0].InstanceName + "</td><td>" + $line[0].StartedDateTimeUtc + "</td><td>" + $line[0].LastActivityDateTimeUtc + "</td><td>" + $line[0].CompletedDateTimeUtc + "</td><td>" + $line[0].DurationSeconds + "</td></tr>"
	}
	$ReportOutput += "</table>"
	$ReportOutput += "</div>"
	
	#
	# !!! CONFIG LOGS PACK - OPSMGR !!!
	#
	#
	
	#
	#
	# !!! CONFIG CHURN - OPSMGR !!!
	#
	#
	
	$ConfigChurnImport = Import-CSV "$CSVFileLocation`\OpsDBConfigChurn.csv"
	$ReportOutput += "<div id='configChurn' class='tabcontent'>"
	$ReportOutput += "<h3>Operations DB Config Churn</h3>"
	$ReportOutput += "<table style='width: 300px;'><th>Entity Type ID</th><th>Type Name</th><th>Number of Changes</th>"
	foreach ($line in $ConfigChurnImport)
	{
		$ReportOutput += "<tr><td>" + $line[0].EntityTypeId + "</td><td>" + $line[0].TypeName + "</td><td>" + $line[0].'Number of changes' + "</td></tr>"
	}
	$ReportOutput += "</table>"
	$ReportOutput += "</div>"
	
	#
	#
	# !!! END CONFIG CHURN - OPSMGR !!!
	#
	#
	
	#
	#
	# !!! MANAGEMENT PACK - OPSMGR !!!
	#
	#
	
	$ManagementPacksImport = Import-CSV "$CSVFileLocation`\ManagementPacks.csv"
	$ReportOutput += "<div id='managementPack' class='tabcontent'>"
	$ReportOutput += "<h3>Management Packs</h3>"
	$ReportOutput += "<table style='width: 300px;'><th>Management Pack ID</th><th>Version</th><th>Friendly Name</th><th>Display Name</th><th>Sealed</th><th>Last Modified</th><th>Time Created</th>"
	foreach ($mp in $ManagementPacksImport)
	{
		$ReportOutput += "<tr><td>" + $mp[0].ManagementPackID + "</td><td>" + $mp[0].Version + "</td><td>" + $mp[0].FriendlyName + "</td><td>" + $mp[0].DisplayName + "</td><td>" + $mp[0].Sealed + "</td><td>" + $mp[0].LastModified + "</td><td>" + $mp[0].TimeCreated + "</td></tr>"
	}
	$ReportOutput += "</table>"
	$ReportOutput += "</div>"
	
	#
	#
	# !!! END MANAGEMENT PACK - OPSMGR !!!
	#
	#
	
	#
	#
	# !!! MANAGEMENT GROUP - OPSMGR !!!
	#
	#
	
	$MGOverviewImport = Import-CSV "$CSVFileLocation`\MG_Overview.csv"
	$ReportOutput += "<div id='managementGroup' class='tabcontent'>"
	$ReportOutput += "<h3>Management Group(s) Overview</h3>"
	$ReportOutput += "<table style='width: 300px;'><th>Management Group Name</th><th>Management Server Count</th><th>Gateway Count</th><th>Agent Count</th><th>Agent's Pending</th><th>Unix/Linux Count</th><th>Network Device Count</th>"
	foreach ($line in $MGOverviewImport)
	{
		$ReportOutput += "<tr><td>" + $line[0].MG_Name + "</td><td>" + $line[0].MS_Count + "</td><td>" + $line[0].GW_Count + "</td><td>" + $line[0].Agent_Count + "</td><td>" + $line[0].Agent_Pending + "</td><td>" + $line[0].Unix_Count + "</td><td>" + $line[0].NetworkDevice_Count + "</td></tr>"
	}
	$ReportOutput += "</table>"
	
	$MGGlobalSettingsImport = Import-CSV "$CSVFileLocation`\MG_GlobalSettings.csv"
	$ReportOutput += "<h3>Management Group(s) Global Settings</h3>"
	$ReportOutput += "<table style='width: 300px;'><th>Property</th><th>Setting Value</th>"
	foreach ($line in $MGGlobalSettingsImport)
	{
		$ReportOutput += "<tr><td>" + $line[0].Property + "</td><td>" + $line[0].SettingValue + "</td></tr>"
	}
	$ReportOutput += "</table>"
	
	$MGUserRolesImport = Import-CSV "$CSVFileLocation`\MG_UserRoles.csv"
	$ReportOutput += "<h3>Management Group User Roles</h3>"
	$ReportOutput += "<table style='width: 300px;'><th>Description</th><th>Role Member</th>"
	foreach ($line in $MGUserRolesImport)
	{
		$ReportOutput += "<tr><td>" + $line[0].Description + "</td><td>" + $line[0].RoleMember + "</td></tr>"
	}
	$ReportOutput += "</table>"
	
	$MGResourcePoolImport = Import-CSV "$CSVFileLocation`\MG_ResourcePools.csv"
	$ReportOutput += "<h3>Management Group Resource Pools</h3>"
	$ReportOutput += "<table style='width: 300px;'><th>Resource Pool</th><th>Member</th>"
	foreach ($line in $MGResourcePoolImport)
	{
		$ReportOutput += "<tr><td>" + $line[0].ResourcePool + "</td><td>" + $line[0].Member + "</td></tr>"
	}
	$ReportOutput += "</table>"
	$ReportOutput += "</div>"
	
	#
	#
	# !!! END MANAGEMENT GROUP - OPSMGR !!!
	#
	#
	
	#
	#
	# !!! INSTANCES - OPSMGR !!!
	#
	#
	
	$InstancesByHostImport = Import-CSV "$CSVFileLocation`\Instances_ByHost.csv"
	$ReportOutput += "<div id='instances' class='tabcontent'>"
	$ReportOutput += "<h3>Instances By Host</h3>"
	$ReportOutput += "<table style='width: 300px;'><th>Display Name</th><th>Hosted Instances</th>"
	foreach ($line in $InstancesByHostImport)
	{
		$ReportOutput += "<tr><td>" + $line[0].DisplayName + "</td><td>" + $line[0].HostedInstances + "</td></tr>"
	}
	$ReportOutput += "</table>"
	
	$InstancesByTypeImport = Import-CSV "$CSVFileLocation`\Instances_ByType.csv"
	$ReportOutput += "<h3>Instances By Type</h3>"
	$ReportOutput += "<table style='width: 300px;'><th>Type Name</th><th>Number of Entities by Type</th>"
	foreach ($line in $InstancesByTypeImport)
	{
		$ReportOutput += "<tr><td>" + $line[0].TypeName + "</td><td>" + $line[0].NumEntitiesByType + "</td></tr>"
	}
	$ReportOutput += "</table>"
	
	$InstancesByTypeMTImport = Import-CSV "$CSVFileLocation`\Instances_ByType_MT.csv"
	$ReportOutput += "<h3>Instances By Type MT</h3>"
	$ReportOutput += "<table style='width: 300px;'><th>MT Table Name</th><th>Row Count</th>"
	foreach ($line in $InstancesByTypeMTImport)
	{
		$ReportOutput += "<tr><td>" + $line[0].MT_TableName + "</td><td>" + $line[0].RowCount + "</td></tr>"
	}
	$ReportOutput += "</table>"
	
	$InstancesByTypeAndHostImport = Import-CSV "$CSVFileLocation`\Instances_ByTypeAndHost.csv"
	$ReportOutput += "<h3>Instances By Type And Host</h3>"
	$ReportOutput += "<table style='width: 300px;'><th>Display Name</th><th>Hosted Instances</th><th>Typed Entity Name</th>"
	foreach ($line in $InstancesByTypeAndHostImport)
	{
		$ReportOutput += "<tr><td>" + $line[0].DisplayName + "</td><td>" + $line[0].HostedInstances + "</td><td>" + $line[0].TypedEntityName + "</td></tr>"
	}
	$ReportOutput += "</table>"
	
	$InstancesTotalBMEImport = Import-CSV "$CSVFileLocation`\Instances_TotalBME.csv"
	$ReportOutput += "<h3>Instances Total BME</h3>"
	$ReportOutput += "<table style='width: 300px;'><th>Total BME</th>"
	foreach ($line in $InstancesTotalBMEImport)
	{
		$ReportOutput += "<tr><td>" + $line[0].Column1 + "</td></tr>"
	}
	$ReportOutput += "</table>"
	$ReportOutput += "</div>"
	
	#
	#
	# !!! END INSTANCES - OPSMGR !!!
	#
	#
	
	#
	#
	# !!! MANAGEMENT SERVER - OPSMGR !!!
	#
	#
	
	$ManagementServersImport = Import-CSV "$CSVFileLocation`\ManagementServers.csv"
	$ReportOutput += "<div id='managementServers' class='tabcontent'>"
	$ReportOutput += "<h3>Management Servers</h3>"
	$ReportOutput += "<table style='width: 300px;'><th>Display Name</th><th>Is Management Server</th><th>Is Gateway</th><th>Is RHS</th><th>Version</th><th>Action Account Identity</th><th>Heartbeat Interval</th>"
	foreach ($line in $ManagementServersImport)
	{
		$ReportOutput += "<tr><td>" + $line[0].DisplayName + "</td><td>" + $line[0].IsManagementServer + "</td><td>" + $line[0].IsGateway + "</td><td>" + $line[0].IsRHS + "</td><td>" + $line[0].Version + "</td><td>" + $line[0].ActionAccountIdentity + "</td><td>" + $line[0].HeartbeatInterval + "</td></tr>"
	}
	$ReportOutput += "</table>"
	$ReportOutput += "</div>"
	
	#
	#
	# !!! END MANAGEMENT SERVER - OPSMGR !!!
	#
	#
	
	#
	#
	# !!! STATE VIEW - OPSMGR !!!
	#
	#
	
	# State Changes by Day
	$StateByDayImport = Import-CSV "$CSVFileLocation`\State_ByDay.csv"
	$ReportOutput += "<div id='stateData' class='tabcontent'>"
	$ReportOutput += "<h3>State Changes by Day</h3>"
	$ReportOutput += "<table style='width: 300px;'><th>Day Generated</th><th>State Changes Per Day</th>"
	foreach ($line in $StateByDayImport)
	{
		$ReportOutput += "<tr><td>" + $line[0].DayGenerated + "</td><td>" + $line[0].StateChangesPerDay + "</td></tr>"
	}
	$ReportOutput += "</table>"
	
	# State Changes by Monitor
	
	$StateByMonitorImport = Import-CSV "$CSVFileLocation`\State_ByMonitor.csv"
	$ReportOutput += "<h3>State Changes by Monitor</h3>"
	$ReportOutput += "<table style='width: 300px;'><th>Number of State Changes</th><th>Monitor Display Name</th><th>Monitor ID Name</th><th>Target Class</th>"
	foreach ($line in $StateByMonitorImport)
	{
		$ReportOutput += "<tr><td>" + $line[0].NumStateChanges + "</td><td>" + $line[0].MonitorDisplayName + "</td><td>" + $line[0].MonitorIdName + "</td><td>" + $line[0].TargetClass + "</td></tr>"
	}
	$ReportOutput += "</table>"
	
	#State Change by Monitor - 7 Days
	
	$StateByMonitor7DayImport = Import-CSV "$CSVFileLocation`\State_ByMonitor_7days.csv"
	$ReportOutput += "<h3>State Changes by Monitor - 7 Days</h3>"
	$ReportOutput += "<table style='width: 300px;'><th>Number of State Changes</th><th>Monitor Display Name</th><th>Monitor ID Name</th><th>Target Class</th>"
	foreach ($line in $StateByMonitor7DayImport)
	{
		$ReportOutput += "<tr><td>" + $line[0].NumStateChanges + "</td><td>" + $line[0].MonitorDisplayName + "</td><td>" + $line[0].MonitorIdName + "</td><td>" + $line[0].TargetClass + "</td></tr>"
	}
	$ReportOutput += "</table>"
	
	# State Change by Monitor and Day
	
	$StateByMonitorAndDayImport = Import-CSV "$CSVFileLocation`\State_ByMonitorAndDay.csv"
	$ReportOutput += "<h3>State Changes by Monitor and Day</h3>"
	$ReportOutput += "<table style='width: 300px;'><th>Day</th><th>Monitor Name</th><th>Total State Changes</th>"
	foreach ($line in $StateByMonitor7DayImport)
	{
		$ReportOutput += "<tr><td>" + $line[0].Day + "</td><td>" + $line[0].MonitorName + "</td><td>" + $line[0].TotalStateChanges + "</td></tr>"
	}
	$ReportOutput += "</table>"
	$ReportOutput += "</div>"
	
	#
	#
	# !!! END STATE CHANGE VIEW - OPSMGR !!!
	#
	#
	
	#
	#
	# !!! AGGREGATION - OPSMGR DW !!!
	#
	#
	
	$DWAggregationHistoryImport = Import-CSV "$CSVFileLocation`\DW_AggregationHistory.csv"
	$ReportOutputDW += "<div id='aggregation' class='tabcontent'>"
	$ReportOutputDW += "<h3>DW Aggregation History</h3>"
	$ReportOutputDW += "<table style='width: 300px;'><th>Dataset Default Name</th><th>Aggregation Date/Time</th><th>Aggregation Type ID</th><th>First Aggregation Start Date/Time</th><th>First Aggregation Duration in Seconds</th><th>Last Aggregation Start Date/Time</th><th>Last Aggregation Duration in Seconds</th><th>Dirty Ind</th><th>Data Last Recieved Date/Time</th><th>Aggregation Count</th>"
	foreach ($line in $DWAggregationHistoryImport)
	{
		$ReportOutputDW += "<tr><td>" + $line[0].DatasetDefaultName + "</td><td>" + $line[0].AggregationDateTime + "</td><td>" + $line[0].AggregationTypeId + "</td><td>" + $line[0].FirstAggregationStartDateTime + "</td><td>" + $line[0].FirstAggregationDurationSeconds + "</td><td>" + $line[0].LastAggregationStartDateTime + "</td><td>" + $line[0].LastAggregationDurationSeconds + "</td><td>" + $line[0].DirtyInd + "</td><td>" + $line[0].DataLastReceivedDateTime + "</td><td>" + $line[0].AggregationCount + "</td></tr>"
	}
	$ReportOutputDW += "</table>"
	
	$DWAggregationStatusImport = Import-CSV "$CSVFileLocation`\DW_AggregationStatus.csv"
	$ReportOutputDW += "<h3>DW Aggregation Status</h3>"
	$ReportOutputDW += "<table style='width: 300px;'><th>Schema Name</th><th>Aggregation Type</th><th>Time UTC - Next to Aggregate</th><th>Number of Outstanding Aggregations</th><th>Max Data Age in Days</th><th>Last Grooming Date & Time</th><th>Debug Level</th><th>Dataset ID</th>"
	foreach ($line in $DWAggregationStatusImport)
	{
		$ReportOutputDW += "<tr><td>" + $line[0].SchemaName + "</td><td>" + $line[0].AggregationType + "</td><td>" + $line[0].TimeUTC_NextToAggregate + "</td><td>" + $line[0].Count_OutstandingAggregations + "</td><td>" + $line[0].MaxDataAgeDays + "</td><td>" + $line[0].LastGroomingDateTime + "</td><td>" + $line[0].DebugLevel + "</td><td>" + $line[0].DataSetId + "</td></tr>"
	}
	$ReportOutputDW += "</table>"
	$ReportOutputDW += "</div>"
	
	#
	#
	# !!! END AGGREGATION - OPSMGR DW !!!
	#
	#
	
	#
	#
	# !!! DATABASE & TABLE SIZE PROP - OPSMGR DW !!!
	#
	#
	
	$DWSQLDBSizeImport = Import-CSV "$CSVFileLocation`\SQL_DBSize_DW.csv"
	$ReportOutputDW += "<div id='databaseSize' class='tabcontent'>"
	$ReportOutputDW += "<h3>Data Warehouse DB Size</h3>"
	$ReportOutputDW += "<table style='width: 300px;'><th>File Size (MB)</th><th>Space Used (MB)</th><th>Free Space (MB)</th><th>Auto Grow</th><th>Auth Growth MB Max </th><th>Name</th><th>Path</th><th>File ID</th>"
	foreach ($line in $DWSQLDBSizeImport)
	{
		$ReportOutputDW += "<tr><td>" + $line[0].'FileSize(MB)' + "</td><td>" + $line[0].'SpaceUsed(MB)' + "</td><td>" + $line[0].'FreeSpace(MB)' + "</td><td>" + $line[0].AutoGrow + "</td><td>" + $line[0].'AutoGrowthMB(MAX)' + "</td><td>" + $line[0].NAME + "</td><td>" + $line[0].PATH + "</td><td>" + $line[0].FILEID + "</td></tr>"
	}
	$ReportOutputDW += "</table>"
	
	
	$DWDatasetSpaceImport = Import-CSV "$CSVFileLocation`\DW_DatasetSpace.csv"
	$ReportOutputDW += "<h3>Data Warehouse Dataset Space</h3>"
	$ReportOutputDW += "<table style='width: 300px;'><th>Dataset Name</th><th>Aggregation Type Name</th><th>Max Data Age in Days</th><th>Size (GB)</th><th>Percent of DW</th>"
	foreach ($line in $DWDatasetSpaceImport)
	{
		$ReportOutputDW += "<tr><td>" + $line[0].DatasetName + "</td><td>" + $line[0].AggregationTypeName + "</td><td>" + $line[0].MaxDataAgeDays + "</td><td>" + $line[0].SizeGB + "</td><td>" + $line[0].PercentOfDW + "</td></tr>"
	}
	$ReportOutputDW += "</table>"
	$ReportOutputDW += "</div>"
	
	#
	#
	# !!! END DATABASE & TABLE SIZE PROP - OPGSMGR DW !!!
	#
	#
	
	#
	#
	# !!! RETENTION - OPSMGR DW !!!
	#
	#
	
	$DWRetentionImport = Import-CSV "$CSVFileLocation`\DW_Retention.csv"
	$ReportOutputDW += "<div id='retention' class='tabcontent'>"
	$ReportOutputDW += "<h3>Data Warehouse Retention</h3>"
	$ReportOutputDW += "<table style='width: 300px;'><th>Dataset Name</th><th>Aggregation Type</th><th>Retention Time in Days</th><th>Last Grooming Date/Time</th><th>Grooming Internal in Minutes</th>"
	foreach ($line in $DWRetentionImport)
	{
		$ReportOutputDW += "<tr><td>" + $line[0].'Dataset Name' + "</td><td>" + $line[0].'Agg Type 0=raw, 20=Hourly, 30=Daily' + "</td><td>" + $line[0].'Retention Time in Days' + "</td><td>" + $line[0].LastGroomingDateTime + "</td><td>" + $line[0].GroomingIntervalMinutes + "</td></tr>"
	}
	$ReportOutputDW += "</table>"
	$ReportOutputDW += "</div>"
	
	#
	#
	# !!! END RETENTION - OPSMGR DW!!!
	#
	#
	
	#
	#
	# !!! INDEX MAINT - OPSMGR DW !!!
	#
	#
	
	$DWIndexMaintImport = Import-CSV "$CSVFileLocation`\DW_Index_Maint.csv"
	$ReportOutputDW += "<div id='indexMaint' class='tabcontent'>"
	$ReportOutputDW += "<h3>Data Warehouse Index Maint</h3>"
	$ReportOutputDW += "<table style='width: 300px;'><th>Base Table Name</th><th>Optimization Start Date/Time</th><th>Optimization Duration in Seconds</th><th>Before Avg. Fragmentation in Percent</th><th>After Avg. Fragmentation in Percent</th><th>Optimization Method</th><th>Online Rebuild Last Performance Date/Time</th>"
	foreach ($line in $DWIndexMaintImport)
	{
		$ReportOutputDW += "<tr><td>" + $line[0].basetablename + "</td><td>" + $line[0].optimizationstartdatetime + "</td><td>" + $line[0].optimizationdurationseconds + "</td><td>" + $line[0].beforeavgfragmentationinpercent + "</td><td>" + $line[0].afteravgfragmentationinpercent + "</td><td>" + $line[0].optimizationmethod + "</td><td>" + $line[0].onlinerebuildlastperformeddatetime + "</td></tr>"
	}
	$ReportOutputDW += "</table>"
	$ReportOutputDW += "</div>"
	
	#
	#
	# !!! END INDEX MAINT - OPSMGR DW!!!
	#
	#
	
	#
	#
	# !!! LARGE TABLES - OPSMGR DW !!!
	#
	#
	
	$DWLargeTablesImport = Import-CSV "$CSVFileLocation`\SQL_LargeTables_DW.csv"
	$ReportOutputDW += "<div id='largeTables' class='tabcontent'>"
	$ReportOutputDW += "<h3>Data Warehouse Large Tables</h3>"
	$ReportOutputDW += "<table style='width: 300px;'><th>Table Name</th><th>Total Space (MB)</th><th>Data Size (MB)</th><th>Index Size (MB)</th><th>Unused (MB)</th><th>Row Count</th><th>l1</th><th>Schema</th>"
	foreach ($line in $DWLargeTablesImport)
	{
		$ReportOutputDW += "<tr><td>" + $line[0].Tablename + "</td><td>" + $line[0].'TotalSpace(MB)' + "</td><td>" + $line[0].'DataSize(MB)' + "</td><td>" + $line[0].'IndexSize(MB)' + "</td><td>" + $line[0].'Unused(MB)' + "</td><td>" + $line[0].Rowcount + "</td><td>" + $line[0].l1 + "</td><td>" + $line[0].Schema + "</td></tr>"
	}
	$ReportOutputDW += "</table>"
	$ReportOutputDW += "</div>"
	
	#
	#
	# !!! END LARGE TABLES - OPSMGR DW!!!
	#
	#
	
	#
	#
	# !!! STAGING/BACKUPS - OPSMGR DW !!!
	#
	#
	
	$DWStagingBacklogImport = Import-CSV "$CSVFileLocation`\DW_StagingBacklog.csv"
	$ReportOutputDW += "<div id='stagingBackups' class='tabcontent'>"
	$ReportOutputDW += "<h3>Data Warehouse Staging Backlog</h3>"
	$ReportOutputDW += "<table style='width: 300px;'><th>Table Name</th><th>Count</th>"
	foreach ($line in $DWStagingBacklogImport)
	{
		$ReportOutputDW += "<tr><td>" + $line[0].TableName + "</td><td>" + $line[0].Count + "</td></tr>"
	}
	$ReportOutputDW += "</table>"
	$ReportOutputDW += "</div>"
	
	#
	#
	# !!! END STAGING/BACKUPS - OPSMGR DW!!!
	#
	#
	
	
	$EndTime = Get-Date
	$TotalRunTime = $EndTime - $StartTime
	
	# Add the time to the Report
	$ReportOutput += "<br>"
	$ReportOutput += "<p>Total Script Run Time: $($TotalRunTime.hours) hrs $($TotalRunTime.minutes) min $($TotalRunTime.seconds) sec</p>"
	
	# Add the time to the DW Report
	$ReportOutputDW += "<br>"
	$ReportOutputDW += "<p>Total Script Run Time: $($TotalRunTime.hours) hrs $($TotalRunTime.minutes) min $($TotalRunTime.seconds) sec</p>"
	
	# Close the Body of the Report
	$ReportOutput += "</body>"
	$ReportOutputDW += "</body>"
	
	#Write-OutputToLog "Saving HTML Report to $ReportPath"
	#Write-OutputToLog "Saving DW HTML Report to $ReportPathDW"
	
	# Save the Final Report to a File
	ConvertTo-HTML -head $Head -body "$ReportOutput" | Out-File $ReportPath
	ConvertTo-HTML -head $HeadDW -body "$ReportOutputDW" | Out-File $ReportPathDW
	return $true
}

			Write-Host "  Generating Report Webpage to be viewed in a Web Browser" -NoNewLine -ForegroundColor Cyan
			Write-Host "-" -NoNewline -ForegroundColor Green
			$reportWebpageCompleted = Report-Webpage
			do { Write-Host "-" -NoNewline -ForegroundColor Green; sleep 1 }
			until ($reportWebpageCompleted)
			Write-Host "> Completed!`n" -NoNewline -ForegroundColor Green
		}
	}
	catch
	{
		"$(Time-Stamp)Unable to run HTML Report due to Error: $($error[0])" | Out-File $OutputPath\Error.log -Append
		Write-Warning $error[0]
	}
	Write-Progress -Activity "Collection Running" -Status "Progress-> 99%" -PercentComplete 99
	write-output " "
	write-output "================================`n   Wrapping Up`n================================"
	Write-Host "Moving stuff around and zipping everything up for easy transport" -ForegroundColor Gray
	Function Wrap-Up
{
	param
	(
		[switch]$BuildPipeline
	)
	$jobstatus = $null
	$jobstatus = (Get-Job -Name "getEvent*", "getPerf*")
	foreach ($job in $jobstatus)
	{
		if ($job.State -eq 'Running')
		{
			Write-Host "`nWaiting for SQL Query `'$($job.Name -split "-" | Select-Object -Last 1)`' to finish gathering data." -ForegroundColor Gray -NoNewline
		}
		do
		{
			if ($job.State -eq 'Running')
			{
				Write-Host "." -ForegroundColor Gray -NoNewline
				sleep 5
			}
		}
		until ($job.State -ne 'Running')
	}
	Write-Host " "
	try
	{
		if (Test-Path $OutputPath\*.csv)
		{
			New-Item -Type Directory -Path $OutputPath\CSV -ErrorAction SilentlyContinue | out-null
			Move-Item $OutputPath\*.csv $OutputPath\CSV
		}
		if ((Get-ChildItem $OutputPath\CSV).Count -eq 0)
		{
			Remove-Item $OutputPath\CSV -Force -ErrorAction SilentlyContinue | out-null
		}
		$FolderNames = (Get-ChildItem "$OutputPath`\*.evtx" | Select-Object Name -ExpandProperty Name) | % { $_.split(".")[0] } | Select -Unique
		$FolderNames | % {
			$currentServer = $_
			mkdir "$OutputPath`\Event Logs\$currentServer" | Out-Null;
			mkdir "$OutputPath`\Event Logs\$currentServer`\localemetadata\" | Out-Null;
			$Eventlogs = Get-ChildItem "$OutputPath`\$currentServer`*.evtx"
			foreach ($eventlog in $Eventlogs)
			{
				Move-Item $eventlog -Destination "$OutputPath`\Event Logs\$currentServer" | Out-Null
			}
			
			$EventlogsMetadata = Get-ChildItem "$OutputPath`\$currentServer`*.mta"
			foreach ($eventlogmetadata in $EventlogsMetadata)
			{
				Move-Item $eventlogmetadata -Destination "$OutputPath`\Event Logs\$currentServer`\localemetadata\" | Out-Null
			}
		}
	}
	catch
	{
		Write-Warning $_
	}
	$fullfilepath = $OutputPath + '\datacollector-' + ((((Get-Content "$currentPath" | Select-String '.VERSION' -Context 1) | Select -First 1 $_.Context.PostContext) -split "`n")[2]).Trim().Split(" ")[0]
	#Write file to show script version in the SDC Results File.

	try
	{
		$EndTime = "$(Get-Date -Format "MMMM dd, yyyy @ h:mm tt") $((Get-TimeZone -ErrorAction SilentlyContinue).DisplayName)"
	}
	catch
	{
		$EndTime = "$(Get-Date -Format "MMMM dd, yyyy @ h:mm tt") (unknown time zone)"
	}
	@"
Script Running as User:
$env:USERDOMAIN\$env:USERNAME

Script Running on Server:
$env:COMPUTERNAME

Script Path:
$ScriptPath\$scriptname

Parameters Passed to Script:
$ScriptPassedArgs

Parameters Passed to Function:
$FunctionPassedArgs

Script execution started on date/time:
$StartTime

Script execution completed on date/time:
$EndTime
"@ | Out-File $fullfilepath -Force
	
	#Zip output
	$Error.Clear()
	Write-Host "Creating zip file of all output data." -ForegroundColor DarkCyan
	[Reflection.Assembly]::LoadWithPartialName("System.IO.Compression.FileSystem") | Out-Null
	[System.AppDomain]::CurrentDomain.GetAssemblies() | Out-Null
	$SourcePath = Resolve-Path $OutputPath
	[string]$filedate = (Get-Date).tostring("MM_dd_yyyy_hh-mm-tt")
	if ($CaseNumber)
	{
		[string]$destfilename = "SDC_Results_$CaseNumber_$filedate`.zip"
	}
	elseif ($BuildPipeline)
	{
		[string]$destfilename = "SDC_Results.zip"
	}
	else
	{
		[string]$destfilename = "SDC_Results_$filedate`.zip"
	}
	
	[string]$global:destfile = "$ScriptPath\$destfilename"
	IF (Test-Path $global:destfile)
	{
		#File exists from a previous run on the same day - delete it
		Write-Host "-Found existing zip file: $destfile.`n Deleting existing file." -ForegroundColor DarkGreen
		Remove-Item $global:destfile -Force
	}
	$compressionLevel = [System.IO.Compression.CompressionLevel]::Optimal
	$includebasedir = $false
	[System.IO.Compression.ZipFile]::CreateFromDirectory($SourcePath, $destfile, $compressionLevel, $includebasedir) | Out-Null
	IF ($Error)
	{
		Write-Error "Error creating zip file."
	}
	ELSE
	{
		Write-Host "-Cleaning up output directory." -ForegroundColor DarkCyan
		Remove-Item $OutputPath -Recurse
		Write-Host "--Saved zip file to: $global:destfile." -ForegroundColor Cyan
	}
}

	Wrap-Up -BuildPipeline:$BuildPipeline
	Write-Progress -Activity "Collection Running" -Status "Progress-> 100%" -PercentComplete 100
	Write-Host "-Script has completed" -ForegroundColor Green -NoNewline
	$x = 1
	do { $x++; Write-Host "." -NoNewline -ForegroundColor Green; Sleep 1 }
	until ($x -eq 3)
	Write-Output " "
	Write-Warning "Exiting script..."
	start C:\Windows\explorer.exe -ArgumentList "/select, $destfile"
	exit 0
}

if ($BuildPipeline -or $CheckTLS -or $CheckCertificates -or $GetEventLogs -or $MSInfo32 -or $AssumeYes -or $ExportMPs -or $CaseNumber -or $Servers -or $GenerateHTML -or $GetRulesAndMonitors -or $GetRunAsAccounts -or $All -or $GPResult -or $SQLLogs -or $NoSQLPermission -or $SQLOnly -or $SQLOnlyOpsDB -or $SQLOnlyDW -or $CheckPorts -or $GetLocalSecurity -or $LeastAmount -or $GetNotificationSubscriptions -or $AdditionalEventLogs -or $GetInstalledSoftware -or $GetSPN -or $ManagementServers -or $SkipConnectivityTests -or $GetConfiguration -or $SkipGeneralInformation -or $SkipSQLQueries -or $CheckGroupPolicy -or $GetInstallLogs -or $SCXAgents -or $SCXUsername -or $SCXPassword -or $GetUserRoles)
{
	if ($all)
	{
		if ($Servers)
		{
			if ($AssumeYes)
			{
				Start-ScomDataCollector -Servers $Servers -GetRulesAndMonitors -GetRunAsAccounts -CheckTLS -CheckCertificates -GetEventLogs -ExportMPs -GPResult -SQLLogs -CheckPorts -GetLocalSecurity -PingAll -AdditionalEventLogs $AdditionalEventLogs -GetInstalledSoftware -GetSPN -AssumeYes -ManagementServers:$ManagementServers -GetConfiguration -CheckGroupPolicy -GetInstallLogs -SkipConnectivityTests:$SkipConnectivityTests -SkipGeneralInformation:$SkipGeneralInformation -SkipSQLQueries:$SkipSQLQueries -MSInfo32:$MSInfo32 -GetUserRoles:$GetUserRoles
			}
			Start-ScomDataCollector -Servers $Servers -GetRulesAndMonitors -GetRunAsAccounts -CheckTLS -CheckCertificates -GetEventLogs -ExportMPs -GPResult -SQLLogs -CheckPorts -GetLocalSecurity -PingAll -AdditionalEventLogs $AdditionalEventLogs -GetInstalledSoftware -GetSPN -ManagementServers:$ManagementServers -GetConfiguration -CheckGroupPolicy -GetInstallLogs -SkipConnectivityTests:$SkipConnectivityTests -SkipGeneralInformation:$SkipGeneralInformation -SkipSQLQueries:$SkipSQLQueries -MSInfo32:$MSInfo32 -GetUserRoles:$GetUserRoles
		}
		if ($AssumeYes)
		{
			Start-ScomDataCollector -GetRulesAndMonitors -GetRunAsAccounts -CheckTLS -CheckCertificates -GetEventLogs -ExportMPs -GPResult -SQLLogs -CheckPorts -GetLocalSecurity -AdditionalEventLogs $AdditionalEventLogs -GetInstalledSoftware -GetSPN -AssumeYes -ManagementServers:$ManagementServers -GetConfiguration -CheckGroupPolicy -GetInstallLogs -SkipConnectivityTests:$SkipConnectivityTests -SkipGeneralInformation:$SkipGeneralInformation -SkipSQLQueries:$SkipSQLQueries -MSInfo32:$MSInfo32 -GetUserRoles:$GetUserRoles
		}
		if ($SCXAgents)
		{
			if ($AssumeYes)
			{
				Start-ScomDataCollector -Servers $Servers -GetRulesAndMonitors -GetRunAsAccounts -CheckTLS -CheckCertificates -GetEventLogs -ExportMPs -GPResult -SQLLogs -CheckPorts -GetLocalSecurity -PingAll -AdditionalEventLogs $AdditionalEventLogs -GetInstalledSoftware -GetSPN -AssumeYes -ManagementServers:$ManagementServers -GetConfiguration -CheckGroupPolicy -GetInstallLogs -SkipConnectivityTests:$SkipConnectivityTests -SkipGeneralInformation:$SkipGeneralInformation -SkipSQLQueries:$SkipSQLQueries -SCXAgents $SCXAgents -SCXUsername $SCXUsername -SCXPassword $SCXPassword -MSInfo32:$MSInfo32 -GetUserRoles:$GetUserRoles
			}
			Start-ScomDataCollector -Servers $Servers -GetRulesAndMonitors -GetRunAsAccounts -CheckTLS -CheckCertificates -GetEventLogs -ExportMPs -GPResult -SQLLogs -CheckPorts -GetLocalSecurity -PingAll -AdditionalEventLogs $AdditionalEventLogs -GetInstalledSoftware -GetSPN -ManagementServers:$ManagementServers -GetConfiguration -CheckGroupPolicy -GetInstallLogs -SkipConnectivityTests:$SkipConnectivityTests -SkipGeneralInformation:$SkipGeneralInformation -SkipSQLQueries:$SkipSQLQueries -SCXAgents $SCXAgents -SCXUsername $SCXUsername -SCXPassword $SCXPassword -MSInfo32:$MSInfo32 -GetUserRoles:$GetUserRoles
		}
		Start-ScomDataCollector -GetRulesAndMonitors -GetRunAsAccounts -CheckTLS -CheckCertificates -GetEventLogs -GPResult -ExportMPs -SQLLogs -CheckPorts -GetLocalSecurity -AdditionalEventLogs $AdditionalEventLogs -GetInstalledSoftware -GetSPN -ManagementServers:$ManagementServers -GetConfiguration -CheckGroupPolicy -GetInstallLogs -SkipConnectivityTests:$SkipConnectivityTests -SkipGeneralInformation:$SkipGeneralInformation -SkipSQLQueries:$SkipSQLQueries -MSInfo32:$MSInfo32 -GetUserRoles:$GetUserRoles
	}
	else
	{
		Start-ScomDataCollector -Servers $Servers -GetRunAsAccounts:$GetRunAsAccounts -CheckTLS:$CheckTLS -CheckCertificates:$CheckCertificates -GetEventLogs:$GetEventLogs -GetUserRoles:$GetUserRoles -GetRulesAndMonitors:$GetRulesAndMonitors -GPResult:$GPResult -ManagementServers:$ManagementServers -MSInfo32:$MSInfo32 -SQLLogs:$SQLLogs -ExportMPs:$ExportMPs -CaseNumber:$CaseNumber -GenerateHTML:$GenerateHTML -AssumeYes:$AssumeYes -NoSQLPermission:$NoSQLPermission -SQLOnly:$SQLOnly -SQLOnlyOpsDB:$SQLOnlyOpsDB -SQLOnlyDW:$SQLOnlyDW -CheckPorts:$CheckPorts -GetLocalSecurity:$GetLocalSecurity -LeastAmount:$LeastAmount -GetNotificationSubscriptions:$GetNotificationSubscriptions -AdditionalEventLogs $AdditionalEventLogs -GetInstalledSoftware:$GetInstalledSoftware -GetSPN:$GetSPN -SkipConnectivityTests:$SkipConnectivityTests -SkipGeneralInformation:$SkipGeneralInformation -SkipSQLQueries:$SkipSQLQueries -GetConfiguration:$GetConfiguration -CheckGroupPolicy:$CheckGroupPolicy -GetInstallLogs:$GetInstallLogs -BuildPipeline:$BuildPipeline -SCXAgents $SCXAgents -SCXUsername $SCXUsername -SCXPassword $SCXPassword
	}
}
elseif (!$SQLOnly)
{
	#Start Built-in Menu
	Function DataCollector-Menu
{
	function Main-Menu
	{
		param (
			[string]$Title = 'System Center Operations Manager: Data Collector'
		)
		Clear-Host
		Write-Host "================ " -NoNewline -ForegroundColor DarkYellow
		sleep -Milliseconds 120
		Write-Host $Title -ForegroundColor Cyan -NoNewline
		sleep -Milliseconds 120
		Write-Host " ================" -ForegroundColor DarkYellow
		sleep -Milliseconds 120
		
		Write-Host "1" -NoNewline -ForegroundColor Green
		Write-Host ": Type `'" -NoNewline
		Write-Host "1" -NoNewline -ForegroundColor Green
		Write-Host "`' to gather as much data as possible."
		
		Write-Host "2" -NoNewline -ForegroundColor Green
		Write-Host ": Type `'" -NoNewline
		Write-Host "2" -NoNewline -ForegroundColor Green
		Write-Host "`' to gather information from specific Windows Agent(s)."
		
		Write-Host "3" -NoNewline -ForegroundColor Green
		Write-Host ": Type `'" -NoNewline
		Write-Host "3" -NoNewline -ForegroundColor Green
		Write-Host "`' to gather minimum information."
		
		Write-Host "4" -NoNewline -ForegroundColor Green
		Write-Host ": Type `'" -NoNewline
		Write-Host "4" -NoNewline -ForegroundColor Green
		Write-Host "`' to update to the latest release of the Data Collector on GitHub."
		
		Write-Host "Q" -NoNewline -ForegroundColor Green
		Write-Host ": Type `'" -NoNewline
		Write-Host "Q" -NoNewline -ForegroundColor Green
		Write-Host "`' to Quit."
	}
	function Sub-Menu-All
	{
		param (
			[string]$Title = 'System Center Operations Manager: Data Collector - Gather Everything'
		)
		Clear-Host
		Write-Host "================ " -NoNewline -ForegroundColor DarkYellow
		sleep -Milliseconds 120
		Write-Host $Title -ForegroundColor Cyan -NoNewline
		sleep -Milliseconds 120
		Write-Host " ================" -ForegroundColor DarkYellow
		sleep -Milliseconds 120
		
		Write-Host "1a" -NoNewline -ForegroundColor Green
		Write-Host ": Type `'" -NoNewline
		Write-Host "1a" -NoNewline -ForegroundColor Green
		Write-Host "`' to also gather information from specific Windows Agent(s)."
		
		Write-Host "1b" -NoNewline -ForegroundColor Green
		Write-Host ": Type `'" -NoNewline
		Write-Host "1b" -NoNewline -ForegroundColor Green
		Write-Host "`' to continue and start script."
		
		Write-Host "1c" -NoNewline -ForegroundColor Green
		Write-Host ": Type `'" -NoNewline
		Write-Host "1c" -NoNewline -ForegroundColor Green
		Write-Host "`' to run the SCOM Linux Data Collector."
		
		Write-Host " Q" -NoNewline -ForegroundColor Green
		Write-Host ": Type `'" -NoNewline
		Write-Host "Q" -NoNewline -ForegroundColor Green
		Write-Host "`' to Quit."
	}
	function Sub-Menu-SpecificAgents
	{
		param (
			[string]$Title = 'System Center Operations Manager: Data Collector - Specific Agents'
		)
		Clear-Host
		Write-Host "================ " -NoNewline -ForegroundColor DarkYellow
		sleep -Milliseconds 120
		Write-Host $Title -ForegroundColor Cyan -NoNewline
		sleep -Milliseconds 120
		Write-Host " ================" -ForegroundColor DarkYellow
		sleep -Milliseconds 120
		
		Write-Host "2a" -NoNewline -ForegroundColor Green
		Write-Host ": Type `'" -NoNewline
		Write-Host "2a" -NoNewline -ForegroundColor Green
		Write-Host "`' to gather minimum information from Windows Agent(s) + All Management Servers in Management Group."
		
		Write-Host "2b" -NoNewline -ForegroundColor Green
		Write-Host ": Type `'" -NoNewline
		Write-Host "2b" -NoNewline -ForegroundColor Green
		Write-Host "`' to gather Multiple types of information from Windows Agent(s) + All Management Servers in Management Group."
		
		Write-Host "2c" -NoNewline -ForegroundColor Green
		Write-Host ": Type `'" -NoNewline
		Write-Host "2c" -NoNewline -ForegroundColor Green
		Write-Host "`' to gather Event Logs Only (Application, System, Operations Manager) from Windows Agent(s) + All Management Servers in Management Group."
		
		Write-Host "2d" -NoNewline -ForegroundColor Green
		Write-Host ": Type `'" -NoNewline
		Write-Host "2d" -NoNewline -ForegroundColor Green
		Write-Host "`' to gather Run As Accounts Only + get minimum information from specific Windows Agent(s) and All Management Servers in Management Group."
		
		Write-Host "2e" -NoNewline -ForegroundColor Green
		Write-Host ": Type `'" -NoNewline
		Write-Host "2e" -NoNewline -ForegroundColor Green
		Write-Host "`' to check Certificates Only for specific Windows Agent(s) + All Management Servers in Management Group."
		
		Write-Host "2f" -NoNewline -ForegroundColor Green
		Write-Host ": Type `'" -NoNewline
		Write-Host "2f" -NoNewline -ForegroundColor Green
		Write-Host "`' to check Check TLS against specific Windows Agent(s) and All Management Servers in Management Group."
		
		Write-Host "2g" -NoNewline -ForegroundColor Green
		Write-Host ": Type `'" -NoNewline
		Write-Host "2g" -NoNewline -ForegroundColor Green
		Write-Host "`' to check Export Management Packs + get minimum information from specific Windows Agent(s) and All Management Servers in Management Group."
		
		Write-Host "2h" -NoNewline -ForegroundColor Green
		Write-Host ": Type `'" -NoNewline
		Write-Host "2h" -NoNewline -ForegroundColor Green
		Write-Host "`' to export Rules and Monitors + get minimum information from specific Windows Agent(s) and All Management Servers in Management Group."
		
		Write-Host "2i" -NoNewline -ForegroundColor Green
		Write-Host ": Type `'" -NoNewline
		Write-Host "2i" -NoNewline -ForegroundColor Green
		Write-Host "`' to export MSInfo32 information from specific Windows Agent(s) + All Management Servers in Management Group."
		
		Write-Host "2j" -NoNewline -ForegroundColor Green
		Write-Host ": Type `'" -NoNewline
		Write-Host "2j" -NoNewline -ForegroundColor Green
		Write-Host "`' to export Group Policy Results from specific Windows Agent(s) and All Management Servers in Management Group."
		
		Write-Host "2k" -NoNewline -ForegroundColor Green
		Write-Host ": Type `'" -NoNewline
		Write-Host "2k" -NoNewline -ForegroundColor Green
		Write-Host "`' to gather SQL Error Logs + get minimum information from specific Windows Agent(s) and All Management Servers in Management Group."
		
		Write-Host "2l" -NoNewline -ForegroundColor Green
		Write-Host ": Type `'" -NoNewline
		Write-Host "2l" -NoNewline -ForegroundColor Green
		Write-Host "`' to ping the Management Server(s) in Management Group from each Windows Agent(s) to verify connectability (output at bottom of `'General Information.txt`' file in zip output) + get minimum information from specific Windows Agent(s) and All Management Servers in Management Group."
		
		Write-Host " Q" -NoNewline -ForegroundColor Green
		Write-Host ": Type `'" -NoNewline
		Write-Host "Q" -NoNewline -ForegroundColor Green
		Write-Host "`' to Quit."
	}
	
	
	do
	{
		Main-Menu
		$selection = $null
		$selection = Read-Host "Please make a selection"
		switch ($selection)
		{
			'1' {
				
				do
				{
					Sub-Menu-All
					Write-Host "`n   NOTE:" -ForegroundColor Yellow
					Write-Host "    Option 1 does not gather the following: " -NoNewLine
					Write-Host "-MSInfo32" -NoNewLine -ForegroundColor DarkGreen
					Write-Host " and " -NoNewLine
					Write-Host "-GetNotificationSubscriptions" -NoNewLine -ForegroundColor DarkGreen
					Write-Host "`n     To gather these you will need to run the data collector with its switches:`n   " -NoNewLine
					Write-Host "   .\DataCollector-v#.#.#.ps1" -NoNewLine -ForegroundColor Yellow
					Write-Host " -All -MSInfo32 -GetNotificationSubscriptions`n`n" -NoNewLine -ForegroundColor Gray
					$selection = $null
					$selection = Read-Host "Please make a selection"
					switch ($selection)
					{
						'1a'
						{
							[string]$Servers = $null
							[string]$Servers = Read-Host 'Please Type the Names of the Windows Agents (ex. Agent1.contoso.com, Agent2.contoso.com)'
							do
							{
								$PermissionforSQL = Read-Host "Does the following account have permissions to run SQL queries against the Operations Manager DB and Data Warehouse DB? `'$runningas`' Y/N"
							}
							until ($PermissionforSQL -eq "y" -or $PermissionforSQL -eq "n")
							if ($PermissionforSQL -like 'y')
							{
								if ($Servers -ne $null)
								{
									Start-ScomDataCollector -Servers $Servers -GetRulesAndMonitors -GetRunAsAccounts -CheckTLS -CheckCertificates -GetEventLogs -ExportMPs -GPResult -SQLLogs -CheckPorts -GetLocalSecurity -GetInstalledSoftware -GetSPN -AssumeYes -GetConfiguration -CheckGroupPolicy -GetInstallLogs -GetUserRoles
								}
								else
								{
									Start-ScomDataCollector -GetRulesAndMonitors -GetRunAsAccounts -CheckTLS -CheckCertificates -GetEventLogs -ExportMPs -GPResult -SQLLogs -CheckPorts -GetLocalSecurity -GetInstalledSoftware -GetSPN -GetConfiguration -CheckGroupPolicy -GetInstallLogs -Yes -GetUserRoles
								}
							}
							if ($PermissionforSQL -like 'n')
							{
								if ($Servers -ne $null)
								{
									Start-ScomDataCollector -Servers $Servers -GetRulesAndMonitors -GetRunAsAccounts -CheckTLS -CheckCertificates -GetEventLogs -ExportMPs -GPResult -SQLLogs -CheckPorts -GetLocalSecurity -GetInstalledSoftware -GetSPN -GetConfiguration -CheckGroupPolicy -GetInstallLogs -NoSQLPermission -GetUserRoles
								}
								else
								{
									Start-ScomDataCollector -GetRulesAndMonitors -GetRunAsAccounts -CheckTLS -CheckCertificates -GetEventLogs -ExportMPs -GPResult -SQLLogs -CheckPorts -GetLocalSecurity -GetInstalledSoftware -GetSPN -GetConfiguration -CheckGroupPolicy -GetInstallLogs -NoSQLPermission -GetUserRoles
								}
							}
						}
						'1b'
						{
							do
							{
								$PermissionforSQL = Read-Host "Does the following account have permissions to run SQL queries against the Operations Manager DB and Data Warehouse DB? `'$runningas`' Y/N"
							}
							until ($PermissionforSQL -eq "y" -or $PermissionforSQL -eq "n")
							if ($PermissionforSQL -like 'y')
							{
								Start-ScomDataCollector -GetRulesAndMonitors -GetRunAsAccounts -CheckTLS -CheckCertificates -GetEventLogs -ExportMPs -GPResult -SQLLogs -CheckPorts -GetLocalSecurity -GetInstalledSoftware -GetSPN -AssumeYes -GetConfiguration -CheckGroupPolicy -GetInstallLogs -GetUserRoles
							}
							if ($PermissionforSQL -like 'n')
							{
								Start-ScomDataCollector -GetRulesAndMonitors -GetRunAsAccounts -CheckTLS -CheckCertificates -GetEventLogs -ExportMPs -GPResult -SQLLogs -CheckPorts -GetLocalSecurity -GetInstalledSoftware -GetSPN -GetConfiguration -CheckGroupPolicy -GetInstallLogs -NoSQLPermission -GetUserRoles
							}
							
						}
						'1c'
						{
							do
							{
								$PermissionforSQL = Read-Host "Does the following account have permissions to run SQL queries against the Operations Manager DB and Data Warehouse DB? `'$runningas`' Y/N"
							}
							until ($PermissionforSQL -eq "y" -or $PermissionforSQL -eq "n")
							do
							{
								$SCXAgents = Read-Host "Type the SCX Agents (comma separated) you would like to run the Linux Data Collector against"
								$SCXUsername = Read-Host "Type the Username to be used to gather data via SSH (preferably high user rights)"
								$SCXPassword = Read-Host "Type the Password to be used to gather data via SSH (optional)" -AsSecureString
							}
							until (($SCXAgents -and $SCXUsername) -or ($SCXAgents -and $SCXUsername -and $SCXPassword))
							if ($PermissionforSQL -like 'y')
							{
								Start-ScomDataCollector -GetRulesAndMonitors -GetRunAsAccounts -CheckTLS -CheckCertificates -GetEventLogs -ExportMPs -GPResult -SQLLogs -CheckPorts -GetLocalSecurity -GetInstalledSoftware -GetSPN -AssumeYes -GetConfiguration -CheckGroupPolicy -GetInstallLogs -SCXAgents $SCXAgents -SCXUsername $SCXUsername -SCXPassword $SCXPassword -GetUserRoles
							}
							if ($PermissionforSQL -like 'n')
							{
								Start-ScomDataCollector -GetRulesAndMonitors -GetRunAsAccounts -CheckTLS -CheckCertificates -GetEventLogs -ExportMPs -GPResult -SQLLogs -CheckPorts -GetLocalSecurity -GetInstalledSoftware -GetSPN -GetConfiguration -CheckGroupPolicy -GetInstallLogs -SCXAgents $SCXAgents -SCXUsername $SCXUsername -SCXPassword $SCXPassword -NoSQLPermission -GetUserRoles
							}
							
						}
					}
				}
				until ($selection)
			}
			'2'
			{
				do
				{
					Sub-Menu-SpecificAgents
					$selection = $null
					$selection = Read-Host "Please make a selection"
					switch ($selection)
					{
						'2a' {
							[string]$Servers = $null
							[string]$Servers = Read-Host 'Please Type the Names of the Windows Agents (ex. Agent1.contoso.com, Agent2.contoso.com)'
							do
							{
								$PermissionforSQL = Read-Host "Does the following account have permissions to run SQL queries against the Operations Manager DB and Data Warehouse DB? `'$runningas`' Y/N"
							}
							until ($PermissionforSQL -eq "y" -or $PermissionforSQL -eq "n")
							if ($PermissionforSQL -like 'y')
							{
								if ($Servers -ne $null)
								{
									Start-ScomDataCollector -Servers $Servers -Yes
								}
								else
								{
									Start-ScomDataCollector -Yes
								}
							}
							if ($PermissionforSQL -like 'n')
							{
								if ($Servers -ne $null)
								{
									Start-ScomDataCollector -Servers $Servers -NoSQLPermission
								}
								else
								{
									Start-ScomDataCollector -NoSQLPermission
								}
							}
						}
						'2b' {
							Write-Host 'DO NOT USE :: NOT WORKING :: Options to choose from:
	graa = Run As Accounts
	gel = Event Logs
	cc = Check Certificates
	ct = Check TLS
	em = Export Management Packs
	gram = Get Rules and Monitors
	mi32 = Gather MSInfo32
	gp = Get Currently Configured Group Policy
	sql = Gather SQL Error Logs
'
							[array]$argumentsforscript = Read-Host "Type your selection(s) seperated by spaces ex:`'gel gp sql`'"
							[string]$Servers = $null
							[string]$Servers = Read-Host 'Please Type the Names of the Windows Agents (ex. Agent1.contoso.com, Agent2.contoso.com)'
							do
							{
								$PermissionforSQL = Read-Host "Does the following account have permissions to run SQL queries against the Operations Manager DB and Data Warehouse DB? `'$runningas`' Y/N"
							}
							until ($PermissionforSQL -eq "y" -or $PermissionforSQL -eq "n")
							if ($PermissionforSQL -like 'y')
							{
								if ($Servers -ne $null)
								{
									Start-ScomDataCollector -Servers $Servers ($argumentsforscript | % { [boolean]$_ }) -Yes
								}
								else
								{
									Start-ScomDataCollector $($argumentsforscript) -Yes
								}
								
							}
							if ($PermissionforSQL -like 'n')
							{
								if ($Servers -ne $null)
								{
									Start-ScomDataCollector -Servers $Servers $($argumentsforscript) -NoSQLPermission
								}
								else
								{
									Start-ScomDataCollector $($argumentsforscript) -NoSQLPermission
								}
							}
							
						}
						'2c' {
							[string]$Servers = $null
							[string]$Servers = Read-Host 'Please Type the Names of the Windows Agents (ex. Agent1.contoso.com, Agent2.contoso.com)'
							do
							{
								$PermissionforSQL = Read-Host "Does the following account have permissions to run SQL queries against the Operations Manager DB and Data Warehouse DB? `'$runningas`' Y/N"
							}
							until ($PermissionforSQL -eq "y" -or $PermissionforSQL -eq "n")
							if ($PermissionforSQL -like 'y')
							{
								if ($Servers -ne $null)
								{
									Start-ScomDataCollector -Servers $Servers -gel -Yes
								}
								else
								{
									Start-ScomDataCollector -gel -Yes
								}
								
							}
							if ($PermissionforSQL -like 'n')
							{
								if ($Servers -ne $null)
								{
									Start-ScomDataCollector -Servers $Servers -gel -NoSQLPermission
								}
								else
								{
									Start-ScomDataCollector -gel -NoSQLPermission
								}
							}
							
						}
						'2d' {
							[string]$Servers = $null
							[string]$Servers = Read-Host 'Please Type the Names of the Windows Agents (ex. Agent1.contoso.com, Agent2.contoso.com)'
							do
							{
								$PermissionforSQL = Read-Host "Does the following account have permissions to run SQL queries against the Operations Manager DB and Data Warehouse DB? `'$runningas`' Y/N"
							}
							until ($PermissionforSQL -eq "y" -or $PermissionforSQL -eq "n")
							if ($PermissionforSQL -like 'y')
							{
								if ($Servers -ne $null)
								{
									Start-ScomDataCollector -Servers $Servers -graa -Yes
								}
								else
								{
									Start-ScomDataCollector -graa -Yes
								}
								
							}
							if ($PermissionforSQL -like 'n')
							{
								if ($Servers -ne $null)
								{
									Start-ScomDataCollector -Servers $Servers -graa -NoSQLPermission
								}
								else
								{
									Start-ScomDataCollector -graa -NoSQLPermission
								}
							}
						}
						'2e' {
							[string]$Servers = $null
							[string]$Servers = Read-Host 'Please Type the Names of the Windows Agents (ex. Agent1.contoso.com, Agent2.contoso.com)'
							do
							{
								$PermissionforSQL = Read-Host "Does the following account have permissions to run SQL queries against the Operations Manager DB and Data Warehouse DB? `'$runningas`' Y/N"
							}
							until ($PermissionforSQL -eq "y" -or $PermissionforSQL -eq "n")
							if ($PermissionforSQL -like 'y')
							{
								if ($Servers -ne $null)
								{
									Start-ScomDataCollector -Servers $Servers -cc -Yes
								}
								else
								{
									Start-ScomDataCollector -cc -Yes
								}
								
							}
							if ($PermissionforSQL -like 'n')
							{
								if ($Servers -ne $null)
								{
									Start-ScomDataCollector -Servers $Servers -cc -NoSQLPermission
								}
								else
								{
									Start-ScomDataCollector -cc -NoSQLPermission
								}
							}
						}
						'2f' {
							[string]$Servers = $null
							[string]$Servers = Read-Host 'Please Type the Names of the Windows Agents (ex. Agent1.contoso.com, Agent2.contoso.com)'
							do
							{
								$PermissionforSQL = Read-Host "Does the following account have permissions to run SQL queries against the Operations Manager DB and Data Warehouse DB? `'$runningas`' Y/N"
							}
							until ($PermissionforSQL -eq "y" -or $PermissionforSQL -eq "n")
							if ($PermissionforSQL -like 'y')
							{
								if ($Servers -ne $null)
								{
									Start-ScomDataCollector -Servers $Servers -ct -Yes
								}
								else
								{
									Start-ScomDataCollector -ct -Yes
								}
								
							}
							if ($PermissionforSQL -like 'n')
							{
								if ($Servers -ne $null)
								{
									Start-ScomDataCollector -Servers $Servers -ct -NoSQLPermission
								}
								else
								{
									Start-ScomDataCollector -ct -NoSQLPermission
								}
							}
						}
						'2g' {
							[string]$Servers = $null
							[string]$Servers = Read-Host 'Please Type the Names of the Windows Agents (ex. Agent1.contoso.com, Agent2.contoso.com)'
							do
							{
								$PermissionforSQL = Read-Host "Does the following account have permissions to run SQL queries against the Operations Manager DB and Data Warehouse DB? `'$runningas`' Y/N"
							}
							until ($PermissionforSQL -eq "y" -or $PermissionforSQL -eq "n")
							if ($PermissionforSQL -like 'y')
							{
								if ($Servers -ne $null)
								{
									Start-ScomDataCollector -Servers $Servers -em -Yes
								}
								else
								{
									Start-ScomDataCollector -em -Yes
								}
								
							}
							if ($PermissionforSQL -like 'n')
							{
								if ($Servers -ne $null)
								{
									Start-ScomDataCollector -Servers $Servers -em -NoSQLPermission
								}
								else
								{
									Start-ScomDataCollector -em -NoSQLPermission
								}
							}
						}
						'2h' {
							[string]$Servers = $null
							[string]$Servers = Read-Host 'Please Type the Names of the Windows Agents (ex. Agent1.contoso.com, Agent2.contoso.com)'
							do
							{
								$PermissionforSQL = Read-Host "Does the following account have permissions to run SQL queries against the Operations Manager DB and Data Warehouse DB? `'$runningas`' Y/N"
							}
							until ($PermissionforSQL -eq "y" -or $PermissionforSQL -eq "n")
							if ($PermissionforSQL -like 'y')
							{
								if ($Servers -ne $null)
								{
									Start-ScomDataCollector -Servers $Servers -gram -Yes
								}
								else
								{
									Start-ScomDataCollector -gram -Yes
								}
								
							}
							if ($PermissionforSQL -like 'n')
							{
								if ($Servers -ne $null)
								{
									Start-ScomDataCollector -Servers $Servers -gram -NoSQLPermission
								}
								else
								{
									Start-ScomDataCollector -gram -NoSQLPermission
								}
							}
						}
						'2i' {
							[string]$Servers = $null
							[string]$Servers = Read-Host 'Please Type the Names of the Windows Agents (ex. Agent1.contoso.com, Agent2.contoso.com)'
							do
							{
								$PermissionforSQL = Read-Host "Does the following account have permissions to run SQL queries against the Operations Manager DB and Data Warehouse DB? `'$runningas`' Y/N"
							}
							until ($PermissionforSQL -eq "y" -or $PermissionforSQL -eq "n")
							if ($PermissionforSQL -like 'y')
							{
								if ($Servers -ne $null)
								{
									Start-ScomDataCollector -Servers $Servers -mi32 -Yes
								}
								else
								{
									Start-ScomDataCollector -mi32 -Yes
								}
								
							}
							if ($PermissionforSQL -like 'n')
							{
								if ($Servers -ne $null)
								{
									Start-ScomDataCollector -Servers $Servers -mi32 -NoSQLPermission
								}
								else
								{
									Start-ScomDataCollector -mi32 -NoSQLPermission
								}
							}
						}
						'2j' {
							[string]$Servers = $null
							[string]$Servers = Read-Host 'Please Type the Names of the Windows Agents (ex. Agent1.contoso.com, Agent2.contoso.com)'
							do
							{
								$PermissionforSQL = Read-Host "Does the following account have permissions to run SQL queries against the Operations Manager DB and Data Warehouse DB? `'$runningas`' Y/N"
							}
							until ($PermissionforSQL -eq "y" -or $PermissionforSQL -eq "n")
							if ($PermissionforSQL -like 'y')
							{
								if ($Servers -ne $null)
								{
									Start-ScomDataCollector -Servers $Servers -gp -Yes
								}
								else
								{
									Start-ScomDataCollector -gp -Yes
								}
								
							}
							if ($PermissionforSQL -like 'n')
							{
								if ($Servers -ne $null)
								{
									Start-ScomDataCollector -Servers $Servers -gp -NoSQLPermission
								}
								else
								{
									Start-ScomDataCollector -gp -NoSQLPermission
								}
							}
						}
						'2k' {
							[string]$Servers = $null
							[string]$Servers = Read-Host 'Please Type the Names of the Windows Agents (ex. Agent1.contoso.com, Agent2.contoso.com)'
							do
							{
								$PermissionforSQL = Read-Host "Does the following account have permissions to run SQL queries against the Operations Manager DB and Data Warehouse DB? `'$runningas`' Y/N"
							}
							until ($PermissionforSQL -eq "y" -or $PermissionforSQL -eq "n")
							if ($PermissionforSQL -like 'y')
							{
								if ($Servers -ne $null)
								{
									Start-ScomDataCollector -Servers $Servers -sql -Yes
								}
								else
								{
									Start-ScomDataCollector -sql -Yes
								}
								
							}
							if ($PermissionforSQL -like 'n')
							{
								if ($Servers -ne $null)
								{
									Start-ScomDataCollector -Servers $Servers -sql -NoSQLPermission
								}
								else
								{
									Start-ScomDataCollector -sql -NoSQLPermission
								}
							}
						}
						'2l' {
							[string]$Servers = $null
							[string]$Servers = Read-Host 'Please Type the Names of the Windows Agents (ex. Agent1.contoso.com, Agent2.contoso.com)'
							do
							{
								$PermissionforSQL = Read-Host "Does the following account have permissions to run SQL queries against the Operations Manager DB and Data Warehouse DB? `'$runningas`' Y/N"
							}
							until ($PermissionforSQL -eq "y" -or $PermissionforSQL -eq "n")
							if ($PermissionforSQL -like 'y')
							{
								if ($Servers -ne $null)
								{
									Start-ScomDataCollector -Servers $Servers -PingAll -Yes
								}
								else
								{
									Start-ScomDataCollector -PingAll -Yes
								}
								
							}
							if ($PermissionforSQL -like 'n')
							{
								if ($Servers -ne $null)
								{
									Start-ScomDataCollector -Servers $Servers -PingAll -NoSQLPermission
								}
								else
								{
									Start-ScomDataCollector -PingAll -NoSQLPermission
								}
							}
						}
					}
				}
				until ($selection)
			} '3' {
				do
				{
					$PermissionforSQL = Read-Host "Does the following account have permissions to run SQL queries against the Operations Manager DB and Data Warehouse DB? `'$runningas`' Y/N"
				}
				until ($PermissionforSQL -eq "y" -or $PermissionforSQL -eq "n")
				if ($PermissionforSQL -like 'y')
				{
					Start-ScomDataCollector -Yes
				}
				if ($PermissionforSQL -like 'n')
				{
					Start-ScomDataCollector -NoSQLPermission
				}
			} '4' {
				function Invoke-AutoUpdater
{
	BEGIN
	{
		Function Time-Stamp
		{
			$TimeStamp = Get-Date -Format "MM/dd/yyyy hh:mm:ss tt"
			return "$TimeStamp - "
		}
	}
	PROCESS
	{
		try
		{
			# Get Latest Release from the GitHub Repo
			$githubLatestRelease = (Invoke-WebRequest -ErrorAction Stop -Uri 'https://api.github.com/repos/blakedrumm/SCOM-Scripts-and-SQL/releases/latest').Content | ConvertFrom-Json
		}
		catch
		{
			Write-Host "$(Time-Stamp)Unable to access the website: " -NoNewline
			Write-Host 'https://api.github.com/repos/blakedrumm/SCOM-Scripts-and-SQL/releases/latest' -ForegroundColor Red
			sleep 8
			break
		}
		$latestRelease = $githubLatestRelease.tag_name
		try
		{
			if ($PSScriptRoot)
			{
				$content = Get-Content "$PSScriptRoot\DataCollector*.ps1" -ErrorAction Stop
			}
			else
			{
				$content = Get-Content ".\DataCollector*.ps1" -ErrorAction Stop
			}
		}
		catch
		{
			Write-Warning "$(Time-Stamp)Unable to access the DataCollector.ps1 or DataCollector*.ps1 file ($pwd). Make sure you are running this in the script directory!"
			do
			{
				$answer = Read-Host "$(Time-Stamp)Attempt to download latest release from the internet? (Y/N)"
			}
			until ($answer -eq 'y' -or $answer -eq 'n')
			if ($answer -eq 'n')
			{
				Write-Host "$(Time-Stamp)Stopping script"
				break
			}
			else
			{
				Write-Host "$(Time-Stamp)Latest SCOM Data Collector Release: " -NoNewline
				Write-Host $latestRelease -ForegroundColor Green
				Write-Host "$(Time-Stamp)Finding asset: SCOM-DataCollector.zip"
				$githubAsset = ($githubLatestRelease.Assets.Where{ $_.Name -eq 'SCOM-DataCollector.zip' })
				$zipFilePath = "$(if ($content) { ($content).PSParentPath[0] }
					else { $pwd })\$($githubAsset.Name)"
				Write-Host "$(Time-Stamp)Downloading asset: SCOM-DataCollector.zip -> $zipFilePath"
				Invoke-WebRequest $githubAsset.browser_download_url -OutFile $zipFilePath
				Write-Host "$(Time-Stamp)Expanding zip archive: SCOM-DataCollector.zip"
				Expand-Archive -LiteralPath $zipFilePath -DestinationPath $(if ($content) { ($content).PSParentPath[0] }
					else { $pwd }) -Force
				Write-Host "$(Time-Stamp)Cleaning up zip release..."
				Remove-Item -LiteralPath $zipFilePath -Force | Out-Null
			}
		}
		# Get the version of the current script
		if (!$answer)
		{
			$scriptVersion = ($content | Select-String .VERSION -Context 0, 1 | ForEach-Object { $_.Context.DisplayPostContext }).Trim().Split(" - ") | Select-Object -First 1
			
			# If the latest release and script version don't match
			if ([version]$scriptVersion.Replace('v', '') -gt [version]($latestRelease).Replace('v-', ''))
			{
				Write-Host "$(Time-Stamp)You are currently on a development build of $($content.PSChildName[0]): " -NoNewline
				Write-Host $scriptVersion -ForegroundColor Green
			}
			elseif ([version]$scriptVersion.Replace('v', '') -lt [version]($latestRelease).Replace('v-', ''))
			{
				Write-Host "$(Time-Stamp)Current Script Version: " -NoNewline
				Write-Host $($scriptVersion.Insert(1, '-')) -ForegroundColor Red
				Write-Host "$(Time-Stamp)Latest SCOM Data Collector Release: " -NoNewline
				Write-Host $latestRelease -ForegroundColor Green
				Write-Host "$(Time-Stamp)Removing all current script items / queries to replace with the newer versions."
				Get-ChildItem -Path .\ -Include DataCollector*, DataCollector-v*.*.*, Queries | Remove-Item -Recurse -Force
				
				Write-Host "$(Time-Stamp)Finding asset: SCOM-DataCollector.zip"
				$githubAsset = ($githubLatestRelease.Assets.Where{ $_.Name -eq 'SCOM-DataCollector.zip' })
				$zipFilePath = "$(($content).PSParentPath[0])\$($githubAsset.Name)"
				Write-Host "$(Time-Stamp)Downloading asset: SCOM-DataCollector.zip -> $zipFilePath"
				Invoke-WebRequest $githubAsset.browser_download_url -OutFile $zipFilePath
				Write-Host "$(Time-Stamp)Expanding zip archive: SCOM-DataCollector.zip"
				Expand-Archive -LiteralPath $zipFilePath -DestinationPath ($content).PSParentPath[0] -Force
				Write-Host "$(Time-Stamp)Cleaning up zip release..."
				Remove-Item -LiteralPath $zipFilePath -Force | Out-Null
			}
			else
			{
				Write-Host "$(Time-Stamp)You are currently on the latest update of $($content.PSChildName[0]): " -NoNewline
				Write-Host $latestRelease -ForegroundColor Green
			}
		}
	}
	END
	{
		Write-Host "$(Time-Stamp)Script completed!"
		Start-Sleep -Seconds 8
	}
}
Invoke-AutoUpdater

				exit 0
			}
		}
		
	}
	until ($selection -ne $null)
}

	DataCollector-Menu
}
# or you can run the below to gather minimal data.
#Start-ScomDataCollector
$issueOccurred = "$(Time-Stamp)ISSUE: Something is wrong, Script has been stopped"
Write-Host $issueOccurred -ForegroundColor Yellow
$issueOccurred | Out-File $OutputPath\Error.log -Append
$x = 1
do { $x++; Write-Host "." -NoNewline -ForegroundColor Yellow; Sleep 1 }
until ($x -eq 3)
Write-Output " "
Write-Warning "Exiting script..."
exit 1
