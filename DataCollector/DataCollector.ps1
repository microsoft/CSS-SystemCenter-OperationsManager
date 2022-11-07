<#
	.SYNOPSIS
		This script collects data from your SCOM Environment that can be very helpful in troubleshooting.
	
	.DESCRIPTION
		For full support, please run this script from a Management Server..
	
	.PARAMETER AcceptEula
		Accept the End User License Agreement. The EULA acceptance state is stored in HKCU (HKCU:\Software\Microsoft\CESDiagnosticTools\SCOM Data Collector EULA Accepted) to prevent multiple popups every time the tool is launched.
	
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
		v3.8.15 - November 3rd, 2022
#>
[CmdletBinding()]
[OutputType([string])]
param
(
	[Parameter(Position = 1,
			   HelpMessage = 'Accept the End User License Agreement. The EULA acceptance state is stored in HKCU (HKCU:\Software\Microsoft\CESDiagnosticTools\SCOM Data Collector EULA Accepted) to prevent multiple popups every time the tool is launched.')]
	[Alias('ae')]
	[switch]$AcceptEula,
	[Parameter(Mandatory = $false,
			   Position = 2,
			   HelpMessage = 'Gather additional Event Logs. (Example: -AdditionalEventLogs Security)')]
	[array]$AdditionalEventLogs,
	[Parameter(Mandatory = $false,
			   Position = 3,
			   HelpMessage = 'Allows you to Specify all the Switches Available for use. (Except: MSInfo32)')]
	[switch]$All,
	[Parameter(Mandatory = $false,
			   Position = 4,
			   HelpMessage = 'This will allow you to not be prompted for anything.')]
	[Alias('yes')]
	[switch]$AssumeYes,
	[Parameter(Mandatory = $false,
			   Position = 5,
			   HelpMessage = 'Azure DevOps Build Pipeline switch to output the SDC Results file without any File Date or CaseNumber.',
			   DontShow = $true)]
	[Alias('bp')]
	[switch]$BuildPipeline,
	[Parameter(Mandatory = $false,
			   Position = 6,
			   HelpMessage = 'Add an Optional Case Number to the Output of the Zip File.')]
	[Alias('case')]
	[string]$CaseNumber,
	[Parameter(Mandatory = $false,
			   Position = 7,
			   HelpMessage = 'Check the Certificates for validity for SCOM use, output in TXT format.')]
	[Alias('cc')]
	[switch]$CheckCertificates,
	[Parameter(Position = 8,
			   HelpMessage = 'Check the group policy for each server listed in -Servers as well as any Management Servers and SQL Servers.')]
	[switch]$CheckGroupPolicy,
	[Parameter(Mandatory = $false,
			   Position = 9,
			   HelpMessage = 'Check SCOM Common Ports against every Management Server in Management Group and SQL Servers, as well as any -Servers listed.')]
	[switch]$CheckPorts,
	[Parameter(Mandatory = $false,
			   Position = 10,
			   HelpMessage = 'Check for TLS 1.2 Readiness, output in TXT format.')]
	[Alias('ct')]
	[switch]$CheckTLS,
	[Parameter(Mandatory = $false,
			   Position = 11,
			   HelpMessage = 'Export all Sealed/Unsealed MPs.')]
	[Alias('em')]
	[switch]$ExportMPs,
	[Parameter(Mandatory = $false,
			   Position = 12,
			   HelpMessage = 'Generate a HTML Report Page { EXPERIMENTAL }')]
	[Alias('html')]
	[switch]$GenerateHTML,
	[Parameter(Position = 13,
			   HelpMessage = 'Gather the Registry / ConfigService.config Configuration of the Management Servers.')]
	[switch]$GetConfiguration,
	[Parameter(Mandatory = $false,
			   Position = 14,
			   HelpMessage = 'Gather Event Logs with the localemetadata to ensure that you are able to open the Event log from any machine.')]
	[Alias('gel')]
	[switch]$GetEventLogs,
	[Parameter(Mandatory = $false,
			   Position = 15,
			   HelpMessage = 'Gather software installed from Management Servers / Agents / Gateways.')]
	[switch]$GetInstalledSoftware,
	[Parameter(Position = 16)]
	[switch]$GetInstallLogs,
	[Parameter(Mandatory = $false,
			   Position = 17,
			   HelpMessage = 'Get Local Administrators and Logon Rights.')]
	[Alias('gls')]
	[switch]$GetLocalSecurity,
	[Parameter(Mandatory = $false,
			   Position = 18,
			   HelpMessage = 'A description of the GetNotificationSubscriptions parameter.')]
	[switch]$GetNotificationSubscriptions,
	[Parameter(Mandatory = $false,
			   Position = 19,
			   HelpMessage = 'A description of the GetRulesAndMonitors parameter.')]
	[Alias('gram')]
	[switch]$GetRulesAndMonitors,
	[Parameter(Mandatory = $false,
			   Position = 20,
			   HelpMessage = 'Get RunAs Accounts that are set on each Management Server.')]
	[Alias('graa')]
	[switch]$GetRunAsAccounts,
	[Parameter(Mandatory = $false,
			   Position = 21,
			   HelpMessage = 'Get SPN Configuration from Active Directory.')]
	[Alias('gs')]
	[switch]$GetSPN,
	[Parameter(Position = 22,
			   HelpMessage = 'Gathers User Roles and the configurations from SCOM.')]
	[switch]$GetUserRoles,
	[Parameter(Mandatory = $false,
			   Position = 23,
			   HelpMessage = 'Gathers Group Policy Results to verify Harmful Policies are not present, Generated in HTML and TXT Format.')]
	[Alias('gp')]
	[switch]$GPResult,
	[Parameter(Mandatory = $false,
			   Position = 24,
			   HelpMessage = 'Pull the least amount of data from SCOM.')]
	[switch]$LeastAmount,
	[Parameter(Mandatory = $false,
			   Position = 25,
			   HelpMessage = 'Only run data gathering against the Management Servers specified here.')]
	[Alias('ms')]
	[array]$ManagementServers,
	[Parameter(Mandatory = $false,
			   Position = 26,
			   HelpMessage = 'Export MSInfo32 for viewing in TXT Format.')]
	[Alias('mi32')]
	[switch]$MSInfo32,
	[Parameter(Position = 27,
			   HelpMessage = 'Internal Script Switch.')]
	[switch]$NoSQLPermission,
	[Parameter(Mandatory = $false,
			   Position = 28,
			   HelpMessage = 'Ping every Management Server, including servers mentioned in -Servers switch.')]
	[switch]$PingAll,
	[Parameter(Mandatory = $false,
			   Position = 29,
			   HelpMessage = 'Linux/Unix Agents you want to gather data from, via Bash Script that is transmitted via ssh.')]
	[Alias('LinuxAgents')]
	[Array]$SCXAgents,
	[Parameter(Mandatory = $false,
			   Position = 30,
			   HelpMessage = 'The password you would like to use for SCX Agent SSH Authentication.')]
	[Alias('LinuxPassword')]
	[string]$SCXPassword,
	[Parameter(Mandatory = $false,
			   Position = 31,
			   HelpMessage = 'The username you would like to use for SCX Agent SSH Authentication.')]
	[Alias('LinuxUsername')]
	[string]$SCXUsername,
	[Parameter(Mandatory = $false,
			   Position = 32,
			   HelpMessage = 'Set additional servers to run checks against. This can be Agents or Gateways, they have to be in the same domain at this time.')]
	[Alias('s')]
	[Array]$Servers,
	[Parameter(Position = 33,
			   HelpMessage = 'Skip the tests for remote accessibility, use this if you know your environment passes these tests. DO NOT USE THIS IF YOU ARENT SURE!')]
	[Alias('sct')]
	[switch]$SkipConnectivityTests,
	[Parameter(Position = 34,
			   HelpMessage = 'Skip the General Information file gathering.')]
	[Alias('sgi')]
	[switch]$SkipGeneralInformation,
	[Parameter(Mandatory = $false,
			   Position = 35,
			   HelpMessage = 'Skip the SQL Queries. This will leave you with much less data in the data collector. Other functions in the data collector may rely on the SQL Queries and may be missing data.')]
	[Alias('NoSQLQueries')]
	[switch]$SkipSQLQueries,
	[Parameter(Position = 36,
			   HelpMessage = 'Gather SQL Logs from OperationsManager and DataWarehouse DBs.')]
	[switch]$SQLLogs,
	[Parameter(Mandatory = $false,
			   Position = 37,
			   HelpMessage = 'Run only SQL Queries and Output to CSV.')]
	[switch]$SQLOnly,
	[Parameter(Mandatory = $false,
			   Position = 38,
			   HelpMessage = 'Internal Script Switch.',
			   DontShow = $true)]
	[switch]$SQLOnlyDW,
	[Parameter(Mandatory = $false,
			   Position = 39,
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
	[void][System.Reflection.Assembly]::Load('System.Drawing, Version=4.0.0.0, Culture=neutral, PublicKeyToken=b03f5f7f11d50a3a')
	[void][System.Reflection.Assembly]::Load('System.Windows.Forms, Version=4.0.0.0, Culture=neutral, PublicKeyToken=b77a5c561934e089')
	
	function Show-EULAPopup($mode)
	{
		$EULA = New-Object -TypeName System.Windows.Forms.Form
		$richTextBox1 = New-Object System.Windows.Forms.RichTextBox
		$btnAcknowledge = New-Object System.Windows.Forms.Button
		$btnCancel = New-Object System.Windows.Forms.Button
		
		$EULA.SuspendLayout()
		$EULA.Name = "EULA"
		$EULA.Text = "Microsoft Diagnostic Tools End User License Agreement"
		
		$richTextBox1.Anchor = [System.Windows.Forms.AnchorStyles]::Top -bor [System.Windows.Forms.AnchorStyles]::Bottom -bor [System.Windows.Forms.AnchorStyles]::Left -bor [System.Windows.Forms.AnchorStyles]::Right
		$richTextBox1.Location = New-Object System.Drawing.Point(12, 12)
		$richTextBox1.Name = "richTextBox1"
		$richTextBox1.ScrollBars = [System.Windows.Forms.RichTextBoxScrollBars]::Vertical
		$richTextBox1.Size = New-Object System.Drawing.Size(776, 397)
		$richTextBox1.TabIndex = 0
		$richTextBox1.ReadOnly = $True
		$richTextBox1.Add_LinkClicked({ Start-Process -FilePath $_.LinkText })
		$richTextBox1.Rtf = @"
{\rtf1\ansi\ansicpg1252\deff0\nouicompat{\fonttbl{\f0\fswiss\fprq2\fcharset0 Segoe UI;}{\f1\fnil\fcharset0 Calibri;}{\f2\fnil\fcharset0 Microsoft Sans Serif;}}
{\colortbl ;\red0\green0\blue255;}
{\*\generator Riched20 10.0.19041}{\*\mmathPr\mdispDef1\mwrapIndent1440 }\viewkind4\uc1 
\pard\widctlpar\f0\fs19\lang1033 MICROSOFT SOFTWARE LICENSE TERMS\par
Microsoft Diagnostic Scripts and Utilities\par
\par
{\pict{\*\picprop}\wmetafile8\picw26\pich26\picwgoal32000\pichgoal15 
0100090000035000000000002700000000000400000003010800050000000b0200000000050000
000c0202000200030000001e000400000007010400040000000701040027000000410b2000cc00
010001000000000001000100000000002800000001000000010000000100010000000000000000
000000000000000000000000000000000000000000ffffff00000000ff040000002701ffff0300
00000000
}These license terms are an agreement between you and Microsoft Corporation (or one of its affiliates). IF YOU COMPLY WITH THESE LICENSE TERMS, YOU HAVE THE RIGHTS BELOW. BY USING THE SOFTWARE, YOU ACCEPT THESE TERMS.\par
{\pict{\*\picprop}\wmetafile8\picw26\pich26\picwgoal32000\pichgoal15 
0100090000035000000000002700000000000400000003010800050000000b0200000000050000
000c0202000200030000001e000400000007010400040000000701040027000000410b2000cc00
010001000000000001000100000000002800000001000000010000000100010000000000000000
000000000000000000000000000000000000000000ffffff00000000ff040000002701ffff0300
00000000
}\par
\pard 
{\pntext\f0 1.\tab}{\*\pn\pnlvlbody\pnf0\pnindent0\pnstart1\pndec{\pntxta.}}
\fi-360\li360 INSTALLATION AND USE RIGHTS. Subject to the terms and restrictions set forth in this license, Microsoft Corporation (\ldblquote Microsoft\rdblquote ) grants you (\ldblquote Customer\rdblquote  or \ldblquote you\rdblquote ) a non-exclusive, non-assignable, fully paid-up license to use and reproduce the script or utility provided under this license (the "Software"), solely for Customer\rquote s internal business purposes, to help Microsoft troubleshoot issues with one or more Microsoft products, provided that such license to the Software does not include any rights to other Microsoft technologies (such as products or services). \ldblquote Use\rdblquote  means to copy, install, execute, access, display, run or otherwise interact with the Software. \par
\pard\widctlpar\par
\pard\widctlpar\li360 You may not sublicense the Software or any use of it through distribution, network access, or otherwise. Microsoft reserves all other rights not expressly granted herein, whether by implication, estoppel or otherwise. You may not reverse engineer, decompile or disassemble the Software, or otherwise attempt to derive the source code for the Software, except and to the extent required by third party licensing terms governing use of certain open source components that may be included in the Software, or remove, minimize, block, or modify any notices of Microsoft or its suppliers in the Software. Neither you nor your representatives may use the Software provided hereunder: (i) in a way prohibited by law, regulation, governmental order or decree; (ii) to violate the rights of others; (iii) to try to gain unauthorized access to or disrupt any service, device, data, account or network; (iv) to distribute spam or malware; (v) in a way that could harm Microsoft\rquote s IT systems or impair anyone else\rquote s use of them; (vi) in any application or situation where use of the Software could lead to the death or serious bodily injury of any person, or to physical or environmental damage; or (vii) to assist, encourage or enable anyone to do any of the above.\par
\par
\pard\widctlpar\fi-360\li360 2.\tab DATA. Customer owns all rights to data that it may elect to share with Microsoft through using the Software. You can learn more about data collection and use in the help documentation and the privacy statement at {{\field{\*\fldinst{HYPERLINK https://aka.ms/privacy }}{\fldrslt{https://aka.ms/privacy\ul0\cf0}}}}\f0\fs19 . Your use of the Software operates as your consent to these practices.\par
\pard\widctlpar\par
\pard\widctlpar\fi-360\li360 3.\tab FEEDBACK. If you give feedback about the Software to Microsoft, you grant to Microsoft, without charge, the right to use, share and commercialize your feedback in any way and for any purpose.\~ You will not provide any feedback that is subject to a license that would require Microsoft to license its software or documentation to third parties due to Microsoft including your feedback in such software or documentation. \par
\pard\widctlpar\par
\pard\widctlpar\fi-360\li360 4.\tab EXPORT RESTRICTIONS. Customer must comply with all domestic and international export laws and regulations that apply to the Software, which include restrictions on destinations, end users, and end use. For further information on export restrictions, visit {{\field{\*\fldinst{HYPERLINK https://aka.ms/exporting }}{\fldrslt{https://aka.ms/exporting\ul0\cf0}}}}\f0\fs19 .\par
\pard\widctlpar\par
\pard\widctlpar\fi-360\li360\qj 5.\tab REPRESENTATIONS AND WARRANTIES. Customer will comply with all applicable laws under this agreement, including in the delivery and use of all data. Customer or a designee agreeing to these terms on behalf of an entity represents and warrants that it (i) has the full power and authority to enter into and perform its obligations under this agreement, (ii) has full power and authority to bind its affiliates or organization to the terms of this agreement, and (iii) will secure the permission of the other party prior to providing any source code in a manner that would subject the other party\rquote s intellectual property to any other license terms or require the other party to distribute source code to any of its technologies.\par
\pard\widctlpar\par
\pard\widctlpar\fi-360\li360\qj 6.\tab DISCLAIMER OF WARRANTY. THE SOFTWARE IS PROVIDED \ldblquote AS IS,\rdblquote  WITHOUT WARRANTY OF ANY KIND, EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL MICROSOFT OR ITS LICENSORS BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF THE SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.\par
\pard\widctlpar\qj\par
\pard\widctlpar\fi-360\li360\qj 7.\tab LIMITATION ON AND EXCLUSION OF DAMAGES. IF YOU HAVE ANY BASIS FOR RECOVERING DAMAGES DESPITE THE PRECEDING DISCLAIMER OF WARRANTY, YOU CAN RECOVER FROM MICROSOFT AND ITS SUPPLIERS ONLY DIRECT DAMAGES UP TO U.S. $5.00. YOU CANNOT RECOVER ANY OTHER DAMAGES, INCLUDING CONSEQUENTIAL, LOST PROFITS, SPECIAL, INDIRECT, OR INCIDENTAL DAMAGES. This limitation applies to (i) anything related to the Software, services, content (including code) on third party Internet sites, or third party applications; and (ii) claims for breach of contract, warranty, guarantee, or condition; strict liability, negligence, or other tort; or any other claim; in each case to the extent permitted by applicable law. It also applies even if Microsoft knew or should have known about the possibility of the damages. The above limitation or exclusion may not apply to you because your state, province, or country may not allow the exclusion or limitation of incidental, consequential, or other damages.\par
\pard\widctlpar\par
\pard\widctlpar\fi-360\li360 8.\tab BINDING ARBITRATION AND CLASS ACTION WAIVER. This section applies if you live in (or, if a business, your principal place of business is in) the United States.  If you and Microsoft have a dispute, you and Microsoft agree to try for 60 days to resolve it informally. If you and Microsoft can\rquote t, you and Microsoft agree to binding individual arbitration before the American Arbitration Association under the Federal Arbitration Act (\ldblquote FAA\rdblquote ), and not to sue in court in front of a judge or jury. Instead, a neutral arbitrator will decide. Class action lawsuits, class-wide arbitrations, private attorney-general actions, and any other proceeding where someone acts in a representative capacity are not allowed; nor is combining individual proceedings without the consent of all parties. The complete Arbitration Agreement contains more terms and is at {{\field{\*\fldinst{HYPERLINK https://aka.ms/arb-agreement-4 }}{\fldrslt{https://aka.ms/arb-agreement-4\ul0\cf0}}}}\f0\fs19 . You and Microsoft agree to these terms. \par
\pard\widctlpar\par
\pard\widctlpar\fi-360\li360 9.\tab LAW AND VENUE. If U.S. federal jurisdiction exists, you and Microsoft consent to exclusive jurisdiction and venue in the federal court in King County, Washington for all disputes heard in court (excluding arbitration). If not, you and Microsoft consent to exclusive jurisdiction and venue in the Superior Court of King County, Washington for all disputes heard in court (excluding arbitration).\par
\pard\widctlpar\par
\pard\widctlpar\fi-360\li360 10.\tab ENTIRE AGREEMENT. This agreement, and any other terms Microsoft may provide for supplements, updates, or third-party applications, is the entire agreement for the software.\par
\pard\sa200\sl276\slmult1\f1\fs22\lang9\par
\pard\f2\fs17\lang2057\par
}
"@
		$richTextBox1.BackColor = [System.Drawing.Color]::White
		$btnAcknowledge.Anchor = [System.Windows.Forms.AnchorStyles]::Bottom -bor [System.Windows.Forms.AnchorStyles]::Right
		$btnAcknowledge.Location = New-Object System.Drawing.Point(544, 415)
		$btnAcknowledge.Name = "btnAcknowledge";
		$btnAcknowledge.Size = New-Object System.Drawing.Size(119, 23)
		$btnAcknowledge.TabIndex = 1
		$btnAcknowledge.Text = "Accept"
		$btnAcknowledge.UseVisualStyleBackColor = $True
		$btnAcknowledge.Add_Click({ $EULA.DialogResult = [System.Windows.Forms.DialogResult]::Yes })
		
		$btnCancel.Anchor = [System.Windows.Forms.AnchorStyles]::Bottom -bor [System.Windows.Forms.AnchorStyles]::Right
		$btnCancel.Location = New-Object System.Drawing.Point(669, 415)
		$btnCancel.Name = "btnCancel"
		$btnCancel.Size = New-Object System.Drawing.Size(119, 23)
		$btnCancel.TabIndex = 2
		if ($mode -ne 0)
		{
			$btnCancel.Text = "Close"
		}
		else
		{
			$btnCancel.Text = "Decline"
		}
		$btnCancel.UseVisualStyleBackColor = $True
		$btnCancel.Add_Click({ $EULA.DialogResult = [System.Windows.Forms.DialogResult]::No })
		
		$EULA.AutoScaleDimensions = New-Object System.Drawing.SizeF(6.0, 13.0)
		$EULA.AutoScaleMode = [System.Windows.Forms.AutoScaleMode]::Font
		$EULA.ClientSize = New-Object System.Drawing.Size(800, 450)
		$EULA.Controls.Add($btnCancel)
		$EULA.Controls.Add($richTextBox1)
		if ($mode -ne 0)
		{
			$EULA.AcceptButton = $btnCancel
		}
		else
		{
			$EULA.Controls.Add($btnAcknowledge)
			$EULA.AcceptButton = $btnAcknowledge
			$EULA.CancelButton = $btnCancel
		}
		$EULA.ResumeLayout($false)
		$EULA.Size = New-Object System.Drawing.Size(800, 650)
		
		Return ($EULA.ShowDialog())
	}
	
	function Show-EULAIfNeeded($toolName, $mode)
	{
		$eulaRegPath = "HKCU:Software\Microsoft\CESDiagnosticTools"
		$eulaAccepted = "No"
		$eulaValue = $toolName + " EULA Accepted"
		if (Test-Path $eulaRegPath)
		{
			$eulaRegKey = Get-Item $eulaRegPath
			$eulaAccepted = $eulaRegKey.GetValue($eulaValue, "No")
		}
		else
		{
			$eulaRegKey = New-Item $eulaRegPath
		}
		if ($mode -eq 2) # silent accept
		{
			$eulaAccepted = "Yes"
			$ignore = New-ItemProperty -Path $eulaRegPath -Name $eulaValue -Value $eulaAccepted -PropertyType String -Force
		}
		else
		{
			if ($eulaAccepted -eq "No")
			{
				$eulaAccepted = Show-EULAPopup($mode)
				if ($eulaAccepted -eq [System.Windows.Forms.DialogResult]::Yes)
				{
					$eulaAccepted = "Yes"
					$ignore = New-ItemProperty -Path $eulaRegPath -Name $eulaValue -Value $eulaAccepted -PropertyType String -Force
				}
			}
		}
		return $eulaAccepted
	}
	
	# Call ShowEULAIfNeeded from your main entry point, with your tool name (used to maintain 'already accepted' registry value)
	# $mode: 
	#    0=popup eula if not yet accepted for this tool
	#    1=popup eula for display
	#    2=silently accept eula
	# if the function does not return "Yes" then you should exit
	# e.g.
	# 
	# 
	#
	if ($AcceptEula)
	{
		$eulaAccepted = Show-EULAIfNeeded "SCOM Data Collector" 2
	}
	else
	{
		$eulaAccepted = Show-EULAIfNeeded "SCOM Data Collector" 0
	}
	
	if ($eulaAccepted -ne "Yes")
	{
		Write-Verbose "EULA Declined for SCOM Data Collector"
		break
	}
	Write-Verbose "EULA Accepted for SCOM Data Collector"
	# ... continue
	Write-Host "Attempting to run the following command to unblock the Powershell Scripts under the current folder:`nGet-ChildItem $ScriptPath -Recurse | Unblock-File" -ForegroundColor Gray; Get-ChildItem $ScriptPath -Recurse | Unblock-File | Out-Null
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
		[Parameter(Position = 1,
				   HelpMessage = 'Accept the End User License Agreement. The EULA acceptance state is stored in HKCU (HKCU:\Software\Microsoft\CESDiagnosticTools\SCOM Data Collector EULA Accepted) to prevent multiple popups every time the tool is launched.')]
		[Alias('ae')]
		[switch]$AcceptEula = 0,
		[Parameter(Mandatory = $false,
				   Position = 2,
				   HelpMessage = 'Gather additional Event Logs. (Example: -AdditionalEventLogs Security)')]
		[array]$AdditionalEventLogs,
		[Parameter(Mandatory = $false,
				   Position = 3,
				   HelpMessage = 'Allows you to Specify all the Switches Available for use. (Except: MSInfo32)')]
		[switch]$All,
		[Parameter(Mandatory = $false,
				   Position = 4,
				   HelpMessage = 'This will allow you to not be prompted for anything.')]
		[Alias('yes')]
		[switch]$AssumeYes,
		[Parameter(Mandatory = $false,
				   Position = 5,
				   HelpMessage = 'Azure DevOps Build Pipeline switch to output the SDC Results file without any File Date or CaseNumber.',
				   DontShow = $true)]
		[Alias('bp')]
		[switch]$BuildPipeline,
		[Parameter(Mandatory = $false,
				   Position = 6,
				   HelpMessage = 'Add an Optional Case Number to the Output of the Zip File.')]
		[Alias('case')]
		[string]$CaseNumber,
		[Parameter(Mandatory = $false,
				   Position = 7,
				   HelpMessage = 'Check the Certificates for validity for SCOM use, output in TXT format.')]
		[Alias('cc')]
		[switch]$CheckCertificates,
		[Parameter(Position = 8,
				   HelpMessage = 'Check the group policy for each server listed in -Servers as well as any Management Servers and SQL Servers.')]
		[switch]$CheckGroupPolicy,
		[Parameter(Mandatory = $false,
				   Position = 9,
				   HelpMessage = 'Check SCOM Common Ports against every Management Server in Management Group and SQL Servers, as well as any -Servers listed.')]
		[switch]$CheckPorts,
		[Parameter(Mandatory = $false,
				   Position = 10,
				   HelpMessage = 'Check for TLS 1.2 Readiness, output in TXT format.')]
		[Alias('ct')]
		[switch]$CheckTLS,
		[Parameter(Mandatory = $false,
				   Position = 11,
				   HelpMessage = 'Export all Sealed/Unsealed MPs.')]
		[Alias('em')]
		[switch]$ExportMPs,
		[Parameter(Mandatory = $false,
				   Position = 12,
				   HelpMessage = 'Generate a HTML Report Page { EXPERIMENTAL }')]
		[Alias('html')]
		[switch]$GenerateHTML,
		[Parameter(Position = 13,
				   HelpMessage = 'Gather the Registry / ConfigService.config Configuration of the Management Servers.')]
		[switch]$GetConfiguration,
		[Parameter(Mandatory = $false,
				   Position = 14,
				   HelpMessage = 'Gather Event Logs with the localemetadata to ensure that you are able to open the Event log from any machine.')]
		[Alias('gel')]
		[switch]$GetEventLogs,
		[Parameter(Mandatory = $false,
				   Position = 15,
				   HelpMessage = 'Gather software installed from Management Servers / Agents / Gateways.')]
		[switch]$GetInstalledSoftware,
		[Parameter(Position = 16)]
		[switch]$GetInstallLogs,
		[Parameter(Mandatory = $false,
				   Position = 17,
				   HelpMessage = 'Get Local Administrators and Logon Rights.')]
		[Alias('gls')]
		[switch]$GetLocalSecurity,
		[Parameter(Mandatory = $false,
				   Position = 18,
				   HelpMessage = 'A description of the GetNotificationSubscriptions parameter.')]
		[switch]$GetNotificationSubscriptions,
		[Parameter(Mandatory = $false,
				   Position = 19,
				   HelpMessage = 'A description of the GetRulesAndMonitors parameter.')]
		[Alias('gram')]
		[switch]$GetRulesAndMonitors,
		[Parameter(Mandatory = $false,
				   Position = 20,
				   HelpMessage = 'Get RunAs Accounts that are set on each Management Server.')]
		[Alias('graa')]
		[switch]$GetRunAsAccounts,
		[Parameter(Mandatory = $false,
				   Position = 21,
				   HelpMessage = 'Get SPN Configuration from Active Directory.')]
		[Alias('gs')]
		[switch]$GetSPN,
		[Parameter(Position = 22,
				   HelpMessage = 'Gathers User Roles and the configurations from SCOM.')]
		[switch]$GetUserRoles,
		[Parameter(Mandatory = $false,
				   Position = 23,
				   HelpMessage = 'Gathers Group Policy Results to verify Harmful Policies are not present, Generated in HTML and TXT Format.')]
		[Alias('gp')]
		[switch]$GPResult,
		[Parameter(Mandatory = $false,
				   Position = 24,
				   HelpMessage = 'Pull the least amount of data from SCOM.')]
		[switch]$LeastAmount,
		[Parameter(Mandatory = $false,
				   Position = 25,
				   HelpMessage = 'Only run data gathering against the Management Servers specified here.')]
		[Alias('ms')]
		[array]$ManagementServers,
		[Parameter(Mandatory = $false,
				   Position = 26,
				   HelpMessage = 'Export MSInfo32 for viewing in TXT Format.')]
		[Alias('mi32')]
		[switch]$MSInfo32,
		[Parameter(Position = 27,
				   HelpMessage = 'Internal Script Switch.')]
		[switch]$NoSQLPermission,
		[Parameter(Mandatory = $false,
				   Position = 28,
				   HelpMessage = 'Ping every Management Server, including servers mentioned in -Servers switch.')]
		[switch]$PingAll,
		[Parameter(Mandatory = $false,
				   Position = 29,
				   HelpMessage = 'Linux/Unix Agents you want to gather data from, via Bash Script that is transmitted via ssh.')]
		[Alias('LinuxAgents')]
		[Array]$SCXAgents,
		[Parameter(Mandatory = $false,
				   Position = 30,
				   HelpMessage = 'The password you would like to use for SCX Agent SSH Authentication.')]
		[Alias('LinuxPassword')]
		[string]$SCXPassword,
		[Parameter(Mandatory = $false,
				   Position = 31,
				   HelpMessage = 'The username you would like to use for SCX Agent SSH Authentication.')]
		[Alias('LinuxUsername')]
		[string]$SCXUsername,
		[Parameter(Mandatory = $false,
				   Position = 32,
				   HelpMessage = 'Set additional servers to run checks against. This can be Agents or Gateways, they have to be in the same domain at this time.')]
		[Alias('s')]
		[Array]$Servers,
		[Parameter(Position = 33,
				   HelpMessage = 'Skip the tests for remote accessibility, use this if you know your environment passes these tests. DO NOT USE THIS IF YOU ARENT SURE!')]
		[Alias('sct')]
		[switch]$SkipConnectivityTests,
		[Parameter(Position = 34,
				   HelpMessage = 'Skip the General Information file gathering.')]
		[Alias('sgi')]
		[switch]$SkipGeneralInformation,
		[Parameter(Mandatory = $false,
				   Position = 35,
				   HelpMessage = 'Skip the SQL Queries. This will leave you with much less data in the data collector. Other functions in the data collector may rely on the SQL Queries and may be missing data.')]
		[Alias('NoSQLQueries')]
		[switch]$SkipSQLQueries,
		[Parameter(Position = 36,
				   HelpMessage = 'Gather SQL Logs from OperationsManager and DataWarehouse DBs.')]
		[switch]$SQLLogs,
		[Parameter(Mandatory = $false,
				   Position = 37,
				   HelpMessage = 'Run only SQL Queries and Output to CSV.')]
		[switch]$SQLOnly,
		[Parameter(Mandatory = $false,
				   Position = 38,
				   HelpMessage = 'Internal Script Switch.',
				   DontShow = $true)]
		[switch]$SQLOnlyDW,
		[Parameter(Mandatory = $false,
				   Position = 39,
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
		. $ScriptPath`\Functions\SQL-Queries.ps1
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
			. $ScriptPath`\Functions\Wrapping-Up.ps1
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
		. $ScriptPath`\Functions\Linux-DataCollector.ps1
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
				. $ScriptPath`\Functions\Get-RunasAccount.ps1
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
				. $ScriptPath`\Functions\Certificate-Check.ps1
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
				. $ScriptPath`\Functions\Get-InstalledSoftware.ps1
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
				. $ScriptPath`\Functions\Get-SPN.ps1
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
				. $ScriptPath`\Functions\Get-TLSRegKeys.ps1
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
				. $ScriptPath`\Functions\Get-Configuration.ps1
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
				. $ScriptPath`\Functions\Get-EventLog.ps1
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
						. $ScriptPath`\Functions\Export-ManagementPack.ps1
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
				. $ScriptPath`\Functions\Get-RulesAndMonitors.ps1
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
				. $ScriptPath`\Functions\Get-LocalUserAccountsRights.ps1
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
				. $ScriptPath`\Functions\Test-SCOMPorts.ps1
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
				. $ScriptPath`\Functions\MsInfo32.ps1
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
				. $ScriptPath`\Functions\Get-SCOMNotificationSubscriptionDetails.ps1
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
				. $ScriptPath`\Functions\Get-InstallLogs.ps1
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
				. $ScriptPath`\Functions\Check-GroupPolicy.ps1
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
		. $ScriptPath`\Functions\General-Info.ps1
		Write-Progress -Activity "Collection Running" -Status "Progress-> 66%" -PercentComplete 66
		Write-Verbose "$(Time-Stamp)Executing General Info Function"
		Get-SCOMGeneralInfo -Servers $TestedTLSservers
		Write-Host "> Completed!`n" -NoNewline -ForegroundColor Green
		Write-Progress -Activity "Collection Running" -Status "Progress-> 97%" -PercentComplete 97
	}
	# Best Practices
	Write-Verbose "$(Time-Stamp)Executing Best Practice Function"
	. $ScriptPath`\Functions\Get-BestPractices.ps1
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
			. $ScriptPath`\Functions\Report-Webpage.ps1
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
	. $ScriptPath`\Functions\Wrapping-Up.ps1
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

if ($AcceptEula -or $BuildPipeline -or $CheckTLS -or $CheckCertificates -or $GetEventLogs -or $MSInfo32 -or $AssumeYes -or $ExportMPs -or $CaseNumber -or $Servers -or $GenerateHTML -or $GetRulesAndMonitors -or $GetRunAsAccounts -or $All -or $GPResult -or $SQLLogs -or $NoSQLPermission -or $SQLOnly -or $SQLOnlyOpsDB -or $SQLOnlyDW -or $CheckPorts -or $GetLocalSecurity -or $LeastAmount -or $GetNotificationSubscriptions -or $AdditionalEventLogs -or $GetInstalledSoftware -or $GetSPN -or $ManagementServers -or $SkipConnectivityTests -or $GetConfiguration -or $SkipGeneralInformation -or $SkipSQLQueries -or $CheckGroupPolicy -or $GetInstallLogs -or $SCXAgents -or $SCXUsername -or $SCXPassword -or $GetUserRoles)
{
	if ($all)
	{
		if ($Servers)
		{
			if ($AssumeYes)
			{
				Start-ScomDataCollector -AcceptEula:$AcceptEula -Servers $Servers -GetRulesAndMonitors -GetRunAsAccounts -CheckTLS -CheckCertificates -GetEventLogs -ExportMPs -GPResult -SQLLogs -CheckPorts -GetLocalSecurity -PingAll -AdditionalEventLogs $AdditionalEventLogs -GetInstalledSoftware -GetSPN -AssumeYes -ManagementServers:$ManagementServers -GetConfiguration -CheckGroupPolicy -GetInstallLogs -SkipConnectivityTests:$SkipConnectivityTests -SkipGeneralInformation:$SkipGeneralInformation -SkipSQLQueries:$SkipSQLQueries -MSInfo32:$MSInfo32 -GetUserRoles:$GetUserRoles
			}
			Start-ScomDataCollector -AcceptEula:$AcceptEula -Servers $Servers -GetRulesAndMonitors -GetRunAsAccounts -CheckTLS -CheckCertificates -GetEventLogs -ExportMPs -GPResult -SQLLogs -CheckPorts -GetLocalSecurity -PingAll -AdditionalEventLogs $AdditionalEventLogs -GetInstalledSoftware -GetSPN -ManagementServers:$ManagementServers -GetConfiguration -CheckGroupPolicy -GetInstallLogs -SkipConnectivityTests:$SkipConnectivityTests -SkipGeneralInformation:$SkipGeneralInformation -SkipSQLQueries:$SkipSQLQueries -MSInfo32:$MSInfo32 -GetUserRoles:$GetUserRoles
		}
		if ($AssumeYes)
		{
			Start-ScomDataCollector -AcceptEula:$AcceptEula -GetRulesAndMonitors -GetRunAsAccounts -CheckTLS -CheckCertificates -GetEventLogs -ExportMPs -GPResult -SQLLogs -CheckPorts -GetLocalSecurity -AdditionalEventLogs $AdditionalEventLogs -GetInstalledSoftware -GetSPN -AssumeYes -ManagementServers:$ManagementServers -GetConfiguration -CheckGroupPolicy -GetInstallLogs -SkipConnectivityTests:$SkipConnectivityTests -SkipGeneralInformation:$SkipGeneralInformation -SkipSQLQueries:$SkipSQLQueries -MSInfo32:$MSInfo32 -GetUserRoles:$GetUserRoles
		}
		if ($SCXAgents)
		{
			if ($AssumeYes)
			{
				Start-ScomDataCollector -AcceptEula:$AcceptEula -Servers $Servers -GetRulesAndMonitors -GetRunAsAccounts -CheckTLS -CheckCertificates -GetEventLogs -ExportMPs -GPResult -SQLLogs -CheckPorts -GetLocalSecurity -PingAll -AdditionalEventLogs $AdditionalEventLogs -GetInstalledSoftware -GetSPN -AssumeYes -ManagementServers:$ManagementServers -GetConfiguration -CheckGroupPolicy -GetInstallLogs -SkipConnectivityTests:$SkipConnectivityTests -SkipGeneralInformation:$SkipGeneralInformation -SkipSQLQueries:$SkipSQLQueries -SCXAgents $SCXAgents -SCXUsername $SCXUsername -SCXPassword $SCXPassword -MSInfo32:$MSInfo32 -GetUserRoles:$GetUserRoles
			}
			Start-ScomDataCollector -AcceptEula:$AcceptEula -Servers $Servers -GetRulesAndMonitors -GetRunAsAccounts -CheckTLS -CheckCertificates -GetEventLogs -ExportMPs -GPResult -SQLLogs -CheckPorts -GetLocalSecurity -PingAll -AdditionalEventLogs $AdditionalEventLogs -GetInstalledSoftware -GetSPN -ManagementServers:$ManagementServers -GetConfiguration -CheckGroupPolicy -GetInstallLogs -SkipConnectivityTests:$SkipConnectivityTests -SkipGeneralInformation:$SkipGeneralInformation -SkipSQLQueries:$SkipSQLQueries -SCXAgents $SCXAgents -SCXUsername $SCXUsername -SCXPassword $SCXPassword -MSInfo32:$MSInfo32 -GetUserRoles:$GetUserRoles
		}
		Start-ScomDataCollector -AcceptEula:$AcceptEula -GetRulesAndMonitors -GetRunAsAccounts -CheckTLS -CheckCertificates -GetEventLogs -GPResult -ExportMPs -SQLLogs -CheckPorts -GetLocalSecurity -AdditionalEventLogs $AdditionalEventLogs -GetInstalledSoftware -GetSPN -ManagementServers:$ManagementServers -GetConfiguration -CheckGroupPolicy -GetInstallLogs -SkipConnectivityTests:$SkipConnectivityTests -SkipGeneralInformation:$SkipGeneralInformation -SkipSQLQueries:$SkipSQLQueries -MSInfo32:$MSInfo32 -GetUserRoles:$GetUserRoles
	}
	else
	{
		Start-ScomDataCollector -AcceptEula:$AcceptEula -Servers $Servers -GetRunAsAccounts:$GetRunAsAccounts -CheckTLS:$CheckTLS -CheckCertificates:$CheckCertificates -GetEventLogs:$GetEventLogs -GetUserRoles:$GetUserRoles -GetRulesAndMonitors:$GetRulesAndMonitors -GPResult:$GPResult -ManagementServers:$ManagementServers -MSInfo32:$MSInfo32 -SQLLogs:$SQLLogs -ExportMPs:$ExportMPs -CaseNumber:$CaseNumber -GenerateHTML:$GenerateHTML -AssumeYes:$AssumeYes -NoSQLPermission:$NoSQLPermission -SQLOnly:$SQLOnly -SQLOnlyOpsDB:$SQLOnlyOpsDB -SQLOnlyDW:$SQLOnlyDW -CheckPorts:$CheckPorts -GetLocalSecurity:$GetLocalSecurity -LeastAmount:$LeastAmount -GetNotificationSubscriptions:$GetNotificationSubscriptions -AdditionalEventLogs $AdditionalEventLogs -GetInstalledSoftware:$GetInstalledSoftware -GetSPN:$GetSPN -SkipConnectivityTests:$SkipConnectivityTests -SkipGeneralInformation:$SkipGeneralInformation -SkipSQLQueries:$SkipSQLQueries -GetConfiguration:$GetConfiguration -CheckGroupPolicy:$CheckGroupPolicy -GetInstallLogs:$GetInstallLogs -BuildPipeline:$BuildPipeline -SCXAgents $SCXAgents -SCXUsername $SCXUsername -SCXPassword $SCXPassword
	}
}
elseif (!$SQLOnly)
{
	#Start Built-in Menu
	. $ScriptPath`\Functions\Builtin-Menu.ps1
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