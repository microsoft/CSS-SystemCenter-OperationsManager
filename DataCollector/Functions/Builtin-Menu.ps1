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
				. $ScriptPath`\Script-Auto-Updater.ps1
				exit 0
			}
		}
		
	}
	until ($selection -ne $null)
}