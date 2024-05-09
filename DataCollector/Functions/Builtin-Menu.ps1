Function Invoke-DataCollectorMenu
{
	function Invoke-MainMenu
	{
		param (
			[string]$Title = 'System Center Operations Manager: Data Collector'
		)
		Clear-Host
		Write-Console "================ " -NoNewline -ForegroundColor DarkYellow
		Start-Sleep -Milliseconds 120
		Write-Console $Title -ForegroundColor Cyan -NoNewline
		Start-Sleep -Milliseconds 120
		Write-Console " ================" -ForegroundColor DarkYellow
		Start-Sleep -Milliseconds 120
		
		Write-Console "1" -NoNewline -ForegroundColor Green
		Write-Console ": Type `'" -NoNewline
		Write-Console "1" -NoNewline -ForegroundColor Green
		Write-Console "`' to gather as much data as possible."
		
		Write-Console "2" -NoNewline -ForegroundColor Green
		Write-Console ": Type `'" -NoNewline
		Write-Console "2" -NoNewline -ForegroundColor Green
		Write-Console "`' to gather information from specific Windows Agent(s)."
		
		Write-Console "3" -NoNewline -ForegroundColor Green
		Write-Console ": Type `'" -NoNewline
		Write-Console "3" -NoNewline -ForegroundColor Green
		Write-Console "`' to gather minimum information."
		
		Write-Console "4" -NoNewline -ForegroundColor Green
		Write-Console ": Type `'" -NoNewline
		Write-Console "4" -NoNewline -ForegroundColor Green
		Write-Console "`' to update to the latest release of the Data Collector on GitHub."
		
		Write-Console "Q" -NoNewline -ForegroundColor Green
		Write-Console ": Type `'" -NoNewline
		Write-Console "Q" -NoNewline -ForegroundColor Green
		Write-Console "`' to Quit."
	}
	function Invoke-SubMenuAll
	{
		param (
			[string]$Title = 'System Center Operations Manager: Data Collector - Gather Everything'
		)
		Clear-Host
		Write-Console "================ " -NoNewline -ForegroundColor DarkYellow
		Start-Sleep -Milliseconds 120
		Write-Console $Title -ForegroundColor Cyan -NoNewline
		Start-Sleep -Milliseconds 120
		Write-Console " ================" -ForegroundColor DarkYellow
		Start-Sleep -Milliseconds 120
		
		Write-Console "1a" -NoNewline -ForegroundColor Green
		Write-Console ": Type `'" -NoNewline
		Write-Console "1a" -NoNewline -ForegroundColor Green
		Write-Console "`' to also gather information from specific Windows Agent(s)."
		
		Write-Console "1b" -NoNewline -ForegroundColor Green
		Write-Console ": Type `'" -NoNewline
		Write-Console "1b" -NoNewline -ForegroundColor Green
		Write-Console "`' to continue and start script."
		
		Write-Console "1c" -NoNewline -ForegroundColor Green
		Write-Console ": Type `'" -NoNewline
		Write-Console "1c" -NoNewline -ForegroundColor Green
		Write-Console "`' to run the SCOM Linux Data Collector."
		
		Write-Console " Q" -NoNewline -ForegroundColor Green
		Write-Console ": Type `'" -NoNewline
		Write-Console "Q" -NoNewline -ForegroundColor Green
		Write-Console "`' to Quit."
	}
	function Invoke-SubMenuSpecificAgents
	{
		param (
			[string]$Title = 'System Center Operations Manager: Data Collector - Specific Agents'
		)
		Clear-Host
		Write-Console "================ " -NoNewline -ForegroundColor DarkYellow
		Start-Sleep -Milliseconds 120
		Write-Console $Title -ForegroundColor Cyan -NoNewline
		Start-Sleep -Milliseconds 120
		Write-Console " ================" -ForegroundColor DarkYellow
		Start-Sleep -Milliseconds 120
		
		Write-Console "2a" -NoNewline -ForegroundColor Green
		Write-Console ": Type `'" -NoNewline
		Write-Console "2a" -NoNewline -ForegroundColor Green
		Write-Console "`' to gather minimum information from Windows Agent(s) + All Management Servers in Management Group."
		
		Write-Console "2b" -NoNewline -ForegroundColor Green
		Write-Console ": Type `'" -NoNewline
		Write-Console "2b" -NoNewline -ForegroundColor Green
		Write-Console "`' to gather Multiple types of information from Windows Agent(s) + All Management Servers in Management Group."
		
		Write-Console "2c" -NoNewline -ForegroundColor Green
		Write-Console ": Type `'" -NoNewline
		Write-Console "2c" -NoNewline -ForegroundColor Green
		Write-Console "`' to gather Event Logs Only (Application, System, Operations Manager) from Windows Agent(s) + All Management Servers in Management Group."
		
		Write-Console "2d" -NoNewline -ForegroundColor Green
		Write-Console ": Type `'" -NoNewline
		Write-Console "2d" -NoNewline -ForegroundColor Green
		Write-Console "`' to gather Run As Accounts Only + get minimum information from specific Windows Agent(s) and All Management Servers in Management Group."
		
		Write-Console "2e" -NoNewline -ForegroundColor Green
		Write-Console ": Type `'" -NoNewline
		Write-Console "2e" -NoNewline -ForegroundColor Green
		Write-Console "`' to check Certificates Only for specific Windows Agent(s) + All Management Servers in Management Group."
		
		Write-Console "2f" -NoNewline -ForegroundColor Green
		Write-Console ": Type `'" -NoNewline
		Write-Console "2f" -NoNewline -ForegroundColor Green
		Write-Console "`' to check Check TLS against specific Windows Agent(s) and All Management Servers in Management Group."
		
		Write-Console "2g" -NoNewline -ForegroundColor Green
		Write-Console ": Type `'" -NoNewline
		Write-Console "2g" -NoNewline -ForegroundColor Green
		Write-Console "`' to check Export Management Packs + get minimum information from specific Windows Agent(s) and All Management Servers in Management Group."
		
		Write-Console "2h" -NoNewline -ForegroundColor Green
		Write-Console ": Type `'" -NoNewline
		Write-Console "2h" -NoNewline -ForegroundColor Green
		Write-Console "`' to export Rules and Monitors + get minimum information from specific Windows Agent(s) and All Management Servers in Management Group."
		
		Write-Console "2i" -NoNewline -ForegroundColor Green
		Write-Console ": Type `'" -NoNewline
		Write-Console "2i" -NoNewline -ForegroundColor Green
		Write-Console "`' to export MSInfo32 information from specific Windows Agent(s) + All Management Servers in Management Group."
		
		Write-Console "2j" -NoNewline -ForegroundColor Green
		Write-Console ": Type `'" -NoNewline
		Write-Console "2j" -NoNewline -ForegroundColor Green
		Write-Console "`' to export Group Policy Results from specific Windows Agent(s) and All Management Servers in Management Group."
		
		Write-Console "2k" -NoNewline -ForegroundColor Green
		Write-Console ": Type `'" -NoNewline
		Write-Console "2k" -NoNewline -ForegroundColor Green
		Write-Console "`' to gather SQL Error Logs + get minimum information from specific Windows Agent(s) and All Management Servers in Management Group."
		
		Write-Console "2l" -NoNewline -ForegroundColor Green
		Write-Console ": Type `'" -NoNewline
		Write-Console "2l" -NoNewline -ForegroundColor Green
		Write-Console "`' to ping the Management Server(s) in Management Group from each Windows Agent(s) to verify connectability (output at bottom of `'General Information.txt`' file in zip output) + get minimum information from specific Windows Agent(s) and All Management Servers in Management Group."
		
		Write-Console " Q" -NoNewline -ForegroundColor Green
		Write-Console ": Type `'" -NoNewline
		Write-Console "Q" -NoNewline -ForegroundColor Green
		Write-Console "`' to Quit."
	}
	
	
	do
	{
		Invoke-MainMenu
		$selection = $null
		do
		{
			$selection = Read-Host "Please make a selection"
		}
		until ($selection -match "\d")
		switch ($selection)
		{
			'1' {
				
				do
				{
					Invoke-SubMenuAll
					Write-Console "`n   NOTE:" -ForegroundColor Yellow
					Write-Console "    Option 1 does not gather the following: " -NoNewLine
					Write-Console "-MSInfo32" -NoNewLine -ForegroundColor DarkGreen
					Write-Console " and " -NoNewLine
					Write-Console "-GetNotificationSubscriptions" -NoNewLine -ForegroundColor DarkGreen
					Write-Console "`n     To gather these you will need to run the data collector with its switches:`n   " -NoNewLine
					Write-Console "   .\DataCollector-v#.#.#.ps1" -NoNewLine -ForegroundColor Yellow
					Write-Console " -All -MSInfo32 -GetNotificationSubscriptions`n`n" -NoNewLine -ForegroundColor Gray
					$selection = $null
					do
					{
						$selection = Read-Host "Please make a selection"
					}
					until ($selection -match "\d[a-z]")
					do
					{
						$PingAllServers = Read-Host "Do you want to run extended latency checks? The checks are more thorough and allow you to identify network latency issues between Management Servers and SCOM SQL Server(s). (Y/N)"
					}
					until ($PingAllServers -eq "y" -or $PingAllServers -eq "n")
					if ($PingAllServers -eq "y")
					{
						Write-Console "The Output for the extended latency checks will be in the General Information text file in the output." -ForegroundColor Blue
					}
					switch ($selection)
					{
						'1a'
						{
							[string]$Servers = $null
							do
							{
								[string]$Servers = Read-Host 'Please Type the Names of the Windows Agents (ex. Agent1.contoso.com, Agent2.contoso.com)'
							}
							until ($Servers)
							do
							{
								$PermissionforSQL = Read-Host "Does the following account have permissions to run SQL queries against the Operations Manager DB and Data Warehouse DB? `'$runningas`' (Y/N)"
							}
							until ($PermissionforSQL -eq "y" -or $PermissionforSQL -eq "n")
							if ($PermissionforSQL -like 'y')
							{
								if ($null -ne $Servers)
								{
									if ($PingAllServers -eq "y")
									{
										Start-ScomDataCollector -PingAll -Servers $Servers -GetRulesAndMonitors -GetRunAsAccounts -CheckTLS -CheckCertificates -GetEventLogs -ExportMPs -GPResult -SQLLogs -CheckPorts -GetLocalSecurity -GetInstalledSoftware -GetSPN -AssumeYes -GetConfiguration -CheckGroupPolicy -GetInstallLogs -GetUserRoles
									}
									else
									{
										Start-ScomDataCollector -Servers $Servers -GetRulesAndMonitors -GetRunAsAccounts -CheckTLS -CheckCertificates -GetEventLogs -ExportMPs -GPResult -SQLLogs -CheckPorts -GetLocalSecurity -GetInstalledSoftware -GetSPN -AssumeYes -GetConfiguration -CheckGroupPolicy -GetInstallLogs -GetUserRoles
									}
								}
								else
								{
									if ($PingAllServers -eq "y")
									{
										Start-ScomDataCollector -PingAll -GetRulesAndMonitors -GetRunAsAccounts -CheckTLS -CheckCertificates -GetEventLogs -ExportMPs -GPResult -SQLLogs -CheckPorts -GetLocalSecurity -GetInstalledSoftware -GetSPN -GetConfiguration -CheckGroupPolicy -GetInstallLogs -Yes -GetUserRoles
									}
									else
									{
										Start-ScomDataCollector -GetRulesAndMonitors -GetRunAsAccounts -CheckTLS -CheckCertificates -GetEventLogs -ExportMPs -GPResult -SQLLogs -CheckPorts -GetLocalSecurity -GetInstalledSoftware -GetSPN -GetConfiguration -CheckGroupPolicy -GetInstallLogs -Yes -GetUserRoles
									}
								}
							}
							if ($PermissionforSQL -like 'n')
							{
								if ($null -ne $Servers)
								{
									if ($PingAllServers -eq "y")
									{
										Start-ScomDataCollector -PingAll -Servers $Servers -GetRulesAndMonitors -GetRunAsAccounts -CheckTLS -CheckCertificates -GetEventLogs -ExportMPs -GPResult -SQLLogs -CheckPorts -GetLocalSecurity -GetInstalledSoftware -GetSPN -GetConfiguration -CheckGroupPolicy -GetInstallLogs -NoSQLPermission -GetUserRoles
									}
									else
									{
										Start-ScomDataCollector -Servers $Servers -GetRulesAndMonitors -GetRunAsAccounts -CheckTLS -CheckCertificates -GetEventLogs -ExportMPs -GPResult -SQLLogs -CheckPorts -GetLocalSecurity -GetInstalledSoftware -GetSPN -GetConfiguration -CheckGroupPolicy -GetInstallLogs -NoSQLPermission -GetUserRoles
									}
								}
								else
								{
									if ($PingAllServers -eq "y")
									{
										Start-ScomDataCollector -PingAll -GetRulesAndMonitors -GetRunAsAccounts -CheckTLS -CheckCertificates -GetEventLogs -ExportMPs -GPResult -SQLLogs -CheckPorts -GetLocalSecurity -GetInstalledSoftware -GetSPN -GetConfiguration -CheckGroupPolicy -GetInstallLogs -NoSQLPermission -GetUserRoles
									}
									else
									{
										Start-ScomDataCollector -GetRulesAndMonitors -GetRunAsAccounts -CheckTLS -CheckCertificates -GetEventLogs -ExportMPs -GPResult -SQLLogs -CheckPorts -GetLocalSecurity -GetInstalledSoftware -GetSPN -GetConfiguration -CheckGroupPolicy -GetInstallLogs -NoSQLPermission -GetUserRoles
									}
								}
							}
						}
						'1b'
						{
							do
							{
								$PermissionforSQL = Read-Host "Does the following account have permissions to run SQL queries against the Operations Manager DB and Data Warehouse DB? `'$runningas`' (Y/N)"
							}
							until ($PermissionforSQL -eq "y" -or $PermissionforSQL -eq "n")
							if ($PermissionforSQL -like 'y')
							{
								if ($PingAllServers -eq "y")
								{
									Start-ScomDataCollector -PingAll -GetRulesAndMonitors -GetRunAsAccounts -CheckTLS -CheckCertificates -GetEventLogs -ExportMPs -GPResult -SQLLogs -CheckPorts -GetLocalSecurity -GetInstalledSoftware -GetSPN -AssumeYes -GetConfiguration -CheckGroupPolicy -GetInstallLogs -GetUserRoles
								}
								else
								{
									Start-ScomDataCollector -GetRulesAndMonitors -GetRunAsAccounts -CheckTLS -CheckCertificates -GetEventLogs -ExportMPs -GPResult -SQLLogs -CheckPorts -GetLocalSecurity -GetInstalledSoftware -GetSPN -AssumeYes -GetConfiguration -CheckGroupPolicy -GetInstallLogs -GetUserRoles
								}
							}
							if ($PermissionforSQL -like 'n')
							{
								if ($PingAllServers -eq "y")
								{
									Start-ScomDataCollector -PingAll -GetRulesAndMonitors -GetRunAsAccounts -CheckTLS -CheckCertificates -GetEventLogs -ExportMPs -GPResult -SQLLogs -CheckPorts -GetLocalSecurity -GetInstalledSoftware -GetSPN -GetConfiguration -CheckGroupPolicy -GetInstallLogs -NoSQLPermission -GetUserRoles
								}
								else
								{
									Start-ScomDataCollector -GetRulesAndMonitors -GetRunAsAccounts -CheckTLS -CheckCertificates -GetEventLogs -ExportMPs -GPResult -SQLLogs -CheckPorts -GetLocalSecurity -GetInstalledSoftware -GetSPN -GetConfiguration -CheckGroupPolicy -GetInstallLogs -NoSQLPermission -GetUserRoles
								}
							}
							
						}
						'1c'
						{
							do
							{
								$PermissionforSQL = Read-Host "Does the following account have permissions to run SQL queries against the Operations Manager DB and Data Warehouse DB? `'$runningas`' (Y/N)"
							}
							until ($PermissionforSQL -eq "y" -or $PermissionforSQL -eq "n")
							do
							{
								if (-NOT $SCXAgents)
								{
									$SCXAgents = Read-Host "Type the SCX Agents (comma separated) you would like to run the Linux Data Collector against"
								}
								if (-NOT $SCXUsername)
								{
									$SCXUsername = Read-Host "Type the Username to be used to gather data via SSH (preferably high user rights)"
								}
							}
							until ($SCXAgents -and $SCXUsername)
							
							do
							{
								$SCXResourcePools = Read-Host "Type in the UNIX/Linux Resource Pool you want to run the WinRM queries from (comma separated for more than one)"
							}
							until ($SCXResourcePools)
							do
							{
								$EnumerateAllSCXClasses = Read-Host "Do you want to enumerate all SCX Classes from the Linux Agent(s) with WinRM? (Y/N)"
							}
							until ($EnumerateAllSCXClasses -eq "y" -or $EnumerateAllSCXClasses -eq "n")
							if ($EnumerateAllSCXClasses -eq "n")
							{
								$EnumerateAllSCXClasses = $null
								do
								{
									$EnumerateSpecificSCXClasses = Read-Host "Do you want to gather specific SCX Classes ('N' will allow you to gather the default SCX Classes from the Linux Agent(s))? (Y/N)"
								}
								until ($EnumerateSpecificSCXClasses -eq "y" -or $EnumerateSpecificSCXClasses -eq "n")
								if ($EnumerateSpecificSCXClasses -eq "y")
								{
									$EnumerateSpecificSCXClasses = $null
									do
									{
										$EnumerateSpecificSCXClasses = Read-Host "Type in a comma separated list of SCX Classes you want to gather. Default: SCX_UnixProcess, SCX_Agent, SCX_OperatingSystem"
									}
									until ($EnumerateSpecificSCXClasses)
								}
								else
								{
									$EnumerateSpecificSCXClasses = 'SCX_UnixProcess', 'SCX_Agent', 'SCX_OperatingSystem'
								}
							}
							if ($PermissionforSQL -like 'y')
							{
								if ($SCXWinRMEnumerateAllClasses)
								{
									Start-ScomDataCollector -GetRulesAndMonitors -GetRunAsAccounts -CheckTLS -CheckCertificates -GetEventLogs -ExportMPs -GPResult -SQLLogs -CheckPorts -GetLocalSecurity -GetInstalledSoftware -GetSPN -AssumeYes -GetConfiguration -CheckGroupPolicy -GetInstallLogs -SCXAgents $SCXAgents -SCXUsername $SCXUsername -SCXWinRMEnumerateAllClasses -SCXResourcePoolDisplayName $SCXResourcePoolDisplayName -GetUserRoles -ExportSCXCertificates
								}
								else
								{
									Start-ScomDataCollector -GetRulesAndMonitors -GetRunAsAccounts -CheckTLS -CheckCertificates -GetEventLogs -ExportMPs -GPResult -SQLLogs -CheckPorts -GetLocalSecurity -GetInstalledSoftware -GetSPN -AssumeYes -GetConfiguration -CheckGroupPolicy -GetInstallLogs -SCXAgents $SCXAgents -SCXUsername $SCXUsername -SCXWinRMEnumerateSpecificClasses $EnumerateSpecificSCXClasses -SCXResourcePoolDisplayName $SCXResourcePoolDisplayName -GetUserRoles -ExportSCXCertificates
								}
								
							}
							if ($PermissionforSQL -like 'n')
							{
								if ($SCXWinRMEnumerateAllClasses)
								{
									Start-ScomDataCollector -GetRulesAndMonitors -GetRunAsAccounts -CheckTLS -CheckCertificates -GetEventLogs -ExportMPs -GPResult -SQLLogs -CheckPorts -GetLocalSecurity -GetInstalledSoftware -GetSPN -AssumeYes -GetConfiguration -CheckGroupPolicy -GetInstallLogs -SCXAgents $SCXAgents -SCXUsername $SCXUsername -SCXWinRMEnumerateAllClasses -SCXResourcePoolDisplayName $SCXResourcePoolDisplayName -GetUserRoles -ExportSCXCertificates -NoSQLPermission
								}
								else
								{
									Start-ScomDataCollector -GetRulesAndMonitors -GetRunAsAccounts -CheckTLS -CheckCertificates -GetEventLogs -ExportMPs -GPResult -SQLLogs -CheckPorts -GetLocalSecurity -GetInstalledSoftware -GetSPN -AssumeYes -GetConfiguration -CheckGroupPolicy -GetInstallLogs -SCXAgents $SCXAgents -SCXUsername $SCXUsername -SCXWinRMEnumerateSpecificClasses $EnumerateSpecificSCXClasses -SCXResourcePoolDisplayName $SCXResourcePoolDisplayName -GetUserRoles -ExportSCXCertificates -NoSQLPermission
								}
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
					Invoke-SubMenuSpecificAgents
					$selection = $null
					do
					{
						$selection = Read-Host "Please make a selection"
					}
					until ($selection -match "\d[a-z]")
					switch ($selection)
					{
						'2a' {
							[string]$Servers = $null
							[string]$Servers = Read-Host 'Please Type the Names of the Windows Agents (ex. Agent1.contoso.com, Agent2.contoso.com)'
							do
							{
								$PermissionforSQL = Read-Host "Does the following account have permissions to run SQL queries against the Operations Manager DB and Data Warehouse DB? `'$runningas`' (Y/N)"
							}
							until ($PermissionforSQL -eq "y" -or $PermissionforSQL -eq "n")
							if ($PermissionforSQL -like 'y')
							{
								if ($null -ne $Servers)
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
								if ($null -ne $Servers)
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
							Write-Console 'DO NOT USE :: NOT WORKING :: Options to choose from:
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
								$PermissionforSQL = Read-Host "Does the following account have permissions to run SQL queries against the Operations Manager DB and Data Warehouse DB? `'$runningas`' (Y/N)"
							}
							until ($PermissionforSQL -eq "y" -or $PermissionforSQL -eq "n")
							if ($PermissionforSQL -like 'y')
							{
								if ($null -ne $Servers)
								{
									Start-ScomDataCollector -Servers $Servers ($argumentsforscript | ForEach-Object { [boolean]$_ }) -Yes
								}
								else
								{
									Start-ScomDataCollector $($argumentsforscript) -Yes
								}
								
							}
							if ($PermissionforSQL -like 'n')
							{
								if ($null -ne $Servers)
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
								$PermissionforSQL = Read-Host "Does the following account have permissions to run SQL queries against the Operations Manager DB and Data Warehouse DB? `'$runningas`' (Y/N)"
							}
							until ($PermissionforSQL -eq "y" -or $PermissionforSQL -eq "n")
							if ($PermissionforSQL -like 'y')
							{
								if ($null -ne $Servers)
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
								if ($null -ne $Servers)
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
								$PermissionforSQL = Read-Host "Does the following account have permissions to run SQL queries against the Operations Manager DB and Data Warehouse DB? `'$runningas`' (Y/N)"
							}
							until ($PermissionforSQL -eq "y" -or $PermissionforSQL -eq "n")
							if ($PermissionforSQL -like 'y')
							{
								if ($null -ne $Servers)
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
								if ($null -ne $Servers)
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
								$PermissionforSQL = Read-Host "Does the following account have permissions to run SQL queries against the Operations Manager DB and Data Warehouse DB? `'$runningas`' (Y/N)"
							}
							until ($PermissionforSQL -eq "y" -or $PermissionforSQL -eq "n")
							if ($PermissionforSQL -like 'y')
							{
								if ($null -ne $Servers)
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
								if ($null -ne $Servers)
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
								$PermissionforSQL = Read-Host "Does the following account have permissions to run SQL queries against the Operations Manager DB and Data Warehouse DB? `'$runningas`' (Y/N)"
							}
							until ($PermissionforSQL -eq "y" -or $PermissionforSQL -eq "n")
							if ($PermissionforSQL -like 'y')
							{
								if ($null -ne $Servers)
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
								if ($null -ne $Servers)
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
								$PermissionforSQL = Read-Host "Does the following account have permissions to run SQL queries against the Operations Manager DB and Data Warehouse DB? `'$runningas`' (Y/N)"
							}
							until ($PermissionforSQL -eq "y" -or $PermissionforSQL -eq "n")
							if ($PermissionforSQL -like 'y')
							{
								if ($null -ne $Servers)
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
								if ($null -ne $Servers)
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
								$PermissionforSQL = Read-Host "Does the following account have permissions to run SQL queries against the Operations Manager DB and Data Warehouse DB? `'$runningas`' (Y/N)"
							}
							until ($PermissionforSQL -eq "y" -or $PermissionforSQL -eq "n")
							if ($PermissionforSQL -like 'y')
							{
								if ($null -ne $Servers)
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
								if ($null -ne $Servers)
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
								$PermissionforSQL = Read-Host "Does the following account have permissions to run SQL queries against the Operations Manager DB and Data Warehouse DB? `'$runningas`' (Y/N)"
							}
							until ($PermissionforSQL -eq "y" -or $PermissionforSQL -eq "n")
							if ($PermissionforSQL -like 'y')
							{
								if ($null -ne $Servers)
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
								if ($null -ne $Servers)
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
								$PermissionforSQL = Read-Host "Does the following account have permissions to run SQL queries against the Operations Manager DB and Data Warehouse DB? `'$runningas`' (Y/N)"
							}
							until ($PermissionforSQL -eq "y" -or $PermissionforSQL -eq "n")
							if ($PermissionforSQL -like 'y')
							{
								if ($null -ne $Servers)
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
								if ($null -ne $Servers)
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
								$PermissionforSQL = Read-Host "Does the following account have permissions to run SQL queries against the Operations Manager DB and Data Warehouse DB? `'$runningas`' (Y/N)"
							}
							until ($PermissionforSQL -eq "y" -or $PermissionforSQL -eq "n")
							if ($PermissionforSQL -like 'y')
							{
								if ($null -ne $Servers)
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
								if ($null -ne $Servers)
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
								$PermissionforSQL = Read-Host "Does the following account have permissions to run SQL queries against the Operations Manager DB and Data Warehouse DB? `'$runningas`' (Y/N)"
							}
							until ($PermissionforSQL -eq "y" -or $PermissionforSQL -eq "n")
							if ($PermissionforSQL -like 'y')
							{
								if ($null -ne $Servers)
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
								if ($null -ne $Servers)
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
					$PermissionforSQL = Read-Host "Does the following account have permissions to run SQL queries against the Operations Manager DB and Data Warehouse DB? `'$runningas`' (Y/N)"
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
	until ($null -ne $selection)
}