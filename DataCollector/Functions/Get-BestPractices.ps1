Function Invoke-GetBestPractices
{
	[cmdletbinding()]
	param ([String[]]$Servers)
	begin
	{
		# Updated on 11/7/2023
		Function Invoke-TimeStamp
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
			"$(Invoke-TimeStamp)Caught Exception: $e :: Message: $msg :: at line: $line" | Out-File $OutputPath\Error.log -Append
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
		function Invoke-InnerGetBestPractices
		{
			[CmdletBinding()]
			param ()
			
			Function Invoke-TimeStamp
			{
				$TimeStamp = Get-Date -Format "MM/dd/yyyy hh:mm:ss tt"
				return "$TimeStamp - "
			}
			
			function Write-Console
			{
				param
				(
					[Parameter(Position = 1)]
					[string]$Text,
					[Parameter(Position = 2)]
					$ForegroundColor,
					[Parameter(Position = 3)]
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
			
			Write-Verbose "========================================"
			Write-Verbose "$(Invoke-TimeStamp)  Working on: $env:COMPUTERNAME"
			$bestpractice = @()
			if ($OutputPath)
			{
				$OutputResolvedPath = Resolve-Path $OutputPath -ErrorAction SilentlyContinue
			}
			else
			{
				$OutputResolvedPath = $false
			}
			
			Write-Verbose "$(Invoke-TimeStamp)Checking the Operations Manager Event log for 33333 event ids and messages like: *Violation of PRIMARY KEY constraint 'PK_StateChangeEvent'. Cannot insert duplicate key in object 'dbo.StateChangeEvent'. The duplicate key value is*"
			$events = (Get-EventLog -LogName 'Operations Manager' -Source 'DataAccessLayer' -ErrorAction SilentlyContinue | Where-Object { $_.EventID -eq 33333 })
			Write-Host '-' -NoNewline -ForegroundColor Green
			# If Event 33333 found in the OperationsManager Event Log, do the below
			if (($events.Message -like "*Violation of PRIMARY KEY constraint 'PK_StateChangeEvent'. Cannot insert duplicate key in object 'dbo.StateChangeEvent'. The duplicate key value is*") -and ($events.Message -like "*f1baeb56-8cce-f8c7-79ae-d69796c9d926*"))
			{
				$message = $events | ForEach-Object{ ($_ | Select-Object -Property Message -ExpandProperty Message) }
				$matches = $message -split "," | select-string "MonitorId=(.*)"
				$match = $matches.matches.groups[1].value.TrimEnd(")")
				$bestpractice += "$env:COMPUTERNAME : Found $($message.count) issues with the Event ID 33333 (Monitor Id: $match), see the following article:`n   https://kevinholman.com/2017/05/29/stop-healthservice-restarts-in-scom-2016/"
				Write-Verbose "$(Invoke-TimeStamp)$env:COMPUTERNAME : Found $($message.count) issues with the Event ID 33333 (Monitor Id: $match), see the following article:`n   https://kevinholman.com/2017/05/29/stop-healthservice-restarts-in-scom-2016/"
				
				Write-Console "-" -NoNewline -ForegroundColor Green
			}
			# Check if Async Notification Channel Issue is Present
			Write-Verbose "$(Invoke-TimeStamp)Check if Async Notification Channel Issue is Present"
			$AsyncEvents = (Get-EventLog -LogName 'Operations Manager' -Source 'Health Service Modules' -ErrorAction SilentlyContinue | Where-Object { $_.EventID -eq 21410 })
			if ($AsyncEvents.Message -like "*The process could not be created because the maximum number of asynchronous responses*")
			{
				$AsyncMessage = $AsyncEvents | ForEach-Object{ ($_ | Select-Object -Property Message -ExpandProperty Message) }
				$AsyncMatches = $AsyncMessage -split "," | select-string "(.*)"
				$AsyncMatch = $AsyncMatches.matches.groups[1].value.TrimEnd(")")
				$bestpractice += "$env:COMPUTERNAME : Found Event ID 21410, regarding issue with asynchronous responses for Command Notification Channel. Consider increasing the registry key (HKLM:\SOFTWARE\Microsoft\Microsoft Operations Manager\3.0\Modules\Global\Command Executer\AsyncProcessLimit or HKLM:\SOFTWARE\Microsoft\Microsoft Operations Manager\3.0\Modules\Global\AsyncProcessLimit) between 5 (default) and 100 (max).`n    Current Async responses possible: '$AsyncMatch'`n      https://kevinholman.com/2021/08/25/what-account-will-command-channel-notifications-run-as-in-scom/"
				Write-Verbose "$(Invoke-TimeStamp)$env:COMPUTERNAME : Found Event ID 21410, regarding issue with asynchronous responses for Command Notification Channel. Consider increasing the registry key (HKLM:\SOFTWARE\Microsoft\Microsoft Operations Manager\3.0\Modules\Global\Command Executer\AsyncProcessLimit or HKLM:\SOFTWARE\Microsoft\Microsoft Operations Manager\3.0\Modules\Global\AsyncProcessLimit) between 5 (default) and 100 (max).`n    Current Async responses possible: '$AsyncMatch'`n      https://kevinholman.com/2021/08/25/what-account-will-command-channel-notifications-run-as-in-scom/"
				Write-Host '-' -NoNewline -ForegroundColor Green
			}
			
			# Check if Management Server has MMA Configured to report to an Management Group
			Write-Verbose "$(Invoke-TimeStamp)Check if Management Server has MMA Configured to report to an Management Group"
			$ServerMG = Get-ItemProperty -Path 'HKLM:\SOFTWARE\Microsoft\Microsoft Operations Manager\3.0\Server Management Groups\*' -Name IsServer | Select-Object IsServer -ExpandProperty IsServer
			if ($ServerMG)
			{
				$AgentMG = Get-Item -Path 'HKLM:\SOFTWARE\Microsoft\Microsoft Operations Manager\3.0\Agent Management Groups\*' -ErrorAction SilentlyContinue
				if ($AgentMG)
				{
					Write-Verbose "$(Invoke-TimeStamp)$env:COMPUTERNAME : Found Microsoft Monitoring Agent has Management Groups Configured on a Management Server:`n   Remove all Management Groups under Microsoft Monitoring Agent in Control Panel."
					$bestpractice += "$env:COMPUTERNAME : Found Microsoft Monitoring Agent has Management Groups Configured on a Management Server:`n   Remove all Management Groups under Microsoft Monitoring Agent in Control Panel."
					Write-Console "-" -NoNewline -ForegroundColor Green
				}
			}
			Write-Host '-' -NoNewline -ForegroundColor Green
			# Check DW Writer Login from Database against RunAs Profile 'Data Warehouse Account'
			if ($OutputResolvedPath)
			{
				try
				{
					Write-Verbose "$(Invoke-TimeStamp)Check DW Writer Login from Database against RunAs Profile 'Data Warehouse Account'"
					$writerLoginName = (Import-Csv -ErrorAction SilentlyContinue -Path $OutputPath\DW_WriterLoginName.csv).WriterLoginName
					$DWAction = (Import-Csv -Path $OutputPath\RunAsAccountInfo.csv -ErrorAction SilentlyContinue | Where-Object { $_.ProfileName -eq 'Microsoft.SystemCenter.DataWarehouse.ActionAccount' }) | Select-Object Domain, UserName, SSID, AccountName, TypeName -Unique
					$DWWriterAccount = @()
					if ($DWAction)
					{
						if (($DWAction | Select-Object -ExpandProperty SSID -Unique).Count -ne 1 -or (($DWAction.Count -ne 4) -and ($DWAction.Count -ne 3)))
						{
							$j = 0
							foreach ($actionAccount in $DWAction)
							{
								if (($($actionAccount.TypeName) -eq 'Microsoft.SystemCenter.CollectionManagementServer') -or ($($actionAccount.TypeName) -eq 'Microsoft.SystemCenter.DataWarehouse.DataSet') -or ($($actionAccount.TypeName) -eq 'Microsoft.SystemCenter.Apm.DataTransferService') -or ($($actionAccount.TypeName) -eq 'Microsoft.SystemCenter.DataWarehouseSynchronizationService'))
								{
									Write-Verbose "$(Invoke-TimeStamp)$($actionAccount.Domain)\$($actionAccount.UserName) : `"$($actionAccount.AccountName)`" - KEEP"
									$DWWriterAccount += "$($actionAccount.Domain)\$($actionAccount.UserName) : `"$($actionAccount.AccountName)`" - KEEP"
								}
								else
								{
									Write-Verbose "$(Invoke-TimeStamp)$($actionAccount.Domain)\$($actionAccount.UserName) : `"$($actionAccount.AccountName)`" - REMOVE"
									$DWWriterAccount += "$($actionAccount.Domain)\$($actionAccount.UserName) : `"$($actionAccount.AccountName)`" - REMOVE"
								}
								if ($actionAccount.TypeName -eq 'Microsoft.SystemCenter.CollectionManagementServer')
								{
									$j++
									
								}
								elseif ($dwwrite.TypeName -eq 'Microsoft.SystemCenter.DataWarehouse.DataSet')
								{
									$j++
									
								}
								elseif ($dwwrite.TypeName -eq 'Microsoft.SystemCenter.Apm.DataTransferService')
								{
									#$j++
									#$j = $j
								}
								elseif ($dwwrite.TypeName -eq 'Microsoft.SystemCenter.DataWarehouseSynchronizationService')
								{
									$j++
									
								}
								else
								{
									$j = $j - 4
								}
								
							}
							$DWActionSSID = $DWAction | Select-Object -ExpandProperty SSID -Unique
							if ($j -lt '3' -or $j -gt '4')
							{
								Write-Verbose "$(Invoke-TimeStamp)$env:COMPUTERNAME : Missing one of the core class types that are required for the Data Warehouse Action Account profile, you should verify the RunAs Profile 'Data Warehouse Account' is set to the intended accounts:`n`n    Check this blog post: https://blakedrumm.com/blog/data-reader-account-provided-is-not-same-as-that-in-the-management-group/"
								$bestpractice += "$env:COMPUTERNAME : Missing one of the core class types that are required for the Data Warehouse Action Account profile, you should verify the RunAs Profile 'Data Warehouse Account' is set to the intended accounts:`n`n    Check this blog post: https://blakedrumm.com/blog/data-reader-account-provided-is-not-same-as-that-in-the-management-group/"
							}
							elseif ($DWActionSSID.Count -ne 1)
							{
								$bestpractice += "$env:COMPUTERNAME : Found an issue with the Data Warehouse Action Account RunAs Profile, you should verify the RunAs Profile 'Data Warehouse Account' is set to the intended accounts:`n`n    SQL Query DW_WriterLoginName:    $writerLoginName`n    Current Data Warehouse Action Account: $($DWWriterAccount -join "`n                                           ")"
								Write-Verbose "$(Invoke-TimeStamp)$env:COMPUTERNAME : Found an issue with the Data Warehouse Action Account RunAs Profile, you should verify the RunAs Profile 'Data Warehouse Account' is set to the intended accounts:`n`n    SQL Query DW_WriterLoginName:    $writerLoginName`n    Current Data Warehouse Action Account: $($DWWriterAccount -join "`n                                           ")"
							}
							Write-Console "-" -NoNewline -ForegroundColor Green
						}
						else
						{
							$DWWriter = "$($DWAction.Domain | Select-Object -First 1)\$($DWAction.UserName | Select-Object -First 1)"
							if ($writerLoginName -ine $DWWriter)
							{
								$MGID = (Import-Csv -Path $OutputPath\MG_Info.csv).ManagementGroupId
								$bestpractice += "$env:COMPUTERNAME : Found mismatch with the Data Warehouse Action Account, you should verify the RunAs Profile 'Data Warehouse Account' is set to the intended accounts:`n    SQL Query DW_WriterLoginName:    $writerLoginName`n    Data Warehouse Action Account:   $DWWriter`n`n    Query to update the Data Warehouse DB:`n                                           UPDATE dbo.ManagementGroup SET WriterLoginName='$DWWriter' WHERE ManagementGroupGuid='$MGID'"
								Write-Verbose "$(Invoke-TimeStamp)Found mismatch with the Data Warehouse Action Account"
								Write-Console "-" -NoNewline -ForegroundColor Green
							}
							
							$j = 0
							foreach ($dwaccount in $DWAction)
							{
								if ($dwaccount.TypeName -eq 'Microsoft.SystemCenter.CollectionManagementServer')
								{
									$j++
									
								}
								elseif ($dwaccount.TypeName -eq 'Microsoft.SystemCenter.DataWarehouse.DataSet')
								{
									$j++
									
								}
								elseif ($dwaccount.TypeName -eq 'Microsoft.SystemCenter.Apm.DataTransferService')
								{
									#$j++
									#$j = $j
								}
								elseif ($dwaccount.TypeName -eq 'Microsoft.SystemCenter.DataWarehouseSynchronizationService')
								{
									$j++
									
								}
								else
								{
									$j = $j - 4
								}
							}
							if ($j -lt '3' -or $j -gt '4')
							{
								Write-Verbose "$(Invoke-TimeStamp)$env:COMPUTERNAME : Found an issue with the Data Warehouse Action Account, you should verify the RunAs Profile 'Data Warehouse Account' is set to the intended accounts:`n`n    Check this blog post: https://blakedrumm.com/blog/data-reader-account-provided-is-not-same-as-that-in-the-management-group/"
								$bestpractice += "$env:COMPUTERNAME : Found an issue with the Data Warehouse Action Account, you should verify the RunAs Profile 'Data Warehouse Account' is set to the intended accounts:`n`n    Check this blog post: https://blakedrumm.com/blog/data-reader-account-provided-is-not-same-as-that-in-the-management-group/"
							}
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
					
					Write-Verbose "Caught Exception: $($error[0]) at line: $line`n`n$msg"
					"$(Invoke-TimeStamp)Caught Exception: $($error[0]) at line: $line`n`n$msg" | Out-File $OutputPath\Error.log -Append
				}
				Write-Host '-' -NoNewline -ForegroundColor Green
				Write-Verbose "$(Invoke-TimeStamp)Local output path resolved, this is a local machine."
				# Check RunAs Profile 'Data Warehouse Report Deployment Account'
				try
				{
					Write-Verbose "$(Invoke-TimeStamp)Check RunAs Profile 'Data Warehouse Report Deployment Account'"
					$rptDeploymentAccount = @()
					$DWReportDeployment = (Import-Csv -Path $OutputPath\RunAsAccountInfo.csv | Where-Object { $_.ProfileName -eq 'Microsoft.SystemCenter.DataWarehouse.ReportDeploymentActionAccount' }) | Select-Object Domain, UserName, AccountName, TypeName -Unique
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
							$bestpractice += "$env:COMPUTERNAME : Found an issue with the Data Warehouse Report Deployment Action Account RunAs Profile, you should verify the RunAs Profile 'Data Warehouse Report Deployment Account' is set to the intended accounts:`n`n    Check this blog post: https://blakedrumm.com/blog/data-reader-account-provided-is-not-same-as-that-in-the-management-group/"
							Write-Verbose "$(Invoke-TimeStamp)Found an issue with the Data Warehouse Report Deployment Action Account RunAs Profile"
							Write-Console "-" -NoNewline -ForegroundColor Green
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
								Write-Verbose "$(Invoke-TimeStamp)$env:COMPUTERNAME : Found an issue with the Data Warehouse Report Deployment Action Account RunAs Profile, you should verify the RunAs Profile 'Data Warehouse Report Deployment Account' is set to the intended accounts:`n`n    Check this blog post: https://blakedrumm.com/blog/data-reader-account-provided-is-not-same-as-that-in-the-management-group/"
								$bestpractice += "$env:COMPUTERNAME : Found an issue with the Data Warehouse Report Deployment Action Account RunAs Profile, you should verify the RunAs Profile 'Data Warehouse Report Deployment Account' is set to the intended accounts:`n`n    Check this blog post: https://blakedrumm.com/blog/data-reader-account-provided-is-not-same-as-that-in-the-management-group/"
							}
							
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
					
					Write-Verbose "Caught Exception: $($error[0]) at line: $line`n`n$msg"
					"$(Invoke-TimeStamp)Caught Exception: $($error[0]) at line: $line`n`n$msg" | Out-File $OutputPath\Error.log -Append
				}
				#=============================================================
				# Check SQL Configuration for Best Practices
				#=============================================================
				try
				{
					#=============================================================
					# Operations Manager DB
					#=============================================================
					Write-Verbose "$(Invoke-TimeStamp)Checking SCOM SQL Configuration for Best Practices"
					try
					{
						Write-Verbose "$(Invoke-TimeStamp)Importing CSV: $OutputPath\SQL_Properties_OpsDB.csv"
						
						$SQLPropertiesOpsDB = Import-Csv "$OutputPath\SQL_Properties_OpsDB.csv" -ErrorAction SilentlyContinue
						if ($SQLPropertiesOpsDB)
						{
							$SQLOpsDB_Instance = $SQLPropertiesOpsDB.ServerName
							
							Write-Verbose "$(Invoke-TimeStamp)Is the correct edition of SQL Server being used for the OpsDB: $($SQLPropertiesOpsDB.Edition)"
							if (($SQLPropertiesOpsDB).Edition)
							{
								if (($SQLPropertiesOpsDB).Edition -notmatch "Enterprise|Standard")
								{
									Write-Verbose "$(Invoke-TimeStamp)Found an issue with the edition of SQL Server for the Operations Manager Database SQL Instance, Operations Manager only allows Enterprise and Standard edition of SQL Server:`n    You are currently running: $(($SQLPropertiesOpsDB).Edition)`n    https://learn.microsoft.com/system-center/scom/plan-sqlserver-design#sql-server-requirements"
									$bestpractice += "Found an issue with the edition of SQL Server for the Operations Manager Database SQL Instance, Operations Manager only allows Enterprise and Standard edition of SQL Server:`n    You are currently running: $(($SQLPropertiesOpsDB).Edition)`n    https://learn.microsoft.com/system-center/scom/plan-sqlserver-design#sql-server-requirements"
								}
							}
							else
							{
								$bestpractice += "Unable to detect the editon of SQL Server for the Operations Manager Database SQL Instance."
							}
							
							Write-Verbose "$(Invoke-TimeStamp)Is Broker enabled for the OpsDB: $($SQLPropertiesOpsDB.Is_Broker_Enabled)"
							if ($SQLPropertiesOpsDB.Is_Broker_Enabled)
							{
								if ($SQLPropertiesOpsDB.Is_Broker_Enabled -eq 'FALSE')
								{
									Write-Verbose "$(Invoke-TimeStamp)SQL Broker is not enabled on the Operations Manager Database. You need to enable it: https://learn.microsoft.com/troubleshoot/system-center/scom/troubleshoot-sql-server-service-broker-issues"
									$bestpractice += "SQL Broker is not enabled on the Operations Manager Database. You need to enable it: https://learn.microsoft.com/troubleshoot/system-center/scom/troubleshoot-sql-server-service-broker-issues"
								}
							}
							else
							{
								$bestpractice += "Unable to detect if Broker is enabled for the Operations Manager Database SQL Instance."
							}
							
							Write-Verbose "$(Invoke-TimeStamp)Is CLR enabled for the OpsDB: $($SQLPropertiesOpsDB.Is_CLR_Enabled)"
							if ($SQLPropertiesOpsDB.Is_CLR_Enabled)
							{
								if ($SQLPropertiesOpsDB.Is_CLR_Enabled -eq 'FALSE')
								{
									Write-Verbose "$(Invoke-TimeStamp)SQL CLR is not enabled on the Operations Manager Database. You need to enable it: https://learn.microsoft.com/sql/relational-databases/clr-integration/clr-integration-enabling"
									$bestpractice += "SQL CLR is not enabled on the Operations Manager Database. You need to enable it: https://learn.microsoft.com/sql/relational-databases/clr-integration/clr-integration-enabling"
								}
							}
							else
							{
								$bestpractice += "Unable to detect if CLR is enabled for the Operations Manager Database SQL Instance."
							}
							Write-Verbose "$(Invoke-TimeStamp)Is Full Text Installed for the OpsDB: $($SQLPropertiesOpsDB.IsFullTextInstalled)"
							if ($SQLPropertiesOpsDB.IsFullTextInstalled)
							{
								if ($SQLPropertiesOpsDB.IsFullTextInstalled -eq 'FALSE')
								{
									Write-Verbose "$(Invoke-TimeStamp)SQL Full Text is not installed on the Operations Manager Database. To fix this you will need to reinstall the SQL Instance and check FullText during setup of SQL Instance."
									$bestpractice += "SQL Full Text is not installed on the Operations Manager Database. To fix this you will need to reinstall the SQL Instance and check FullText during setup of SQL Instance."
								}
							}
							else
							{
								$bestpractice += "Unable to detect if SQL Full Text is installed for the Operations Manager Database SQL Instance."
							}
							
							Write-Verbose "$(Invoke-TimeStamp)Checking if SQL Collation set correctly for OpsDB SQL Instance: $($SQLPropertiesOpsDB.Collation)"
							if ($SQLPropertiesOpsDB.Collation)
							{
								if ($SQLPropertiesOpsDB.Collation -notmatch "SQL_Latin1_General_CP1_CI_AS|Latin1_General_CI_AS|Latin1_General_100_CI_AS|French_CI_AS|French_100_CI_AS|Cyrillic_General_CI_AS|Chinese_PRC_CI_AS|Chinese_Simplified_Pinyin_100_CI_AS|Chinese_Traditional_Stroke_Count_100_CI_AS|Japanese_CI_ASJapanese_XJIS_100_CI_AS|Traditional_Spanish_CI_AS|Modern_Spanish_100_CI_AS|Latin1_General_CI_AS|Cyrillic_General_100_CI_AS|Korean_100_CI_AS|Czech_100_CI_AS|Hungarian_100_CI_AS|Polish_100_CI_AS|Finnish_Swedish_100_CI_AS")
								{
									Write-Verbose "$(Invoke-TimeStamp)SQL Server Collation is not set correctly for the Operations Manager SQL Instance: $($SQLPropertiesOpsDB.Collation)"
									$bestpractice += "SQL Server Collation is not set correctly for the Operations Manager SQL Instance: $($SQLPropertiesOpsDB.Collation)"
								}
							}
							else
							{
								$bestpractice += "Unable to detect if SQL Collation is set correctly for the Operations Manager Database SQL Instance."
							}
						}
					}
					catch
					{
						"$(Invoke-TimeStamp)Unable to run Best Practice Analyzer for SCOM OpsDB Configuration due to Error: $($error[0])`n`n    Line: $line`n    Message:$msg" | Out-File $OutputPath\Error.log -Append
						#potential error code
						#use continue or break keywords
						#$e = $_.Exception
						$line = $_.InvocationInfo.ScriptLineNumber
						$msg = $e.Message
						
						Write-Verbose "$(Invoke-TimeStamp)Unable to run Best Practice Analyzer for SCOM OpsDB due to Error: $($error[0])`n`n    Line: $line`n    Message:$msg"
					}
					#=============================================================
					# Data Warehouse DB
					#=============================================================
					Write-Verbose "$(Invoke-TimeStamp)Importing CSV: $OutputPath\SQL_Properties_DW.csv"
					$SQLPropertiesDW = Import-Csv "$OutputPath\SQL_Properties_DW.csv" -ErrorAction SilentlyContinue
					if ($SQLPropertiesDW)
					{
						$SQLDW_Instance = $SQLPropertiesDW.ServerName
						
						Write-Verbose "$(Invoke-TimeStamp)Is the correct edition of SQL Server being used for the Data Warehouse: $($SQLPropertiesDW.Edition)"
						if (($SQLPropertiesDW).Edition)
						{
							if (($SQLPropertiesDW).Edition -notmatch "Enterprise|Standard")
							{
								Write-Verbose "$(Invoke-TimeStamp)Found an issue with the edition of SQL Server for the Operations Manager Data Warehouse Database SQL Instance, Operations Manager only allows Enterprise and Standard edition of SQL Server:`n    You are currently running: $(($SQLPropertiesDW).Edition)`n    https://learn.microsoft.com/system-center/scom/plan-sqlserver-design#sql-server-requirements"
								$bestpractice += "Found an issue with the edition of SQL Server for the Operations Manager Data Warehouse Database SQL Instance, Operations Manager only allows Enterprise and Standard edition of SQL Server:`n    You are currently running: $(($SQLPropertiesDW).Edition)`n    https://learn.microsoft.com/system-center/scom/plan-sqlserver-design#sql-server-requirements"
							}
						}
						else
						{
							$bestpractice += "Unable to detect the editon of SQL Server for the Operations Manager Data Warehouse Database SQL Instance."
						}
						Write-Verbose "$(Invoke-TimeStamp)Is Full Text Installed for the Data Warehouse: $($SQLPropertiesDW.IsFullTextInstalled)"
						if ($SQLPropertiesDW.IsFullTextInstalled)
						{
							if ($SQLPropertiesDW.IsFullTextInstalled -eq 'FALSE')
							{
								Write-Verbose "SQL Full Text is not installed on the Data Warehouse Database. To fix this you will need to reinstall the SQL Instance and check FullText during setup of SQL Instance."
								$bestpractice += "SQL Full Text is not installed on the Data Warehouse Database. To fix this you will need to reinstall the SQL Instance and check FullText during setup of SQL Instance."
							}
						}
						else
						{
							$bestpractice += "Unable to detect if SQL Full Text is installed for the Operations Manager Data Warehouse Database SQL Instance."
						}
						
						Write-Verbose "$(Invoke-TimeStamp)Checking if SQL Collation set correctly for Data Warehouse SQL Instance: $($SQLPropertiesDW.Collation)"
						if ($SQLPropertiesDW.Collation)
						{
							if ($SQLPropertiesDW.Collation -notmatch "SQL_Latin1_General_CP1_CI_AS|Latin1_General_CI_AS|Latin1_General_100_CI_AS|French_CI_AS|French_100_CI_AS|Cyrillic_General_CI_AS|Chinese_PRC_CI_AS|Chinese_Simplified_Pinyin_100_CI_AS|Chinese_Traditional_Stroke_Count_100_CI_AS|Japanese_CI_ASJapanese_XJIS_100_CI_AS|Traditional_Spanish_CI_AS|Modern_Spanish_100_CI_AS|Latin1_General_CI_AS|Cyrillic_General_100_CI_AS|Korean_100_CI_AS|Czech_100_CI_AS|Hungarian_100_CI_AS|Polish_100_CI_AS|Finnish_Swedish_100_CI_AS")
							{
								Write-Verbose "SQL Server Collation is not set correctly for the Data Warehouse SQL Instance: $($SQLPropertiesDW.Collation)"
								$bestpractice += "SQL Server Collation is not set correctly for the Data Warehouse SQL Instance: $($SQLPropertiesDW.Collation)"
							}
						}
						else
						{
							$bestpractice += "Unable to detect if SQL Collation is set correctly for the Operations Manager Data Warehouse Database SQL Instance."
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
					Write-Verbose "$(Invoke-TimeStamp)Running check for the SCOM DB Sizes"
					Write-Verbose "$(Invoke-TimeStamp)Importing CSV: $OutputPath\SQL_DBSize_OpsDB.csv"
					$SQLDBSizesOpsDB = Import-Csv "$OutputPath\SQL_DBSize_OpsDB.csv" -ErrorAction SilentlyContinue
					if ($SQLDBSizesOpsDB)
					{
						$OpsDB_MOMData = $SQLDBSizesOpsDB | Where-Object { $_.Name -eq 'MOM_DATA' }
						if ($OpsDB_MOMData.'FreeSpace(%)')
						{
							if ([int]$(($OpsDB_MOMData.'FreeSpace(%)').Split("%").Trim()[0]) -lt 15)
							{
								Write-Verbose "$(Invoke-TimeStamp)Operations Manager Database is nearing full, less than 15% free:`n $($OpsDB_MOMData.'FreeSpace(%)') free space`n $($OpsDB_MOMData.'FreeSpace(MB)') MB free space`n $($OpsDB_MOMData.'SpaceUsed(MB)') MB space used"
								$bestpractice += "Operations Manager Database is nearing full, less than 15% free:`n $($OpsDB_MOMData.'FreeSpace(%)') free space`n $($OpsDB_MOMData.'FreeSpace(MB)') MB free space`n $($OpsDB_MOMData.'SpaceUsed(MB)') MB space used"
							}
						}
						else
						{
							$bestpractice += "Unable to check the Operations Manager Database Free Space."
							Write-Verbose "$(Invoke-TimeStamp)Unable to check the Operations Manager Database Free Space."
						}
						
						if ($OpsDB_MOMData.Location)
						{
							$OpsDB_DataDiskDrive = ($OpsDB_MOMData.Location).Split(":")[0]
						}
						else
						{
							$OpsDB_DataDiskDrive = $null
						}
					}
					else
					{
						$OpsDB_DataDiskDrive = $null
					}
					
					#=============================================================
					# Data Warehouse DB
					#=============================================================
					Write-Verbose "$(Invoke-TimeStamp)Importing CSV: $OutputPath\SQL_DBSize_DW.csv"
					$SQLDBSizesDWDB = Import-Csv "$OutputPath\SQL_DBSize_DW.csv" -ErrorAction SilentlyContinue
					if ($SQLDBSizesDWDB)
					{
						$DWDB_MOMData = $SQLDBSizesDWDB | Where-Object { $_.Name -eq 'MOM_DATA' }
						if ($OpsDB_MOMData.'FreeSpace(%)')
						{
							if ([int]$(($DWDB_MOMData.'FreeSpace(%)').Split(" %")[0]) -lt 15)
							{
								Write-Verbose "$(Invoke-TimeStamp)Operations Manager Data Warehouse Database is nearing full, less than 15% free:`n $($DWDB_MOMData.'FreeSpace(%)') free space`n $($DWDB_MOMData.'FreeSpace(MB)') MB free space`n $($DWDB_MOMData.'SpaceUsed(MB)') MB space used"
								$bestpractice += "Operations Manager Data Warehouse Database is nearing full, less than 15% free:`n $($DWDB_MOMData.'FreeSpace(%)') free space`n $($DWDB_MOMData.'FreeSpace(MB)') MB free space`n $($DWDB_MOMData.'SpaceUsed(MB)') MB space used"
							}
						}
						else
						{
							$bestpractice += "Unable to check the Operations Manager Data Warehouse Database Free Space."
							Write-Verbose "$(Invoke-TimeStamp)Unable to check the Operations Manager Data Warehouse Database Free Space."
						}
						
						
						
						if ($DWDB_MOMData.Location)
						{
							$DWDB_DataDiskDrive = ($DWDB_MOMData.Location).Split(":")[0]
						}
						else
						{
							$DWDB_DataDiskDrive = $null
						}
					}
					else
					{
						$DWDB_DataDiskDrive = $null
					}
					
					#=============================================================
					# tempdb DB
					#=============================================================
					[int]$freespace_percent = $null
					Write-Verbose "$(Invoke-TimeStamp)Importing CSV: $OutputPath\SQL_DBSize_OpsDB_TempDB.csv"
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
								Write-Verbose "$(Invoke-TimeStamp)Operations Manager tempdb Database is nearing full, less than 10% free overall: $resultNumber`% free space"
								$bestpractice += "Operations Manager tempdb Database is nearing full, less than 10% free overall: $resultNumber`% free space"
							}
						}
						$OpsDB_tempdb_driveLetters = @()
						$OpsDB_tempdbJustDriveLetters = @()
						foreach ($OpsDBtempdbDrive in $SQLOpsDB_tempdb.Location)
						{
							$OpsDB_tempdb_driveLetters += "$($OpsDBtempdbDrive.Split(":") | Select-Object -First 1)`:\ "
							$OpsDB_tempdbJustDriveLetters += $($OpsDBtempdbDrive.Split(":") | Select-Object -First 1)
						}
						$OpsDB_tempdb_driveLetters = $OpsDB_tempdb_driveLetters.Split(" ") | Select-Object -Unique
						$OpsDB_tempdbJustDriveLetters = $OpsDB_tempdbJustDriveLetters.Split(" ") | Select-Object -Unique
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
								Write-Verbose "$(Invoke-TimeStamp)Operations Manager Data Warehouse tempdb Database is nearing full, less than 10% free overall: $resultNumber`% free space"
								$bestpractice += "Operations Manager Data Warehouse tempdb Database is nearing full, less than 10% free overall: $resultNumber`% free space"
							}
						}
						$DW_tempdb_driveLetters = @()
						$DW_tempdbJustDriveLetters = @()
						foreach ($DWDBtempdbDrive in $SQLDW_tempdb.Location)
						{
							$DW_tempdb_driveLetters += "$($DWDBtempdbDrive.Split(":") | Select-Object -First 1)`:\ "
							$DW_tempdbJustDriveLetters += $($DWDBtempdbDrive.Split(":") | Select-Object -First 1)
						}
						$DW_tempdb_driveLetters = $DW_tempdb_driveLetters.Split(" ") | Select-Object -Unique
						$DW_tempdbJustDriveLetters = $DW_tempdbJustDriveLetters.Split(" ") | Select-Object -Unique
						
						if ($SQLDW_Instance -ne $SQLOpsDB_Instance -and
							($OpsDB_DataDiskDrive -eq $DWDB_DataDiskDrive -or
								$OpsDB_DataDiskDrive -match $OpsDB_tempdbJustDriveLetters -or
								$DWDB_DataDiskDrive -match $DW_tempdbJustDriveLetters))
						{
							Write-Verbose "$(Invoke-TimeStamp)Operations Manager Database files (MOM_DATA) are sharing the same drive as the Data Warehouse or tempdb. It is recommended to seperate these to their own respective drives due to I/O constraints and other issues that arise.`n    Operations Manager Database File Location: $($OpsDB_MOMData.Location)`n    Data Warehouse Database File Location: $($DWDB_MOMData.Location)`n    Operations Manager tempdb Database File Location: $OpsDB_tempdb_driveLetters `n    Data Warehouse tempdb Database File Location: $DW_tempdb_driveLetters"
							$bestpractice += "Operations Manager Database files (MOM_DATA) are sharing the same drive as the Data Warehouse or tempdb. It is recommended to seperate these to their own respective drives due to I/O constraints and other issues that arise.`n    Operations Manager Database File Location: $($OpsDB_MOMData.Location)`n    Data Warehouse Database File Location: $($DWDB_MOMData.Location)`n    Operations Manager tempdb Database File Location: $OpsDB_tempdb_driveLetters `n    Data Warehouse tempdb Database File Location: $DW_tempdb_driveLetters"
						}
						if ($SQLDW_Instance -ne $SQLOpsDB_Instance -and $OpsDB_DataDiskDrive -match $OpsDB_tempdbJustDriveLetters)
						{
							Write-Verbose "$(Invoke-TimeStamp)Operations Manager Database file (MOM_DATA) is sharing the same drive as the tempdb. It is recommended to seperate these to their own respective drives due to I/O constraints and other issues that arise.`n    Operations Manager Database File Location: $($OpsDB_MOMData.Location)`n    Operations Manager tempdb Database File Location: $OpsDB_tempdb_driveLetters"
							$bestpractice += "Operations Manager Database file (MOM_DATA) is sharing the same drive as the tempdb. It is recommended to seperate these to their own respective drives due to I/O constraints and other issues that arise.`n    Operations Manager Database File Location: $($OpsDB_MOMData.Location)`n    Operations Manager tempdb Database File Location: $OpsDB_tempdb_driveLetters"
						}
						if ($SQLDW_Instance -ne $SQLOpsDB_Instance -and $DWDB_DataDiskDrive -match $DW_tempdbJustDriveLetters)
						{
							Write-Verbose "$(Invoke-TimeStamp)Operations Manager Data Warehouse Database file (MOM_DATA) is sharing the same drive as the tempdb. It is recommended to seperate these to their own respective drives due to I/O constraints and other issues that arise.`n    Data Warehouse Database File Location: $($DWDB_MOMData.Location)`n    Data Warehouse tempdb Database File Location: $DW_tempdb_driveLetters"
							$bestpractice += "Operations Manager Database Data Warehouse file (MOM_DATA) is sharing the same drive as the tempdb. It is recommended to seperate these to their own respective drives due to I/O constraints and other issues that arise.`n    Data Warehouse Database File Location: $($DWDB_MOMData.Location)`n    Data Warehouse tempdb Database File Location: $DW_tempdb_driveLetters"
						}
					}
					
					
					
					#=============================================================
					#=============================================================
					
				}
				catch
				{
					#potential error code
					#use continue or break keywords
					$e = $_.Exception
					$line = $_.InvocationInfo.ScriptLineNumber
					$msg = $e.Message
					
					"$(Invoke-TimeStamp)Unable to run Best Practice Analyzer for SCOM DW SQL Configuration due to Error: $($error[0])`n`n    Line: $line`n    Message:$msg" | Out-File $OutputPath\Error.log -Append
					Write-Verbose "$(Invoke-TimeStamp)Unable to run Best Practice Analyzer for SCOM DW SQL Configuration due to Error: $($error[0])`n`n    Line: $line`n    Message:$msg"
				}
				
				
				#=============================================================
				# Check SPN gathered Data for discrepancies
				#$outputpath = '.\'
				#=============================================================
				#=============================================================
				#=============================================================
				$error.Clear()
				try
				{
					function Get-SPNBestPractice
					{
						Write-Verbose "$(Invoke-TimeStamp)Starting SPN Checker"
						Write-Verbose "$(Invoke-TimeStamp)Importing CSV: $(Resolve-Path -Path "$OutputPath\SPN-Output.csv" -ErrorAction Stop)"
						$SPNdata = Import-Csv "$OutputPath\SPN-Output.csv" -ErrorAction Stop
						if (-NOT ($script:ManagementServers))
						{
							try
							{
								$script:ManagementServers = Import-Csv "$OutputPath\ManagementServers.csv" -ErrorAction Stop
							}
							catch
							{
								if (!$script:ManagementServers)
								{
									$script:ManagementServers = Get-SCOMManagementServer
								}
							}
							[array]$MSlist = $script:ManagementServers | Select-Object -Property DisplayName -ExpandProperty DisplayName -Unique
						}
						else
						{
							[array]$MSlist = $script:ManagementServers
						}
						
						ForEach ($ManagementServer in $MSlist)
						{
							Write-Verbose "SPN Best Practices for: $ManagementServer"
							$MS = (($ManagementServer | Out-String).Split("."))[0]
							#$SPNdata | Where { ($_.ServiceClass -eq 'MSOMHSvc') -and ($_.ComputerName -eq "$MS") }
							$MSOMSDKSvc = $SPNdata | Where-Object { ($_.ServiceClass -eq 'MSOMSdkSvc') -and ($_.SPN -eq "MSOMSdkSvc/$MS") -or ($_.SPN -eq "MSOMSdkSvc/$ManagementServer") }
							
							$OSServicesData = (Get-CimInstance Win32_service -ComputerName $ManagementServer -ErrorAction SilentlyContinue).where{ $_.name -eq 'omsdk' -or $_.name -eq 'cshost' -or $_.name -eq 'HealthService' }
							$OSServices = $null
							
							if ($OSServicesData)
							{
								$OSServices = @()
								$OSServicesData | ForEach-Object {
									$OSServices += [PSCustomObject]@{
										ComputerName	   = $MS
										ServiceDisplayName = $_.DisplayName
										ServiceName	       = $_.Name
										AccountName	       = $_.StartName
										StartMode		   = $_.StartMode
										CurrentState	   = $_.State
									}
								} | Sort-Object ServiceName
							}
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
															$bestpractice += "$ManagementServer : SPNs are set incorrectly for MSOMSdkSvc (Service Running as Computer Account), the following commands will resolve your SPN issues:`n    setspn -D $($SDKSvcName.SPN) $($SDKSvcName.SAMAccountName)`n    setspn -S $($SDKSvcName.SPN) $fullAccountName`n"
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
															$bestpractice += "$ManagementServer : SPNs are set incorrectly for MSOMSdkSvc (Service Running as User Account), the following commands will resolve your SPN issues:`n    setspn -D $($SDKSvcName.SPN) $($SDKSvcName.SAMAccountName)`n    setspn -S $($SDKSvcName.SPN) $($Service.AccountName)`n"
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
									Write-Verbose "$(Invoke-TimeStamp)  Unable to gather OSServices data for checking the account SCOM is running as."
									"$(Invoke-TimeStamp)  Unable to gather OSServices data for checking the account SCOM is running as." | Out-File $OutputPath\Error.log -Append
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
						$script:ManagementServers = Import-Csv "$OutputPath\ManagementServers.csv" -ErrorAction Stop
					}
					catch
					{
						if (!$script:ManagementServers)
						{
							$script:ManagementServers = Get-SCOMManagementServer | Select-Object -ExpandProperty DisplayName
						}
					}
					#>
					
					Write-Verbose "$(Invoke-TimeStamp)Running SPN best practice analyzer"
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
					"$(Invoke-TimeStamp)Unable to run Best Practice Analyzer for SPN data due to Error: $error" | Out-File $OutputPath\Error.log -Append
					Write-Verbose "$(Invoke-TimeStamp)Unable to run Best Practice Analyzer for SPN data due to Error: $error"
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
							$obj | Add-Member -MemberType NoteProperty -Name DiscoveryName -Value ($Group.GetMonitoringDiscoveries() | ForEach-Object { $_ | Select-Object -ExpandProperty DisplayName })
							$obj | Add-Member -MemberType NoteProperty -Name DiscoveryID -Value ($Group.GetMonitoringDiscoveries() | Select-Object -ExpandProperty ID)
							$obj | Add-Member -MemberType NoteProperty -Name OuterXML -Value ($Group.GetMonitoringDiscoveries().CreateNavigator() | Select-Object -ExpandProperty OuterXml)
							$obj | Add-Member -MemberType NoteProperty -Name Typedvalue -Value ($Group.GetMonitoringDiscoveries().CreateNavigator() | Select-Object -ExpandProperty TypedValue)
							$obj | Add-Member -MemberType NoteProperty -Name DynamicExpressionCount -Value (($obj.OuterXML | ForEach-Object{ $_ | Select-Xml -XPath "//Expression" }).Count)
							$obj | Add-Member -MemberType NoteProperty -Name MemberCount -Value $($Group | Get-SCOMClassInstance).Count
							Write-Debug "         - Object: `n$($obj | Select-Object *)"
							$groupOut += $obj | Where-Object { $_.OuterXML -match "<Expression>" }
							Write-Verbose "              - Dynamic Expression Count: $($obj.DynamicExpressionCount)"
						}
					}
					
					if ($groupOut.DynamicExpressionCount -gt 15)
					{
						Write-Verbose "           - Tagged Group, too many Dynamic expressions!`n------------------------------------------------------------------"
						$GroupCalcPollingIntervalInMilliseconds = (Get-ItemProperty "HKLM:\SOFTWARE\Microsoft\System Center\2010\Common\" -ErrorAction SilentlyContinue).GroupCalcPollingIntervalMilliseconds
						if (-NOT $GroupCalcPollingIntervalInMilliseconds)
						{
							$GroupCalcPollingIntervalInMilliseconds = '(not present)'
						}
						$bestpractice += @"
A high number of dynamic groups detected, this may cause some issues with group calculation (https://kevinholman.com/2017/03/08/recommended-registry-tweaks-for-scom-2016-management-servers/). Try updating the following registry key:
     Path: HKLM:\SOFTWARE\Microsoft\System Center\2010\Common\
     REG_DWORD Decimal Value:       GroupCalcPollingIntervalMilliseconds = 1800000

     SCOM existing registry value:  $GroupCalcPollingIntervalInMilliseconds
     SCOM default code value:  30000 (30 seconds)

     Description:  This setting will slow down how often group calculation runs to find changes in group memberships. Group calculation can be very expensive, especially with a large number of groups, large agent count, or complex group membership expressions.
                   Groups with complex expressions in large environments can actually take several minutes to calculate. Multiply that times a large number of groups and you have problems. Slowing this down will help keep groupcalc from consuming all the healthservice and database I/O.
                  1800000 milliseconds is every 30 minutes. This means once a group initializes (31410 event) on a management server in the pool, that specific group will wait 30 minutes before evaluating if any members need to be added/removed based on dynamic inclusion criteria in the expression.


     Overall Dynamic Membership Group Count: $($groupOut.Count)
"@
					}
					$($groupOut | Select-Object DynamicGroupName, DiscoveryName, DynamicExpressionCount, MemberCount | Sort-Object DynamicExpressionCount, MemberCount -Descending) | Out-File "$OutputPath\GroupMembershipInformation.txt" -Width 4096
					$($groupOut | Select-Object DynamicGroupName, DiscoveryName, DynamicExpressionCount, MemberCount | Sort-Object DynamicExpressionCount, MemberCount -Descending) | Export-CSV -Path "$OutputPath\GroupMembershipInformation.csv" -NoTypeInformation
				}
				catch
				{
					"$(Invoke-TimeStamp)Unable to run Best Practice Analyzer for SCOM Group Checker due to Error: $($error[0])" | Out-File $OutputPath\Error.log -Append
					Write-Verbose $_
				}
			}

			# #=============================================================
			# General Info Checker
			# #=============================================================
			# Check information in General Info Text File for discrepancies
			$GeneralInfo = Get-Content "$OutputPath\General Information.txt" -ErrorAction SilentlyContinue
			if ($GeneralInfo)
			{
				Write-Verbose "$(Invoke-TimeStamp)Starting General Information Text file analysis"
				foreach ($line in $GeneralInfo)
				{
					# Check Latency between Management Server(s) and SQL Database(s)
					$objectSplit = ($line | Where-Object {
							($_ -match "-> $(($script:OpsDB_SQLServer).Replace("\", "\\")) :|-> $(($script:DW_SQLServer).Replace("\", "\\")):")
						}) -split " "
					if ($objectSplit)
					{
						$serverName = $objectSplit | Select-Object -Index 0
						$dbServerName = $objectSplit | Select-Object -Index 2
						$responseTime = $objectSplit | Select-Object -Last 2
						if ([int]$($responseTime.Split(" ") | Select-Object -First 1) -gt 10)
						{
							$bestpractice += "Management Server: $serverName has high (greater than 10ms) response time to Database: $dbServerName - ($responseTime)"
						}
					}
					# Check that time is synchronized
					$timeSync = ($line | Where-Object { $_ -match "Time NOT synchronized between :" })
					if ($timeSync)
					{
						$bestpractice += $timeSync
					}
					# Verify the ConfigService.config file is the same across all the Management Servers
					$configCheck = ($line | Where-Object { $_ -match "There are differences between :" }) -split " "
					if ($configCheck)
					{
						$originManagementServer = $configCheck | Select-Object -Index 5
						$destinationManagementServer = $configCheck | Select-Object -Index 7
						$bestpractice += "Configuration differences between $originManagementServer and $destinationManagementServer. (ConfigService.config)"
					}
				}
			}
			Write-Verbose "$(Invoke-TimeStamp)Completed Best Practice Analysis!"
			return $bestpractice
		}
		$gatheredData = @()
		# Go through each server passed to the main function: Invoke-GetBestPractices
		foreach ($server in $Servers)
		{
			Write-Console "    $server" -NoNewline -ForegroundColor Cyan
			if ($server -match $env:COMPUTERNAME)
			{
				# If Local
				Write-Host '-' -NoNewline -ForegroundColor Green
				$scriptOutput = Invoke-InnerGetBestPractices
				$gatheredData += $scriptOutput
				
				Write-Console "> Completed!`n" -NoNewline -ForegroundColor Green
			}
			else
			{
				# If Remote
				Write-Host '-' -NoNewline -ForegroundColor Green
				$InnerGetBestPracticesFunctionScript = "function Invoke-InnerGetBestPractices { ${function:Invoke-InnerGetBestPractices} }"
				$scriptOutput = Invoke-Command -ComputerName $server -ArgumentList $InnerGetBestPracticesFunctionScript, $VerbosePreference -ScriptBlock {
					Param ($script,
						$VerbosePreference)
					. ([ScriptBlock]::Create($script))
					<#
					if ($VerbosePreference.value__ -ne 0)
					{
						return Invoke-InnerGetBestPractices -Verbose
					}
					else
					{
						return Invoke-InnerGetBestPractices
					}
					#>
					$scriptOutput = Invoke-InnerGetBestPractices
					if ($scriptOutput)
					{
						return $scriptOutput
					}
					else
					{
						return $null
					}
				}
				if ($scriptOutput -or $null -ne $scriptOutput)
				{
					$gatheredData += $scriptOutput
				}
				Write-Console "> Completed!`n" -NoNewline -ForegroundColor Green
			}
		}
	}
	END
	{
		$i = 0
		# Organize the output so it looks clean and seperated, each item will have its own number. (1, 2, 3, 4, etc.)
		if ($null -eq $gatheredData -or $gatheredData -eq ' ')
		{
			$finalOut = @"
$header
No issues detected with the data provided.
"@
		}
		else
		{
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
No issues detected with the data provided.
"@
			}
		}
		Write-Verbose "Writing Best Practices text file: $OutputPath\Best Practices.txt"
		$finalOut | Out-File -FilePath "$OutputPath\Best Practices.txt"
	}
}