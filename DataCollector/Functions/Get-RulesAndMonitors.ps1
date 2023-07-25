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
		Write-Console "Output folder not found for ($OutputDirectory).  Creating folder..."
		mkdir $OutputDirectory
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
		Write-Console "  Gathering all Rules in SCOM..." -ForegroundColor Green
		$Rules = Get-SCOMRule
		Write-Console "   Found $($Rules.Count) rules" -ForegroundColor Gray
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
		
		Write-Console "    Gathering Properties from each Rule..." -ForegroundColor Green
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
			$obj | Add-Member -MemberType NoteProperty -Name "ID" -Value $RuleID
			$obj | Add-Member -MemberType NoteProperty -Name "WorkFlowType" -Value "Rule"
			$obj | Add-Member -MemberType NoteProperty -Name "DisplayName" -Value $RuleDisplayName
			$obj | Add-Member -MemberType NoteProperty -Name "Name" -Value $RuleName
			$obj | Add-Member -MemberType NoteProperty -Name "TargetDisplayName" -Value $TargetDisplayName
			$obj | Add-Member -MemberType NoteProperty -Name "TargetName" -Value $TargetName
			$obj | Add-Member -MemberType NoteProperty -Name "Category" -Value $Category
			$obj | Add-Member -MemberType NoteProperty -Name "Enabled" -Value $Enabled
			$obj | Add-Member -MemberType NoteProperty -Name "Alert" -Value $GenAlert
			$obj | Add-Member -MemberType NoteProperty -Name "AlertName" -Value $AlertDisplayName
			$obj | Add-Member -MemberType NoteProperty -Name "AlertPriority" -Value $AlertPriority
			$obj | Add-Member -MemberType NoteProperty -Name "AlertSeverity" -Value $AlertSeverity
			$obj | Add-Member -MemberType NoteProperty -Name "MPDisplayName" -Value $MPDisplayName
			$obj | Add-Member -MemberType NoteProperty -Name "MPName" -Value $MPName
			$obj | Add-Member -MemberType NoteProperty -Name "RuleDataSource" -Value $RuleDS
			$obj | Add-Member -MemberType NoteProperty -Name "MonitorClassification" -Value ""
			$obj | Add-Member -MemberType NoteProperty -Name "MonitorType" -Value ""
			$obj | Add-Member -MemberType NoteProperty -Name "Description" -Value $Description
			$RuleReport += $obj
		}
		Write-Console "     Generating Rules (CSV and TXT) at ($OutputDirectory)..." -ForegroundColor Magenta
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
		"$(Invoke-TimeStamp)Caught Exception: $e :: Message: $msg :: at line: $line" | Out-File $OutputPath\Error.log -Append
	}
	#=========================
	# End Rules section
	Write-Console " "
	# Begin Monitors section
	#=========================
	try
	{
		#Get all the SCOM Monitors
		Write-Console "  Gathering all Monitors in SCOM..." -ForegroundColor Green
		$Monitors = Get-SCOMMonitor
		Write-Console "   Found $($Monitors.Count) monitors" -ForegroundColor Gray
		#Loop through each monitor and get properties
		Write-Console "    Gathering Properties from each Monitor..." -ForegroundColor Green
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
			$obj | Add-Member -MemberType NoteProperty -Name "ID" -Value $MonitorID
			$obj | Add-Member -MemberType NoteProperty -Name "WorkFlowType" -Value "Monitor"
			$obj | Add-Member -MemberType NoteProperty -Name "DisplayName" -Value $MonitorDisplayName
			$obj | Add-Member -MemberType NoteProperty -Name "Name" -Value $MonitorName
			$obj | Add-Member -MemberType NoteProperty -Name "TargetDisplayName" -Value $TargetDisplayName
			$obj | Add-Member -MemberType NoteProperty -Name "TargetName" -Value $TargetName
			$obj | Add-Member -MemberType NoteProperty -Name "Category" -Value $Category
			$obj | Add-Member -MemberType NoteProperty -Name "Enabled" -Value $Enabled
			$obj | Add-Member -MemberType NoteProperty -Name "Alert" -Value $GenAlert
			$obj | Add-Member -MemberType NoteProperty -Name "AlertName" -Value $AlertDisplayName
			$obj | Add-Member -MemberType NoteProperty -Name "AlertPriority" -Value $AlertPriority
			$obj | Add-Member -MemberType NoteProperty -Name "AlertSeverity" -Value $AlertSeverity
			$obj | Add-Member -MemberType NoteProperty -Name "MPDisplayName" -Value $MPDisplayName
			$obj | Add-Member -MemberType NoteProperty -Name "MPName" -Value $MPName
			$obj | Add-Member -MemberType NoteProperty -Name "RuleDataSource" -Value ""
			$obj | Add-Member -MemberType NoteProperty -Name "MonitorClassification" -Value $MonitorClassification
			$obj | Add-Member -MemberType NoteProperty -Name "MonitorType" -Value $MonitorType
			$obj | Add-Member -MemberType NoteProperty -Name "Description" -Value $Description
			$MonitorReport += $obj
		}
		
		Write-Console "     Generating Monitors (CSV and TXT) at ($OutputDirectory)..." -ForegroundColor Magenta
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
		"$(Invoke-TimeStamp)Get-RulesAndMonitors - Caught Exception: $e :: Message: $msg :: at line: $line" | Out-File $OutputPath\Error.log -Append
	}
	#=========================
	# End Monitors section
	#End of Script
}