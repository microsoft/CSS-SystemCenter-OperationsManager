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