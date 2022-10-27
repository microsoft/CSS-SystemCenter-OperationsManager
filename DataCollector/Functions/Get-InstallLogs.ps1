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