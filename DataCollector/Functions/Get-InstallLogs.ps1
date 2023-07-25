Function Invoke-GetInstallLogs
{
	param
	(
		[Parameter(Position = 0)]
		[string[]]$Servers = $env:COMPUTERNAME
	)
	BEGIN
	{
		#region Install Log Inner Function
		function Invoke-InnerInstallLog
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
				return "function:Invoke-InnerInstallLog - $($Error[0])"
			}
			return "$env:TEMP\SCOM-DataCollector-InstallLogs\"
		}
		#endregion Install Log Inner Function
		New-Item -ItemType Directory -Path "$OutputPath\Install Logs\AppData Install Logs" -Force -ErrorAction SilentlyContinue | Out-Null
		$OutputDirectory = "$OutputPath\Install Logs\AppData Install Logs"
		Write-Verbose "  Gathering Install Logs from:"
		$InnerInstallLogFunctionScript = "function Invoke-InnerInstallLog { ${Function:Invoke-InnerInstallLog} }"
		$RemotePath = "\\$env:COMPUTERNAME\$($OutputPath.Replace(':', '$'))"
	}
	PROCESS
	{
		foreach ($server in $Servers)
		{
			Write-Console "  $server" -NoNewline -ForegroundColor Cyan
			$serverPath = "$OutputPath\Install Logs\AppData Install Logs\$server"
			New-Item -ItemType Directory -Path $serverPath -Force -ErrorAction SilentlyContinue | Out-Null
			if ($server -match $env:COMPUTERNAME)
			{
				Write-Console '-' -NoNewline -ForegroundColor Green
				try
				{
					$finalout += Invoke-InnerInstallLog -ErrorAction Stop
					if ($finalout -like "function:Invoke-InnerInstallLog*")
					{
						Write-Verbose "$(Invoke-TimeStamp)function:Invoke-GetInstallLogs - Local - $server - $($error[0])"
						"$(Invoke-TimeStamp)function:Invoke-GetInstallLogs - Local - $server - $($error[0])" | Out-File $OutputPath\Error.log -Append
					}
					Copy-Item "\\$server\$($finalout.Replace(':', '$'))\*" $serverPath -Force -Recurse -ErrorAction Stop
					Remove-Item "\\$server\$($finalout.Replace(':', '$'))\*" -Recurse -Force -ErrorAction SilentlyContinue
				}
				catch
				{
					Write-Verbose "$(Invoke-TimeStamp)function:Invoke-GetInstallLogs - Local - $server - $($error[0])"
					"$(Invoke-TimeStamp)function:Invoke-GetInstallLogs - Local - $server - $($error[0])" | Out-File $OutputPath\Error.log -Append
					
				}
				Write-Console "> Completed!`n" -NoNewline -ForegroundColor Green
			}
			else
			{
				try
				{
					$remoteOutput += Invoke-Command -ComputerName $server -ArgumentList $InnerInstallLogFunctionScript -ScriptBlock {
						Param ($script)
						. ([ScriptBlock]::Create($script))
						return Invoke-InnerInstallLog
					} -ErrorAction Stop
					if ($remoteOutput -like "function:Invoke-InnerInstallLog*")
					{
						Write-Verbose "$(Invoke-TimeStamp)function:Invoke-GetInstallLogs - Remote - $server - $($error[0])"
						"$(Invoke-TimeStamp)function:Invoke-GetInstallLogs - Remote - $server - $($error[0])" | Out-File $OutputPath\Error.log -Append
					}
					Copy-Item "\\$server\$($remoteOutput.Replace(':', '$'))\*" $serverPath -Force -Recurse -ErrorAction Stop
					Remove-Item "\\$server\$($remoteOutput.Replace(':', '$'))\*" -Recurse -Force -ErrorAction SilentlyContinue
				}
				catch
				{
					Write-Verbose "$(Invoke-TimeStamp)function:Invoke-GetInstallLogs - Remote - $server - $($error[0])"
					"$(Invoke-TimeStamp)function:Invoke-GetInstallLogs - Remote - $server - $($error[0])" | Out-File $OutputPath\Error.log -Append
				}
				
				Write-Console '-' -NoNewline -ForegroundColor Green
				Write-Console "> Completed!`n" -NoNewline -ForegroundColor Green
			}
		}
	}
	END
	{
		Write-Verbose "$(Invoke-TimeStamp)End of 'Invoke-GetInstallLogs'"
	}
}