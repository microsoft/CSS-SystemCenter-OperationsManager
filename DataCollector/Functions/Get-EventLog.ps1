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
		"$(Invoke-TimeStamp)Caught Exception: $e :: Message: $msg :: at line: $line" | Out-File $OutputPath\Error.log -Append
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
				Write-Console "    Locally " -NoNewline -ForegroundColor DarkCyan
				Write-Console "Exporting Event Log " -NoNewline -ForegroundColor Cyan
				Write-Console "on " -NoNewline -ForegroundColor DarkCyan
				Write-Console "$server " -NoNewline -ForegroundColor Cyan
				Write-Console ": " -NoNewline -ForegroundColor DarkCyan
				Write-Console "$originalLogName" -NoNewline -ForegroundColor Cyan
				$fileCheck = test-path "c:\windows\Temp\$server.$log.evtx"
				if ($fileCheck -eq $true)
				{
					Remove-Item "c:\windows\Temp\$server.$log.evtx" -Force
				}
				Write-Console "-" -NoNewline -ForegroundColor Green;
				$eventcollect = wevtutil epl $originalLogName "c:\windows\Temp\$server.$log.evtx"; wevtutil al "c:\windows\Temp\$server.$log.evtx"
				do { Write-Console "-" -NoNewline -ForegroundColor Green; Start-Sleep 1 }
				while ($eventcollect)
				Write-Console "> Collected Events`n" -NoNewline -ForegroundColor Green
				try
				{
					Write-Console "     Locally moving files using Move-Item" -NoNewline -ForegroundColor DarkCyan
					$movelocalevtx = Move-Item "C:\Windows\temp\$server.$log.evtx" $ScriptPath\output -force -ErrorAction Stop; Move-Item "C:\Windows\temp\localemetadata\*.mta" $ScriptPath\output -force -ErrorAction Stop
					Write-Console "-" -NoNewline -ForegroundColor Green
					do { Write-Console "-" -NoNewline -ForegroundColor Green; Start-Sleep 1 }
					while ($movelocalevtx | Out-Null)
					Write-Console "> Transfer Completed!" -NoNewline -ForegroundColor Green
					Write-Output " "
					continue
				}
				catch
				{
					Write-Warning $_
				}
				try
				{
					Write-Console "     Locally moving files using Robocopy" -NoNewline -ForegroundColor DarkCyan
					Robocopy "C:\Windows\temp" "$ScriptPath\output" "$server.$log.evtx" /MOVE /R:2 /W:10 | Out-Null
					Robocopy "C:\Windows\temp\localemetadata" "$ScriptPath\output" "*.MTA" /MOVE /R:2 /W:10 | Out-Null
					Write-Console "      Transfer Completed!" -NoNewline -ForegroundColor Green
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
				$eventlog_ispresent = Get-EventLog -LogName * -ComputerName $server | Where-Object { $_.Log -eq $log }
				if ($eventlog_ispresent)
				{
					Write-Console "    Remotely " -NoNewline -ForegroundColor DarkCyan
					Write-Console "Exporting Event Log " -NoNewline -ForegroundColor Cyan
					Write-Console "on " -NoNewline -ForegroundColor DarkCyan
					Write-Console "$server " -NoNewline -ForegroundColor Cyan
					Write-Console ": " -NoNewline -ForegroundColor DarkCyan
					Write-Console "$log" -NoNewline -ForegroundColor Cyan
					Write-Console "-" -NoNewline -ForegroundColor Green
					try
					{
						Write-Console "-" -NoNewline -ForegroundColor Green
						Invoke-Command -ComputerName $server {
							
                            function Write-Console
                            {
	                            param
	                            (
		                            [Parameter(Position = 1)]
		                            [string]$Text,
		                            [Parameter(Position = 2)]
		                            $BackgroundColor,
		                            [Parameter(Position = 3)]
		                            $ForegroundColor,
		                            [Parameter(Position = 4)]
		                            [switch]$NoNewLine
	                            )
	
	                            if ([Environment]::UserInteractive)
	                            {
                                    if ($ForegroundColor)
                                    {
                                        if ($BackgroundColor)
                                        {
                                            Write-Host $Text -BackgroundColor $BackgroundColor -ForegroundColor $ForegroundColor -NoNewLine:$NoNewLine
                                        }
                                        else
                                        {
                                            Write-Host $Text -ForegroundColor $ForegroundColor -NoNewLine:$NoNewLine
                                        }
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
							$localAdmin = ([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole] "Administrator")
							if ($localadmin) { $LA = "$true" }
							else { $LA = "$false" }
							
							
							$fileCheck = Test-Path "c:\windows\Temp\$using:server.$using:log.evtx"
							if ($fileCheck -eq $true)
							{
								Remove-Item "c:\windows\Temp\$using:server.$using:log.evtx" -Force
							}
							if ($la -eq $true)
							{
								try
								{
									$eventcollect = wevtutil epl $using:originalLogName "c:\windows\Temp\$using:server.$using:log.evtx"; wevtutil al "c:\windows\Temp\$using:server.$using:log.evtx"
								}
								catch
								{
									Write-Warning $_
									continue
								}
							}
							continue
						}
						Write-Console "> Collected Events" -NoNewline -ForegroundColor Green
						Write-Output " "
					}
					catch { Write-Warning $_ }
					try
					{
						Write-Console "     Transferring using Move-Item" -NoNewLine -ForegroundColor DarkCyan
						$moveevents = Move-Item "\\$server\c$\windows\temp\$server.$log.evtx" $ScriptPath\output -force -ErrorAction Stop; Move-Item "\\$server\c$\windows\temp\localemetadata\*.mta" $ScriptPath\output -force -ErrorAction Stop
						Write-Console "-" -NoNewline -ForegroundColor Green
						do { Write-Console "-" -NoNewline -ForegroundColor Green; Start-Sleep 1 }
						while ($moveevents)
						Write-Console "> Transfer Completed!" -NoNewline -ForegroundColor Green
						Write-Output " "
						continue
					}
					catch
					{
						Write-Warning $_
					}
					try
					{
						Write-Console "     Transferring using Robocopy" -NoNewline -ForegroundColor DarkCyan
						Robocopy "\\$server\c$\windows\temp" "$ScriptPath\output" "$server.$log.evtx" /MOVE /R:2 /W:10 | Out-Null
						Robocopy "\\$server\c$\windows\temp\localemetadata" "$ScriptPath\output" "*.MTA" /MOVE /R:2 /W:10 | Out-Null
						Write-Console "      Transfer Completed!" -NoNewline -ForegroundColor Green
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