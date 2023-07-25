Function Invoke-MSInfo32Gathering
{
	if ((Test-Path -Path "$OutputPath\MSInfo32") -eq $false)
	{
		mkdir $OutputPath\MSInfo32 | out-null
	}
	else
	{
		Remove-Item $OutputPath\MSInfo32 -Recurse
	}
	try
	{
		$TestedTLSservers | ForEach-Object { $serv = $_; Write-Console "    Gathering MSInfo32 from: " -NoNewline; Write-Console "$serv" -ForegroundColor Cyan; Start-Process "msinfo32.exe" -ArgumentList "/report `"$OutputPath\MSInfo32\$_.msinfo32.txt`" /computer $serv" -NoNewWindow -Wait; $serv = $null; }
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
				$running = get-process msinfo32 -ErrorAction SilentlyContinue
				if ($running)
				{
					Write-Output "    MSInfo32 is still running on $name. Pausing 1 minute, and rechecking..."
					start-sleep -Seconds 60
					$run = 1
					$runtime = $runtime - 1
					if ($runtime -lt 1)
					{
						Write-Warning "    MSInfo32 process on $name appears hung, killing process"
						get-process msinfo32 | Stop-Process
						$run = 0
					}
				}
				else
				{
					$run = 0
				}
			}
		}
		Write-Console "    Completed on $name"
		Get-PSSession | Remove-PSSession
		write-Output " "
		Write-output "Moving MSInfo32 Reports to $env:COMPUTERNAME"
		foreach ($rserv in $TestedTLSservers)
		{
			Write-output " Retrieving MSInfo32 Report from $rserv"
			Move-Item "\\$rserv\c$\windows\Temp\*.msinfo32.txt" "$OutputPath\MSInfo32"
			Write-Console "    Completed Retrieving MSInfo32 Report from $rserv" -ForegroundColor Green
		}
	}
}