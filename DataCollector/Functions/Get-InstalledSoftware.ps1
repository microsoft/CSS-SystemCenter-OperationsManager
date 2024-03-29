function Invoke-GetInstalledSoftware
{
	param
	(
		[Parameter(Position = 0)]
		[string[]]$Servers = $env:COMPUTERNAME
	)
	function Invoke-InnerInstalledSoftware
	{
		# Add additional property InstallDateObj that will hold the parsed DateTime object
		$Installed_Software = @()
		# Get 64bit installed software
		$Installed_Software += Get-ItemProperty HKLM:\Software\Wow6432Node\Microsoft\Windows\CurrentVersion\Uninstall\* | Select-Object  DisplayName, DisplayVersion, Publisher, InstallDate, InstallDateObj, @{ Name = 'Architecture'; Expression = { '64bit' } }
		$Installed_Software += Get-ItemProperty HKLM:\Software\Microsoft\Windows\CurrentVersion\Uninstall\* | Select-Object  DisplayName, DisplayVersion, Publisher, InstallDate, InstallDateObj, @{ Name = 'Architecture'; Expression = { '32bit' } }
		
		$TheDate = (([datetime]::Now))
     	<# Try to parse dates.
		$Installed_Software.ForEach({
				
				# add more formats if you need
				[string[]]$formats = @("yyyyMMdd", "MM/dd/yyyy")
				
				$installDate = $_.InstallDate
				$installedDateObj = $null;
				$formats.ForEach({
						[DateTime]$dt = New-Object DateTime; if ([datetime]::TryParseExact($installDate, $_, [System.Globalization.CultureInfo]::InvariantCulture, [System.Globalization.DateTimeStyles]::None, [ref]$dt))
						{
							$installedDateObj = $dt
						} 
					});
				$_.InstallDateObj = $installedDateObj
			})
		#>
		$Installed_recently = @()
		$Installed_recently = $Installed_Software | Where-Object { ($null -ne $_.DisplayName) } # -or ($(try{($TheDate - $_.InstallDateObj).Days -le $Days}catch{$Test = $true}))) }
		$array = @()
		if ($Installed_recently.Count -gt 0)
		{
			foreach ($software in $Installed_recently)
			{
				$array += [pscustomobject]@{
					'Installed Software' = $software.DisplayName;
					#'Software Version'   = [version]$software.DisplayVersion;
					'Software Version'   = $software.DisplayVersion;
					'Publisher'		     = $software.Publisher;
					'Install Date'	     = $(try { [Datetime]::ParseExact($software.InstallDate, 'yyyyMMdd', $null) | Get-Date -UFormat "%m/%d/%Y" }
						catch { Write-Verbose "Unable to determine Install Date" })
					Architecture		 = $software.Architecture;
					ComputerName		 = $env:COMPUTERNAME
				}
			}
		}
		else
		{
			$array += [pscustomobject]@{
				'Installed Software' = 'Nothing found.';
				'Software Version'   = $null;
				'Publisher'		     = $null;
				'Install Date'	     = $null;
				Architecture		 = $null;
				ComputerName		 = $env:COMPUTERNAME
			}
		}
		return $array
	}
	$finalout = @()
	Write-Console "  Running the Function to gather Installed Software on:`n" -NoNewline -ForegroundColor Gray
	foreach ($server in $Servers)
	{
		Write-Console "    $server" -NoNewline -ForegroundColor Cyan
		if ($server -match $env:COMPUTERNAME)
		{
			Write-Console '-' -NoNewline -ForegroundColor Green
			$finalout += Invoke-InnerInstalledSoftware
			Write-Console "> Completed!`n" -NoNewline -ForegroundColor Green
		}
		else
		{
			$finalout += Invoke-Command -ComputerName $server -ScriptBlock ${Function:Invoke-InnerInstalledSoftware}
			Write-Console '-' -NoNewline -ForegroundColor Green
			Write-Console "> Completed!`n" -NoNewline -ForegroundColor Green
		}
	}
	return $finalout | Select-Object 'Installed Software', 'Software Version', 'Publisher', 'Install Date', 'Architecture', 'ComputerName' | Sort-Object -Property @{ Expression = 'ComputerName'; Descending = $false }, @{ Expression = 'Install Date'; Descending = $false }, @{ Expression = 'Software Version'; Descending = $true }
}