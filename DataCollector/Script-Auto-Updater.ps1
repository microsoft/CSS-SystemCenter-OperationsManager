function Invoke-AutoUpdater
{
	BEGIN
	{
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
	}
	PROCESS
	{
		try
		{
			# Get Latest Release from the GitHub Repo
			$githubLatestRelease = (Invoke-WebRequest -ErrorAction Stop -Uri 'https://api.github.com/repos/blakedrumm/SCOM-Scripts-and-SQL/releases/latest').Content | ConvertFrom-Json
		}
		catch
		{
			Write-Console "$(Invoke-TimeStamp)Unable to access the website: " -NoNewline
			Write-Console 'https://api.github.com/repos/blakedrumm/SCOM-Scripts-and-SQL/releases/latest' -ForegroundColor Red
			Start-Sleep 8
			break
		}
		$latestRelease = $githubLatestRelease.tag_name
		try
		{
			if ($PSScriptRoot)
			{
				$content = Get-Content "$PSScriptRoot\DataCollector*.ps1" -ErrorAction Stop
			}
			else
			{
				$content = Get-Content ".\DataCollector*.ps1" -ErrorAction Stop
			}
		}
		catch
		{
			Write-Warning "$(Invoke-TimeStamp)Unable to access the DataCollector.ps1 or DataCollector*.ps1 file ($pwd). Make sure you are running this in the script directory!"
			do
			{
				$answer = Read-Host "$(Invoke-TimeStamp)Attempt to download latest release from the internet? (Y/N)"
			}
			until ($answer -eq 'y' -or $answer -eq 'n')
			if ($answer -eq 'n')
			{
				Write-Console "$(Invoke-TimeStamp)Stopping script"
				break
			}
			else
			{
				Write-Console "$(Invoke-TimeStamp)Latest SCOM Data Collector Release: " -NoNewline
				Write-Console $latestRelease -ForegroundColor Green
				Write-Console "$(Invoke-TimeStamp)Finding asset: SCOM-DataCollector.zip"
				$githubAsset = ($githubLatestRelease.Assets.Where{ $_.Name -eq 'SCOM-DataCollector.zip' })
				$zipFilePath = "$(if ($content) { ($content).PSParentPath[0] }
					else { $pwd })\$($githubAsset.Name)"
				Write-Console "$(Invoke-TimeStamp)Downloading asset: SCOM-DataCollector.zip -> $zipFilePath"
				Invoke-WebRequest $githubAsset.browser_download_url -OutFile $zipFilePath
				Write-Console "$(Invoke-TimeStamp)Expanding zip archive: SCOM-DataCollector.zip"
				Expand-Archive -LiteralPath $zipFilePath -DestinationPath $(if ($content) { ($content).PSParentPath[0] }
					else { $pwd }) -Force
				Write-Console "$(Invoke-TimeStamp)Cleaning up zip release..."
				Remove-Item -LiteralPath $zipFilePath -Force | Out-Null
			}
		}
		# Get the version of the current script
		if (!$answer)
		{
			$scriptVersion = ($content | Select-String .VERSION -Context 0, 1 | ForEach-Object { $_.Context.DisplayPostContext }).Trim().Split(" - ") | Select-Object -First 1
			
			# If the latest release and script version don't match
			if ([version]$scriptVersion.Replace('v', '') -gt [version]($latestRelease).Replace('v-', ''))
			{
				Write-Console "$(Invoke-TimeStamp)You are currently on a development build of $($content.PSChildName[0]): " -NoNewline
				Write-Console $scriptVersion -ForegroundColor Green
			}
			elseif ([version]$scriptVersion.Replace('v', '') -lt [version]($latestRelease).Replace('v-', ''))
			{
				Write-Console "$(Invoke-TimeStamp)Current Script Version: " -NoNewline
				Write-Console $($scriptVersion.Insert(1, '-')) -ForegroundColor Red
				Write-Console "$(Invoke-TimeStamp)Latest SCOM Data Collector Release: " -NoNewline
				Write-Console $latestRelease -ForegroundColor Green
				Write-Console "$(Invoke-TimeStamp)Removing all current script items / queries to replace with the newer versions."
				Get-ChildItem -Path .\ -Include DataCollector*, DataCollector-v*.*.*, Queries | Remove-Item -Recurse -Force
				
				Write-Console "$(Invoke-TimeStamp)Finding asset: SCOM-DataCollector.zip"
				$githubAsset = ($githubLatestRelease.Assets.Where{ $_.Name -eq 'SCOM-DataCollector.zip' })
				$zipFilePath = "$(($content).PSParentPath[0])\$($githubAsset.Name)"
				Write-Console "$(Invoke-TimeStamp)Downloading asset: SCOM-DataCollector.zip -> $zipFilePath"
				Invoke-WebRequest $githubAsset.browser_download_url -OutFile $zipFilePath
				Write-Console "$(Invoke-TimeStamp)Expanding zip archive: SCOM-DataCollector.zip"
				Expand-Archive -LiteralPath $zipFilePath -DestinationPath ($content).PSParentPath[0] -Force
				Write-Console "$(Invoke-TimeStamp)Cleaning up zip release..."
				Remove-Item -LiteralPath $zipFilePath -Force | Out-Null
			}
			else
			{
				Write-Console "$(Invoke-TimeStamp)You are currently on the latest update of $($content.PSChildName[0]): " -NoNewline
				Write-Console $latestRelease -ForegroundColor Green
			}
		}
	}
	END
	{
		Write-Console "$(Invoke-TimeStamp)Script completed!"
		Start-Sleep -Seconds 8
	}
}
Invoke-AutoUpdater