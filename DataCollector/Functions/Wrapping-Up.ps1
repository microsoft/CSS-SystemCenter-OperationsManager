Function Invoke-WrapUp
{
	param
	(
		[switch]$BuildPipeline
	)
	$jobstatus = $null
	$jobstatus = (Get-Job -Name "getEvent*", "getPerf*")
	foreach ($job in $jobstatus)
	{
		if ($job.State -eq 'Running')
		{
			Write-Console "`nWaiting for SQL Query `'$($job.Name -split "-" | Select-Object -Last 1)`' to finish gathering data." -ForegroundColor Gray -NoNewline
		}
		do
		{
			if ($job.State -eq 'Running')
			{
				Write-Console "." -ForegroundColor Gray -NoNewline
				Start-Sleep 5
			}
		}
		until ($job.State -ne 'Running')
	}
	Write-Console " "
	try
	{
		if (Test-Path $OutputPath\*.csv)
		{
			New-Item -ItemType Directory -Path $OutputPath\CSV -ErrorAction SilentlyContinue | out-null
			Move-Item $OutputPath\*.csv $OutputPath\CSV
		}
		if ((Get-ChildItem $OutputPath\CSV -ErrorAction SilentlyContinue).Count -eq 0 -or (-Not ($(Resolve-Path "$OutputPath\CSV"))))
		{
			Remove-Item $OutputPath\CSV -Force -ErrorAction SilentlyContinue | out-null
		}
		$FolderNames = (Get-ChildItem "$OutputPath`\*.evtx" | Select-Object Name -ExpandProperty Name) | ForEach-Object { $_.split(".")[0] } | Select-Object -Unique
		$FolderNames | ForEach-Object {
			$currentServer = $_
			mkdir "$OutputPath`\Event Logs\$currentServer" | Out-Null;
			mkdir "$OutputPath`\Event Logs\$currentServer`\localemetadata\" | Out-Null;
			$Eventlogs = Get-ChildItem "$OutputPath`\$currentServer`*.evtx"
			foreach ($eventlog in $Eventlogs)
			{
				Move-Item $eventlog -Destination "$OutputPath`\Event Logs\$currentServer" | Out-Null
			}
			
			$EventlogsMetadata = Get-ChildItem "$OutputPath`\$currentServer`*.mta"
			foreach ($eventlogmetadata in $EventlogsMetadata)
			{
				Move-Item $eventlogmetadata -Destination "$OutputPath`\Event Logs\$currentServer`\localemetadata\" | Out-Null
			}
		}
	}
	catch
	{
		Write-Warning $_
	}
	$fullfilepath = $OutputPath + '\datacollector-' + ((((Get-Content "$currentPath" | Select-String '.VERSION' -Context 1) | Select-Object -First 1 $_.Context.PostContext) -split "`n")[2]).Trim().Split(" ")[0]
	#Write file to show script version in the SDC Results File.
	
	try
	{
		$EndTime = "$(Get-Date -Format "MMMM dd, yyyy @ h:mm tt") $((Get-TimeZone -ErrorAction SilentlyContinue).DisplayName)"
	}
	catch
	{
		$EndTime = "$(Get-Date -Format "MMMM dd, yyyy @ h:mm tt") (unknown time zone)"
	}
	@"
Script Running as User:
$env:USERDOMAIN\$env:USERNAME

Script Running on Server:
$env:COMPUTERNAME

Script Path:
$ScriptPath\$scriptname

Parameters Passed to Script:
$ScriptPassedArgs

Parameters Passed to Function:
$FunctionPassedArgs

Script execution started on date/time:
$StartTime

Script execution completed on date/time:
$EndTime
"@ | Out-File $fullfilepath -Force
	
	#Zip output
	$Error.Clear()
	Write-Console "Creating zip file of all output data." -ForegroundColor DarkCyan
	[Reflection.Assembly]::LoadWithPartialName("System.IO.Compression.FileSystem") | Out-Null
	[System.AppDomain]::CurrentDomain.GetAssemblies() | Out-Null
	$SourcePath = Resolve-Path $OutputPath
	[string]$filedate = (Get-Date).tostring("MM_dd_yyyy_hh-mm-tt")
	if ($CaseNumber)
	{
		[string]$destfilename = "SDC_Results_$CaseNumber_$filedate`.zip"
	}
	elseif ($BuildPipeline)
	{
		[string]$destfilename = "SDC_Results.zip"
	}
	else
	{
		[string]$destfilename = "SDC_Results_$filedate`.zip"
	}
	
	[string]$destfile = "$ScriptPath\$destfilename"
	IF (Test-Path $destfile)
	{
		#File exists from a previous run on the same day - delete it
		Write-Console "-Found existing zip file: $destfile.`n Deleting existing file." -ForegroundColor DarkGreen
		Remove-Item $destfile -Force
	}
	$compressionLevel = [System.IO.Compression.CompressionLevel]::Optimal
	$includebasedir = $false
	[System.IO.Compression.ZipFile]::CreateFromDirectory($SourcePath, $destfile, $compressionLevel, $includebasedir) | Out-Null
	IF ($Error)
	{
		Write-Error "Error creating zip file."
	}
	ELSE
	{
		Write-Console "-Cleaning up output directory." -ForegroundColor DarkCyan
		Remove-Item $OutputPath -Recurse
		Write-Console "--Saved zip file to: $destfile." -ForegroundColor Cyan
	}
}