<#
Information
	Author: Blake Drumm (blakedrumm@microsoft.com)
	This script takes all the functions from .\Functions\* and combines them into the main powershell script. Allowing the Data Collector to run with just one PS1 file and the SQL Queries folder.
	
	This has to be in the same folder as the DataCollector.ps1 file / Functions Folder to work.

	For this to work the functions names have to be on the first lines of each file in the functions folder.
#>
$ScriptPath = (Get-Location).Path
$mainscript = Get-Content .\DataCollector.ps1
$ScriptFunctions = Get-ChildItem .\Functions | Where-Object{ $_ -like '*.ps1' } | Select-Object FullName -ExpandProperty FullName
# Main Script Functions
foreach ($script in $ScriptFunctions)
{
	$filename = $null
	$functionpath = $null
	$innerfunction = $null
	$innerfunctionName = $null
	$filename = $script | Split-Path -Leaf
	$functionpath = '. $ScriptPath`\Functions\' + $filename
	$innerfunction = Get-Content $script | Out-String
	$innerfunctionName = ((Get-Content $script -TotalCount 1).Split(" "))[1]
	foreach ($f in $innerfunctionName)
	{
		$mainscript = ($mainscript).Replace("$functionpath", $innerfunction)
	}
	
}
# Remove commands in script
$mainscript = ($mainscript).Replace('Write-Host "Attempting to run the following command to unblock the Powershell Scripts under the current folder:`nGet-ChildItem $ScriptPath -Recurse | Unblock-File" -ForegroundColor Gray; Get-ChildItem $ScriptPath -Recurse | Unblock-File | Out-Null', $null)
# Product Versions Functions
$ScriptProductVersions = Get-ChildItem .\Functions\ProductVersions | Where-Object{ $_ -like '*.ps1' } | Select-Object FullName -ExpandProperty FullName
foreach ($powershellscript in $ScriptProductVersions)
{
	$filename = $null
	$functionpath = $null
	$innerfunction = $null
	$innerfunctionName = $null
	$filename = $powershellscript | Split-Path -Leaf
	$functionpath = '. $ScriptPath`\Functions\ProductVersions\' + $filename
	$innerfunction = Get-Content $powershellscript | Out-String
	$innerfunctionName = ((Get-Content $powershellscript -TotalCount 1).Split(" "))[1]
	foreach ($f in $innerfunctionName)
	{
		$mainscript = ($mainscript).Replace("$functionpath", $innerfunction)
	}
}
# Auto Updater Function
$mainscript = ($mainscript).Replace('. $ScriptPath`\Script-Auto-Updater.ps1', (Get-Content .\Script-Auto-Updater.ps1 | Out-String))
# Replace any $global: variables with $script: variables
$mainscript = ($mainscript).Replace('$global:','$script:')
# Update version
$version = Get-Item .\v* | Select-Object Name -ExpandProperty Name

# Update License year for release data collector script
$mainscript = $mainscript.Replace("$($mainscript | Select-String -SimpleMatch "Copyright" | Select-Object -First 1)", "Copyright (c) $((Get-Date).Year) Blake Drumm")

# Update License year for Main Data Collector script
(Get-Content "$ScriptPath\DataCollector.ps1").Replace("$(Get-Content .\DataCollector.ps1 | Select-String -SimpleMatch "Copyright" | Select-Object -First 1)", "Copyright (c) $((Get-Date).Year) Blake Drumm") | Set-Content "$ScriptPath\DataCollector.ps1" -Force

# Update License year for Readme.md file
(Get-Content "$ScriptPath\Readme.md").Replace("$(Get-Content "$ScriptPath\Readme.md" | Select-String "Copyright" | Select-Object -First 1)", "Copyright (c) 2022 Blake Drumm") | Set-Content "$ScriptPath\Readme.md"

$mainscript | Set-Content ".\DataCollector-$version.ps1" -Force