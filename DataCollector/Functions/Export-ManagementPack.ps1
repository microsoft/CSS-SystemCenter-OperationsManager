Function Invoke-MPExport
{
	if ((Test-Path -Path "$OutputPath\Unsealed Management Packs") -eq $false)
	{
		Write-Console "  Creating Folder: $OutputPath\Unsealed Management Packs" -ForegroundColor Gray
		New-Item -Type Directory -Path "$OutputPath\Unsealed Management Packs" | Out-Null
	}
	else
	{
		Write-Console "  Existing Folder Found: $OutputPath\Unsealed Management Packs" -ForegroundColor Gray
		Remove-Item "$OutputPath\Unsealed Management Packs" -Recurse | Out-Null
		Write-Console "   Deleting folder contents" -ForegroundColor Gray
		New-Item -Type Directory -Path "$OutputPath\Unsealed Management Packs" | out-null
		Write-Console "    Folder Created: $OutputPath\Unsealed Management Packs" -ForegroundColor Gray
	}
	
	try
	{
		Get-SCOMManagementPack | Where-Object{ $_.Sealed -eq $false } | Export-SCOMManagementPack -path "$OutputPath\Unsealed Management Packs" | out-null
		Write-Console "    Completed Exporting Unsealed Management Packs" -ForegroundColor Green
	}
	catch
	{
		#potential error code
		#use continue or break keywords
		$e = $_.Exception
		$line = $_.InvocationInfo.ScriptLineNumber
		$msg = $e.Message
		
		Write-Warning "Caught Exception: $e :: Message: $msg :: at line: $line"
		"$(Invoke-TimeStamp)Caught Exception: $e :: Message: $msg :: at line: $line" | Out-File $OutputPath\Error.log -Append
	}
	
	if ((Test-Path -Path "$OutputPath\Sealed Management Packs") -eq $false)
	{
		Write-Console "  Creating Folder: $OutputPath\Sealed Management Packs" -ForegroundColor Gray
		New-Item -Type Directory -Path "$OutputPath\Sealed Management Packs" | Out-Null
	}
	else
	{
		Write-Console "  Existing Folder Found: $OutputPath\Sealed Management Packs" -ForegroundColor Gray
		Remove-Item "$OutputPath\Sealed Management Packs" -Recurse | Out-Null
		Write-Console "   Deleting folder contents" -ForegroundColor Gray
		New-Item -Type Directory -Path "$OutputPath\Sealed Management Packs" | out-null
		Write-Console "    Folder Created: $OutputPath\Sealed Management Packs" -ForegroundColor Gray
	}
	
	try
	{
		Get-SCOMManagementPack | Where-Object{ $_.Sealed -eq $true } | Export-SCOMManagementPack -path "$OutputPath\Sealed Management Packs" | out-null
		Write-Console "    Completed Exporting Sealed Management Packs" -ForegroundColor Green
	}
	catch
	{
		#potential error code
		#use continue or break keywords
		$e = $_.Exception
		$line = $_.InvocationInfo.ScriptLineNumber
		$msg = $e.Message
		
		Write-Warning "Caught Exception: $e :: Message: $msg :: at line: $line"
		"$(Invoke-TimeStamp)Caught Exception: $e :: Message: $msg :: at line: $line" | Out-File $OutputPath\Error.log -Append
	}
}