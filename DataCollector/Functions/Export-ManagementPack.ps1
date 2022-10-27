Function MP-Export
{
	if ((Test-Path -Path "$OutputPath\Unsealed Management Packs") -eq $false)
	{
		Write-Host "  Creating Folder: $OutputPath\Unsealed Management Packs" -ForegroundColor Gray
		md "$OutputPath\Unsealed Management Packs" | Out-Null
	}
	else
	{
		Write-Host "  Existing Folder Found: $OutputPath\Unsealed Management Packs" -ForegroundColor Gray
		Remove-Item "$OutputPath\Unsealed Management Packs" -Recurse | Out-Null
		Write-Host "   Deleting folder contents" -ForegroundColor Gray
		md "$OutputPath\Unsealed Management Packs" | out-null
		Write-Host "    Folder Created: $OutputPath\Unsealed Management Packs" -ForegroundColor Gray
	}
	
	try
	{
		Get-SCOMManagementPack | Where{ $_.Sealed -eq $false } | Export-SCOMManagementPack -path "$OutputPath\Unsealed Management Packs" | out-null
		Write-Host "    Completed Exporting Unsealed Management Packs" -ForegroundColor Green
	}
	catch
	{
		#potential error code
		#use continue or break keywords
		$e = $_.Exception
		$line = $_.InvocationInfo.ScriptLineNumber
		$msg = $e.Message
		
		Write-Warning "Caught Exception: $e :: Message: $msg :: at line: $line"
		"$(Time-Stamp)Caught Exception: $e :: Message: $msg :: at line: $line" | Out-File $OutputPath\Error.log -Append
	}
	
	if ((Test-Path -Path "$OutputPath\Sealed Management Packs") -eq $false)
	{
		Write-Host "  Creating Folder: $OutputPath\Sealed Management Packs" -ForegroundColor Gray
		md "$OutputPath\Sealed Management Packs" | Out-Null
	}
	else
	{
		Write-Host "  Existing Folder Found: $OutputPath\Sealed Management Packs" -ForegroundColor Gray
		Remove-Item "$OutputPath\Sealed Management Packs" -Recurse | Out-Null
		Write-Host "   Deleting folder contents" -ForegroundColor Gray
		md "$OutputPath\Sealed Management Packs" | out-null
		Write-Host "    Folder Created: $OutputPath\Sealed Management Packs" -ForegroundColor Gray
	}
	
	try
	{
		Get-SCOMManagementPack | Where{ $_.Sealed -eq $true } | Export-SCOMManagementPack -path "$OutputPath\Sealed Management Packs" | out-null
		Write-Host "    Completed Exporting Sealed Management Packs" -ForegroundColor Green
	}
	catch
	{
		#potential error code
		#use continue or break keywords
		$e = $_.Exception
		$line = $_.InvocationInfo.ScriptLineNumber
		$msg = $e.Message
		
		Write-Warning "Caught Exception: $e :: Message: $msg :: at line: $line"
		"$(Time-Stamp)Caught Exception: $e :: Message: $msg :: at line: $line" | Out-File $OutputPath\Error.log -Append
	}
}