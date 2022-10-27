Function Check-GroupPolicy
{
	[CmdletBinding()]
	Param
	(
		[string[]]$Servers
	)
	function Invoke-GPCheck
	{
		Write-Host "  Checking / Updating Group Policy on $env:COMPUTERNAME`:" -NoNewline -ForegroundColor Gray
		$out = @"
================================================
$env:COMPUTERNAME
"@
        Write-Host "-" -NoNewLine -ForegroundColor Green
		$out += Get-Service gpsvc | Out-String -Width 2048
        Write-Host "-" -NoNewLine -ForegroundColor Green
        $expectedresult = @"
Updating policy...



Computer Policy update has completed successfully.

User Policy update has completed successfully.




"@
        $gp = (gpupdate | Out-String)
        if($gp -eq $expectedresult)
        {
            $out += "Group Policy is updating correctly`n"
        }
        else
        {
            $out += $gp
        }
        Write-Host "-" -NoNewLine -ForegroundColor Green
		$out += (Get-EventLog -LogName 'System' -Source 'Microsoft-Windows-GroupPolicy' -Newest 2) | ft EventID, Message, UserName, TimeWritten, EntryType -AutoSize | Out-String -Width 4096
        Write-Host "> Completed!" -ForegroundColor Green
		return $out
	}
	$finalout = $null
	foreach ($server in $servers)
	{
		if ($Comp -ne $server)
		{
			$finalout += Invoke-Command -ComputerName $server -ScriptBlock ${function:Invoke-GPCheck}
		}
		else
		{
			$finalout += Invoke-GPCheck
		}
	}
	$finalout | Out-File -FilePath "$OutputPath\GP-Check.txt"
}