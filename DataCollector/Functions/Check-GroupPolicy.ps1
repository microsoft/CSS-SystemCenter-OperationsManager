Function Check-GroupPolicy
{
	[CmdletBinding()]
	Param
	(
		[string[]]$Servers
	)
	function Invoke-GPCheck
	{
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
		Write-Console "  Checking / Updating Group Policy on $env:COMPUTERNAME`:" -NoNewline -ForegroundColor Gray
		$out = @"
================================================
$env:COMPUTERNAME
"@
        Write-Console "-" -NoNewLine -ForegroundColor Green
		$out += Get-Service gpsvc | Out-String -Width 2048
        Write-Console "-" -NoNewLine -ForegroundColor Green
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
        Write-Console "-" -NoNewLine -ForegroundColor Green
		$out += (Get-EventLog -LogName 'System' -Source 'Microsoft-Windows-GroupPolicy' -Newest 2) | Format-Table EventID, Message, UserName, TimeWritten, EntryType -AutoSize | Out-String -Width 4096
        Write-Console "> Completed!" -ForegroundColor Green
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