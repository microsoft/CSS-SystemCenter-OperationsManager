function Export-SCOMMSCertificate
{
	param
	(
		[string[]]$Servers,
		[string]$ExportPath
	)
	
	function Inner-ExportCertificate
	{
		param (
			[byte[]]$RawData,
			[string]$ExportPath
		)
		
		$directory = Split-Path -Path $ExportPath -Parent
		if (-not (Test-Path -Path $directory))
		{
			New-Item -ItemType Directory -Path $directory | Out-Null
		}
		
		[System.IO.File]::WriteAllBytes($ExportPath, $RawData)
	}
	
	[scriptblock]$scriptblock = {
		$certs = Get-ChildItem cert:\LocalMachine\my
		$regKeys = get-itemproperty -path "HKLM:\SOFTWARE\Microsoft\Microsoft Operations Manager\3.0\Machine Settings"
		
		$regSerial = ""
        if ($regKeys.ChannelCertificateSerialNumber)
        {
		    $regKeys.ChannelCertificateSerialNumber | ForEach-Object { $regSerial += $_.ToString("X2") }
		
		    foreach ($cert in $certs)
		    {
			    $certSerialReversed = @()
			    $certSerial = $cert.SerialNumber -replace " ", ""
			    -1 .. -19 | ForEach-Object { $certSerialReversed += $certSerial[2 * $_] + $certSerial[2 * $_ + 1] }
			    $certSerialReversed = -join $certSerialReversed
			
			    if ($certSerialReversed -eq $regSerial)
			    {
				    return $cert.RawData, $env:COMPUTERNAME
			    }
		    }
		}
		return $null, $env:COMPUTERNAME
	}
	
	# The servers that you want to run this script against. 
	#$Servers = @('MS01-2019', 'MS02-2019') # Replace with actual server names.
	
	foreach ($server in $Servers)
	{
		if ($server -eq $env:COMPUTERNAME)
		{
			$output = & $scriptblock
		}
		else
		{
			$output = Invoke-Command -ComputerName $server -ScriptBlock $scriptblock
		}
		
		if ($output -and $output[0])
		{
			$exportFullPath = Join-Path -Path $ExportPath -ChildPath ("$($output[1]).cer")
			Inner-ExportCertificate -RawData $output[0] -ExportPath $exportFullPath
			Write-Host "Exported certificate for $($output[1]) to $exportFullPath"
		}
		else
		{
			Write-Warning "No matching certificate found or an error occurred on $($output[1])."
		}
	}
}