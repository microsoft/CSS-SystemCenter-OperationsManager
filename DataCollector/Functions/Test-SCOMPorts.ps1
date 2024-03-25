function Invoke-TestSCOMPorts
{
	param
	(
		[Parameter(Mandatory = $false,
				   Position = 1)]
		[array]$SourceServer,
		[Parameter(Mandatory = $true,
				   ValueFromPipeline = $true,
				   Position = 2)]
		[array]$DestinationServer,
		[Parameter(Position = 3)]
		[string]$OutputFile,
		[Parameter(Position = 4)]
		[ValidateSet("Text", "CSV", "Table")]
		[string[]]$OutputType = 'Table'
	)
	<#
	.SYNOPSIS
		Test the ports SCOM Uses with Test-NetConnection Automatically.
	
	.DESCRIPTION
		This script tests the ports for SCOM.
	
	.PARAMETER SourceServer
		A description of the SourceServer parameter.
	
	.PARAMETER DestinationServer
		A description of the DestinationServer parameter.
	
	.PARAMETER OutputFile
		A description of the OutputFile parameter.
	
	.PARAMETER OutputType
		A description of the OutputType parameter.
	
	.PARAMETER Servers
		An array of Servers, or alternatively you can pipe in objects from Get-SCOMAgent or Get-SCOMManagementServer.
	
	.EXAMPLE
		PS C:\> Get-SCOMAgent | Where {$_.Name -match "IIS-server"} | .\Test-SCOMPorts
		PS C:\> Get-SCOMManagementServer | .\Test-SCOMPorts
		PS C:\> .\Test-SCOMPorts -Servers Agent1.contoso.com, SQL-Server.contoso.com
	
	.NOTES
		.AUTHOR
		Blake Drumm (blakedrumm@microsoft.com)
		.LAST MODIFIED
		08/04/2021
		
		https://www.stefanroth.net/2013/10/08/powershell-4-0-checking-scom-required-ports/
#>
	
	function Correct-PathName
	{
		param (
			$Path,
			$Type
		)
		if ($Path -match ".")
		{
			$SplitPath = $Path.Split(".")[0]
		}
		else
		{
			$SplitPath = $Path
		}
		
		if ($Type -eq 'CSV')
		{
			$FinalPath = "$($SplitPath).csv"
		}
		if ($Type -eq 'Text')
		{
			$FinalPath = "$($SplitPath).txt"
		}
		return $FinalPath
	}
	
	if (!$SourceServer)
	{
		$SourceServer = $env:COMPUTERNAME
	}
	if ($DestinationServer -match 'Microsoft.EnterpriseManagement.Administration.ManagementServer')
	{
		$DestinationServer = $DestinationServer.DisplayName
	}
	elseif ($DestinationServer -match 'Microsoft.EnterpriseManagement.Administration.AgentManagedComputer')
	{
		$DestinationServer = $DestinationServer.DisplayName
	}
	else
	{
		$DestinationServer = $DestinationServer
	}
	Write-Output " "
	Write-Output @"
================================
Starting SCOM Port Checker
"@
	Write-Host "  Running function:"
	function Check-SCOMPorts
	{
		param
		(
			[Parameter(Mandatory = $true,
					   Position = 0)]
			[array]$DestinationServer,
			[Parameter(Mandatory = $false,
					   Position = 1)]
			[array]$SourceServer
		)
		$payload = $null
		$payload = @()
		Write-Host "    $env:COMPUTERNAME" -ForegroundColor Cyan -NoNewLine
		$ports = @{
			"Management Server / Agent Port"   = 5723;
			"Web Console / Console Port"	   = 5724;
			"Connector Framework Source Port"  = 51905;
			"ACS Forwarder Port"			   = 51909;
			"AEM Port"						   = 51906;
			"SQL Server (Default) Port"	       = 1433;
			"SSH Port"						   = 22;
			"WS-MAN Port"					   = 1270;
			"Web Console (HTTP) Port"		   = 80;
			"Web Console (HTTPS) Port"		   = 443;
			"SNMP (Get) Port"				   = 161;
			"SNMP (Trap) Port"				   = 162
			
			"Remote Procedure Call (DCOM/RPC)" = 135;
			#"NetBIOS (Name Services UDP)"  = 137;
			#"NetBIOS (Datagram Services UDP)"  = 138;
			"NetBIOS (Session Services)"	   = 139;
			"SMB Over IP (Direct TCP/IP)"	   = 445;
			#"Private/Dynamic Range (Beginning)" = 49152;
			#"Private/Dynamic Range (Middle)" = 57343;
			#"Private/Dynamic Range (End)" = 65535;
		}
		foreach ($server in $DestinationServer)
		{
			ForEach ($port in $ports.GetEnumerator())
			{
				$tcp = $null
				$tcp = Test-NetConnection -Computername $server -Port $port.Value -WarningAction SilentlyContinue
				Write-Host '-' -ForegroundColor Green -NoNewline
				Switch ($($tcp.TcpTestSucceeded))
				{
					True { $payload += new-object psobject -property @{ Availability = 'Up'; 'Service Name' = $($port.Name); Port = $($port.Value); SourceServer = $env:COMPUTERNAME; DestinationServer = $server } }
					
					False { $payload += new-object psobject -property @{ Availability = 'Down'; 'Service Name' = $($port.Name); Port = $($port.Value); SourceServer = $env:COMPUTERNAME; DestinationServer = $server } }
				}
			}
			
		}
		Write-Host '> Complete!' -ForegroundColor Green
		return $payload
	}
	$scriptout = $null
	$sb = (get-item Function:Check-SCOMPorts).ScriptBlock
	foreach ($source in $SourceServer)
	{
		if ($source -match "^$env:COMPUTERNAME")
		{
			$scriptout += Check-SCOMPorts -SourceServer $source -DestinationServer $DestinationServer
		}
		else
		{
			$scriptout += Invoke-Command -ComputerName $source -ScriptBlock $sb -ArgumentList ( ,$DestinationServer)
		}
		
	}
	
	$finalout = $scriptout | Select-Object 'Service Name', SourceServer, Port, Availability, DestinationServer | Sort-Object -Property @{
		expression = 'SourceServer'
		descending = $false
	}, @{
		expression = 'DestinationServer'
		descending = $false
	}, @{
		expression = 'Port'
		descending = $false
	}
	
	if ($OutputFile)
	{
		if (!$OutputType)
		{
			$OutputType = 'Text'
		}
	}
	
	if ($OutputType -eq 'CSV')
	{
		#Write-Host "Output to " -NoNewline -ForegroundColor Gray
		#Write-Host $OutputFile -NoNewline -ForegroundColor Cyan
		$OutputFile = Correct-PathName -Path $OutputFile -Type CSV
		$finalout | Export-Csv -Path $OutputFile -NoTypeInformation
	}
	if ($OutputType -eq 'Text')
	{
		#Write-Host "Output to " -NoNewline -ForegroundColor Gray
		#Write-Host $OutputFile -NoNewline -ForegroundColor Cyan
		$OutputFile = Correct-PathName -Path $OutputFile -Type Text
		$finalout | Format-Table * -AutoSize | Out-File $OutputFile
	}
	if ($OutputType -eq 'Table')
	{
		$finalout | Format-Table * -AutoSize
	}
}