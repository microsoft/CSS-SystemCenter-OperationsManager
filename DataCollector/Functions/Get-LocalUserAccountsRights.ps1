function Get-LocalUserAccountsRights
{
	param
	(
		[Parameter(Mandatory = $false,
				   Position = 1)]
		[array]$Servers
	)
	trap
	{
		#potential error code
		#use continue or break keywords
		$e = $_.Exception
		$line = $_.InvocationInfo.ScriptLineNumber
		$msg = $e.Message
		
		Write-Verbose "Caught Exception: $e :: Message: $msg :: at line: $line"
		"$(Time-Stamp)Caught Exception: $e :: Message: $msg :: at line: $line" | Out-File $OutputPath\Error.log -Append
	}
	if (!$Servers)
	{
		$Servers = $env:COMPUTERNAME
	}
	
	function Inner-LocalAdministrators
	{
		$members = net localgroup administrators |
		where { $_ -AND $_ -notmatch "command completed successfully" } |
		select -skip 4
		
		$dtable = New-Object System.Data.DataTable
		$dtable.Columns.Add("ComputerName", "System.String") | Out-Null
		$dtable.Columns.Add("Group", "System.String") | Out-Null
		$dtable.Columns.Add("Members", "System.String") | Out-Null
		
		foreach ($member in $members)
		{
			Write-Host "-" -ForegroundColor DarkCyan -NoNewline
			$nRow = $dtable.NewRow()
			$nRow.ComputerName = $env:COMPUTERNAME
			$nRow.Group = "Administrators"
			$nRow.Members = $member
			
			$dtable.Rows.Add($nRow)
		}
		return $dtable
	}
	Write-Host "  Gathering Local Administrators:" -ForegroundColor DarkCyan
	$localadmin = @()
	$localAdministratorsScriptBlock = (get-item Function:Inner-LocalAdministrators).ScriptBlock
	foreach ($Server in $Servers)
	{
		Write-Host "   $Server" -ForegroundColor Cyan -NoNewline
		if ($Server -match $env:COMPUTERNAME)
		{
			Write-Host "-" -ForegroundColor DarkCyan -NoNewline
			$localadmin += Inner-LocalAdministrators
		}
		else
		{
			Write-Host "-" -ForegroundColor DarkCyan -NoNewline
			$localadmin += Invoke-Command -ComputerName $Server -ScriptBlock $localAdministratorsScriptBlock -HideComputerName | Select * -ExcludeProperty RunspaceID, PSShowComputerName, PSComputerName | Sort-Object -Property @{ Expression = "ComputerName"; Descending = $False }, @{ Expression = "Members"; Descending = $False }
		}
		Write-Host "> " -ForegroundColor DarkCyan -NoNewline
		Write-Host 'Complete!' -ForegroundColor Green
	}
	Write-Host " "
	New-Item -ItemType Directory -Path "$OutputPath\Local Administrators Group" -Force -ErrorAction Stop | Out-Null
	$localadmin | Export-CSV $OutputPath\Server_LocalAdministratorsGroup.csv -NoTypeInformation
	$localadmin | Out-String -Width 4096 | Out-File "$OutputPath\Local Administrators Group\LocalAdministratorsGroup.txt"
	Write-Host "  Gathering Local User Rights Assignment:" -ForegroundColor DarkCyan
	$localrights = @()
	function Inner-UserSecurityRights
	{
		# The better version of this function is located here: https://github.com/blakedrumm/SCOM-Scripts-and-SQL/blob/master/Powershell/General%20Functions/Get-UserRights.ps1
		# Full blog post here: https://blakedrumm.com/blog/set-and-check-user-rights-assignment/
		function Get-SecurityPolicy
		{
			#requires -version 2
			
			# Fail script if we can't find SecEdit.exe
			$SecEdit = Join-Path ([Environment]::GetFolderPath([Environment+SpecialFolder]::System)) "SecEdit.exe"
			if (-not (Test-Path $SecEdit))
			{
				Write-Error "File not found - '$SecEdit'" -Category ObjectNotFound
				return
			}
			
			# LookupPrivilegeDisplayName Win32 API doesn't resolve logon right display
			# names, so use this hashtable
			$UserLogonRights = @{
				"SeBatchLogonRight"				    = "Log on as a batch job"
				"SeDenyBatchLogonRight"			    = "Deny log on as a batch job"
				"SeDenyInteractiveLogonRight"	    = "Deny log on locally"
				"SeDenyNetworkLogonRight"		    = "Deny access to this computer from the network"
				"SeDenyRemoteInteractiveLogonRight" = "Deny log on through Remote Desktop Services"
				"SeDenyServiceLogonRight"		    = "Deny log on as a service"
				"SeInteractiveLogonRight"		    = "Allow log on locally"
				"SeNetworkLogonRight"			    = "Access this computer from the network"
				"SeRemoteInteractiveLogonRight"	    = "Allow log on through Remote Desktop Services"
				"SeServiceLogonRight"			    = "Log on as a service"
			}
			
			# Create type to invoke LookupPrivilegeDisplayName Win32 API
			$Win32APISignature = @'
[DllImport("advapi32.dll", SetLastError=true)]
public static extern bool LookupPrivilegeDisplayName(
  string systemName,
  string privilegeName,
  System.Text.StringBuilder displayName,
  ref uint cbDisplayName,
  out uint languageId
);
'@
			$AdvApi32 = Add-Type advapi32 $Win32APISignature -Namespace LookupPrivilegeDisplayName -PassThru
			
			# Use LookupPrivilegeDisplayName Win32 API to get display name of privilege
			# (except for user logon rights)
			function Get-PrivilegeDisplayName
			{
				param (
					[String]$name
				)
				$displayNameSB = New-Object System.Text.StringBuilder 1024
				$languageId = 0
				$ok = $AdvApi32::LookupPrivilegeDisplayName($null, $name, $displayNameSB, [Ref]$displayNameSB.Capacity, [Ref]$languageId)
				if ($ok)
				{
					$displayNameSB.ToString()
				}
				else
				{
					# Doesn't lookup logon rights, so use hashtable for that
					if ($UserLogonRights[$name])
					{
						$UserLogonRights[$name]
					}
					else
					{
						$name
					}
				}
			}
			# Outputs list of hashtables as a PSObject
			function Out-Object
			{
				param (
					[System.Collections.Hashtable[]]$hashData
				)
				$order = @()
				$result = @{ }
				$hashData | ForEach-Object {
					$order += ($_.Keys -as [Array])[0]
					$result += $_
				}
				$out = New-Object PSObject -Property $result | Select-Object $order
				return $out
			}
			
			# Translates a SID in the form *S-1-5-... to its account name;
			function Get-AccountName
			{
				param (
					[String]$principal
				)
				try
				{
					$sid = New-Object System.Security.Principal.SecurityIdentifier($principal.Substring(1))
					$sid.Translate([Security.Principal.NTAccount])
				}
				catch { $principal }
			}
			
			$TemplateFilename = Join-Path ([IO.Path]::GetTempPath()) ([IO.Path]::GetRandomFileName())
			$LogFilename = Join-Path ([IO.Path]::GetTempPath()) ([IO.Path]::GetRandomFileName())
			$StdOut = & $SecEdit /export /cfg $TemplateFilename /areas USER_RIGHTS /log $LogFilename
			if ($LASTEXITCODE -eq 0)
			{
				$dtable = $null
				$dtable = New-Object System.Data.DataTable
				$dtable.Columns.Add("Privilege", "System.String") | Out-Null
				$dtable.Columns.Add("PrivilegeName", "System.String") | Out-Null
				$dtable.Columns.Add("Principal", "System.String") | Out-Null
				$dtable.Columns.Add("ComputerName", "System.String") | Out-Null
				Select-String '^(Se\S+) = (\S+)' $TemplateFilename | Foreach-Object {
					Write-Host "-" -ForegroundColor DarkCyan -NoNewline
					$Privilege = $_.Matches[0].Groups[1].Value
					$Principals = $_.Matches[0].Groups[2].Value -split ','
					foreach ($Principal in $Principals)
					{
						$nRow = $dtable.NewRow()
						$nRow.Privilege = $Privilege
						$nRow.PrivilegeName = Get-PrivilegeDisplayName $Privilege
						$nRow.Principal = Get-AccountName $Principal
						$nRow.ComputerName = $env:COMPUTERNAME
						
						$dtable.Rows.Add($nRow)
					}
					return $dtable
					
				}
			}
			else
			{
				$OFS = ""
				Write-Error "$StdOut"
			}
			Remove-Item $TemplateFilename, $LogFilename -ErrorAction SilentlyContinue
		}
		return Get-SecurityPolicy
	}
	$localUserSecurityRightsScriptBlock = (get-item Function:Inner-UserSecurityRights).ScriptBlock
	foreach ($Server in $Servers)
	{
		Write-Host "   $Server" -ForegroundColor Cyan -NoNewline
		if ($Server -match "^$env:COMPUTERNAME")
		{
			Write-Host "-" -ForegroundColor DarkCyan -NoNewline
			$localrights += Inner-UserSecurityRights
		}
		else
		{
			Write-Host "-" -ForegroundColor DarkCyan -NoNewline
			$localrights += Invoke-Command -ComputerName $Server -ScriptBlock $localUserSecurityRightsScriptBlock -HideComputerName | Select * -ExcludeProperty RunspaceID, PSShowComputerName, PSComputerName -Unique
		}
		Write-Host "> " -ForegroundColor DarkCyan -NoNewline
		Write-Host 'Complete!' -ForegroundColor Green
	}
	New-Item -ItemType Directory -Path "$OutputPath\Local User Rights" -Force -ErrorAction Stop | Out-Null
	# Export CSV
	$localrights | Select-Object Privilege, PrivilegeName, Principal, ComputerName -Unique | Export-CSV $OutputPath\Server_UserRightsAssignment.csv -NoTypeInformation
	# Export TXT
	$localrights | Select-Object Privilege, PrivilegeName, Principal, ComputerName -Unique | Format-Table -AutoSize | Out-String -Width 4096 | Out-File "$OutputPath\Local User Rights\UserRightsAssignment.txt"
}