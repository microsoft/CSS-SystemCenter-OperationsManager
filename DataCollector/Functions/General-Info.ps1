function Get-SCOMGeneralInfo
{
	#Last modified: October 24th, 2022
	param
	(
		[cmdletbinding()]
		[Parameter(Position = 1)]
		[array]$Servers
	)
	trap
	{
		#potential error code
		#use continue or break keywords
		$e = $_.Exception
		$line = $_.InvocationInfo.ScriptLineNumber
		$msg = $e.Message
		
		Write-Verbose "$(Time-Stamp)Caught Exception: $e :: Message: $msg :: at line: $line"
		"$(Time-Stamp)Caught Exception: $e :: Message: $msg :: at line: $line" | Out-File $OutputPath\Error.log -Append
	}
	Write-Verbose "$(Time-Stamp)Loading Product Version"
	. $ScriptPath`\Functions\ProductVersions\ProductVersion.ps1
	Write-Progress -Activity "Collection Running" -Status "Progress-> 67%" -PercentComplete 67
	foreach ($server in $Servers)
	{
		function Inner-GeneralInfoFunction
		{
			param
			(
				[cmdletbinding()]
				[switch]$LocalManagementServer
			)
			# Uncomment the below to turn on Verbose Output.
			#$VerbosePreference = 'Continue'
			trap
			{
				#potential error code
				#use continue or break keywords
				$e = $_.Exception
				$line = $_.InvocationInfo.ScriptLineNumber
				$msg = $e.Message
				
				Write-Verbose "Caught Exception: $e at line: $line"
				"$(Time-Stamp)Caught Exception: $e at line: $line" | Out-File $OutputPath\Error.log -Append
			}
			Function Time-Stamp
			{
				$TimeStamp = Get-Date -Format "MM/dd/yyyy hh:mm:ss tt"
				return "$TimeStamp - "
			}
			Write-Verbose "================================================================"
			Write-Verbose "$(Time-Stamp)Started gathering on this machine: $env:COMPUTERNAME"
			Write-Verbose "$(Time-Stamp)Loading Product Version Function"
			#region AllServersGeneralInfo
			$ProductVersionScript = "function Get-ProductVersion { ${function:Get-ProductVersion} }"
			. ([ScriptBlock]::Create($ProductVersionScript))
			Write-Verbose "$(Time-Stamp)Grabbing System Uptime"
			$Uptime = (($(Get-Date) - $(Get-CimInstance -ClassName Win32_OperatingSystem | Select LastBootUpTime -ExpandProperty LastBootUpTime)) | Select Hours, Minutes, Seconds) | % { Write-Output "$($_.Hours) hour(s), $($_.Minutes) minute(s), $($_.Seconds) second(s)" }
			
			#=======================================================================
			# Start General Information Gather
			#=======================================================================
			# Get PowerShell Version section
			#=======================================================================
			$PSVer = $PSVersionTable.PSVersion
			[string]$PSMajor = $PSVer.Major
			[string]$PSMinor = $PSVer.Minor
			$PSVersion = $PSMajor + "." + $PSMinor
			#=======================================================================
			# Get PowerShell CLR Version section
			#=======================================================================
			$CLRVer = $PSVersionTable.CLRVersion
			[string]$CLRMajor = $CLRVer.Major
			[string]$CLRMinor = $CLRVer.Minor
			$CLRVersion = $CLRMajor + "." + $CLRMinor
			#=======================================================================
			$OSVersion = (Get-CimInstance win32_operatingsystem).Caption
			$Freespace = Get-PSDrive -PSProvider FileSystem | Select-Object @{ Name = 'Drive'; Expression = { $_.Root } }, @{ Name = "Used (GB)"; Expression = { "{0:###0.00}" -f ($_.Used / 1GB) } }, @{ Name = "Free (GB)"; Expression = { "{0:###0.00}" -f ($_.Free / 1GB) } }, @{ Name = "Total (GB)"; Expression = { "{0:###0.00}" -f (($_.Free / 1GB) + ($_.Used / 1GB)) } }
			$localServicesList = (Get-CimInstance Win32_service).where{ $_.name -eq 'omsdk' -or $_.name -eq 'cshost' -or $_.name -eq 'HealthService' -or $_.name -eq 'System Center Management APM' -or $_.name -eq 'AdtAgent' -or $_.name -match "MSSQL" -or $_.name -like "SQLAgent*" -or $_.name -eq 'SQLBrowser' -or $_.name -eq 'SQLServerReportingServices' }
			
			$localServices = $localServicesList | Format-List @{ Label = "Service Display Name"; Expression = 'DisplayName' }, @{ Label = "Service Name"; Expression = 'Name' }, @{ Label = "Account Name"; Expression = 'StartName' }, @{ Label = "Start Mode"; Expression = 'StartMode' }, @{ Label = "Current State"; Expression = 'State' } | Out-String -Width 4096
			$WinHTTPProxy = netsh winhttp show proxy
			#=======================================================================
			# Build IP List from Windows Computer Property
			#=======================================================================
			#We want to remove Link local IP
			$ip = ([System.Net.Dns]::GetHostAddresses($Env:COMPUTERNAME)).IPAddressToString;
			[string]$IPList = ""
			$IPSplit = $IP.Split(", ")
			FOREACH ($IPAddr in $IPSplit)
			{
				[string]$IPAddr = $IPAddr.Trim()
				IF (!($IPAddr.StartsWith("fe80") -or $IPAddr.StartsWith("169.254")))
				{
					$IPList = $IPList + $IPAddr + ", "
				}
			}
			$IPList = $IPList.TrimEnd(", ")
			#=======================================================================
			# Get TLS12Enforced Section
			#=======================================================================
			#Set the value to good by default then look for any bad or missing settings
			$TLS12Enforced = $True
			
			IF (Test-Path "HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\SSL 2.0\Client")
			{
				$Enabled = (Get-ItemProperty "HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\SSL 2.0\Client").Enabled
				$DisabledByDefault = (Get-ItemProperty "HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\SSL 2.0\Client").DisabledByDefault
				IF ($Enabled -ne 0 -or $DisabledByDefault -ne 1)
				{
					$TLS12Enforced = $False
				}
			}
			ELSE
			{
				$TLS12Enforced = $False
			}
			
			IF (Test-Path "HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\SSL 2.0\Server")
			{
				$Enabled = (Get-ItemProperty "HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\SSL 2.0\Server").Enabled
				$DisabledByDefault = (Get-ItemProperty "HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\SSL 2.0\Server").DisabledByDefault
				IF ($Enabled -ne 0 -or $DisabledByDefault -ne 1)
				{
					$TLS12Enforced = $False
				}
			}
			ELSE
			{
				$TLS12Enforced = $False
			}
			
			IF (Test-Path "HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\SSL 3.0\Client")
			{
				$Enabled = (Get-ItemProperty "HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\SSL 3.0\Client").Enabled
				$DisabledByDefault = (Get-ItemProperty "HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\SSL 3.0\Client").DisabledByDefault
				IF ($Enabled -ne 0 -or $DisabledByDefault -ne 1)
				{
					$TLS12Enforced = $False
				}
			}
			ELSE
			{
				$TLS12Enforced = $False
			}
			
			IF (Test-Path "HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\SSL 3.0\Server")
			{
				$Enabled = (Get-ItemProperty "HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\SSL 3.0\Server").Enabled
				$DisabledByDefault = (Get-ItemProperty "HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\SSL 3.0\Server").DisabledByDefault
				IF ($Enabled -ne 0 -or $DisabledByDefault -ne 1)
				{
					$TLS12Enforced = $False
				}
			}
			ELSE
			{
				$TLS12Enforced = $False
			}
			
			IF (Test-Path "HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\TLS 1.0\Client")
			{
				$Enabled = (Get-ItemProperty "HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\TLS 1.0\Client").Enabled
				$DisabledByDefault = (Get-ItemProperty "HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\TLS 1.0\Client").DisabledByDefault
				IF ($Enabled -ne 0 -or $DisabledByDefault -ne 1)
				{
					$TLS12Enforced = $False
				}
			}
			ELSE
			{
				$TLS12Enforced = $False
			}
			
			IF (Test-Path "HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\TLS 1.0\Server")
			{
				$Enabled = (Get-ItemProperty "HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\TLS 1.0\Server").Enabled
				$DisabledByDefault = (Get-ItemProperty "HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\TLS 1.0\Server").DisabledByDefault
				IF ($Enabled -ne 0 -or $DisabledByDefault -ne 1)
				{
					$TLS12Enforced = $False
				}
			}
			ELSE
			{
				$TLS12Enforced = $False
			}
			
			IF (Test-Path "HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\TLS 1.1\Client")
			{
				$Enabled = (Get-ItemProperty "HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\TLS 1.1\Client").Enabled
				$DisabledByDefault = (Get-ItemProperty "HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\TLS 1.1\Client").DisabledByDefault
				IF ($Enabled -ne 0 -or $DisabledByDefault -ne 1)
				{
					$TLS12Enforced = $False
				}
			}
			ELSE
			{
				$TLS12Enforced = $False
			}
			
			IF (Test-Path "HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\TLS 1.1\Server")
			{
				$Enabled = (Get-ItemProperty "HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\TLS 1.1\Server").Enabled
				$DisabledByDefault = (Get-ItemProperty "HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\TLS 1.1\Server").DisabledByDefault
				IF ($Enabled -ne 0 -or $DisabledByDefault -ne 1)
				{
					$TLS12Enforced = $False
				}
			}
			ELSE
			{
				$TLS12Enforced = $False
			}
			
			IF (Test-Path "HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\TLS 1.2\Client")
			{
				$Enabled = (Get-ItemProperty "HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\TLS 1.2\Client").Enabled
				$DisabledByDefault = (Get-ItemProperty "HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\TLS 1.2\Client").DisabledByDefault
				IF ($Enabled -ne 1 -or $DisabledByDefault -ne 0)
				{
					$TLS12Enforced = $False
				}
			}
			ELSE
			{
				$TLS12Enforced = $False
			}
			
			IF (Test-Path "HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\TLS 1.2\Server")
			{
				$Enabled = (Get-ItemProperty "HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\TLS 1.2\Server").Enabled
				$DisabledByDefault = (Get-ItemProperty "HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\TLS 1.2\Server").DisabledByDefault
				IF ($Enabled -ne 1 -or $DisabledByDefault -ne 0)
				{
					$TLS12Enforced = $False
				}
			}
			ELSE
			{
				$TLS12Enforced = $False
			}
			
			IF (Test-Path "HKLM:\SOFTWARE\Microsoft\.NETFramework\v4.0.30319")
			{
				$SchUseStrongCrypto = (Get-ItemProperty "HKLM:\SOFTWARE\Microsoft\.NETFramework\v4.0.30319").SchUseStrongCrypto
				IF ($SchUseStrongCrypto -ne 1)
				{
					$TLS12Enforced = $False
				}
			}
			ELSE
			{
				$TLS12Enforced = $False
			}
			
			IF (Test-Path "HKLM:\SOFTWARE\WOW6432Node\Microsoft\.NETFramework\v4.0.30319")
			{
				$SchUseStrongCrypto = (Get-ItemProperty "HKLM:\SOFTWARE\WOW6432Node\Microsoft\.NETFramework\v4.0.30319").SchUseStrongCrypto
				IF ($SchUseStrongCrypto -ne 1)
				{
					$TLS12Enforced = $False
				}
			}
			ELSE
			{
				$TLS12Enforced = $False
			}
			Write-Verbose "$(Time-Stamp)Gathering File System Allocation Information"
			$driveData = @()
			try
			{
				$Freespace | Foreach-Object {
					$driveLetter = ($_.Drive -replace "\\", '')
					$driveData += (Get-CimInstance Win32_Volume) | Where { $driveLetter -eq $_.DriveLetter } | Select-Object -Property @{ Name = 'DriveLetter'; Expression = { $_.DriveLetter } }, @{ Name = 'BytesPerCluster'; Expression = { "$($_.BlockSize) ($($_.BlockSize / 1kb) KB)" } }
				}
			}
			catch
			{
				Write-Verbose "$(Time-Stamp) - Unable to gather the File System Allocation Information!"
			}
			Write-Verbose "$(Time-Stamp)Gathering w32tm Information"
			$w32tmQueryStatus = & 'w32tm' '/query', '/status'
			try
			{
				$PowershellGPOs = (Get-ChildItem 'HKLM:\SOFTWARE\WOW6432Node\Policies\Microsoft\Windows\PowerShell\' -ErrorAction Stop | Out-String).Replace("Hive: HKEY_LOCAL_MACHINE", "Path: HKLM:")
			}
			catch
			{
				$PowershellGPOs = 'Unable to locate any Group Policies'
			}
			
			###################################################
			# Test .NET Framework version on ALL servers
			# Get version from registry
			Write-Verbose "$(Time-Stamp)Checking .NET Version"
			$RegPath = "HKLM:SOFTWARE\Microsoft\NET Framework Setup\NDP\v4\Full\"
			[int]$ReleaseRegValue = (Get-ItemProperty $RegPath -ErrorAction SilentlyContinue).Release
			# Interpret .NET version
			[string]$dotNetVersionString = switch ($ReleaseRegValue)
			{
				"378389" { ".NET Framework 4.5" }
				"378675" { ".NET Framework 4.5.1" }
				"378758" { ".NET Framework 4.5.1" }
				"379893" { ".NET Framework 4.5.2" }
				"393295" { ".NET Framework 4.6" }
				"393297" { ".NET Framework 4.6" }
				"394254" { ".NET Framework 4.6.1" }
				"394271" { ".NET Framework 4.6.1" }
				"394802" { ".NET Framework 4.6.2" }
				"394806" { ".NET Framework 4.6.2" }
				"460798" { ".NET Framework 4.7" }
				"460805" { ".NET Framework 4.7" }
				"461308" { ".NET Framework 4.7.1" }
				"461310" { ".NET Framework 4.7.1" }
				"461814" { ".NET Framework 4.7.2" }
				"461808" { ".NET Framework 4.7.2" }
				"461814" { ".NET Framework 4.7.2" }
				"528040" { ".NET Framework 4.8" }
				"528372" { ".NET Framework 4.8" }
				"528049" { ".NET Framework 4.8" }
				"528449" { ".NET Framework 4.8" }
				default { "Unknown .NET version: $ReleaseRegValue" }
			}
			Write-Verbose "$(Time-Stamp) - .NET Version detected: $dotNetVersionString"
			Write-Host '-' -NoNewline -ForegroundColor Green
			#endregion AllServersGeneralInfo
			Write-Verbose "$(Time-Stamp)End all servers general info"
			Add-Type -TypeDefinition @"
public class OpsMgrSetupRegKey{
    public string CurrentVersion;
    public string DatabaseName;
    public string DatabaseServerName;
    public string DatabaseVersion;
    public string DataWarehouseDBName;
    public string DataWarehouseDBServerName;
    public string InstallDirectory;
    public string InstalledOn;
    public string ManagementServerPort;
    public string Product;
    public string ServerVersion;
    public string UIVersion;
}
"@
			# this is the path we want to retrieve the values from
			$opsMgrSetupRegKeyPath = 'HKLM:\SOFTWARE\Microsoft\Microsoft Operations Manager\3.0\Setup'
			Write-Verbose "$(Time-Stamp)Start gathering registry information regarding Operations Manager in this path: $opsMgrSetupRegKeyPath"
			# get the values
			try
			{
				$opsMgrSetupRegKey = Get-ItemProperty -Path $opsMgrSetupRegKeyPath -ErrorAction Stop
				
				# construct a new object
				$setuplocation = New-Object OpsMgrSetupRegKey
				
				#set the object values from the registry key
				$setuplocation.CurrentVersion = $opsMgrSetupRegKey.CurrentVersion
				$setuplocation.DatabaseName = $opsMgrSetupRegKey.DatabaseName
				$setuplocation.DatabaseServerName = $opsMgrSetupRegKey.DatabaseServerName
				$setuplocation.DatabaseVersion = $opsMgrSetupRegKey.DatabaseVersion
				$setuplocation.DataWarehouseDBName = $opsMgrSetupRegKey.DataWarehouseDBName
				$setuplocation.DataWarehouseDBServerName = $opsMgrSetupRegKey.DataWarehouseDBServerName
				$setuplocation.InstallDirectory = $opsMgrSetupRegKey.InstallDirectory
				$setuplocation.InstalledOn = $opsMgrSetupRegKey.InstalledOn
				$setuplocation.ManagementServerPort = $opsMgrSetupRegKey.ManagementServerPort
				$setuplocation.Product = $opsMgrSetupRegKey.Product
				$setuplocation.ServerVersion = $opsMgrSetupRegKey.ServerVersion
				$setuplocation.UIVersion = $opsMgrSetupRegKey.UIVersion
				
				$Agent = $false
				$ManagementServer = $false
				$Gateway = $false
			}
			catch
			{
				$setuplocation = $null
				Write-Verbose "$(Time-Stamp)Unable to return the data from registry: $opsMgrSetupRegKeyPath"
			}
			if ($setuplocation)
			{
				if ($setuplocation.Product -eq "Microsoft Monitoring Agent")
				{
					Write-Verbose "$(Time-Stamp)Found Microsoft Monitoring Agent"
					$Agent = $true
					$installdir = (Resolve-Path "$($setuplocation.InstallDirectory)`..\")
				}
				elseif ($setuplocation.Product -like "System Center Operations Manager*Server")
				{
					Write-Verbose "$(Time-Stamp)Found System Center Operations Manager Server"
					$ManagementServer = $true
					$installdir = (Resolve-Path "$($setuplocation.InstallDirectory)`..\")
					$SCOMPath = $installdir.Path.TrimEnd("\")
					if ($LocalManagementServer)
					{
						$global:localLocation = $installdir
					}
					if ($setuplocation.InstallDirectory -like "*Gateway*")
					{
						Write-Verbose "$(Time-Stamp)Found System Center Operations Manager Gateway Server"
						$Gateway = $true
					}
				}
				Write-Verbose "$(Time-Stamp)Grabbing Health Service State Folder Properties"
				$healthServiceState = Get-ItemProperty "$($setuplocation.InstallDirectory)\Health Service State"
				
				function Get-FolderSize
				{
					
					Begin
					{
						
						$fso = New-Object -comobject Scripting.FileSystemObject
					}
					
					Process
					{
						
						$Path = $input.Fullname
						$Folder = $Fso.GetFolder($Path)
						$DateModified = $Folder.DateLastModified
						$DateCreated = $Folder.DateCreated
						$Size = $Folder.Size
						[PSCustomObject]@{ Location = $Path; Size = (Format-FileSize $Size); Modified = $DateModified; Created = $DateCreated }
					}
				}
				
				Function Format-FileSize($size)
				{
					# Param ([int]$size)
					If ($size -gt 1TB) { [string]::Format("{0:0.00} TB", $size / 1TB) }
					ElseIf ($size -gt 1GB) { [string]::Format("{0:0.00} GB", $size / 1GB) }
					ElseIf ($size -gt 1MB) { [string]::Format("{0:0.00} MB", $size / 1MB) }
					ElseIf ($size -gt 1KB) { [string]::Format("{0:0.00} kB", $size / 1KB) }
					ElseIf ($size -gt 0) { [string]::Format("{0:0.00} B", $size) }
					Else { "" }
				}
				$HSStateFolder = $healthServiceState | Get-FolderSize
				
				try
				{
					$configUpdated = @()
					Write-Verbose "$(Time-Stamp)Grabbing Connector Configuration Cache on $env:COMPUTERNAME"
					$mgsFound = Get-ChildItem -Path "$($HSStateFolder.Location)\Connector Configuration Cache" -ErrorAction Stop
					Write-Verbose "$(Time-Stamp)Management Groups Found: $mgsFound"
					foreach ($ManagementGroup in $mgsFound)
					{
						Write-Verbose "$(Time-Stamp)Current Management Group: $ManagementGroup"
						$HSConfigInformation = $null
						$HSConfigInformation = [pscustomobject] @{ }
						$HSConfigInformation | Add-Member -MemberType NoteProperty -Name 'Management Group Name' -Value $ManagementGroup.Name
						try
						{
							Write-Verbose "$(Time-Stamp)Get-ItemProperty `"$($ManagementGroup.PSPath)\OpsMgrConnector.Config.xml`""
							$LastUpdated = ((Get-ItemProperty "$($ManagementGroup.PSPath)\OpsMgrConnector.Config.xml" -ErrorAction Stop).LastWriteTime | Get-Date -Format "MMMM dd, yyyy h:mm tt")
							$HSConfigInformation | Add-Member -MemberType NoteProperty -Name 'Last Time Configuration Updated' -Value $($LastUpdated)
						}
						catch
						{
							Write-Verbose "$(Time-Stamp)Could not detect file: OpsMgrConnector.Config.xml"
							$HSConfigInformation | Add-Member -MemberType NoteProperty -Name 'Last Time Configuration Updated' -Value 'Could not detect file: OpsMgrConnector.Config.xml'
						}
						Write-Verbose "$(Time-Stamp)Adding: $HSConfigInformation"
						$configUpdated += $HSConfigInformation
					}
					Write-Verbose "$(Time-Stamp)Completed: $configUpdated"
				}
				catch
				{
					Write-Verbose "$(Time-Stamp)$($error[0])"
					$configUpdated = $false
				}
			}
			
			#Start SCOM Management Server, Agent, and Gateway Related Gathering.
			if ($ManagementServer)
			{
				#=======================================================================
				# Get Certificate Section
				#=======================================================================
				$CertRegKey = "HKLM:\SOFTWARE\Microsoft\Microsoft Operations Manager\3.0\Machine Settings"
				IF (Test-Path $CertRegKey)
				{
					[array]$CertValue = (Get-ItemProperty $CertRegKey).ChannelCertificateSerialNumber
					IF ($Certvalue)
					{
						$CertLoaded = $True
						[string]$ThumbPrint = (Get-ItemProperty $CertRegKey).ChannelCertificateHash
						$Cert = Get-ChildItem -path cert:\LocalMachine\My | Where-Object { $_.Thumbprint -eq $ThumbPrint }
						IF ($Cert)
						{
							[datetime]$CertExpiresDateTime = $Cert.NotAfter
							[string]$CertExpires = $CertExpiresDateTime.ToShortDateString()
							$CertIssuerArr = $Cert.Issuer
							$CertIssuerSplit = $CertIssuerArr.Split(",")
							[string]$CertIssuer = $CertIssuerSplit[0].TrimStart("CN=")
						}
						ELSE
						{
							$CertIssuer = "NotFound"
							$CertExpires = "NotFound"
						}
						
					}
					ELSE
					{
						$CertLoaded = $False
					}
				}
				ELSE
				{
					$CertLoaded = $False
				}
				try
				{
					$LinuxAuthType = Get-ItemProperty -Path 'HKLM:\SOFTWARE\Microsoft\Microsoft Operations Manager\3.0\Setup\Linux Auth' -ErrorAction SilentlyContinue | Select-Object Authentication -ExpandProperty Authentication
				}
				catch
				{
					$LinuxAuthType = $null
				}
				$ServerVersionSwitch = (Get-ProductVersion -Product SCOM -BuildVersion $setuplocation.ServerVersion)
				$LocalServerVersionSwitchOut = $ServerVersionSwitch + " (" + $setuplocation.ServerVersion + ")"
				Write-Verbose "$(Time-Stamp)Gathering Server Version - Registry - via Product Version Function: $LocalServerVersionSwitchOut"
				
				$serverdll = Get-Item "$($setuplocation.InstallDirectory)`MOMAgentManagement.dll" | foreach-object { "{0}" -f [System.Diagnostics.FileVersionInfo]::GetVersionInfo($_).FileVersion }
				$ServerVersionDLLSwitch = (Get-ProductVersion -Product SCOM -BuildVersion $serverdll)
				$ServerVersionDLL = $ServerVersionDLLSwitch + " (" + $serverdll + ")"
				Write-Verbose "$(Time-Stamp)Gathering Server Version - DLL - via Product Version Function: $ServerVersionDLL"
				
				$OctoberPatchserverDLL = Get-Item "$($setuplocation.InstallDirectory)`MOMModules2.dll" | foreach-object { "{0}" -f [System.Diagnostics.FileVersionInfo]::GetVersionInfo($_).FileVersion }
				$OctoberPatchserverDLLSwitch = (Get-ProductVersion -Product SCOM -BuildVersion $OctoberPatchserverDLL)
				$OctoberPatchserver = $OctoberPatchserverDLLSwitch + " (" + $OctoberPatchserverDLL + ")"
				Write-Verbose "$(Time-Stamp)Gathering Server Version (SCOM 2019 October 2021 Patch) - DLL - via Product Version Function: $ServerVersionDLL"
				
				try
				{
					$ServerAgentOMVersionDLL = Get-Item "$($setuplocation.InstallDirectory)`\AgentManagement\amd64\OMVersion.dll" -ErrorAction Stop | foreach-object { "{0}" -f [System.Diagnostics.FileVersionInfo]::GetVersionInfo($_).FileVersion }
					if ($ServerAgentOMVersionDLL)
					{
						$ServerAgentVersionDLLSwitch = (Get-ProductVersion -Product SCOM -BuildVersion $ServerAgentOMVersionDLL)
						$ServerAgentVersionDLL = $ServerAgentVersionDLLSwitch + " (" + $ServerAgentOMVersionDLL + ")"
						Write-Verbose "$(Time-Stamp)Server Agent Management DLL Version - $ServerAgentVersionDLL"
						$ServerAgentVersion_info = $true
					}
					$ServerAgentUnixVersionDLL = Get-ItemProperty "$($setuplocation.InstallDirectory)`\AgentManagement\UnixAgents\DownloadedKits\*" -ErrorAction Stop | Format-Table Name -AutoSize | Out-String -Width 4096
				}
				catch
				{
					$ServerAgentVersion_info = $false
				}
				try
				{
					$UIExe = Get-Item "$($setuplocation.InstallDirectory)`..\Console\Microsoft.EnterpriseManagement.Monitoring.Console.exe" -ErrorAction Stop | foreach-object { "{0}" -f [System.Diagnostics.FileVersionInfo]::GetVersionInfo($_).FileVersion }
					if (($setuplocation.UIVersion) -and ($UIExe))
					{
						$UIVersionSwitch = (Get-ProductVersion -Product SCOM -BuildVersion $setuplocation.UIVersion)
						$UIVersionFinal = $UIVersionSwitch + " (" + $setuplocation.UIVersion + ")"
						
						$UIVersionExeSwitch = (Get-ProductVersion -Product SCOM -BuildVersion $UIExe)
						$UIVersionExe = $UIVersionExeSwitch + " (" + $UIExe + ")"
						$UI_info = $true
					}
					
				}
				catch
				{
					$UI_info = $false
				}
				try
				{
					$WebConsoleDLL = Get-Item "$($setuplocation.InstallDirectory)`..\WebConsole\MonitoringView\OMVersion.dll" -ErrorAction Stop | foreach-object { "{0}" -f [System.Diagnostics.FileVersionInfo]::GetVersionInfo($_).FileVersion }
					$WebConsoleDLLSwitch = (Get-ProductVersion -Product SCOM -BuildVersion $WebConsoleDLL)
					$WebConsoleVersionDLL = $WebConsoleDLLSwitch + " (" + $WebConsoleDLL + ")"
					
					$WebConsole_info = $true
					try
					{
						if (Test-Path -Path "$($setuplocation.InstallDirectory)`..\WebConsole\AppDiagnostics\AppAdvisor\Web\Bin\ARViewer.dll")
						{
							$WebConsolePatchPath = "..\WebConsole\AppDiagnostics\AppAdvisor\Web\Bin\ARViewer.dll"
							$WebConsolePatchDLL = Get-Item "$($setuplocation.InstallDirectory)`..\WebConsole\AppDiagnostics\AppAdvisor\Web\Bin\ARViewer.dll" -ErrorAction Stop | foreach-object { "{0}" -f [System.Diagnostics.FileVersionInfo]::GetVersionInfo($_).FileVersion }
						}
						else
						{
							$WebConsolePatchPath = "..\WebConsole\AppDiagnostics\Web\bin\SEMWebViewer.dll"
							$WebConsolePatchDLL = Get-Item "$($setuplocation.InstallDirectory)`..\WebConsole\AppDiagnostics\Web\bin\SEMWebViewer.dll" -ErrorAction Stop | foreach-object { "{0}" -f [System.Diagnostics.FileVersionInfo]::GetVersionInfo($_).FileVersion }
						}
						$WebConsolePatchSwitch = (Get-ProductVersion -Product SCOM -BuildVersion $WebConsolePatchDLL)
						$WebConsolePatchVersionDLL = $WebConsolePatchSwitch + " (" + $WebConsolePatchDLL + ")"
					}
					catch
					{
						return
					}
				}
				catch { $WebConsole_info = $false }
				$CurrentVersionSwitch = (Get-ProductVersion -Product SCOM -BuildVersion $setuplocation.CurrentVersion)
				if ($LocalManagementServer)
				{
					try
					{
						$SQLPatchVersionOpsDB = (Import-Csv "$OutputPath`\MG_SQLPatchVersion_OpsDB.csv" -ErrorAction Stop) | Where { $_.State -eq 'COMPLETED' } | Sort-Object @{ Expression = { [version]$_.Value } } -Descending | Select-Object -First 1
						if ($SQLPatchVersionOpsDB)
						{
							$SQLPatchVersionOpsDBSwitch = (Get-ProductVersion -Product SCOM -BuildVersion $SQLPatchVersionOpsDB.Value)
							$SQLPatchVersionOpsDBInfo = $SQLPatchVersionOpsDBSwitch + " (" + $SQLPatchVersionOpsDB.Value + ")"
						}
					}
					catch
					{
						#potential error code
						#use continue or break keywords
						#$e = $_.Exception
						$line = $_.InvocationInfo.ScriptLineNumber
						$msg = $e.Message
						
						Write-Verbose "$(Time-Stamp)Caught Exception: $($error[0]) at line: $line"
						"$(Time-Stamp)Caught Exception: $($error[0]) at line: $line" | Out-File $OutputPath\Error.log -Append
					}
					try
					{
						$SQLPatchVersionDW = (Import-Csv "$OutputPath`\MG_SQLPatchVersion_DW.csv" -ErrorAction SilentlyContinue) | Where{ $_.State -eq 'COMPLETED' } | Sort-Object @{ Expression = { [version]$_.Value } } -Descending | Select-Object -First 1
						if ($SQLPatchVersionDW)
						{
							$SQLPatchVersionDWSwitch = (Get-ProductVersion -Product SCOM -BuildVersion $SQLPatchVersionDW.Value)
							$SQLPatchVersionDWInfo = $SQLPatchVersionDWSwitch + " (" + $SQLPatchVersionDW.Value + ")"
						}
					}
					catch
					{
						#potential error code
						#use continue or break keywords
						#$e = $_.Exception
						$line = $_.InvocationInfo.ScriptLineNumber
						$msg = $e.Message
						
						Write-Verbose "$(Time-Stamp)Caught Exception: $($error[0]) at line: $line"
						"$(Time-Stamp)Caught Exception: $($error[0]) at line: $line" | Out-File $OutputPath\Error.log -Append
					}
				}
				
				$CurrentVersionFinal = $CurrentVersionSwitch + " (" + $setuplocation.CurrentVersion + ")"
				
				
				$ReportingRegistryKey = get-itemproperty -path "HKLM:\SOFTWARE\Microsoft\System Center Operations Manager\12\Setup\Reporting" -ErrorAction SilentlyContinue | Select-Object * -exclude PSPath, PSParentPath, PSChildName, PSProvider, PSDrive
				
				try
				{
					Write-Verbose "$(Time-Stamp)Running - Get-SCOMRMSEmulator"
					$rmsEmulator = Get-SCOMRMSEmulator -ErrorAction Stop | Select-Object -Property DisplayName -ExpandProperty DisplayName
				}
				catch
				{
					$rmsEmulator = "Unable to run Get-SCOMRMSEmulator."
				}
				
				Write-Host "-" -NoNewline -ForegroundColor Green
				try
				{
					Write-Verbose "$(Time-Stamp)Running - Get-SCOMManagementGroup"
					$ManagementGroup = Get-SCOMManagementGroup -ErrorAction Stop | Select-Object -Property Name -ExpandProperty Name
				}
				catch
				{
					$ManagementGroup = "Unable to run Get-SCOMManagementGroup."
				}
				$LastUpdatedConfiguration = (Get-WinEvent -LogName 'Operations Manager' -ErrorAction SilentlyContinue | Where{ $_.Id -eq 1210 } | Select-Object -First 1).TimeCreated
				if (!$LastUpdatedConfiguration) { $LastUpdatedConfiguration = "No Event ID 1210 Found in Operations Manager Event Log" }
				else { $LastUpdatedConfiguration = $LastUpdatedConfiguration | Get-Date -Format "MMMM dd, yyyy h:mm tt" }
				
				[double]$WorkflowCount = $null
				[double]$WorkflowCount = (((Get-Counter -Counter '\Health Service\Workflow Count' -ErrorAction SilentlyContinue -SampleInterval 5 -MaxSamples 5).CounterSamples).CookedValue | Measure-Object -Average).Average
				Write-Verbose "$(Time-Stamp)Workflow count - $WorkflowCount"
				#=======================================================================
				
				$ACSReg = "HKLM:\SYSTEM\CurrentControlSet\Services\AdtServer"
				IF (Test-Path $ACSReg)
				{
					#This is an ACS Collector server
					$ACS = $true
					
				}
				ELSE
				{
					#This is NOT an ACS Collector server
					$ACS = $false
					
				}
				
			}
			elseif ($Agent)
			{
				Write-Verbose "$(Time-Stamp)Agent Detected"
				#$ManagementGroups = Get-Item "HKLM:\SOFTWARE\Microsoft\Microsoft Operations Manager\3.0\Agent Management Groups\*" | Select-Object PSChildName -ExpandProperty PSChildName
				$ADIntegration = (Get-ItemProperty HKLM:\SYSTEM\CurrentControlSet\Services\HealthService\Parameters\ConnectorManager).EnableADIntegration
				
				$ADIntegrationSwitch = switch ($ADIntegration)
				{
					'0' { "Disabled" }
					'1' { "Enabled" }
				}
				
				$LastUpdatedConfiguration = (Get-WinEvent -LogName 'Operations Manager' | Where{ $_.Id -eq 1210 } | Select-Object -First 1).TimeCreated
				if (!$LastUpdatedConfiguration) { $LastUpdatedConfiguration = "No Event ID 1210 Found in Operations Manager Event Log" }
				else { $LastUpdatedConfiguration = $LastUpdatedConfiguration | Get-Date -Format "MMMM dd, yyyy h:mm tt" }
				
				[string]$SCOMAgentURVersion = (Get-ProductVersion -Product SCOM -BuildVersion $setuplocation.CurrentVersion)
				Write-Verbose "$(Time-Stamp)Load Agent Scripting Module"
				# Load Agent Scripting Module
				#=======================================================================
				$AgentCfg = New-Object -ComObject "AgentConfigManager.MgmtSvcCfg"
				#=======================================================================
				
				# Get Agent Management groups section
				#=======================================================================
				#Get management groups
				Write-Verbose "$(Time-Stamp)Gathering Management Groups"
				$MGs = $AgentCfg.GetManagementGroups()
				$MGDetails = @()
				foreach ($MG in $MGs)
				{
					Write-Verbose "$(Time-Stamp)Found Management Group - $MG"
					$MGDetails += $MG | Select *
					<#
				    $managementGroup.ManagementGroupName
				    $managementGroup.ManagementServer
				    $managementGroup.ManagementServerPort
				    $managementGroup.IsManagementGroupFromActiveDirectory
				    $managementGroup.ActionAccount
				    #>
				}
				# Get Agent OMS Workspaces section
				#=======================================================================
				# This section depends on AgentConfigManager.MgmtSvcCfg object in previous section
				[string]$OMSList = ''
				# Agent might not support OMS
				$AgentSupportsOMS = $AgentCfg | Get-Member -Name 'GetCloudWorkspaces'
				IF (!$AgentSupportsOMS)
				{
					Write-Verbose "$(Time-Stamp)This agent version does not support Cloud Workspaces"
					#This agent version does not support Cloud Workspaces.
				}
				ELSE
				{
					$OMSWorkSpaces = $AgentCfg.GetCloudWorkspaces()
					FOREACH ($OMSWorkSpace in $OMSWorkSpaces)
					{
						$OMSList = $OMSList + $OMSWorkspace.workspaceId + ", "
					}
					IF ($OMSList)
					{
						$OMSList = $OMSList.TrimEnd(", ")
					}
					Write-Verbose "$(Time-Stamp)OMS List - $OMSList"
					#Get ProxyURL
					[string]$ProxyURL = $AgentCfg.proxyUrl
				}
				
				#=======================================================================
				# Get Certificate Section
				#=======================================================================
				$CertRegKey = "HKLM:\SOFTWARE\Microsoft\Microsoft Operations Manager\3.0\Machine Settings"
				IF (Test-Path $CertRegKey)
				{
					[array]$CertValue = (Get-ItemProperty $CertRegKey).ChannelCertificateSerialNumber
					IF ($Certvalue)
					{
						Write-Verbose "$(Time-Stamp)Found Certificate Registry Key"
						$CertLoaded = $True
						[string]$ThumbPrint = (Get-ItemProperty $CertRegKey).ChannelCertificateHash
						$Cert = Get-ChildItem -path cert:\LocalMachine\My | Where-Object { $_.Thumbprint -eq $ThumbPrint }
						IF ($Cert)
						{
							[datetime]$CertExpiresDateTime = $Cert.NotAfter
							[string]$CertExpires = $CertExpiresDateTime.ToShortDateString()
							$CertIssuerArr = $Cert.Issuer
							$CertIssuerSplit = $CertIssuerArr.Split(",")
							[string]$CertIssuer = $CertIssuerSplit[0].TrimStart("CN=")
						}
						ELSE
						{
							$CertIssuer = "NotFound"
							$CertExpires = "NotFound"
						}
						
					}
					ELSE
					{
						Write-Verbose "$(Time-Stamp)MOMCertImport needs to be run"
						$CertLoaded = $False
					}
				}
				ELSE
				{
					Write-Verbose "$(Time-Stamp)Certificate key not present"
					$CertLoaded = $False
				}
				# Build IP List from Windows Computer Property
				#=======================================================================
				#We want to remove Link local IP
				$ip = ([System.Net.Dns]::GetHostAddresses($Env:COMPUTERNAME)).IPAddressToString;
				[string]$IPList = ""
				$IPSplit = $IP.Split(",")
				FOREACH ($IPAddr in $IPSplit)
				{
					[string]$IPAddr = $IPAddr.Trim()
					IF (!($IPAddr.StartsWith("fe80") -or $IPAddr.StartsWith("169.254")))
					{
						$IPList = $IPList + $IPAddr + ","
					}
				}
				$IPList = $IPList.TrimEnd(",")
				$SCOMAgentVersion = $SCOMAgentURVersion + " (" + $setuplocation.CurrentVersion + ")"
				
				$AgentURDLL = Get-Item "$($setuplocation.InstallDirectory)`..\Agent\Tools\TMF\OMAgentTraceTMFVer.Dll" -ErrorAction SilentlyContinue | foreach-object { "{0}" -f [System.Diagnostics.FileVersionInfo]::GetVersionInfo($_).FileVersion }
				[string]$SCOMAgentURVersionDLL = (Get-ProductVersion -Product SCOM -BuildVersion $AgentURDLL)
				$SCOMAgentVersionDLL = $SCOMAgentURVersionDLL + " (" + $AgentURDLL + ")"
			}
			elseif ($Gateway)
			{
				$GatewayDLL = Get-Item "$($setuplocation.InstallDirectory)`..\Gateway\MOMAgentManagement.dll" | foreach-object { "{0}" -f [System.Diagnostics.FileVersionInfo]::GetVersionInfo($_).FileVersion }
			}
			
			#Author: Blake Drumm (blakedrumm@microsoft.com)
			#Date Created: August 10th, 2022
			
			# This returns information almost identical to the Task Manager
			
			function Resource-Info
			{
				$CPUInfo = (Get-CIMInstance -ErrorAction Stop -Class 'CIM_Processor')
				$ComputerSystem = (Get-CIMInstance -ErrorAction Stop 'CIM_ComputerSystem')
				"Computer Manufacturer: $($ComputerSystem.Manufacturer)"
				"  Computer Model     : $($ComputerSystem.Model)"
				"  System Type        : $($ComputerSystem.SystemType)"
				
				" "
				
				"CPU Name: $($CPUInfo.Name)"
				"  CPU Load                    : $(($CPUInfo | Measure-Object -Property LoadPercentage -Average).Average)%"
				"  CPU Sockets                 : $(($CPUInfo.SocketDesignation).Count)"
				"  Number of Cores             : $($CPUInfo.NumberOfCores)"
				"  Number of Logical Processors: $($CPUInfo.NumberOfLogicalProcessors)"
				"  Virtualization              : $(
					$HypervisorPresent = switch (($ComputerSystem).HypervisorPresent)
					{
						True{ 'Enabled' }; False{ 'Disabled' }
					}
					if ($HypervisorPresent -eq 'Disabled')
					{
						if ($CPUInfo.VirtualizationFirmwareEnabled)
						{
							switch ($CPUInfo.VirtualizationFirmwareEnabled)
							{
								True{ 'Enabled' }; False{ 'Disabled' }
							}
						}
						else
						{
							$HypervisorPresent
						}
					}
					else
					{
						$HypervisorPresent
					}
				)"
				
				" "
				
				$MemoryInfo = (Get-CIMInstance -ErrorAction Stop -Class 'CIM_PhysicalMemory')
				"Total Memory: $(($MemoryInfo | Measure-Object -Property capacity -Sum).sum / 1gb) GB"
				$MemorySlotInfo = (Get-CIMInstance -ErrorAction Stop -Class 'Win32_PhysicalMemoryArray')
				"  Memory Slots      : $($MemoryInfo.Count) of $($MemorySlotInfo.MemoryDevices) used"
				$OSInfo = Get-CIMInstance -ErrorAction Stop -Class CIM_OperatingSystem
				"  Memory Utilization: $([math]::Round(($OSInfo.TotalVisibleMemorySize - $OSInfo.FreePhysicalMemory) / 1mb, 1)) GB / $([math]::Round($OSInfo.TotalVisibleMemorySize / 1mb, 1)) GB ($([math]::Round(((($OSInfo.TotalVisibleMemorySize - $OSInfo.FreePhysicalMemory) * 100)/ $OSInfo.TotalVisibleMemorySize), 0))%)"
				" "
				"  Memory Sockets:"
				$i = 0
				foreach ($memory in $MemoryInfo)
				{
					$i++
					$i = $i
					"      $i)     Name: $($memory.Name)"
					"             Type: $(
						switch ($memory.MemoryType)
						{
							0{ 'Unknown' }
							1{ 'Other' }
							2{ 'DRAM' }
							3{ 'Synchronous DRAM' }
							4{ 'Cache DRAM' }
							5{ 'EDO' }
							6{ 'EDRAM' }
							7{ 'VRAM' }
							8{ 'SRAM' }
							9{ 'RAM' }
							10{ 'ROM' }
							11{ 'Flash' }
							12{ 'EEPROM' }
							13{ 'FEPROM' }
							14{ 'EPROM' }
							15{ 'CDRAM' }
							16{ '3DRAM' }
							17{ 'SDRAM' }
							18{ 'SGRAM' }
							19{ 'RDRAM' }
							20{ 'DDR' }
							21{ 'DDR2' }
							22{ 'DDR2 FB-DIMM' }
							24{ 'DDR3' }
							25{ 'FBD2' }
							26{ 'DDR4' }
							default { 'Unknown' }
						})"
					"      Memory Size: $($memory.Capacity / 1gb) GB"
					"      Form Factor: $(
						switch ($memory.FormFactor)
						{
							0{ 'Unknown' }
							1{ 'Other' }
							2{ 'SIP' }
							3{ 'DIP' }
							4{ 'ZIP' }
							5{ 'SOJ' }
							6{ 'Proprietary' }
							7{ 'SIMM' }
							8{ 'DIMM' }
							9{ 'TSOP' }
							10{ 'PGA' }
							11{ 'RIMM' }
							12{ 'SODIMM' }
							13{ 'SRIMM' }
							14{ 'SMD' }
							15{ 'SSMP' }
							16{ 'QFP' }
							17{ 'TQFP' }
							18{ 'SOIC' }
							19{ 'LCC' }
							20{ 'PLCC' }
							21{ 'BGA' }
							22{ 'FPBGA' }
							23{ 'LGA' }
							24{ 'FB-DIMM' }
							default { 'Unknown' }
						})"
					"     Memory Speed: $($memory.ConfiguredClockSpeed) MHz"
					" "
					return
				}
			}
			$ResourceAllocation = try { Resource-Info | Out-String -Width 4096 }catch{ 'Unable to gather OS Resource Information.' }
			
			$setupOutput = [pscustomobject]@{ }
			$setupOutput | Add-Member -MemberType NoteProperty -Name 'Computer Name' -Value $env:COMPUTERNAME
			if ($Uptime)
			{
				$setupOutput | Add-Member -MemberType NoteProperty -Name 'System Uptime' -Value $Uptime
			}
			if ($WorkflowCount)
			{
				$setupOutput | Add-Member -MemberType NoteProperty -Name 'Workflow Count' -Value $WorkflowCount
			}
			
			$setupOutput | Add-Member -MemberType NoteProperty -Name 'IP Address' -Value $IPList
			$setupOutput | Add-Member -MemberType NoteProperty -Name 'OS Version' -Value $OSVersion
			$setupOutput | Add-Member -MemberType NoteProperty -Name 'WinHTTP Proxy' -Value $WinHTTPProxy
			$setupOutput | Add-Member -MemberType NoteProperty -Name 'Resource Information' -Value $ResourceAllocation
			if ($setuplocation)
			{
				if ($setuplocation.ManagementServerPort)
				{
					$setupOutput | Add-Member -MemberType NoteProperty -Name 'Management Server Port' -Value $setuplocation.ManagementServerPort
				}
				$setupOutput | Add-Member -MemberType NoteProperty -Name 'Product' -Value $setuplocation.Product
				$setupOutput | Add-Member -MemberType NoteProperty -Name 'Installed On' -Value $setuplocation.InstalledOn
			}
			if ($ACS)
			{
				$setupOutput | Add-Member -MemberType NoteProperty -Name 'ACS Collector' -Value 'True'
			}
			else
			{
				$setupOutput | Add-Member -MemberType NoteProperty -Name 'ACS Collector' -Value 'False'
			}
			if ($SCOMAgentVersion)
			{
				$setupOutput | Add-Member -MemberType NoteProperty -Name 'Current Agent Version (Registry: HKLM:\SOFTWARE\Microsoft\Microsoft Operations Manager\3.0\Setup)' -Value $SCOMAgentVersion
				$setupOutput | Add-Member -MemberType NoteProperty -Name 'Current Agent Version (DLL: ..\Agent\Tools\TMF\OMAgentTraceTMFVer.Dll)' -Value $SCOMAgentVersionDLL
			}
			if ($CurrentVersionFinal)
			{
				$setupOutput | Add-Member -MemberType NoteProperty -Name 'Current Version (Registry: HKLM:\SOFTWARE\Microsoft\Microsoft Operations Manager\3.0\Setup)' -Value $CurrentVersionFinal
			}
			if ($LocalServerVersionSwitchOut)
			{
				$setupOutput | Add-Member -MemberType NoteProperty -Name 'Server Version (Registry: HKLM:\SOFTWARE\Microsoft\Microsoft Operations Manager\3.0\Setup)' -Value $LocalServerVersionSwitchOut
				$setupOutput | Add-Member -MemberType NoteProperty -Name '               (DLL: ..\Server\MOMAgentManagement.dll)' -Value $ServerVersionDLL
			}
			if ('10.19.10552.0' -eq $OctoberPatchserverDLL)
			{
				$setupOutput | Add-Member -MemberType NoteProperty -Name 'Server Version [Patch] (DLL: ..\Server\MOMModules2.dll)' -Value $OctoberPatchserver
			}
			if ($ServerAgentVersion_info)
			{
				$setupOutput | Add-Member -MemberType NoteProperty -Name 'Agent Management Windows Version (DLL: ..\Server\AgentManagement\amd64\OMVersion.dll)' -Value $ServerAgentVersionDLL
				$setupOutput | Add-Member -MemberType NoteProperty -Name 'Agent Management Unix/Linux Versions (Files: ..\Server\AgentManagement\UnixAgents\DownloadedKits\*)' -Value $ServerAgentUnixVersionDLL
			}
			
			if ($UI_info)
			{
				$setupOutput | Add-Member -MemberType NoteProperty -Name 'UI Version (Registry: HKLM:\SOFTWARE\Microsoft\Microsoft Operations Manager\3.0\Setup)' -Value $UIVersionFinal
				$setupOutput | Add-Member -MemberType NoteProperty -Name '           (EXE: ..\Console\Microsoft.EnterpriseManagement.Monitoring.Console.exe)' -Value $UIVersionExe
			}
			if ($WebConsole_info)
			{
				$setupOutput | Add-Member -MemberType NoteProperty -Name "Web Console Version (DLL: $WebConsolePatchPath)" -Value $WebConsoleVersionDLL
				if ('10.19.10550.0' -eq $WebConsolePatchDLL)
				{
					$setupOutput | Add-Member -MemberType NoteProperty -Name "Web Console Version [Patch] (DLL: $WebConsolePatchPath)" -Value $WebConsolePatchVersionDLL
				}
			}
			if ($LocalManagementServer)
			{
				$setupOutput | Add-Member -MemberType NoteProperty -Name 'Operations Manager DB Version (Query)' -Value $SQLPatchVersionOpsDBInfo
				$setupOutput | Add-Member -MemberType NoteProperty -Name 'Data Warehouse DB Version (Query)' -Value $SQLPatchVersionDWInfo
			}
			if ($ManagementServer)
			{
				if ($LinuxAuthType)
				{
					$setupOutput | Add-Member -MemberType NoteProperty -Name 'Linux Authentication Type (Registry: HKLM:\SOFTWARE\Microsoft\Microsoft Operations Manager\3.0\Setup\Linux Auth)' -Value $LinuxAuthType
				}
				else
				{
					$setupOutput | Add-Member -MemberType NoteProperty -Name 'Linux Authentication Type (Registry: HKLM:\SOFTWARE\Microsoft\Microsoft Operations Manager\3.0\Setup\Linux Auth)' -Value 'Missing Registry Key, assuming: Basic'
				}
			}
			if ($ADIntegrationSwitch)
			{
				$setupOutput | Add-Member -MemberType NoteProperty -Name 'AD Integration' -Value $ADIntegrationSwitch
			}
			
			if ($setuplocation)
			{
				$setupOutput | Add-Member -MemberType NoteProperty -Name 'Installation Directory' -Value $setuplocation.InstallDirectory
			}
			if ($MGDetails)
			{
				$setupOutput | Add-Member -MemberType NoteProperty -Name '(Agent) Management Group Details' -Value ($MGDetails | Format-List * | Out-String -Width 4096)
			}
			elseif ($MGlist)
			{
				$setupOutput | Add-Member -MemberType NoteProperty -Name '(Agent) Management Group Name' -Value $MGlist
			}
			elseif ($ManagementGroup)
			{
				$setupOutput | Add-Member -MemberType NoteProperty -Name '(Management Server) Management Group Name' -Value $ManagementGroup
			}
			if ($ManagementServers)
			{
				$setupOutput | Add-Member -MemberType NoteProperty -Name 'Management Servers in Management Group' -Value (($ManagementServers | Sort-Object) -join ", ")
			}
			if ($OMSList)
			{
				$setupOutput | Add-Member -MemberType NoteProperty -Name 'Agent OMS Workspaces' -Value $OMSList
			}
			if ($ProxyURL)
			{
				$setupOutput | Add-Member -MemberType NoteProperty -Name 'Proxy URL' -Value $ProxyURL
			}
			
			if ($rmsEmulator)
			{
				$setupOutput | Add-Member -MemberType NoteProperty -Name 'Remote Management Server Emulator (Primary Server)' -Value "$rmsEmulator"
			}
			if ($Freespace)
			{
				$setupOutput | Add-Member -MemberType NoteProperty -Name 'Free Space' -Value $($Freespace | Format-Table * -AutoSize | Out-String)
			}
			
			if ($driveData)
			{
				$setupOutput | Add-Member -MemberType NoteProperty -Name 'Disk Allocation Unit Size' -Value $($driveData | Format-Table * -AutoSize | Out-String -Width 4096)
			}
			if ($CertLoaded)
			{
				$setupOutput | Add-Member -MemberType NoteProperty -Name 'Certificate Loaded' -Value $CertLoaded
			}
			else
			{
				$setupOutput | Add-Member -MemberType NoteProperty -Name 'Certificate Loaded' -Value 'Unable to detect any certificate in registry.'
			}
			$setupOutput | Add-Member -MemberType NoteProperty -Name 'TLS 1.2 Enforced' -Value $TLS12Enforced
			$setupOutput | Add-Member -MemberType NoteProperty -Name 'Powershell Version' -Value $PSVersion
			$setupOutput | Add-Member -MemberType NoteProperty -Name 'CLR Version' -Value $CLRVersion
			if ($dotNetVersionString)
			{
				$setupOutput | Add-Member -MemberType NoteProperty -Name '.NET Version' -Value $dotNetVersionString
			}
			if ($PowershellGPOs)
			{
				$setupOutput | Add-Member -MemberType NoteProperty -Name 'Powershell Group Policy' -Value $PowershellGPOs
			}
			if ($setuplocation)
			{
				$setupOutput | Add-Member -MemberType NoteProperty -Name 'Health Service State Directory' -Value $($HSStateFolder | Format-Table * -AutoSize | Out-String -Width 4096)
			}
			if ($configUpdated)
			{
				$setupOutput | Add-Member -MemberType NoteProperty -Name 'Last Time Configuration Updated (File: ..\OpsMgrConnector.Config.xml)' -Value $($configUpdated | Format-Table -AutoSize | Out-String -Width 4096)
			}
			if ($LastUpdatedConfiguration)
			{
				$setupOutput | Add-Member -MemberType NoteProperty -Name 'Last Time Configuration Updated (1210 EventID)' -Value $LastUpdatedConfiguration
			}
			else
			{
				$setupOutput | Add-Member -MemberType NoteProperty -Name 'Last Time Configuration Updated (1210 EventID)' -Value 'Unable to locate 1210 EventID.'
			}
			$setupOutput | Add-Member -MemberType NoteProperty -Name 'Current System Time' -Value (Get-Date -Format "MMMM dd, yyyy h:mm tt")
			
			if ('7.2.11719.0' -ge $setuplocation.ServerVersion) # SCOM 2016 RTM
			{
				try { $UseMIAPI = (Get-Item 'HKLM:\SOFTWARE\Microsoft\Microsoft Operations Manager\3.0\Setup\UseMIAPI' -ErrorAction Stop | Select-Object Name, Property).Property | Out-String } # https://docs.microsoft.com/en-us/system-center/scom/whats-new-in-om?view=sc-om-2019#scalability-improvement-with-unix-or-linux-agent-monitoring
				catch [System.Management.Automation.RuntimeException]{ $UseMIAPI = 'Not Set (or Unknown)' }
				$setupOutput | Add-Member -MemberType NoteProperty -Name 'UseMIAPI Registry' -Value $UseMIAPI
			}
			try
			{
				$ReportingRegistryKey = get-itemproperty -path "HKLM:\SOFTWARE\Microsoft\System Center Operations Manager\12\Setup\Reporting" -ErrorAction SilentlyContinue | Select-Object * -exclude PSPath, PSParentPath, PSChildName, PSProvider, PSDrive
				if ($ReportingRegistryKey)
				{
					Write-Verbose "$(Time-Stamp)  Found SSRS Registry Key: $ReportingRegistryKey"
						<#
$setupOutputRemote += @"

================================ `
=---- Reporting Server ----= `
================================
"@
#>
					$ReportingInstallPath = $ReportingRegistryKey.InstallDirectory
					$ReportingDLL = Get-Item "$ReportingInstallPath`\Tools\TMF\OMTraceTMFVer.Dll" -ErrorAction Stop | foreach-object { "{0}" -f [System.Diagnostics.FileVersionInfo]::GetVersionInfo($_).FileVersion }
					$ReportingProductVersionSwitch = (Get-ProductVersion -Product SCOM -BuildVersion $ReportingDLL)
					$ReportingInfo = $ReportingProductVersionSwitch + " (" + $ReportingDLL + ")"
					$setupOutput | Add-Member -MemberType NoteProperty -Name 'Reporting Services Version (DLL: ..\Reporting\Tools\TMF\OMTraceTMFVer.dll)' -Value $ReportingInfo
					try
					{
						
						$RS = "root\Microsoft\SqlServer\ReportServer\" + (Get-CimInstance -Namespace root\Microsoft\SqlServer\ReportServer -Class __Namespace -Recurse -ErrorAction Stop | Select -First 1).Name
						$RSV = $RS + "\" + (Get-CimInstance -Namespace $RS -Class __Namespace -Recurse -ErrorAction Stop | Select -First 1).Name + "\Admin"
						$RSInfo = Get-CimInstance -Namespace $RSV -Class MSReportServer_ConfigurationSetting -ErrorAction Stop
						
						try
						{
							$RSInfoSwitch = (Get-ProductVersion -Product SSRS -BuildVersion $RSInfo.Version)
							$RSInfoSwitchInfo = $RSInfoSwitch + " (" + $RSInfo.Version + ")"
						}
						catch
						{
							$RSInfoSwitchInfo = "Unable to detect / return Product version for SSRS"
							Write-Verbose "$(Time-Stamp)Unable to detect / return Product version for SSRS: $($error[0])"
						}
						
						$SSRS_Info = [pscustomobject]@{ }
						$SSRS_Info | Add-Member -MemberType NoteProperty -Name 'ConnectionPoolSize' -Value $RSInfo.ConnectionPoolSize -ErrorAction SilentlyContinue
						$SSRS_Info | Add-Member -MemberType NoteProperty -Name 'DatabaseLogonAccount' -Value $RSInfo.DatabaseLogonAccount -ErrorAction SilentlyContinue
						$SSRS_Info | Add-Member -MemberType NoteProperty -Name 'DatabaseLogonTimeout' -Value $RSInfo.DatabaseLogonTimeout -ErrorAction SilentlyContinue
						$SSRS_Info | Add-Member -MemberType NoteProperty -Name 'DatabaseLogonType' -Value $RSInfo.DatabaseLogonType -ErrorAction SilentlyContinue
						$SSRS_Info | Add-Member -MemberType NoteProperty -Name 'DatabaseName' -Value $RSInfo.DatabaseName -ErrorAction SilentlyContinue
						$SSRS_Info | Add-Member -MemberType NoteProperty -Name 'DatabaseQueryTimeout' -Value $RSInfo.DatabaseQueryTimeout -ErrorAction SilentlyContinue
						$SSRS_Info | Add-Member -MemberType NoteProperty -Name 'ExtendedProtectionLevel' -Value $RSInfo.ExtendedProtectionLevel -ErrorAction SilentlyContinue
						$SSRS_Info | Add-Member -MemberType NoteProperty -Name 'ExtendedProtectionScenario' -Value $RSInfo.ExtendedProtectionScenario -ErrorAction SilentlyContinue
						$SSRS_Info | Add-Member -MemberType NoteProperty -Name 'FileShareAccount' -Value $RSInfo.FileShareAccount -ErrorAction SilentlyContinue
						$SSRS_Info | Add-Member -MemberType NoteProperty -Name 'InstanceName' -Value $RSInfo.InstanceName -ErrorAction SilentlyContinue
						$SSRS_Info | Add-Member -MemberType NoteProperty -Name 'IsInitialized' -Value $RSInfo.IsInitialized -ErrorAction SilentlyContinue
						$SSRS_Info | Add-Member -MemberType NoteProperty -Name 'IsPowerBIFeatureEnabled' -Value $RSInfo.IsPowerBIFeatureEnabled -ErrorAction SilentlyContinue
						$SSRS_Info | Add-Member -MemberType NoteProperty -Name 'IsReportManagerEnabled' -Value $RSInfo.IsReportManagerEnabled -ErrorAction SilentlyContinue
						$SSRS_Info | Add-Member -MemberType NoteProperty -Name 'IsSharePointIntegrated' -Value $RSInfo.IsSharePointIntegrated -ErrorAction SilentlyContinue
						$SSRS_Info | Add-Member -MemberType NoteProperty -Name 'IsWebServiceEnabled' -Value $RSInfo.IsWebServiceEnabled -ErrorAction SilentlyContinue
						$SSRS_Info | Add-Member -MemberType NoteProperty -Name 'IsWindowsServiceEnabled' -Value $RSInfo.IsWindowsServiceEnabled -ErrorAction SilentlyContinue
						$SSRS_Info | Add-Member -MemberType NoteProperty -Name 'MachineAccountIdentity' -Value $RSInfo.MachineAccountIdentity -ErrorAction SilentlyContinue
						$SSRS_Info | Add-Member -MemberType NoteProperty -Name 'PathName' -Value $RSInfo.PathName -ErrorAction SilentlyContinue
						$SSRS_Info | Add-Member -MemberType NoteProperty -Name 'SecureConnectionLevel' -Value $RSInfo.SecureConnectionLevel -ErrorAction SilentlyContinue
						$SSRS_Info | Add-Member -MemberType NoteProperty -Name 'ServiceName' -Value $RSInfo.ServiceName -ErrorAction SilentlyContinue
						$SSRS_Info | Add-Member -MemberType NoteProperty -Name 'UnattendedExecutionAccount' -Value $RSInfo.UnattendedExecutionAccount -ErrorAction SilentlyContinue
						$SSRS_Info | Add-Member -MemberType NoteProperty -Name 'Version' -Value $RSInfoSwitchInfo -ErrorAction SilentlyContinue
						$SSRS_Info | Add-Member -MemberType NoteProperty -Name 'VirtualDirectoryReportManager' -Value $RSInfo.VirtualDirectoryReportManager -ErrorAction SilentlyContinue
						$SSRS_Info | Add-Member -MemberType NoteProperty -Name 'VirtualDirectoryReportServer' -Value $RSInfo.VirtualDirectoryReportServer -ErrorAction SilentlyContinue
						$SSRS_Info | Add-Member -MemberType NoteProperty -Name 'WindowsServiceIdentityActual' -Value $RSInfo.WindowsServiceIdentityActual -ErrorAction SilentlyContinue
						$SSRS_Info | Add-Member -MemberType NoteProperty -Name 'WindowsServiceIdentityConfigured' -Value $RSInfo.WindowsServiceIdentityConfigured -ErrorAction SilentlyContinue
						$SSRS_Info | Add-Member -MemberType NoteProperty -Name ' ' -Value ' ' -ErrorAction SilentlyContinue
						$setupOutput | Add-Member -MemberType NoteProperty -Name 'Reporting Services Information' -Value ($SSRS_Info | Format-List * | Out-String -Width 4096)
					}
					catch
					{
						#potential error code
						#use continue or break keywords
						$e = $_.Exception
						$line = $_.InvocationInfo.ScriptLineNumber
						$msg = $e.Message
						
						Write-Verbose "$(Time-Stamp)Caught Exception during Reporting Services gathering: $e :: Message: $msg :: at line: $line"
						"$(Time-Stamp)Caught Exception during Reporting Services gathering: $e :: Message: $msg :: at line: $line" | Out-File $OutputPath\Error.log -Append
					}
				}
			}
			catch
			{
				#potential error code
				#use continue or break keywords
				$e = $_.Exception
				$line = $_.InvocationInfo.ScriptLineNumber
				$msg = $e.Message
				
				Write-Verbose "$(Time-Stamp)Caught Exception during Reporting Services gathering: $e :: Message: $msg :: at line: $line"
				"$(Time-Stamp)Caught Exception during Reporting Services gathering: $e :: Message: $msg :: at line: $line" | Out-File $OutputPath\Error.log -Append
			}
			if ($w32tmQueryStatus)
			{
				$setupOutput | Add-Member -MemberType NoteProperty -Name 'w32tm Query Status' -Value ($w32tmQueryStatus | Out-String -Width 4096)
			}
			$setupOutput | Add-Member -MemberType NoteProperty -Name 'Services' -Value $localServices
			Write-Verbose "Completed Inner-GeneralInformation Function : `n$setupOutput"
			return $setupOutput
		}
		#End Inner General Info
		trap
		{
			#potential error code
			#use continue or break keywords
			$e = $_.Exception
			$line = $_.InvocationInfo.ScriptLineNumber
			$msg = $e.Message
			Write-Host "Caught Exception: $e at line: $line" -ForegroundColor Red
			"$(Time-Stamp)Caught Exception: $e at line: $line" | Out-File $OutputPath\Error.log -Append
		}
		if ($server -match "^$env:COMPUTERNAME") # If server equals Local Computer
		{
			$localServicesList = (Get-CimInstance Win32_service).where{ $_.name -eq 'omsdk' -or $_.name -eq 'cshost' -or $_.name -eq 'HealthService' -or $_.name -eq 'System Center Management APM' -or $_.name -eq 'AdtAgent' -or $_.name -match "^SQL" -or $_.name -match "MSSQL" -or $_.name -like "SQLAgent*" -or $_.name -eq 'SQLBrowser' -or $_.name -eq 'SQLServerReportingServices' }
			$localServicesList | % {
				[PSCustomObject]@{
					ComputerName	   = $server
					ServiceDisplayName = $_.DisplayName
					ServiceName	       = $_.Name
					AccountName	       = $_.StartName
					StartMode		   = $_.StartMode
					CurrentState	   = $_.State
				}
			} | Sort-Object ServiceName | Export-Csv "$OutputPath`\OS_Services.csv" -NoTypeInformation -Append
			$GeneralInfoGather = Inner-GeneralInfoFunction -LocalManagementServer
			@"
======================================
=---- Local General Information  ----=
======================================
"@ | Out-File -FilePath "$OutputPath\General Information.txt" -Append -Width 4096
			$GeneralInfoGather | Out-File -FilePath "$OutputPath\General Information.txt" -Append -Width 4096
		}
		else
		{
			$InnerGeneralInfoFunctionScript = "function Inner-GeneralInfoFunction { ${function:Inner-GeneralInfoFunction} }"
			$ProductVersionScript = "function Get-ProductVersion { ${function:Get-ProductVersion} }"
			$GeneralInfoGather = Invoke-Command -ComputerName $server -ArgumentList $InnerGeneralInfoFunctionScript, $ProductVersionScript, $VerbosePreference -ScriptBlock {
				Param ($script,
					$versionscript,
					$VerbosePreference)
				. ([ScriptBlock]::Create($script))
				. ([ScriptBlock]::Create($versionscript))
				if ($VerbosePreference -eq 'continue')
				{
					Inner-GeneralInfoFunction -Verbose
				}
				else
				{
					Inner-GeneralInfoFunction
				}
				
			}
			$ServicesList = (Get-CimInstance Win32_service -ComputerName $server).where{ $_.name -eq 'omsdk' -or $_.name -eq 'cshost' -or $_.name -eq 'HealthService' -or $_.name -eq 'System Center Management APM' -or $_.name -eq 'AdtAgent' -or $_.name -match "MSSQL" -or $_.name -like "SQLAgent*" -or $_.name -eq 'SQLBrowser' -or $_.name -eq 'SQLServerReportingServices' }
			$ServicesList | % {
				[PSCustomObject]@{
					ComputerName	   = $server
					ServiceDisplayName = $_.DisplayName
					ServiceName	       = $_.Name
					AccountName	       = $_.StartName
					StartMode		   = $_.StartMode
					CurrentState	   = $_.State
				}
			} | Sort-Object ServiceName | Export-Csv "$OutputPath`\OS_Services.csv" -NoTypeInformation -Append
			@"
========================================
=----- Remote General Information -----=
========================================
"@ | Out-File -FilePath "$OutputPath\General Information.txt" -Append -Width 4096
			$GeneralInfoGather | select * -ExcludeProperty PSComputerName, RunspaceId | Out-String -Width 4096 | Out-File -FilePath "$OutputPath\General Information.txt" -Append
		}
	}
	Write-Progress -Activity "Collection Running" -Status "Progress-> 76%" -PercentComplete 76
	@"
================================
=---- Database Information ----=
================================
"@ | Out-File -FilePath "$OutputPath\General Information.txt" -Append -Width 4096
	try
	{
		$OMSQLPropertiesImport = Import-Csv "$OutputPath`\SQL_Properties_OpsDB.csv"
		try { $OMSQLOwnerImport = Import-Csv "$OutputPath`\SQL_DBOwner_OpsDB.csv" }
		catch { "$(Time-Stamp)Caught Exception: $e at line: $line" | Out-File $OutputPath\Error.log -Append }
		##########################################
		#########################################
		#####################################
		################################
		$OMSQLVersionSwitch = (Get-ProductVersion -Product SQL -BuildVersion $OMSQLPropertiesImport.ProductVersion)
		$OMSQLProperties = $OMSQLVersionSwitch + "`n(" + ($OMSQLPropertiesImport).ProductVersion + ") -" + " (" + ($OMSQLPropertiesImport).ProductLevel + ")" + " - " + ($OMSQLPropertiesImport).Edition + " - " + ($OMSQLPropertiesImport).Version
		if ($OMSQLOwnerImport)
		{
			$OMSQLProperties = $OMSQLProperties + "`n" + "[DB Owner: $($OMSQLOwnerImport.Owner)]"
		}
		if ('True' -eq $OMSQLPropertiesImport.IsClustered)
		{
			$OMSQLProperties = $OMSQLProperties + "`n" + "[Clustered]"
		}
		else
		{
			$OMSQLProperties = $OMSQLProperties + "`n" + "[Not Clustered]"
		}
		try
		{
			if ('True' -eq $OMSQLPropertiesImport.Is_Broker_Enabled)
			{
				$OMSQLProperties = $OMSQLProperties + "`n" + "[Broker Enabled]"
			}
			else
			{
				$OMSQLProperties = $OMSQLProperties + "`n" + "[Broker Not Enabled]"
			}
		}
		catch
		{
			$OMSQLProperties = $OMSQLProperties + "`n" + "[Broker Not Found or Disabled]"
		}
		try
		{
			if ('True' -eq $OMSQLPropertiesImport.Is_CLR_Enabled)
			{
				$OMSQLProperties = $OMSQLProperties + "`n" + "[CLR Enabled]"
			}
			else
			{
				$OMSQLProperties = $OMSQLProperties + "`n" + "[CLR Not Enabled]"
			}
		}
		catch
		{
			$OMSQLProperties = $OMSQLProperties + "`n" + "[CLR Not Found or Disabled]"
		}
		if ('True' -eq $OMSQLPropertiesImport.IsFullTextInstalled)
		{
			$OMSQLProperties = $OMSQLProperties + "`n" + "[FullText Installed]"
		}
		else
		{
			$OMSQLProperties = $OMSQLProperties + "`n" + "[FullText Not Installed]"
		}
		try
		{
			if ('True' -eq $OMSQLPropertiesImport.Is_AlwaysOn_Enabled)
			{
				$OMSQLProperties = $OMSQLProperties + "`n" + "[Always On Enabled]"
			}
			else
			{
				$OMSQLProperties = $OMSQLProperties + "`n" + "[Always On Disabled]"
			}
		}
		catch
		{
			$OMSQLProperties = $OMSQLProperties + "`n" + "[Always On Not Found or Disabled]"
		}
		if ($OMSQLPropertiesImport.Collation -notmatch "SQL_Latin1_General_CP1_CI_AS|Latin1_General_CI_AS|Latin1_General_100_CI_AS|French_CI_AS|French_100_CI_AS|Cyrillic_General_CI_AS|Chinese_PRC_CI_AS|Chinese_Simplified_Pinyin_100_CI_AS|Chinese_Traditional_Stroke_Count_100_CI_AS|Japanese_CI_ASJapanese_XJIS_100_CI_AS|Traditional_Spanish_CI_AS|Modern_Spanish_100_CI_AS|Latin1_General_CI_AS|Cyrillic_General_100_CI_AS|Korean_100_CI_AS|Czech_100_CI_AS|Hungarian_100_CI_AS|Polish_100_CI_AS|Finnish_Swedish_100_CI_AS")
		{
			$OMSQLProperties = $OMSQLProperties + "`n" + "(ISSUE: " + $OMSQLPropertiesImport.Collation + ") <------------ Correct the Collation to a supported one: https://docs.microsoft.com/system-center/scom/plan-sqlserver-design#sql-server-collation-setting"
		}
		$OMSQLProperties = $OMSQLProperties + "`n"
	}
	catch
	{
		
		#potential error code
		#use continue or break keywords
		#$e = $_.Exception
		$line = $_.InvocationInfo.ScriptLineNumber
		$msg = $e.Message
		
		Write-Verbose "Caught Exception: $($error[0]) at line: $line"
		"$(Time-Stamp)Caught Exception: $($error[0]) at line: $line" | Out-File $OutputPath\Error.log -Append
	}
	Write-Host "-" -NoNewline -ForegroundColor Green
	try
	{
		$DWSQLPropertiesImport = Import-Csv "$OutputPath`\SQL_Properties_DW.csv"
		try { $DWSQLOwnerImport = Import-Csv "$OutputPath`\SQL_DBOwner_DW.csv" }
		catch { "$(Time-Stamp)Caught Exception: $e at line: $line" | Out-File $OutputPath\Error.log -Append }
		##########################################
		#########################################
		#####################################
		################################
		$DWSQLVersionSwitch = (Get-ProductVersion -Product SQL -BuildVersion $DWSQLPropertiesImport.ProductVersion)
		$DWSQLProperties = $DWSQLVersionSwitch + "`n(" + ($DWSQLPropertiesImport).ProductVersion + ") - (" + ($DWSQLPropertiesImport).ProductLevel + ") - " + ($DWSQLPropertiesImport).Edition + " - " + ($DWSQLPropertiesImport).Version
		if ($DWSQLOwnerImport)
		{
			$DWSQLProperties = $DWSQLProperties + "`n" + "[DB Owner: $($DWSQLOwnerImport.Owner)]"
		}
		if ('True' -eq $DWSQLPropertiesImport.IsClustered)
		{
			$DWSQLProperties = $DWSQLProperties + "`n" + "[Clustered]"
		}
		else
		{
			$DWSQLProperties = $DWSQLProperties + "`n" + "[Not Clustered]"
		}
		try
		{
			if ('True' -eq $DWSQLPropertiesImport.Is_Broker_Enabled)
			{
				$DWSQLProperties = $DWSQLProperties + "`n" + "[Broker Enabled]"
			}
			else
			{
				$DWSQLProperties = $DWSQLProperties + "`n" + "[Broker Not Enabled]"
			}
		}
		catch
		{
			$DWSQLProperties = $DWSQLProperties + "`n" + "[Broker Not Found or Disabled]"
		}
		if ('True' -eq $DWSQLPropertiesImport.IsFullTextInstalled)
		{
			$DWSQLProperties = $DWSQLProperties + "`n" + "[FullText Installed]"
		}
		else
		{
			$DWSQLProperties = $DWSQLProperties + "`n" + "[FullText Not Installed]"
		}
		try
		{
			if ('True' -eq $DWSQLPropertiesImport.Is_AlwaysOn_Enabled)
			{
				$DWSQLProperties = $DWSQLProperties + "`n" + "[Always On Enabled]"
			}
			else
			{
				$DWSQLProperties = $DWSQLProperties + "`n" + "[Always On Disabled]"
			}
		}
		catch
		{
			$DWSQLProperties = $DWSQLProperties + "`n" + "[Always On Not Found or Disabled]"
		}
		if ($DWSQLPropertiesImport.Collation -notmatch "SQL_Latin1_General_CP1_CI_AS|Latin1_General_CI_AS|Latin1_General_100_CI_AS|French_CI_AS|French_100_CI_AS|Cyrillic_General_CI_AS|Chinese_PRC_CI_AS|Chinese_Simplified_Pinyin_100_CI_AS|Chinese_Traditional_Stroke_Count_100_CI_AS|Japanese_CI_ASJapanese_XJIS_100_CI_AS|Traditional_Spanish_CI_AS|Modern_Spanish_100_CI_AS|Latin1_General_CI_AS|Cyrillic_General_100_CI_AS|Korean_100_CI_AS|Czech_100_CI_AS|Hungarian_100_CI_AS|Polish_100_CI_AS|Finnish_Swedish_100_CI_AS")
		{
			$DWSQLProperties = $DWSQLProperties + "`n" + "(ISSUE: " + $DWSQLPropertiesImport.Collation + ") <------------ Update the Collation to a supported one: https://docs.microsoft.com/system-center/scom/plan-sqlserver-design#sql-server-collation-setting"
		}
	}
	catch
	{
		#potential error code
		#use continue or break keywords
		#$e = $_.Exception
		$line = $_.InvocationInfo.ScriptLineNumber
		$msg = $e.Message
		
		Write-Verbose "Caught Exception: $($error[0]) at line: $line"
		"$(Time-Stamp)Caught Exception: $($error[0]) at line: $line" | Out-File $OutputPath\Error.log -Append
	}
	try
	{
		Add-Type -TypeDefinition @"
public class OpsMgrSetupRegKey{
    public string CurrentVersion;
    public string DatabaseName;
    public string DatabaseServerName;
    public string DatabaseVersion;
    public string DataWarehouseDBName;
    public string DataWarehouseDBServerName;
    public string InstallDirectory;
    public string InstalledOn;
    public string ManagementServerPort;
    public string Product;
    public string ServerVersion;
    public string UIVersion;
}
"@
		
		# this is the path we want to retrieve the values from
		$opsMgrSetupRegKeyPath = 'HKLM:\SOFTWARE\Microsoft\Microsoft Operations Manager\3.0\Setup'
		
		# get the values
		try
		{
			$opsMgrSetupRegKey = Get-ItemProperty -Path $opsMgrSetupRegKeyPath -ErrorAction Stop
			
			# construct a new object
			$setuplocation = New-Object OpsMgrSetupRegKey
			
			#set the object values from the registry key
			$setuplocation.CurrentVersion = $opsMgrSetupRegKey.CurrentVersion
			$setuplocation.DatabaseName = $opsMgrSetupRegKey.DatabaseName
			$setuplocation.DatabaseServerName = $opsMgrSetupRegKey.DatabaseServerName
			$setuplocation.DatabaseVersion = $opsMgrSetupRegKey.DatabaseVersion
			$setuplocation.DataWarehouseDBName = $opsMgrSetupRegKey.DataWarehouseDBName
			$setuplocation.DataWarehouseDBServerName = $opsMgrSetupRegKey.DataWarehouseDBServerName
			$setuplocation.InstallDirectory = $opsMgrSetupRegKey.InstallDirectory
			$setuplocation.InstalledOn = $opsMgrSetupRegKey.InstalledOn
			$setuplocation.ManagementServerPort = $opsMgrSetupRegKey.ManagementServerPort
			$setuplocation.Product = $opsMgrSetupRegKey.Product
			$setuplocation.ServerVersion = $opsMgrSetupRegKey.ServerVersion
			$setuplocation.UIVersion = $opsMgrSetupRegKey.UIVersion
		}
		catch
		{
			$setuplocation = $null
		}
		$dbOutput = [pscustomobject]@{ }
		$dbOutput | Add-Member -MemberType NoteProperty -Name 'Operations Manager DB Server Name' -Value $setuplocation.DatabaseServerName -ErrorAction SilentlyContinue
		$dbOutput | Add-Member -MemberType NoteProperty -Name 'Operations Manager DB Name' -Value $setuplocation.DatabaseName -ErrorAction SilentlyContinue
		try
		{
			$dbOutput | Add-Member -MemberType NoteProperty -Name 'Operations Manager SQL Properties' -Value $OMSQLProperties -ErrorAction SilentlyContinue
		}
		catch
		{
			$dbOutput | Add-Member -MemberType NoteProperty -Name 'Operations Manager SQL Properties' -Value 'Unable to locate the file needed for this data. Typically this is due to permissions.' -ErrorAction SilentlyContinue
		}
		$dbOutput | Add-Member -MemberType NoteProperty -Name 'Data Warehouse DB Server Name' -Value $setuplocation.DataWarehouseDBServerName -ErrorAction SilentlyContinue
		$dbOutput | Add-Member -MemberType NoteProperty -Name 'Data Warehouse DB Name' -Value $setuplocation.DataWarehouseDBName -ErrorAction SilentlyContinue
		try
		{
			$dbOutput | Add-Member -MemberType NoteProperty -Name 'Data Warehouse SQL Properties' -Value $DWSQLProperties -ErrorAction SilentlyContinue
		}
		catch
		{
			$dbOutput | Add-Member -MemberType NoteProperty -Name 'Data Warehouse SQL Properties' -Value 'Unable to locate the file needed for this data. Typically this is due to permissions.' -ErrorAction SilentlyContinue
		}
		$foundsomething = $false
		try
		{
			$UserRolesImport = Import-Csv "$OutputPath`\UserRoles.csv"
			$UserRoles = "User Role Name" + " - " + "Is System?" + "`n----------------------------`n"
			$UserRolesImport | % {
				if ($_.IsSystem -eq $false)
				{
					$foundsomething = $true
					$UserRoles += $_.UserRoleName + " - " + $_.IsSystem + "`n"
				}
			}
			if ($foundsomething)
			{
				$dbOutput | Add-Member -MemberType NoteProperty -Name 'User Roles (Non-Default)' -Value $UserRoles
			}
		}
		catch
		{
			#potential error code
			#use continue or break keywords
			#$e = $_.Exception
			$line = $_.InvocationInfo.ScriptLineNumber
			$msg = $e.Message
			
			Write-Verbose "Caught Exception: $($error[0]) at line: $line"
			"$(Time-Stamp)Caught Exception: $($error[0]) at line: $line" | Out-File $OutputPath\Error.log -Append
		}
	}
	catch
	{
		Write-Warning $error[0]
	}
	if ($dbOutput)
	{
		$dbOutput | Out-File -FilePath "$OutputPath\General Information.txt" -Append -Width 4096
	}
	else
	{
		"Unable to locate any Data in one of the following files / registry paths:`n..\CSV\SQL_Properties_OpsDB.csv`n..\CSV\SQL_Properties_DW.csv`nHKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Microsoft Operations Manager\3.0\Setup" | Out-File -FilePath "$OutputPath\General Information.txt" -Append -Width 4096
	}
	
	Write-Progress -Activity "Collection Running" -Status "Progress-> 80%" -PercentComplete 80
	$UpdatesOutput = foreach ($Server in $Servers) { Write-Host "-" -NoNewline -ForegroundColor Green; Invoke-Command -ComputerName $Server -ScriptBlock { Get-HotFix } -ErrorAction SilentlyContinue }
	Write-Progress -Activity "Collection Running" -Status "Progress-> 82%" -PercentComplete 82
	if ($UpdatesOutput.HotfixId)
	{
		@"
================================
=----- Installed Updates  -----=
================================
"@ | Out-File -FilePath "$OutputPath\General Information.txt" -Append -Width 4096
		$UpdatesOutput | Sort InstalledOn, PSComputerName -Descending | Add-Member -MemberType AliasProperty -Name 'Computer Name' -Value PSComputerName -PassThru | Select-Object -Property 'Computer Name', Description, HotFixID, InstalledBy, InstalledOn, Caption | Format-Table * -AutoSize | Out-File -FilePath "$OutputPath\General Information.txt" -Append -Width 4096
	}
	else
	{
		@"
=================================================
=----- Unable to Detect Installed Updates  -----=
=================================================
"@ | Out-File -FilePath "$OutputPath\General Information.txt" -Append -Width 4096
	}
	
	Write-Progress -Activity "Collection Running" -Status "Progress-> 84%" -PercentComplete 84
	
	@"
======================================= 
=-- ConfigService.config File Check --= 
=======================================
"@ | Out-File -FilePath "$OutputPath\General Information.txt" -Append -Width 4096
	$localpath = (get-itemproperty -path "HKLM:\SOFTWARE\Microsoft\Microsoft Operations Manager\3.0\Setup" -ErrorAction Stop).InstallDirectory
	Write-Progress -Activity "Collection Running" -Status "Progress-> 80%" -PercentComplete 85
	foreach ($server in $ManagementServers)
	{
		Write-Host "-" -NoNewline -ForegroundColor Green
		if ($server -notmatch $env:COMPUTERNAME)
		{
			try
			{
				$remoteConfig = $null
				$remoteConfig = Invoke-Command -ComputerName $server -ScriptBlock {
					trap
					{
						#potential error code
						#use continue or break keywords
						$e = $_.Exception
						$line = $_.InvocationInfo.ScriptLineNumber
						$msg = $e.Message
						Write-Host "Caught Exception: $e at line: $line" -ForegroundColor Red
					}
					$scompath = (get-itemproperty -path "HKLM:\SOFTWARE\Microsoft\Microsoft Operations Manager\3.0\Setup" -ErrorAction Stop).InstallDirectory
					return (Get-Content -Path "$scompath`\ConfigService.config" -ErrorAction Stop)
				} -ErrorAction Stop
				$compare = Compare-Object -ReferenceObject (Get-Content -Path "$localpath`\ConfigService.config" -ErrorAction Stop) -DifferenceObject $remoteConfig -ErrorAction Stop
				
				if ($compare)
				{
					Write-Output "There are differences between : $server <-> $env:ComputerName" | Out-File -FilePath "$OutputPath\General Information.txt" -Append
				}
				else
				{
					Write-Output "Configuration Matches between : $server <-> $env:ComputerName" | Out-File -FilePath "$OutputPath\General Information.txt" -Append
				}
			}
			catch
			{
				"$(Time-Stamp)$server (Remote) - Unreachable" | Out-File $OutputPath\Error.log -Append
				Write-Output "$server (Remote) - Unreachable" | Out-File -FilePath "$OutputPath\General Information.txt" -Append
			}
		}
		else
		{
			Write-Output "$server (Source)" | Out-File -FilePath "$OutputPath\General Information.txt" -Append
		}
	}
	Write-Progress -Activity "Collection Running" -Status "Progress-> 87%" -PercentComplete 87
	
	" " | Out-File -FilePath "$OutputPath\General Information.txt" -Append
	@"
================================
=------ Clock Sync Check ------=
================================
"@ | Out-File -FilePath "$OutputPath\General Information.txt" -Append -Width 4096
	foreach ($server in $Servers)
	{
		try
		{
			Write-Progress -Activity "Collection Running" -Status "Progress-> 88%" -PercentComplete 88
			Write-Host "-" -NoNewline -ForegroundColor Green
			if ($server -ne $Comp)
			{
				try
				{
					$remoteTime = Invoke-Command -ComputerName $Server { return [System.DateTime]::UtcNow } -ErrorAction Stop
				}
				catch
				{
					Write-Output "Unable to run any commands against the Remote Server : $server" | Out-File -FilePath "$OutputPath\General Information.txt" -Append
					continue
				}
				
				$localTime = [System.DateTime]::UtcNow
				if ($remoteTime.Hour -match $localtime.Hour)
				{
					if ($remoteTime.Minute -match $localtime.Minute)
					{
						Write-Output "Time synchronized between : $server <-> $Comp" | Out-File -FilePath "$OutputPath\General Information.txt" -Append
					}
				}
				elseif (!$remoteTime)
				{
					Write-Output "Unable to check the Time of Remote Server : $server" | Out-File -FilePath "$OutputPath\General Information.txt" -Append
				}
				else
				{
					Write-Output "Time NOT synchronized between : $server <-> $Comp : Remote Time: $remoteTime - Local Time: $localTime" | Out-File -FilePath "$OutputPath\General Information.txt" -Append
				}
			}
		}
		catch { Write-Warning $_ }
	}
	Write-Progress -Activity "Collection Running" -Status "Progress-> 90%" -PercentComplete 90
	########### Gateway Stuff 
	try
	{
		$Gateways = Get-SCOMManagementServer -ErrorAction Stop | where { $_.IsGateway -eq $true }
	}
	catch
	{
		$Gateways = $false
	}
	if ($Gateways)
	{
		" " | Out-File -FilePath "$OutputPath\General Information.txt" -Append
		@"
======================================
=------- Gateway Information --------=
======================================
"@ | Out-File -FilePath "$OutputPath\General Information.txt" -Append -Width 4096
		
		$gwinfo = @()
		# Show the gateway server assignments for primary and failover 
		foreach ($Gateway in $Gateways)
		{
			try
			{
				$gwOSVersion = $null
				$gwOSVersion = (Get-SCOMClass -Name Microsoft.Windows.OperatingSystem -ErrorAction Stop | Get-SCOMClassInstance -ErrorAction Stop | select path, displayname | Where { $_.Path -match "$($Gateway.DisplayName)" }).DisplayName
			}
			catch
			{
				$gwOSVersion = 'Unable to find OS Version in SCOM.'
			}
			try
			{
				$gwAgentCount = ($Gateway | Get-SCOMAgent -ErrorAction Stop).Count
			}
			catch
			{
				$gwAgentCount = "Unable to return the Count of Agents Managed by $Gateway."
			}
			
			$gwinfo += [pscustomobject]@{
				'Gateway Name' = $Gateway.DisplayName
				'Agent Count'  = $gwAgentCount
				'Gateway Domain' = $Gateway.Domain
				'OS Version'   = $gwOSVersion
				'Action Account' = $Gateway.ActionAccountIdentity
				'IP Address'   = $Gateway.IPAddress
				'Communication Port' = $Gateway.CommunicationPort
				'AemEnabled'   = $Gateway.AemEnabled
				'Last Modified' = $Gateway.LastModified.ToString().Trim()
				'Installed On' = $Gateway.InstallTime.ToString().Trim()
				'Primary Management Server' = $Gateway.GetPrimaryManagementServer().DisplayName
				'Failover Management Servers' = $Gateway.GetFailoverManagementServers().DisplayName
				'Auto Approve Manually Installed Agents' = $Gateway.AutoApproveManuallyInstalledAgents.Value
				'Reject Manually Installed Agents' = $Gateway.RejectManuallyInstalledAgents.Value
			}
		}
		$gwinfo | Out-File -FilePath "$OutputPath\General Information.txt" -Append -Width 4096
	}
	###########
	Write-Progress -Activity "Collection Running" -Status "Progress-> 92%" -PercentComplete 92
	" " | Out-File -FilePath "$OutputPath\General Information.txt" -Append
	@"
================================
=------- Latency Check --------=
================================
"@ | Out-File -FilePath "$OutputPath\General Information.txt" -Append -Width 4096
	$OpsDBServer = $global:OpsDB_SQLServer
	$DWDBServer = $global:DW_SQLServer
	foreach ($ms in $ManagementServers) #Go Through each Management Server
	{
		$pingoutput = @()
		if ($ms -notmatch $Comp) #If not equal local
		{
			if ($OpsDBServer -notmatch $DWDBServer) #If OpsDB and DW are not the same run the below
			{
				try
				{
					Invoke-Command -ErrorAction Stop -ComputerName $ms -ScriptBlock {
						$dataoutput = @()
						try
						{
							$test = @()
							$test = (Test-Connection -ComputerName $using:OpsDBServer -Count 4 -ErrorAction Stop | measure-Object -Property ResponseTime -Average).average
							$response = @()
							$response = ($test -as [int])
							$innerdata = @()
							[string]$innerdata = "$using:ms -> $using:OpsDBServer : $response ms"
							$dataoutput += $innerdata
						}
						catch
						{
							Write-Verbose $_
						}
						try
						{
							$test = @()
							$test = (Test-Connection -ComputerName $using:DWDBServer -Count 4 -ErrorAction Stop | measure-Object -Property ResponseTime -Average).average
							$response = @()
							$response = ($test -as [int])
							$innerdata = @()
							[string]$innerdata = "$using:ms -> $using:DWDBServer : $response ms"
							$dataoutput += $innerdata
						}
						catch
						{
							Write-Verbose $_
						}
						# Run Checks Against Management Servers
						try
						{
							foreach ($mgmtserver in $using:ManagementServers)
							{
								$test = @()
								$test = (Test-Connection -ComputerName $mgmtserver -Count 4 -ErrorAction Stop | measure-Object -Property ResponseTime -Average).average
								$response = @()
								$response = ($test -as [int])
								$innerdata = @()
								[string]$innerdata = "$using:ms -> $mgmtserver : $response ms"
								$dataoutput += $innerdata
							}
						}
						catch
						{
							Write-Verbose $_
						}
						return $dataoutput
					} | Out-File -FilePath "$OutputPath\General Information.txt" -Append #end invoke
				}
				catch
				{
					"$ms is Offline or Error occurred." | Out-File -FilePath "$OutputPath\General Information.txt" -Append
				}
				
			} #end if
			else #Else run the below
			{
				try
				{
					Invoke-Command -ComputerName $ms -ErrorAction Stop -ScriptBlock {
						$pingoutput = @()
						try
						{
							$test = @()
							$test = (Test-Connection -ComputerName $using:OpsDBServer -Count 4 -ErrorAction Stop | measure-Object -Property ResponseTime -Average).average
							$response = @()
							$response = ($test -as [int])
							$innerdata = @()
							[string]$innerdata = "$using:ms -> $using:OpsDBServer : $response ms"
							$dataoutput += $innerdata
						}
						catch
						{
							Write-Verbose $_
						}
						return $dataoutput
					} | Out-File -FilePath "$OutputPath\General Information.txt" -Append -Width 4096 #end invoke
				}
				catch
				{
					"$ms is Offline or Error occurred." | Out-File -FilePath "$OutputPath\General Information.txt" -Append
				}
			} #end else
		} #end If not equal local
		else #Local Execution
		{
			if ($OpsDBServer -ne $DWDBServer)
			{
				try
				{
					$test = @()
					$test = (Test-Connection -ComputerName $OpsDBServer -Count 4 -ErrorAction Stop | measure-Object -Property ResponseTime -Average).average
					$response = @()
					$response = ($test -as [int])
					$innerdata = @()
					[string]$innerdata = "$ms -> $OpsDBServer : $response ms"
					$innerdata | Out-File -FilePath "$OutputPath\General Information.txt" -Append
				}
				catch
				{
					Write-Verbose $_
					
				}
				try
				{
					$test = @()
					$test = (Test-Connection -ComputerName $DWDBServer -Count 4 -ErrorAction Stop | measure-Object -Property ResponseTime -Average).average
					$response = @()
					$response = ($test -as [int])
					$innerdata = @()
					[string]$innerdata = "$ms -> $DWDBServer : $response ms"
					$innerdata | Out-File -FilePath "$OutputPath\General Information.txt" -Append
				}
				catch
				{
					Write-Verbose $_
				}
			}
			else
			{
				try
				{
					$test = @()
					$test = (Test-Connection -ComputerName $OpsDBServer -Count 4 -ErrorAction Stop | measure-Object -Property ResponseTime -Average).average
					$response = @()
					$response = ($test -as [int])
					$innerdata = @()
					[string]$innerdata = "$ms -> $OpsDBServer : $response ms"
					$innerdata | Out-File -FilePath "$OutputPath\General Information.txt" -Append
				}
				catch
				{
					Write-Verbose $_
				}
			}
		}
	}
	Write-Progress -Activity "Collection Running" -Status "Progress-> 94%" -PercentComplete 94
	if ($pingall)
	{
		foreach ($server in $TestedTLSservers)
		{
			Invoke-Command -ComputerName $server -ErrorAction SilentlyContinue -ScriptBlock {
				#Start Checking for Connectivity to Management Servers in MG
				$pingoutput = @()
				foreach ($ms in $using:ManagementServers)
				{
					if ($ms -eq $env:COMPUTERNAME) { continue }
					try
					{
						$test = @()
						$test = (Test-Connection -ComputerName $ms -Count 4 | measure-Object -Property ResponseTime -Average).average
						$response = @()
						$response = ($test -as [int])
						$innerdata = @()
						[string]$innerdata = "$using:server -> $ms : $response ms"
					}
					catch
					{
						Write-Warning $_
						continue
					}
				}
				return $innerdata
			} | Out-File -FilePath "$OutputPath\General Information.txt" -Append
		}
	}
	$pingoutput | Out-File -FilePath "$OutputPath\General Information.txt" -Append
	
	$mginfra = @(
		'Operations Manager Management Group',
		'Operations Manager Management Servers',
		'Data Warehouse Database',
		'Operations Database',
		'Operations Manager Agents'
	)
	$atable = New-Object System.Data.DataTable
	$atable.Columns.Add("Management Group Infrastructure", "System.String") | Out-Null
	$atable.Columns.Add("DisplayName", "System.String") | Out-Null
	$atable.Columns.Add("HealthState", "System.String") | Out-Null
	$atable.Columns.Add("IsAvailable", "System.String") | Out-Null
	$atable.Columns.Add("LastModified", "System.String") | Out-Null
	ForEach ($monitor in $mginfra)
	{
		$data = $null
		$data = Get-SCOMClass -DisplayName $monitor | Get-SCOMClassInstance
		$aRow = $atable.NewRow()
		$aRow.DisplayName = $data.DisplayName
		$aRow.HealthState = ($data.HealthState).ToString().Replace("Success", "Healthy")
		$aRow.IsAvailable = $data.IsAvailable
		$aRow.LastModified = $data.LastModified
		$atable.Rows.Add($aRow)
	}
	$mgfunctions = @(
		'All Management Servers Resource Pool',
		'Data Access Service Group',
		'Management Configuration Service Group',
		'Web User Interfaces'
	)
	$btable = New-Object System.Data.DataTable
	$btable.Columns.Add("Management Group Functions", "System.String") | Out-Null
	$btable.Columns.Add("DisplayName", "System.String") | Out-Null
	$btable.Columns.Add("HealthState", "System.String") | Out-Null
	$btable.Columns.Add("IsAvailable", "System.String") | Out-Null
	$btable.Columns.Add("LastModified", "System.String") | Out-Null
	ForEach ($monitor in $mgfunctions)
	{
		$data = $null
		$data = (Get-SCOMClass -DisplayName $monitor | Get-SCOMClassInstance) | Where { $_.FullName -ne 'Microsoft.SystemCenter.ManagementServicePoolWatchersGroup' }
		$bRow = $btable.NewRow()
		$bRow.DisplayName = $data.DisplayName
		$bRow.HealthState = ($data.HealthState).ToString().Replace("Success", "Healthy")
		$bRow.IsAvailable = $data.IsAvailable
		$bRow.LastModified = $data.LastModified
		$btable.Rows.Add($bRow)
	}
	#(Get-SCOMClass -Name 'Microsoft.SystemCenter.ManagementServicePoolWatchersGroup' | Get-SCOMClassInstance | Select -Property DisplayName, HealthState)
	$msstate = @(
		'Microsoft.SystemCenter.CollectionManagementServerWatcherGroup'
	)
	$ctable = New-Object System.Data.DataTable
	$ctable.Columns.Add("Management Server State from Health Service Watcher", "System.String") | Out-Null
	$ctable.Columns.Add("DisplayName", "System.String") | Out-Null
	$ctable.Columns.Add("HealthState", "System.String") | Out-Null
	$ctable.Columns.Add("IsAvailable", "System.String") | Out-Null
	$ctable.Columns.Add("LastModified", "System.String") | Out-Null
	ForEach ($monitor in $msstate)
	{
		$data = $null
		$data = (Get-SCOMClassInstance -Name $monitor)
		$cRow = $ctable.NewRow()
		$cRow.DisplayName = $data.DisplayName
		$cRow.HealthState = ($data.HealthState).ToString().Replace("Success", "Healthy")
		$cRow.IsAvailable = $data.IsAvailable
		$cRow.LastModified = $data.LastModified
		$ctable.Rows.Add($cRow)
	}
	$msservers = Get-SCOMClass -DisplayName 'Management Server' | Get-SCOMClassInstance
	$dtable = New-Object System.Data.DataTable
	$dtable.Columns.Add("Management Server State", "System.String") | Out-Null
	$dtable.Columns.Add("DisplayName", "System.String") | Out-Null
	$dtable.Columns.Add("HealthState", "System.String") | Out-Null
	$dtable.Columns.Add("IsAvailable", "System.String") | Out-Null
	$dtable.Columns.Add("LastModified", "System.String") | Out-Null
	ForEach ($server in $msservers)
	{
		$dRow = $dtable.NewRow()
		$dRow.DisplayName = $server.DisplayName
		$dRow.HealthState = ($server.HealthState).ToString().Replace("Success", "Healthy")
		$dRow.IsAvailable = $server.IsAvailable
		$dRow.LastModified = $server.LastModified
		$dtable.Rows.Add($dRow)
	}
	
	" " | Out-File -FilePath "$OutputPath\General Information.txt" -Append
	@"
=====================================
=------- MG Health Overview --------=
=====================================
"@ | Out-File -FilePath "$OutputPath\General Information.txt" -Append
	$atable | Export-CSV "$OutputPath`\MG_HealthOverview.csv" -Force -NoTypeInformation
	$btable | Export-CSV "$OutputPath`\MG_HealthOverview.csv" -Append -Force -NoTypeInformation
	$ctable | Export-CSV "$OutputPath`\MG_HealthOverview.csv" -Append -Force -NoTypeInformation
	$dtable | Export-CSV "$OutputPath`\MG_HealthOverview.csv" -Append -Force -NoTypeInformation
	$atable | Format-Table -AutoSize | Out-String -Width 4096 | Out-File -FilePath "$OutputPath\General Information.txt" -Append
	$btable | Format-Table -AutoSize | Out-String -Width 4096 | Out-File -FilePath "$OutputPath\General Information.txt" -Append
	$ctable | Format-Table -AutoSize | Out-String -Width 4096 | Out-File -FilePath "$OutputPath\General Information.txt" -Append
	$dtable | Format-Table -AutoSize | Out-String -Width 4096 | Out-File -FilePath "$OutputPath\General Information.txt" -Append
	
	# ==================================================================================
	try
	{
		$mgOverviewImport = Import-Csv "$OutputPath`\MG_Overview.csv"
		Write-Progress -Activity "Collection Running" -Status "Progress-> 95%" -PercentComplete 95
		$mgOverviewImport | % {
			$MGName = $_.MG_Name
			$MSCount = $_.MS_Count
			$GWCount = $_.GW_Count
			$AgentCount = $_.Agent_Count
			$AgentPending = $_.Agent_Pending
			$UnixCount = $_.Unix_Count
			$NetworkDeviceCount = $_.NetworkDevice_Count
			$NoteUpdate = [pscustomobject]@{ }
			$NoteUpdate | Add-Member -MemberType NoteProperty -Name "Management Group Name" -Value $MGName -ErrorAction SilentlyContinue
			$NoteUpdate | Add-Member -MemberType NoteProperty -Name "Gateway Count" -Value $GWCount -ErrorAction SilentlyContinue
			$NoteUpdate | Add-Member -MemberType NoteProperty -Name "Agent Count" -Value $AgentCount -ErrorAction SilentlyContinue
			$NoteUpdate | Add-Member -MemberType NoteProperty -Name "Agent Pending" -Value $AgentPending -ErrorAction SilentlyContinue
			$NoteUpdate | Add-Member -MemberType NoteProperty -Name "Unix Count" -Value $UnixCount -ErrorAction SilentlyContinue
			$NoteUpdate | Add-Member -MemberType NoteProperty -Name "Network Device Count" -Value $NetworkDeviceCount -ErrorAction SilentlyContinue
			$NoteUpdate | Add-Member -MemberType NoteProperty -Name "Environment Type" -Value '(Prod / Non-Prod / Dev)' -ErrorAction SilentlyContinue
			$NoteUpdate | Format-List * | Out-File -FilePath "$OutputPath\note.txt" -Width 4096
		}
	}
	catch
	{
		#potential error code
		#use continue or break keywords
		#$e = $_.Exception
		$line = $_.InvocationInfo.ScriptLineNumber
		$msg = $e.Message
		
		Write-Verbose "Caught Exception: $($error[0]) at line: $line"
		"$(Time-Stamp)Caught Exception: $($error[0]) at line: $line" | Out-File $OutputPath\Error.log -Append
	}
	
	"Environment:" | Out-File -FilePath "$OutputPath\note.txt" -Append
	$NoteUpdate = [pscustomobject]@{ }
	$NoteUpdate | Add-Member -MemberType NoteProperty -Name "SCOM Version" -Value '<Type in Manually>' -ErrorAction SilentlyContinue
	$NoteUpdate | Add-Member -MemberType NoteProperty -Name "MS Server OS Version" -Value $((Get-CimInstance win32_operatingsystem).Caption) -ErrorAction SilentlyContinue
	$NoteUpdate | Add-Member -MemberType NoteProperty -Name "Number of MS" -Value $MSCount -ErrorAction SilentlyContinue
	$NoteUpdate | Add-Member -MemberType NoteProperty -Name "SQL Info" -Value ($dbOutput | fl * | Out-String -Width 4096) -ErrorAction SilentlyContinue
	$NoteUpdate | Format-List * | Out-File -FilePath "$OutputPath\note.txt" -Append -Width 4096
	
	Write-Progress -Activity "Collection Running" -Status "Progress-> 96%" -PercentComplete 96
}