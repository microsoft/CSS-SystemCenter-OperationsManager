Function SQL-Queries
{
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
	function Invoke-SqlCommand
	{
    <#
        .SYNOPSIS
            Executes an SQL statement. Executes using Windows Authentication unless the Username and Password are provided.

        .PARAMETER Server
            The SQL Server instance name.

        .PARAMETER Database
            The SQL Server database name where the query will be executed.

        .PARAMETER Timeout
            The connection timeout.

        .PARAMETER Connection
            The System.Data.SqlClient.SQLConnection instance used to connect.

        .PARAMETER Username
            The SQL Authentication Username.

        .PARAMETER Password
            The SQL Authentication Password.

        .PARAMETER CommandType
            The System.Data.CommandType value specifying Text or StoredProcedure.

        .PARAMETER Query
            The SQL query to execute.

         .PARAMETER Path
            The path to an SQL script.

        .PARAMETER Parameters
            Hashtable containing the key value pairs used to generate as collection of System.Data.SqlParameter.

        .PARAMETER As
            Specifies how to return the result.

            PSCustomObject
             - Returns the result set as an array of System.Management.Automation.PSCustomObject objects.
            DataSet
             - Returns the result set as an System.Data.DataSet object.
            DataTable
             - Returns the result set as an System.Data.DataTable object.
            DataRow
             - Returns the result set as an array of System.Data.DataRow objects.
            Scalar
             - Returns the first column of the first row in the result set. Should be used when a value with no column name is returned (i.e. SELECT COUNT(*) FROM Test.Sample).
            NonQuery
             - Returns the number of rows affected. Should be used for INSERT, UPDATE, and DELETE.

        .EXAMPLE
            PS C:\> Invoke-SqlCommand -Server "DATASERVER" -Database "Web" -Query "SELECT TOP 1 * FROM Test.Sample"

            datetime2         : 1/17/2013 8:46:22 AM
            ID                : 202507
            uniqueidentifier1 : 1d0cf1c0-9fb1-4e21-9d5a-b8e9365400fc
            bool1             : False
            datetime1         : 1/17/2013 12:00:00 AM
            double1           : 1
            varchar1          : varchar11
            decimal1          : 1
            int1              : 1

            Returned the first row as a System.Management.Automation.PSCustomObject.

        .EXAMPLE
            PS C:\> Invoke-SqlCommand -Server "DATASERVER" -Database "Web" -Query "SELECT COUNT(*) FROM Test.Sample" -As Scalar

            9544            
    #>
		[CmdletBinding(DefaultParameterSetName = "Default")]
		param (
			[Parameter(Mandatory = $true, Position = 0)]
			[string]$Server,
			[Parameter(Mandatory = $true, Position = 1)]
			[string]$Database,
			[Parameter(Mandatory = $false, Position = 2)]
			[int]$Timeout = 30,
			[System.Data.SqlClient.SQLConnection]$Connection,
			[string]$Username,
			[string]$Password,
			[System.Data.CommandType]$CommandType = [System.Data.CommandType]::Text,
			[string]$Query,
			[ValidateScript({ Test-Path -Path $_ })]
			[string]$Path,
			[hashtable]$Parameters,
			[ValidateSet("DataSet", "DataTable", "DataRow", "PSCustomObject", "Scalar", "NonQuery")]
			[string]$As = "PSCustomObject"
		)
		
		begin
		{
			if ($Path)
			{
				$Query = [System.IO.File]::ReadAllText("$((Resolve-Path -Path $Path).Path)")
			}
			else
			{
				if (-not $Query)
				{
					throw (New-Object System.ArgumentNullException -ArgumentList "Query", "The query statement is missing.")
				}
			}
			
			$createConnection = (-not $Connection)
			
			if ($createConnection)
			{
				$Connection = New-Object System.Data.SqlClient.SQLConnection
				if ($Username -and $Password)
				{
					$Connection.ConnectionString = "Server=$($Server);Database=$($Database);User Id=$($Username);Password=$($Password);"
				}
				else
				{
					$Connection.ConnectionString = "Server=$($Server);Database=$($Database);Integrated Security=SSPI;"
				}
				if ($PSBoundParameters.Verbose)
				{
					$Connection.FireInfoMessageEventOnUserErrors = $true
					$Connection.Add_InfoMessage([System.Data.SqlClient.SqlInfoMessageEventHandler] { Write-Verbose "$($_)" })
				}
			}
			
			if (-not ($Connection.State -like "Open"))
			{
				try { $Connection.Open() }
				catch [Exception] { throw $_ }
			}
		}
		
		process
		{
			$command = New-Object System.Data.SqlClient.SqlCommand ($query, $Connection)
			$command.CommandTimeout = $Timeout
			$command.CommandType = $CommandType
			if ($Parameters)
			{
				foreach ($p in $Parameters.Keys)
				{
					$command.Parameters.AddWithValue($p, $Parameters[$p]) | Out-Null
				}
			}
			
			$scriptBlock = {
				$result = @()
				$reader = $command.ExecuteReader()
				if ($reader)
				{
					$counter = $reader.FieldCount
					$columns = @()
					for ($i = 0; $i -lt $counter; $i++)
					{
						$columns += $reader.GetName($i)
					}
					
					if ($reader.HasRows)
					{
						while ($reader.Read())
						{
							$row = @{ }
							for ($i = 0; $i -lt $counter; $i++)
							{
								$row[$columns[$i]] = $reader.GetValue($i)
							}
							$result += [PSCustomObject]$row
						}
					}
				}
				$result
			}
			
			if ($As)
			{
				switch ($As)
				{
					"Scalar" {
						$scriptBlock = {
							$result = $command.ExecuteScalar()
							$result
						}
					}
					"NonQuery" {
						$scriptBlock = {
							$result = $command.ExecuteNonQuery()
							$result
						}
					}
					default {
						if ("DataSet", "DataTable", "DataRow" -contains $As)
						{
							$scriptBlock = {
								$ds = New-Object System.Data.DataSet
								$da = New-Object System.Data.SqlClient.SqlDataAdapter($command)
								$da.Fill($ds) | Out-Null
								switch ($As)
								{
									"DataSet" { $result = $ds }
									"DataTable" { $result = $ds.Tables }
									default { $result = $ds.Tables | ForEach-Object -Process { $_.Rows } }
								}
								$result
							}
						}
					}
				}
			}
			
			$result = Invoke-Command -ScriptBlock $ScriptBlock
			$command.Parameters.Clear()
		}
		
		end
		{
			if ($createConnection) { $Connection.Close() }
			Write-Verbose "$($result | Out-String)"
			return $result
		}
	}
	$InvokeSQLcmdFunction = [scriptblock]::Create(@"
  function Invoke-SqlCommand { ${Function:Invoke-SQLCommand} } 
"@)
	## strip fqdn etc...
	If ($global:OpsDB_SQLServerOriginal -like "*,*")
	{
		$global:OpsDB_SQLServer = $OpsDB_SQLServerOriginal.split(',')[0]
		$global:OpsDB_SQLServerPort = $OpsDB_SQLServerOriginal.split(',')[1]
		$global:DW_SQLServerInstance = $null
	}
	elseif ($global:OpsDB_SQLServerOriginal -like "*\*")
	{
		$global:OpsDB_SQLServer = $OpsDB_SQLServerOriginal.split('\')[0]
		$global:OpsDB_SQLServerInstance = $OpsDB_SQLServerOriginal.split('\')[1]
	}
	else
	{
		$global:OpsDB_SQLServerInstance = $null
		$global:OpsDB_SQLServerPort = $null
	}
	
	If ($global:DW_SQLServerOriginal -like "*,*")
	{
		$global:DW_SQLServer = $DW_SQLServerOriginal.split(',')[0]
		$global:DW_SQLServerPort = $DW_SQLServerOriginal.split(',')[1]
		$global:DW_SQLServerInstance = $null
	}
	elseif ($global:DW_SQLServerOriginal -like "*\*")
	{
		$global:DW_SQLServer = $DW_SQLServerOriginal.split('\')[0]
		$global:DW_SQLServerInstance = $DW_SQLServerOriginal.split('\')[1]
	}
	else
	{
		$global:DW_SQLServerInstance = $null
		$global:DW_SQLServerPort = $null
	}
	
	
	
	
	$Populated = 1
	
	## Verify variables are populated
	If ($OpsDB_SQLServer -eq $null)
	{
		write-output "OpsDBServer not found"
		$populated = 0
	}
	If ($DW_SQLServer -eq $null)
	{
		write-output "DataWarehouse server not found"
		$populated = 0
	}
	If ($OpsDB_SQLDBName -eq $null)
	{
		write-output "OpsDBName Not found"
		$populated = 0
	}
	If ($DW_SQLDBName -eq $null)
	{
		write-output "DWDBName not found"
		$populated = 0
	}
	if ($Populated = 0)
	{
		"At least some SQL Information not found, exiting script..."
    <# 
        insert Holman's method from the original script here, then remove the break found below
    #>
		break
	}
	## Hate this output. Want to change it, will eventually, doesnt pose a problem functionally though 
	## so thats a task for a later date. Want a table, not a list like that. 
	## Combine the objects into a single object and display via table.
	$color = "Cyan"
	Write-Output " "
	Write-Host "OpsDB Server        : $global:OpsDB_SQLServer" -ForegroundColor $color -NoNewline
	if ($OpsDB_SQLServerInstance)
	{
		Write-Host "\$OpsDB_SQLServerInstance" -ForegroundColor $color -NoNewline
	}
	if ($OpsDB_SQLServerPort)
	{
		Write-Host "`nOpsDB Server Port   : $OpsDB_SQLServerPort" -ForegroundColor $color -NoNewline
	}
	Write-Host "`nOpsDB Name          : $OpsDB_SQLDBName" -ForegroundColor $color
	Write-Output " "
	Write-Host "DWDB Server         : $($global:DW_SQLServer)" -ForegroundColor $color -NoNewline
	if ($global:DW_SQLServerInstance)
	{
		Write-Host "\$DW_SQLServerInstance" -ForegroundColor $color -NoNewline
	}
	if ($global:DW_SQLServerPort)
	{
		Write-Host "`nDWDB Server Port    : $DW_SQLServerPort" -ForegroundColor $color -NoNewline
	}
	Write-Host "`nDWDB Name           : $DW_SQLDBName" -ForegroundColor $color
	Write-Output " "
	
	if ($SQLOnlyOpsDB)
	{
		$AssumeYes = $true
	}
	elseif ($SQLOnlyDW)
	{
		$skipOpsDBQuery = $true
	}
	else
	{
		$skipOpsDBQuery = $false
	}
	
	if (!$skipOpsDBQuery)
	{
		if (!$AssumeYes)
		{
			do
			{
				
				$answer = Read-Host -Prompt "Do you want to continue with these values? (Y/N)"
				
			}
			until ($answer -eq "y" -or $answer -eq "n")
		}
		else { $answer = "y" }
		IF ($answer -eq "y")
		{
			Write-Host "Connecting to SQL Server...." -ForegroundColor DarkGreen
		}
		ELSE
		{
			do
			{
				
				$answer = Read-Host -Prompt "Do you want to attempt to continue without Queries to your SQL Server? (Y/N)"
				
			}
			until ($answer -eq "y" -or $answer -eq "n")
			if ($answer -eq "y")
			{
				Write-Warning "Be aware, this has not been implemented yet..."
				return
			}			
		}
		# Query the OpsDB Database
		[string]$currentuser = ([Environment]::UserDomainName + "\" + [Environment]::UserName)
		if (!$NoSQLPermission)
		{
			if (!$AssumeYes)
			{
				Write-Host "Currently Detecting User as: $currentuser"
				do
				{
					$answer2 = Read-Host -Prompt " Does the above user have the correct permissions to perform SQL Queries against OpsDB: $OpsDB_SQLServer`? (Y/N)"
				}
				until ($answer2 -eq "y" -or $answer2 -eq "n")
			}
			else { $answer2 = "y" }
		}
		else
		{
			$answer2 = "n"
		}
		if ($answer2 -eq "n")
		{
			do
			{
				$answer3 = Read-Host -Prompt "  Are you setup for `'SQL Credentials`' or `'Domain Credentials`' on OpsDB: $OpsDB_SQLServer`? (SQL/Domain)"
			}
			until ($answer3 -eq "SQL" -or $answer3 -eq "Domain")
			$SQLuser = Read-Host '   What is your username?'
			$SQLpass = Read-Host '   What is your password?' -AsSecureString
			do
			{
				$proceed = Read-Host "    Would you like to proceed with $SQLuser`? (Y/N)"
				if ($proceed -eq "n")
				{
					$SQLuser = $null
					$SQLuser = Read-Host '   What is your username?'
					$SQLpass = Read-Host '   What is your password?' -AsSecureString
				}
			}
			until ($proceed -eq "y")
		}
		else
		{ $answer2 = "y" }
		# Query the DW database
		if (!$NoSQLPermission)
		{
			if (!$AssumeYes)
			{
				do
				{
					$answer4 = Read-Host -Prompt " Does `'$currentuser`' have the correct permissions to perform SQL Queries against DW: $DW_SQLServer`? (Y/N)"
				}
				until ($answer4 -eq "y" -or $answer4 -eq "n")
			}
			else { $answer4 = "y" }
		}
		else
		{
			$answer4 = "n"
		}
		
		if ($answer4 -eq "n")
		{
			if ($SQLuser)
			{
				do
				{
					$answer6 = Read-Host -Prompt "  Would you like to use the same credentials as OpsDB for the DW Queries? `'$SQLuser`'? (Y/N)"
				}
				until ($answer6 -eq "y" -or $answer6 -eq "n")
				if ($answer6 -eq "y")
				{
					$SQLuser2 = $SQLuser
					$SQLpass2 = $SQLpass
					$answer5 = $answer3
				}
				else
				{
					do
					{
						$answer5 = Read-Host -Prompt "  Are you setup for `'SQL Credentials`' or `'Domain Credentials`' on DW: $DW_SQLServer`? (SQL/Domain)"
					}
					until ($answer5 -eq "SQL" -or $answer5 -eq "Domain")
					$SQLuser2 = Read-Host '    What is your username?'
					$SQLpass2 = Read-Host '    What is your password?' -AsSecureString
					do
					{
						$proceed2 = Read-Host "   Would you like to proceed with $SQLuser2`? (Y/N)"
						if ($proceed2 -eq "n")
						{
							$SQLuser2 = $null
							$SQLuser2 = Read-Host '    What is your username?'
							$SQLpass2 = Read-Host '    What is your password?' -AsSecureString
						}
					}
					until ($proceed2 -eq "y")
				}
			}
			else
			{
				do
				{
					$answer5 = Read-Host -Prompt "  Are you setup for `'SQL Credentials`' or `'Domain Credentials`' on DW: $DW_SQLServer`? (SQL/Domain)"
				}
				until ($answer5 -eq "SQL" -or $answer5 -eq "Domain")
				$SQLuser2 = Read-Host '    What is your username?'
				$SQLpass2 = Read-Host '    What is your password?' -AsSecureString
				do
				{
					$proceed2 = Read-Host "   Would you like to proceed with $SQLuser2`? (Y/N)"
					if ($proceed2 -eq "n")
					{
						$SQLuser2 = $null
						$SQLuser2 = Read-Host '    What is your username?'
						$SQLpass2 = Read-Host '    What is your password?' -AsSecureString
					}
				}
				until ($proceed2 -eq "y")
			}
		}
		if ($answer3 -eq "Domain")
		{
			$Credential = New-Object -TypeName System.Management.Automation.PSCredential -ArgumentList $SQLuser, $SQLpass
			$command = "-NoProfile -NoExit -Command cd '$ScriptPath';. '$ScriptPath\$scriptname' -SQLOnlyOpsDB; exit 0"
			Start-Process powershell.exe ($command) -Credential $Credential -Wait -NoNewWindow
			$job1 = $true
		}
		elseif ($answer2 -eq "y")
		{
			$SqlIntegratedSecurity = $true
		}
		elseif ($answer3 -eq "SQL")
		{
			$SqlIntegratedSecurity = $false
		}
		if (!$job1)
		{
			$QueriesPath = "$ScriptPath\queries\OpsDB"
			IF (!(Test-Path $QueriesPath))
			{
				Write-Warning "Path to query files not found ($QueriesPath).  Terminating...."
				break
			}
			Write-Host "`n================================"
			Write-Host "Starting SQL Query Gathering"
			Write-Host "Running SQL Queries against Operations Database"
			try
			{
				$timeout = 30
				if ($SqlIntegratedSecurity)
				{
					$initialCheck = Invoke-SqlCommand -Server $OpsDB_SQLServerOriginal -Database $OpsDB_SQLDBName -Query 'SELECT 1' -As DataRow -Timeout $timeout -ErrorAction Stop
				}
				else
				{
					$initialCheck = Invoke-SqlCommand -Server $OpsDB_SQLServerOriginal -Database $OpsDB_SQLDBName -Username $SQLuser -Password $SQLpass -Query 'SELECT 1' -As DataRow -Timeout $timeout -ErrorAction Stop
				}
				
				if ($initialCheck)
				{
					# 15 minute timeout for each query
					$timeout = 900
					$jobtimeout = 2100
				}
				else
				{
					Write-Warning "Cannot communicate with SQL DB, expect errors."
					"$(Time-Stamp)Cannot communicate with SQL DB, expect errors." | Out-File $OutputPath\Error.log -Append
				}
			}
			catch
			{
				Write-Warning $_
			}
			Write-Host " Current query timeout: $timeout seconds ($($timeout/60) minutes) \ Current query job timeout: $jobtimeout seconds ($($jobtimeout/60) minutes)" -ForegroundColor Gray
			Write-Host "  Looking for query files in: $QueriesPath" -ForegroundColor DarkGray
			$QueryFiles = Get-ChildItem -Path $QueriesPath -Filter "*.sql" ###BH - Remove Where for Filter left
			$QueryFilesCount = $QueryFiles.Count
			Write-Host "   Found ($QueryFilesCount) queries" -ForegroundColor Green
			FOREACH ($QueryFile in $QueryFiles)
			{
				try
				{
					$QueryFileName = ($QueryFile.Name).split('.')[0]
					[string]$OutputFileName = $OutputPath + "\" + $QueryFileName + ".csv"
					if ($SqlIntegratedSecurity)
					{
						$OpsScriptBlock = [scriptblock]::Create(@"
  Invoke-SqlCommand -Server $OpsDB_SQLServerOriginal -Database $OpsDB_SQLDBName -Path "$QueriesPath\$QueryFile" -As DataRow -Timeout $jobtimeout -ErrorAction Stop | Export-Csv -Path "$OutputFileName" -NoTypeInformation
"@)
						#This runs all queries with Perf in the name, as a job
						if ($QueryFileName -match 'Perf')
						{
							Write-Host "     Running query job: " -ForegroundColor Cyan -NoNewline
							Write-Host $QueryFile.Name -ForegroundColor Magenta
							Start-Job -Name "getPerf_Ops-$($QueryFile.Name)" -InitializationScript $InvokeSQLcmdFunction -ScriptBlock $OpsScriptBlock | Out-Null
						}
						elseif ($QueryFileName -match 'Event')
						{
							Write-Host "     Running query job: " -ForegroundColor Cyan -NoNewline
							Write-Host $QueryFile.Name -ForegroundColor Magenta
							Start-Job -Name "getEvent_Ops-$($QueryFile.Name)" -InitializationScript $InvokeSQLcmdFunction -ScriptBlock $OpsScriptBlock | Out-Null
						}
						else
						{
							Write-Host "     Running query: " -ForegroundColor Cyan -NoNewline
							Write-Host $QueryFile.Name -ForegroundColor Magenta
							Invoke-SqlCommand -Server $OpsDB_SQLServerOriginal -Database $OpsDB_SQLDBName -Path "$QueriesPath\$QueryFile" -As DataRow -Timeout $timeout -ErrorAction Stop | Export-Csv -Path "$OutputFileName" -NoTypeInformation
						}
						continue
					}
					else
					{
						$OpsScriptBlock = [scriptblock]::Create(@"
  Invoke-SqlCommand -Server $OpsDB_SQLServerOriginal -Database $OpsDB_SQLDBName -Username $SQLuser -Password $SQLpass -Path "$QueriesPath\$QueryFile" -As DataRow -Timeout $jobtimeout -ErrorAction Stop | Export-Csv -Path "$OutputFileName" -NoTypeInformation
"@)
						
						#This runs all queries with Perf in the name, as a job
						if ($QueryFileName -match 'Perf')
						{
							Write-Host "     Running query job: " -ForegroundColor Cyan -NoNewline
							Write-Host $QueryFile.Name -ForegroundColor Magenta
							Start-Job -Name "getPerf_Ops-$($QueryFile.Name)" -InitializationScript $InvokeSQLcmdFunction -ScriptBlock $OpsScriptBlock | Out-Null
						}
						elseif ($QueryFileName -match 'Event')
						{
							Write-Host "     Running query job: " -ForegroundColor Cyan -NoNewline
							Write-Host $QueryFile.Name -ForegroundColor Magenta
							Start-Job -Name "getEvent_Ops-$($QueryFile.Name)" -InitializationScript $InvokeSQLcmdFunction -ScriptBlock $OpsScriptBlock | Out-Null
						}
						else
						{
							Write-Host "     Running query: " -ForegroundColor Cyan -NoNewline
							Write-Host $QueryFile.Name -ForegroundColor Magenta
							Invoke-SqlCommand -Server $OpsDB_SQLServerOriginal -Database $OpsDB_SQLDBName -Username $SQLuser -Password $SQLpass -Path "$QueriesPath\$QueryFile" -As DataRow -Timeout $timeout -ErrorAction Stop | Export-Csv -Path "$OutputFileName" -NoTypeInformation
						}
						continue
					}
					#write-output "Writing output file" $OutputFileName
				}
				catch
				{
					Write-Host "       Error running SQL query: $QueryFileName
$_
" -ForegroundColor Red
					$_ | Export-Csv -Path "$OutputFileName" -NoTypeInformation
					"$(Time-Stamp)Error running SQL query: $QueryFileName `n$_" | Out-File $OutputPath\Error.log -Append
				}
				
			}
		}
	}
	
	if ($SQLOnlyOpsDB)
	{
		return
	}
	if ($SQLOnlyDW)
	{
		$AssumeYes = $true
	}
	# Query the DW database
	if ($answer5 -eq "Domain")
	{
		$Credential = New-Object -TypeName System.Management.Automation.PSCredential -ArgumentList $SQLuser2, $SQLpass2
		$command = "-NoProfile -NoExit -Command cd '$ScriptPath';. '$ScriptPath\$scriptname' -SQLOnlyDW; exit 0"
		Start-Process powershell.exe ($command) -Credential $Credential -Wait -NoNewWindow
		return
	}
	elseif ($answer4 -eq "y")
	{
		$SqlIntegratedSecurity = $true
	}
	elseif ($answer5 -eq "SQL")
	{
		$SqlIntegratedSecurity = $false
	}
	$QueriesPath = "$ScriptPath\queries\DW"
	IF (!(Test-Path $QueriesPath))
	{
		Write-Error "Path to query files not found ($QueriesPath).  Terminating...."
		"Path to query files not found ($QueriesPath).  Terminating...." | Out-File $OutputPath\Error.log -Append
		break
	}
	Write-Host "`n================================"
	Write-Host "Running SQL Queries against Data Warehouse"
	try
	{
		$timeout = 30
		if ($SqlIntegratedSecurity)
		{
			$initialCheck = Invoke-SqlCommand -Server $DW_SQLServerOriginal -Database $DW_SQLDBName -Query 'SELECT 1' -As DataRow -Timeout $timeout -ErrorAction Stop
		}
		else
		{
			$initialCheck = Invoke-SqlCommand -Server $DW_SQLServerOriginal -Database $DW_SQLDBName -Username $SQLuser2 -Password $SQLpass2 -Query 'SELECT 1' -As DataRow -Timeout $timeout -ErrorAction Stop
		}
		
		if ($initialCheck)
		{
			Write-Verbose "Initial Check:`n$initialCheck"
			# 15 minute timeout for each query
			$timeout = 900
			$jobtimeout = 2100
		}
		else
		{
			Write-Warning "Cannot communicate with SQL DB, expect errors."
		}
		
	}
	catch
	{
		Write-Warning $_
	}
	Write-Host " Current query timeout: $timeout seconds ($($timeout/60) minutes) \ Current query job timeout: $jobtimeout seconds ($($jobtimeout/60) minutes)" -ForegroundColor Gray
	Write-Host "  Gathering query files located here: $QueriesPath" -ForegroundColor DarkGray
	$QueryFiles = Get-ChildItem -Path $QueriesPath -Filter "*.sql" ###BH Remove Where for Filter left
	$QueryFilesCount = $QueryFiles.Count
	Write-Host "   Found ($QueryFilesCount) queries" -ForegroundColor Green
	FOREACH ($QueryFile in $QueryFiles)
	{
		try
		{
			$QueryFileName = ($QueryFile.Name).split('.')[0]
			$OutputFileName = $OutputPath + "\" + $QueryFileName + ".csv"
			if ($SqlIntegratedSecurity)
			{
				$DWScriptBlock = [scriptblock]::Create(@"
  Invoke-SqlCommand -Server $DW_SQLServerOriginal -Database $DW_SQLDBName -Path "$QueriesPath\$QueryFile" -As DataRow -Timeout $jobtimeout -ErrorAction Stop | Export-Csv -Path "$OutputFileName" -NoTypeInformation
"@)
				#This runs all queries with Perf in the name, as a job
				if ($QueryFileName -match 'Perf')
				{
					Write-Host "     Running query job: " -ForegroundColor Cyan -NoNewline
					Write-Host $QueryFile.Name -ForegroundColor Magenta
					Start-Job -Name "getPerf_DW-$($QueryFile.Name)" -InitializationScript $InvokeSQLcmdFunction -ScriptBlock $DWScriptBlock | Out-Null
				}
				elseif ($QueryFileName -match 'Event')
				{
					Write-Host "     Running query job: " -ForegroundColor Cyan -NoNewline
					Write-Host $QueryFile.Name -ForegroundColor Magenta
					Start-Job -Name "getEvent_DW-$($QueryFile.Name)" -InitializationScript $InvokeSQLcmdFunction -ScriptBlock $DWScriptBlock | Out-Null
				}
				else
				{
					Write-Host "     Running query: " -ForegroundColor Cyan -NoNewline
					Write-Host $QueryFile.Name -ForegroundColor Magenta
					Invoke-SqlCommand -Server $DW_SQLServerOriginal -Database $DW_SQLDBName -Path "$QueriesPath\$QueryFile" -As DataRow -Timeout $timeout -ErrorAction Stop | Export-Csv -Path "$OutputFileName" -NoTypeInformation
				}
				continue
			}
			else
			{
				$DWScriptBlock = [scriptblock]::Create(@"
  Invoke-SqlCommand -Server $DW_SQLServerOriginal -Database $DW_SQLDBName -Username $SQLuser2 -Password $SQLpass2 -Path "$QueriesPath\$QueryFile" -As DataRow -Timeout $jobtimeout -ErrorAction Stop | Export-Csv -Path "$OutputFileName" -NoTypeInformation
"@)
				#This runs all queries with Perf in the name, as a job
				if ($QueryFileName -match 'Perf')
				{
					Write-Host "     Running query job: " -ForegroundColor Cyan -NoNewline
					Write-Host $QueryFile.Name -ForegroundColor Magenta
					Start-Job -Name "getPerf_DW-$($QueryFile.Name)" -InitializationScript $InvokeSQLcmdFunction -ScriptBlock $DWScriptBlock | Out-Null
				}
				elseif ($QueryFileName -match 'Event')
				{
					Write-Host "     Running query job: " -ForegroundColor Cyan -NoNewline
					Write-Host $QueryFile.Name -ForegroundColor Magenta
					Start-Job -Name "getEvent_DW-$($QueryFile.Name)" -InitializationScript $InvokeSQLcmdFunction -ScriptBlock $DWScriptBlock | Out-Null
				}
				else
				{
					Write-Host "     Running query: " -ForegroundColor Cyan -NoNewline
					Write-Host $QueryFile.Name -ForegroundColor Magenta
					Invoke-SqlCommand -Server $DW_SQLServerOriginal -Database $DW_SQLDBName -Username $SQLuser2 -Password $SQLpass2 -Path "$QueriesPath\$QueryFile" -As DataRow -Timeout $timeout -ErrorAction Stop | Export-Csv -Path "$OutputFileName" -NoTypeInformation
				}
				continue
			}
		}
		catch
		{
			Write-Host "       Error running SQL query: $QueryFileName
$_
" -ForegroundColor Red
			"$(Time-Stamp)Error running SQL query: $QueryFileName - `n$_" | Out-File $OutputPath\Error.log -Append
			$_ | Export-Csv -Path "$OutputFileName" -NoTypeInformation
		}
	}
}