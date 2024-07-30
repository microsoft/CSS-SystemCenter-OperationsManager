<#
.SYNOPSIS
With SCOM Monitoring, sometimes you want to want to put a certain monitor into "Maintenance Mode", however, monitors cannot be placed into maintenance mode. BUT, the underlying object can, 
which in turn puts the monitor into "Maintenance Mode".

For example, the monitor "TCP/IP NetBIOS Service Health" is a core Windows Operating System monitor that looks at the "LmHosts" service to see if it's running or not. This monitor targets the 
Windows Operating System class. Let's say we want to silence this monitor, this does not appear as an option in the MM Scheduler, and rightfully so, instead what we can do is put the TARGET of
the monitor into maintenance mode. So, if we want to put the "TCP/IP NetBIOS Service Health" monitor into "Maintenance", we need to put the whole Windows Operating System object into maintenance 
for the target server.

That's what this script does. It takes the input of the monitor display name to silence, and puts the underlying target into maintenance mode for the set duration in minutes.
	
.NOTES
For best results, run from a management server, or after connecting to a management group in the current PowerShell process (ex. New-SCManagementGroupConnection -ComputerName "MS1.contoso.com" -Credential (Get-Credential))

.AUTHOR
Lorne Sepaugh
		
.VERSION
v2.0.0 - July 2024
v1.0.0 - May  2021

.PARAMETER MonitorDisplayName
This is the Display Name of the monitor that we want to place into maintenance mode (Alias: DisplayName)

.PARAMETER Comment
Comment on the reason to place the monitor into maintenance mode

.PARAMETER Duration
Provide the number of minutes the monitor should be placed into Maintenance Mode from the start of the script

.PARAMETER ComputerName
You can provide either a path to a text file containing a list of servers (ex. .\ServerList.txt), or an inline comma-delimited list of servers (ex. "server01.contoso.com,server02.contoso.com")

.PARAMETER StartMaintenance
(Default) Indicate that we will be starting maintenance, and set a duration for the maintenance to automatacally end after.

.PARAMETER StopMaintenance
If you need to stop an existing maintenance schedule early.

.EXAMPLE
PS> .\"Set-SCOMMonitorMaintenanceMode.ps1" -monitorDisplayName "TCP/IP NetBIOS Service Health" -comment "Server maintenance" -StartMaintenance -duration 90 -ComputerName ".\Serverlist.txt"

.EXAMPLE
PS> .\"Set-SCOMMonitorMaintenanceMode.ps1" -monitorDisplayName "TCP/IP NetBIOS Service Health" -comment "Server maintenance" -StopMaintenance -ComputerName "agent01.contoso.com,agent02.contoso.com"
#>

[CmdletBinding(DefaultParametersetName="StartMaintenance")]
param (
    [Parameter(ParameterSetName="StartMaintenance")]
    [Switch] $StartMaintenance,
 
    [Parameter(ParameterSetName="StopMaintenance")]
    [Switch] $StopMaintenance,
   
    [Parameter(Mandatory)][Alias('DisplayName')]
    [ValidateNotNullOrEmpty()]
    [String] $MonitorDisplayName,
   
    [Parameter()]
    [String] $Comment,
   
    [Parameter(Mandatory, ParameterSetName="StartMaintenance")]
    [ValidateNotNullOrEmpty()]
    [Int] $Duration = 90,
   
    [Parameter(Mandatory)]
    [ValidateNotNullOrEmpty()]
    [String] $ComputerName,
   
    [Parameter(DontShow)]
    [String] $ScriptPath = (split-path -parent $MyInvocation.MyCommand.Definition)
)
 
Start-Transcript -Path "$($scriptPath)\ScriptTranscript.log" -IncludeInvocationHeader -Force
 
# Log the parameters to transcript
Write-Output @"
-- Parameter Values Provided --
monitorDisplayName = '$($monitorDisplayName)'
comment = '$($comment)'
duration = $($duration)
computerName = '$($computerName)'
------
"@
 
# Import the SCOM Module so that we can load all the cmdlets
Import-Module OperationsManager
 
# Set the starting variables
$EndTime = ((Get-Date).AddMinutes($($duration)).ToString("yyyy-MM-dd HH:mm:ss.fff")) # Set the end time for maintenance based on the indicated duration
$monitor = Get-SCOMMonitor -DisplayName $monitorDisplayName # Get the correct monitor based on the displayName
$targetClass = Get-SCOMClass -Id $($monitor.Target.Id.Guid) # Get the target class for the monitor
$targetClassInstances = $targetClass | Get-SCOMClassInstance # Get the targeted class instances for the monitoring object
 
# Import the list of servers we'll be working with
Switch (Test-Path -path $computerName) {
    $true  { $serverList = Get-Content $ComputerName }
    $false { [array]$serverList = $ComputerName -split ","}
}
 
If ($startMaintenance) {
 
    Write-Output "Setting a Maintenance Window for the monitor '$monitorDisplayName' that will end at '$($EndTime)'`n"
 
    ForEach ($server in $serverList) {
   
        # Get the class instance for the current server in the list
        $currentInstance = $targetClassInstances | Where {$_.Path -like "$($server)*" -or $_.DisplayName -like "$($server)*"}
 
        # Check to see if the current class instance is already in maintenance
        $mmCheck = $currentInstance | Get-SCOMMaintenanceMode -ErrorAction SilentlyContinue
 
        # If an instance of the target class exists for the current server in our list, continue
        If ($currentInstance -eq $null) {
              # negative path – just go to the next iteration in the loop
              Write-Warning "Maintenance Mode did NOT get set for '$($server)', as no class instances were found for it under monitor '$($monitorDisplayName)'."
              continue
         }
 
        # If the current isntance is not already in maintenance mode, continue
        If ($mmCheck -ne $null){
              # negative path – just go to the next iteration in the loop
              Write-Warning "Maintenance Mode was ALREADY scheduled for the '$($currentInstance.DisplayName)' object for '$($server)' and ends at '$($mmCheck.ScheduledEndTime)'."
              continue
        }
       
       # Try setting maintenance for the current class instance
        Try {
            # Set MM schedule for the target instance    
            $currentInstance | Start-SCOMMaintenanceMode -EndTime $EndTime -Reason PlannedApplicationMaintenance -Comment $comment -ErrorAction SilentlyContinue
           
            # Check if maintenance mode was set
            $mmCheck = $currentInstance | Get-SCOMMaintenanceMode
       
            # If maintenance mode was set, rejoice, but continue either way
            If ($mmCheck) {
                Write-Information "Maintenance Mode was scheduled for the '$($currentInstance.DisplayName)' object for '$($server)'."
            }
            Else {
                Write-Warning "Maintenance Mode did NOT get set for '$($server)', this could be due to it already being in maintenance, not having the target object, or something else."
            }
        }
 
        # If setting the maintenance schedule failed, then tell us why
        Catch {
            Write-Error "Maintenance Mode did NOT get set for '$($server)' due to error: $($_)."
        }
    }
}
 
 
If ($StopMaintenance) {
 
    Write-Output "Stopping Maintenance Window for the monitor '$monitorDisplayName'`n"
 
    ForEach ($server in $serverList) {
   
        # Get the class instance for the current server in the list
        $currentInstance = $targetClassInstances | Where {$_.Path -like "$($server)*" -or $_.DisplayName -like "$($server)*"}
 
        # Check to see if the current class instance is currently in maintenance
        $mmCheck = $currentInstance | Get-SCOMMaintenanceMode -ErrorAction SilentlyContinue
       
        # If an instance of the target class exists for the current server in our list, continue
        If ($currentInstance -eq $null) {
              # negative path – just go to the next iteration in the loop
              continue
       }
           
        # If the current isntance is currently in maintenance mode, continue
        If ($mmCheck -eq $null){
              # negative path – just go to the next iteration in the loop
              Write-Information "No current maintenance schedule found for the '$($currentInstance.DisplayName)' object for '$($server)'."
              continue
        }
           
        # Try setting maintenance for the current class instance
        Try {
            # Stop MM schedule for the target instance    
            $currentInstance | Get-SCOMMaintenanceMode | Set-SCOMMaintenanceMode -EndTime ((Get-Date).ToString("yyyy-MM-dd HH:mm:ss.fff"))
                               
            # Check if maintenance mode was stopped
            $mmCheck = $currentInstance | Get-SCOMMaintenanceMode
 
            # If maintenance mode was stopped, rejoice, but continue either way
            If ($mmCheck -eq $null) {
                Write-Information "Maintenance Mode was stopped for the '$($currentInstance.DisplayName)' object for '$($server)'."
            }
            Else {
                Write-Warning "Maintenance Mode did NOT get stopped for the '$($currentInstance.DisplayName)' object for '$($server)'."
            }
        }
        Catch{
            Write-Error "Could not stop Maintenance Mode schedule on the '$($currentInstance.DisplayName)' object for '$($server)'. Error message: $($_)."
        }
    }
}
 
Stop-Transcript