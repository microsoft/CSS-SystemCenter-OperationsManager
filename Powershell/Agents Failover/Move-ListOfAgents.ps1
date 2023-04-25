# ===============================
# Author: Blake Drumm (blakedrumm@microsoft.com)
# Created: September 30th, 2022
# Modified: September 30th, 2022
# Script location: https://github.com/blakedrumm/SCOM-Scripts-and-SQL/blob/master/Powershell/Agents%20Failover/Move-ListOfAgents.ps1
# ===============================

Import-Module OperationsManager

#List of agents to change
$AgentList = @"
SCSM.contoso.local
SQL-SCEM02.contoso.local
"@

#Primary Management Server
$movetoPrimaryMgmtServer = Get-SCOMManagementServer -Name "MS01.contoso.local"
#Secondary Management Server
$movetoFailoverMgmtServer = Get-SCOMManagementServer -Name "MS02.contoso.local"

$i = 0
foreach ($line in ($AgentList -split "`n"))
{
	$SCOMAgents = Get-SCOMAgent $line.trim()
	foreach ($agent in $SCOMAgents)
	{
		$i++
		$i = $i
		
		#Remove Failover Management Server
		Write-Output "($i/$(($AgentList.Trim() -split "`n").Count)) $($agent.DisplayName)`n      Removing Failover: $(($agent.GetFailoverManagementServers()).DisplayName -join ", ")"
		$agent | Set-SCOMParentManagementServer -FailoverServer $null | Out-Null
		#Set Primary Management Server
		Write-Output "      Primary: $(($agent.GetPrimaryManagementServer()).DisplayName) -> $($movetoPrimaryMgmtServer.DisplayName)"
		$agent | Set-SCOMParentManagementServer -PrimaryServer $movetoPrimaryMgmtServer | Out-Null
		#Set Secondary Management Server
		Write-Output "      Failover: $($movetoFailoverMgmtServer.DisplayName)`n"
		$agent | Set-SCOMParentManagementServer -FailoverServer $movetoFailoverMgmtServer | Out-Null
	}
}
