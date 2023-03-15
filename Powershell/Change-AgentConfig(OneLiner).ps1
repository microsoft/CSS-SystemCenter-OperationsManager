#region OneLiner
$ManagementGroup = '<ManagementGroup>'; $ManagementServer = '<ManagementServer>'; [string]$OutFile = "c:\temp\Automate-ChangeSCOMAgent-MS.log"; Stop-Service HealthService -Force; "Removing management group '$ManagementGroup' on agent '$env:computername'" | Out-File -FilePath $OutFile -Append; try { $Agent = New-Object -ComObject AgentConfigManager.MgmtSvcCfg }catch { "Unable to get Agent configuration" | Out-File -FilePath $OutFile -Append; break }; try { $Agent.RemoveManagementGroup($ManagementGroup); $agent.ReloadConfiguration() }catch { "Unable to remove MG, error: " + $_.Exception.Message | Out-File -FilePath $OutFile -Append }; "Successfully removed management group '$ManagementGroup' on agent '$env:computername'" | Out-File -FilePath $OutFile -Append; $regpath1 = "HKLM:\SYSTEM\CurrentControlSet\Services\HealthService\Parameters\Management Groups\$ManagementGroup"; "Removing Registry Key: $regpath1" | Out-File -FilePath $OutFile -Append; Remove-Item "$regpath1" -Force -Recurse -ErrorAction SilentlyContinue; $regpath2 = "HKLM:\SOFTWARE\Microsoft\Microsoft Operations Manager\3.0\Agent Management Groups\$ManagementGroup"; "Removing Registry Key: $regpath2" | Out-File -FilePath $OutFile -Append; Remove-Item "$regpath2" -Force -Recurse -ErrorAction SilentlyContinue; $regpath3 = "$(Get-ItemProperty "HKLM:\SOFTWARE\Microsoft\Microsoft Operations Manager\3.0\Setup" -ErrorAction Stop | Select-Object -Property "InstallDirectory" -ExpandProperty "InstallDirectory")\Health Service State"; "Clearing Health Service State folder: $regpath3" | Out-File -FilePath $OutFile -Append; Remove-Item "$regpath3" -Force -Recurse -ErrorAction SilentlyContinue; Start-Service HealthService; "Adding management group '$ManagementGroup' with server '$ManagementServer' on agent '$env:computername'" | Out-File -FilePath $OutFile -Append; try { $Agent = New-Object -ComObject AgentConfigManager.MgmtSvcCfg }catch { "Unable to get Agent configuration" | Out-File -FilePath $OutFile -Append; break }; try { $Agent.AddManagementGroup($ManagementGroup, $ManagementServer, "5723"); $agent.ReloadConfiguration() }catch { "Unable to add MG, error: " + $_.Exception.Message | Out-File -FilePath $OutFile -Append }; "Successfully added management group '$ManagementGroup' with server '$ManagementServer' on agent '$env:computername'" | Out-File -FilePath $OutFile -Append
#endregion Oneliner

# -----------------------------------------------------------------------------------------------------------------------------------------------------------------------

#region Multiline
$ManagementGroup = '<ManagementGroup>'
$ManagementServer = '<ManagementServer>'

[string]$OutFile = "c:\temp\Automate-ChangeSCOMAgent-MS.log"

Stop-Service HealthService -Force
"Removing management group '$ManagementGroup' on agent '$env:computername'" | Out-File -FilePath $OutFile -Append
try
{
	$Agent = New-Object -ComObject AgentConfigManager.MgmtSvcCfg
}
catch
{
	"Unable to get Agent configuration" | Out-File -FilePath $OutFile -Append
	break
}
try
{
	$Agent.RemoveManagementGroup($ManagementGroup)
	$agent.ReloadConfiguration()
}
catch
{
	"Unable to remove MG, error: " + $_.Exception.Message | Out-File -FilePath $OutFile -Append
}
"Successfully removed management group '$ManagementGroup' on agent '$env:computername'" | Out-File -FilePath $OutFile -Append
$regpath1 = "HKLM:\SYSTEM\CurrentControlSet\Services\HealthService\Parameters\Management Groups\$ManagementGroup"
"Removing Registry Key: $regpath1" | Out-File -FilePath $OutFile -Append
Remove-Item "$regpath1" -Force -Recurse -ErrorAction SilentlyContinue
$regpath2 = "HKLM:\SOFTWARE\Microsoft\Microsoft Operations Manager\3.0\Agent Management Groups\$ManagementGroup"
"Removing Registry Key: $regpath2" | Out-File -FilePath $OutFile -Append
Remove-Item "$regpath2" -Force -Recurse -ErrorAction SilentlyContinue
$regpath3 = "$(Get-ItemProperty "HKLM:\SOFTWARE\Microsoft\Microsoft Operations Manager\3.0\Setup" -ErrorAction Stop | Select-Object -Property "InstallDirectory" -ExpandProperty "InstallDirectory")\Health Service State"
"Clearing Health Service State folder: $regpath3" | Out-File -FilePath $OutFile -Append
Remove-Item "$regpath3" -Force -Recurse -ErrorAction SilentlyContinue
Start-Service HealthService
"Adding management group '$ManagementGroup' with server '$ManagementServer' on agent '$env:computername'" | Out-File -FilePath $OutFile -Append
try
{
	$Agent = New-Object -ComObject AgentConfigManager.MgmtSvcCfg
}
catch
{
	"Unable to get Agent configuration" | Out-File -FilePath $OutFile -Append
	break
}
try
{
	$Agent.AddManagementGroup($ManagementGroup, $ManagementServer, "5723")
	$agent.ReloadConfiguration()
}
catch
{
	"Unable to add MG, error: " + $_.Exception.Message | Out-File -FilePath $OutFile -Append
}

"Successfully added management group '$ManagementGroup' with server '$ManagementServer' on agent '$env:computername'" | Out-File -FilePath $OutFile -Append
#endregion Multiline
